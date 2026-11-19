// Package traefik_rego_acl is a Traefik middleware plugin authorizing requests with a Rego
// policy carried by the middleware and evaluated by an OPA server.
package traefik_rego_acl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config is the middleware configuration.
type Config struct {
	// Policy is the Rego source, without a package line.
	Policy string `json:"policy,omitempty"`
	// OPAURL is the unix:// socket of the OPA sidecar.
	OPAURL string `json:"opaURL,omitempty"`
	// Headers lists the request headers copied into input.request.headers.
	Headers []string `json:"headers,omitempty"`
	// TrustedProxies are the CIDRs whose X-Forwarded-For entries are believed.
	TrustedProxies []string `json:"trustedProxies,omitempty"`
	DenyStatus     int      `json:"denyStatus,omitempty"`
	Timeout        string   `json:"timeout,omitempty"`
	// Issuers are the token issuers data.lib.jwt.claims accepts for this middleware.
	Issuers []Issuer `json:"issuers,omitempty"`
}

// Issuer is a token issuer and the URL of its signing keys.
type Issuer struct {
	Issuer  string `json:"issuer,omitempty"`
	JWKSURI string `json:"jwksURI,omitempty"`
}

// CreateConfig returns the defaults.
func CreateConfig() *Config {
	return &Config{
		OPAURL:     "unix:///run/opa/opa.sock",
		DenyStatus: http.StatusForbidden,
		Timeout:    "1s",
	}
}

type acl struct {
	next       http.Handler
	name       string
	id         string
	policy     string
	headers    []string
	trusted    []*net.IPNet
	issuers    map[string]string
	denyStatus int
	timeout    time.Duration
	client     *http.Client

	mu     sync.Mutex
	pushed bool
}

// errRejected marks a policy OPA or the sandbox refused: retrying cannot help.
var errRejected = errors.New("policy rejected")

var nonIdent = regexp.MustCompile(`[^a-z0-9_]`)

// policyID turns a middleware name into a Rego identifier. The hash keeps two names that
// sanitize alike ("a-b", "a_b") from sharing a policy.
func policyID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "p_" + nonIdent.ReplaceAllString(strings.ToLower(name), "_") + "_" + hex.EncodeToString(sum[:4])
}

// New builds the middleware. A policy the sandbox or the compiler rejects is an error; an
// unreachable OPA is not, the push is retried on the first requests, which are denied meanwhile.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if strings.TrimSpace(config.Policy) == "" {
		return nil, errors.New("policy is empty")
	}
	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	if config.DenyStatus < 400 || config.DenyStatus > 599 {
		return nil, fmt.Errorf("denyStatus %d is not a 4xx or 5xx", config.DenyStatus)
	}
	socket, ok := strings.CutPrefix(config.OPAURL, "unix://")
	if !ok || socket == "" {
		return nil, fmt.Errorf("opaURL %q is not a unix:// socket", config.OPAURL)
	}
	a := &acl{
		next:       next,
		name:       name,
		id:         policyID(name),
		policy:     config.Policy,
		issuers:    map[string]string{},
		denyStatus: config.DenyStatus,
		timeout:    timeout,
		// The default transport keeps 2 idle connections per host: more concurrent requests
		// than that would each dial OPA.
		client: &http.Client{Transport: &http.Transport{
			MaxIdleConnsPerHost: 256,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}},
	}
	for _, h := range config.Headers {
		a.headers = append(a.headers, http.CanonicalHeaderKey(h))
	}
	for _, c := range config.TrustedProxies {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("trustedProxies: %w", err)
		}
		a.trusted = append(a.trusted, n)
	}
	for _, i := range config.Issuers {
		u, err := url.Parse(i.JWKSURI)
		if i.Issuer == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("issuers: %q needs an issuer and an http(s) jwksURI", i.Issuer)
		}
		if _, dup := a.issuers[i.Issuer]; dup {
			return nil, fmt.Errorf("issuers: %q listed twice", i.Issuer)
		}
		a.issuers[i.Issuer] = i.JWKSURI
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := a.push(ctx); err != nil {
		if errors.Is(err, errRejected) {
			return nil, err
		}
		a.log("policy not pushed yet: %v", err)
	}
	return a, nil
}

func (a *acl) log(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rego-acl %s: %s\n", a.name, fmt.Sprintf(format, args...))
}

type traceKey struct{}

// The W3C trace context of the incoming request, forwarded so that OPA's spans join the
// caller's trace. Traefik's own span is out of reach of a plugin: it lives in the context.
var traceHeaders = []string{"Traceparent", "Tracestate"}

// call sends one request to OPA and returns the status and the body.
func (a *acl) call(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://opa"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if trace, ok := ctx.Value(traceKey{}).(http.Header); ok {
		for _, h := range traceHeaders {
			if v := trace.Get(h); v != "" {
				req.Header.Set(h, v)
			}
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

func (a *acl) query(ctx context.Context, path string, input any, out any) error {
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return err
	}
	status, raw, err := a.call(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("POST %s: %d: %s", path, status, raw)
	}
	return json.Unmarshal(raw, out)
}

type violations struct {
	Result *[]string `json:"result"`
}

// push validates the policy against the sandbox, then loads it into OPA.
func (a *acl) push(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var v violations
	err := a.query(ctx, "/v1/data/system/sandbox/violations", map[string]string{"name": a.id, "source": a.policy}, &v)
	if err != nil {
		return err
	}
	// No result means OPA runs without the sandbox policy: never push unchecked.
	if v.Result == nil {
		return errors.New("OPA has no system.sandbox policy loaded")
	}
	if len(*v.Result) > 0 {
		return fmt.Errorf("%w: %s", errRejected, strings.Join(*v.Result, "; "))
	}

	module := "package mw." + a.id + "\n" + a.policy
	status, raw, err := a.call(ctx, http.MethodPut, "/v1/policies/mw/"+a.id, "text/plain", []byte(module))
	if err != nil {
		return err
	}
	if status == http.StatusBadRequest {
		return fmt.Errorf("%w: %s", errRejected, raw)
	}
	if status != http.StatusOK {
		return fmt.Errorf("PUT policy: %d: %s", status, raw)
	}
	a.pushed = true
	return nil
}

type result struct {
	Allow   bool              `json:"allow"`
	Headers map[string]string `json:"headers"`
	Status  int               `json:"status"`
	Reason  string            `json:"reason"`
}

type decision struct {
	Result *result `json:"result"`
}

// decide evaluates the policy. A missing result means OPA lost the policy (it restarted):
// push it again and ask once more.
func (a *acl) decide(ctx context.Context, input any) (*result, error) {
	a.mu.Lock()
	pushed := a.pushed
	a.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if !pushed {
			if err := a.push(ctx); err != nil {
				return nil, err
			}
		}
		var d decision
		if err := a.query(ctx, "/v1/data/mw/"+a.id, input, &d); err != nil {
			return nil, err
		}
		if d.Result != nil {
			return d.Result, nil
		}
		pushed = false
	}
	return nil, errors.New("policy absent from OPA after a push")
}

func (a *acl) trustedIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range a.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP walks X-Forwarded-For from the right and returns the first address that is not a
// trusted proxy, the way the peer address is believed only as far as the proxies we know.
func (a *acl) clientIP(remoteAddr string, forwardedFor []string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	if !a.trustedIP(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(forwardedFor, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		ip = hop
		if !a.trustedIP(hop) {
			break
		}
	}
	return ip
}

func (a *acl) input(req *http.Request) map[string]any {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	headers := map[string]string{}
	for _, h := range a.headers {
		if v := req.Header.Values(h); len(v) > 0 {
			headers[strings.ToLower(h)] = strings.Join(v, ", ")
		}
	}
	in := map[string]any{
		"middleware": a.name,
		"request": map[string]any{
			"method":    req.Method,
			"scheme":    scheme,
			"host":      strings.ToLower(host),
			"path":      req.URL.Path,
			"query":     req.URL.Query(),
			"protocol":  req.Proto,
			"headers":   headers,
			"client_ip": a.clientIP(req.RemoteAddr, req.Header.Values("X-Forwarded-For")),
		},
	}
	if auth := req.Header.Get("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		in["token"] = auth[7:]
	}
	if len(a.issuers) > 0 {
		in["issuers"] = a.issuers
	}
	return in
}

func (a *acl) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithValue(req.Context(), traceKey{}, req.Header), a.timeout)
	res, err := a.decide(ctx, a.input(req))
	cancel()
	if err != nil {
		a.log("%v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !res.Allow {
		status := a.denyStatus
		if res.Status >= 400 && res.Status <= 599 {
			status = res.Status
		}
		reason := res.Reason
		if reason == "" {
			reason = http.StatusText(status)
		}
		http.Error(w, reason, status)
		return
	}
	for k, v := range res.Headers {
		req.Header.Set(k, v)
	}
	a.next.ServeHTTP(w, req)
}
