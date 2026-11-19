package test

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const policy = `
default allow := false

claims := data.lib.jwt.claims(input.token, "whoami")

allow if {
	input.request.method == "GET"
	net.cidr_contains("10.43.0.0/16", input.request.client_ip)
}

allow if "admins" in claims.groups

headers["X-User"] := claims.sub

status := 401 if not input.token

reason := "token required" if not input.token
`

type builder = func(next http.Handler, name, policy, opaURL string, trusted []string, issuers map[string]string) (http.Handler, error)

// plugin loads the middleware the way Traefik does: interpreted by Yaegi from a GOPATH.
func plugin(t testing.TB) builder {
	gopath := t.TempDir()
	dir := filepath.Join(gopath, "src/github.com/HopopOps")
	root, _ := filepath.Abs("..")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "traefik-rego-acl")); err != nil {
		t.Fatal(err)
	}
	i := interp.New(interp.Options{GoPath: gopath})
	if err := i.Use(stdlib.Symbols); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Eval(`
import (
	"context"
	"net/http"

	acl "github.com/HopopOps/traefik-rego-acl"
)

func build(next http.Handler, name, policy, opaURL string, trusted []string, issuers map[string]string) (http.Handler, error) {
	c := acl.CreateConfig()
	c.Policy = policy
	c.OPAURL = opaURL
	c.TrustedProxies = trusted
	for iss, jwks := range issuers {
		c.Issuers = append(c.Issuers, acl.Issuer{Issuer: iss, JWKSURI: jwks})
	}
	return acl.New(context.Background(), next, c, name)
}
`); err != nil {
		t.Fatal(err)
	}
	v, err := i.Eval("build")
	if err != nil {
		t.Fatal(err)
	}
	return v.Interface().(builder)
}

func opaBinary(t testing.TB) string {
	bin := filepath.Join(t.TempDir(), "opa")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/open-policy-agent/opa").CombinedOutput(); err != nil {
		t.Fatalf("build opa: %v\n%s", err, out)
	}
	return bin
}

func socket(t testing.TB) string {
	return "unix://" + filepath.Join(t.TempDir(), "opa.sock")
}

// startOPA runs the server with the flags and the policy tree the sidecar gets.
func startOPA(t testing.TB, bin, addr, conf string, extra ...string) *exec.Cmd {
	cmd := exec.Command(bin, append([]string{"run", "--server", "--addr", addr, "--log-level=error", conf}, extra...)...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for range 100 {
		if c, err := net.Dial("unix", strings.TrimPrefix(addr, "unix://")); err == nil {
			c.Close()
			return cmd
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("opa did not become healthy")
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func token(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	signed := b64([]byte(`{"alg":"ES256","typ":"JWT","kid":"k"}`)) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func TestEndToEnd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","alg":"ES256","use":"sig","x":%q,"y":%q}]}`,
			b64(key.X.FillBytes(make([]byte, 32))), b64(key.Y.FillBytes(make([]byte, 32))))
	}))
	defer idp.Close()

	addr := socket(t)
	bin := opaBinary(t)
	opa := startOPA(t, bin, addr, "../opa")
	build := plugin(t)

	var user string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { user = r.Header.Get("X-User") })
	trusted := []string{"127.0.0.0/8"}
	h, err := build(next, "default-acl@kubernetescrd", policy, addr, trusted, map[string]string{idp.URL: idp.URL})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	do := func(method, xff, bearer string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+"/x", nil)
		req.Header.Set("X-Forwarded-For", xff)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}
	claims := func(aud string, groups ...string) map[string]any {
		return map[string]any{"iss": idp.URL, "aud": aud, "sub": "vianney", "groups": groups, "exp": time.Now().Add(time.Hour).Unix()}
	}
	expect := func(what string, gotStatus int, wantStatus int) {
		t.Helper()
		if gotStatus != wantStatus {
			t.Errorf("%s: status %d, want %d", what, gotStatus, wantStatus)
		}
	}

	status, _ := do("GET", "10.43.16.5", "")
	expect("GET from the lab", status, 200)
	status, _ = do("GET", "198.51.100.9", "")
	expect("GET from outside without a token", status, 401)
	status, body := do("POST", "10.43.16.5", "")
	expect("POST without a token", status, 401)
	if body != "token required" {
		t.Errorf("deny reason = %q", body)
	}
	user = ""
	status, _ = do("POST", "198.51.100.9", token(t, key, claims("whoami", "admins")))
	expect("admin token", status, 200)
	if user != "vianney" {
		t.Errorf("X-User = %q, want vianney", user)
	}
	status, _ = do("POST", "198.51.100.9", token(t, key, claims("whoami", "users")))
	expect("token outside admins", status, 403)
	status, _ = do("POST", "198.51.100.9", token(t, key, claims("other", "admins")))
	expect("token for another audience", status, 403)
	status, _ = do("POST", "198.51.100.9", token(t, other, claims("whoami", "admins")))
	expect("token signed by another key", status, 403)

	if _, err := build(next, "escape@file", "allow if data.mw.p_default_acl_kubernetescrd.allow", addr, nil, nil); err == nil {
		t.Error("policy reading another middleware was accepted")
	}
	if _, err := build(next, "net@file", `allow if http.send({"method": "GET", "url": "http://x"})`, addr, nil, nil); err == nil {
		t.Error("policy calling http.send was accepted")
	}
	if _, err := build(next, "broken@file", "allow if {", addr, nil, nil); err == nil {
		t.Error("policy with a syntax error was accepted")
	}

	// Issuers are per middleware: a valid token means nothing to one that does not list its issuer.
	stranger, err := build(next, "stranger@file", `allow if data.lib.jwt.claims(input.token, "whoami")`, addr, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token(t, key, claims("whoami", "admins")))
	rec := httptest.NewRecorder()
	stranger.ServeHTTP(rec, req)
	expect("token from an issuer the middleware does not list", rec.Code, 403)
	if _, err := build(next, "bad@file", "allow if true", addr, nil, map[string]string{"x": "file:///etc/passwd"}); err == nil {
		t.Error("issuer with a file jwksURI was accepted")
	}

	if _, err := build(next, "tcp@file", "allow if true", "http://127.0.0.1:8181", nil, nil); err == nil {
		t.Error("TCP opaURL was accepted")
	}

	// OPA down: fail closed, and a middleware created meanwhile is not an error.
	opa.Process.Kill()
	opa.Wait()
	status, _ = do("GET", "10.43.16.5", "")
	expect("OPA down", status, 500)
	late, err := build(next, "late@file", "allow if true", addr, nil, nil)
	if err != nil {
		t.Fatalf("middleware created while OPA is down: %v", err)
	}

	// OPA back with an empty store: both push their policy again on the next request.
	startOPA(t, bin, addr, "../opa")
	status, _ = do("GET", "10.43.16.5", "")
	expect("after an OPA restart", status, 200)
	rec = httptest.NewRecorder()
	late.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	expect("deferred push", rec.Code, 200)
}

// OPA's spans must land in the trace of the request the plugin is deciding on.
func TestTracePropagation(t *testing.T) {
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	raw, _ := hex.DecodeString(traceID)
	seen := make(chan struct{}, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			body, _ = gzip.NewReader(r.Body)
		}
		if b, _ := io.ReadAll(body); bytes.Contains(b, raw) {
			select {
			case seen <- struct{}{}:
			default:
			}
		}
	}))
	defer collector.Close()

	addr := socket(t)
	startOPA(t, opaBinary(t), addr, "../opa",
		"--set", "distributed_tracing.type=http",
		"--set", "distributed_tracing.address="+strings.TrimPrefix(collector.URL, "http://"),
		"--set", "distributed_tracing.batch_span_processor_options.batch_timeout_ms=100")
	h, err := plugin(t)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "trace@file", "default allow := true", addr, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("no span of the request's trace reached the collector")
	}
}
