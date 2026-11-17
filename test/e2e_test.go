package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

type builder = func(next http.Handler, name, policy, opaURL string, trusted []string) (http.Handler, error)

// plugin loads the middleware the way Traefik does: interpreted by Yaegi from a GOPATH.
func plugin(t *testing.T) builder {
	gopath := t.TempDir()
	dir := filepath.Join(gopath, "src/code.hopopops.com/kubernetes")
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

	acl "code.hopopops.com/kubernetes/traefik-rego-acl"
)

func build(next http.Handler, name, policy, opaURL string, trusted []string) (http.Handler, error) {
	c := acl.CreateConfig()
	c.Policy = policy
	c.OPAURL = opaURL
	c.TrustedProxies = trusted
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

func opaBinary(t *testing.T) string {
	bin := filepath.Join(t.TempDir(), "opa")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/open-policy-agent/opa").CombinedOutput(); err != nil {
		t.Fatalf("build opa: %v\n%s", err, out)
	}
	return bin
}

// startOPA runs the server with the flags and the policy tree the sidecar gets.
func startOPA(t *testing.T, bin, addr, conf string) *exec.Cmd {
	cmd := exec.Command(bin, "run", "--server", "--addr", addr, "--authorization=basic", "--log-level=error", conf)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 100; i++ {
		if resp, err := http.Get("http://" + addr + "/health"); err == nil {
			resp.Body.Close()
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

	// The sidecar's tree: the shipped policies plus the deployment's issuer list.
	conf := t.TempDir()
	if err := os.CopyFS(conf, os.DirFS("../opa")); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(conf, "lib/config"), 0o755)
	issuers, _ := json.Marshal(map[string]any{"issuers": map[string]any{idp.URL: map[string]string{"jwks_uri": idp.URL}}})
	if err := os.WriteFile(filepath.Join(conf, "lib/config/data.json"), issuers, 0o644); err != nil {
		t.Fatal(err)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	bin := opaBinary(t)
	opa := startOPA(t, bin, addr, conf)
	build := plugin(t)

	var user string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { user = r.Header.Get("X-User") })
	trusted := []string{"127.0.0.0/8"}
	h, err := build(next, "default-acl@kubernetescrd", policy, "http://"+addr, trusted)
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

	if _, err := build(next, "escape@file", "allow if data.mw.p_default_acl_kubernetescrd.allow", "http://"+addr, nil); err == nil {
		t.Error("policy reading another middleware was accepted")
	}
	if _, err := build(next, "net@file", `allow if http.send({"method": "GET", "url": "http://x"})`, "http://"+addr, nil); err == nil {
		t.Error("policy calling http.send was accepted")
	}
	if _, err := build(next, "broken@file", "allow if {", "http://"+addr, nil); err == nil {
		t.Error("policy with a syntax error was accepted")
	}

	// Only the plugin's three paths are open on the API.
	for _, c := range []struct{ method, path string }{
		{"PUT", "/v1/policies/system/authz"}, {"PUT", "/v1/policies/lib/x"}, {"GET", "/v1/policies"},
		{"GET", "/v1/data"}, {"POST", "/v1/data/lib/jwt"}, {"DELETE", "/v1/policies/mw/x"}, {"PUT", "/v1/data/mw/x"},
	} {
		req, _ := http.NewRequest(c.method, "http://"+addr+c.path, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d, want 401", c.method, c.path, resp.StatusCode)
		}
	}

	// OPA down: fail closed, and a middleware created meanwhile is not an error.
	opa.Process.Kill()
	opa.Wait()
	status, _ = do("GET", "10.43.16.5", "")
	expect("OPA down", status, 500)
	late, err := build(next, "late@file", "allow if true", "http://"+addr, nil)
	if err != nil {
		t.Fatalf("middleware created while OPA is down: %v", err)
	}

	// OPA back with an empty store: both push their policy again on the next request.
	startOPA(t, bin, addr, conf)
	status, _ = do("GET", "10.43.16.5", "")
	expect("after an OPA restart", status, 200)
	rec := httptest.NewRecorder()
	late.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	expect("deferred push", rec.Code, 200)
}
