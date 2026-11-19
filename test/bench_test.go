package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	acl "code.hopopops.com/kubernetes/traefik-rego-acl"
)

// The policy of the whoami canary on eored.
const canary = `
default allow := false

lan := {"10.43.0.0/16", "192.168.0.0/16"}

allow if {
	input.request.method == "GET"
	some cidr in lan
	net.cidr_contains(cidr, input.request.client_ip)
	not startswith(input.request.path, "/acl/deny")
}

headers["X-Acl-Client-Ip"] := input.request.client_ip

reason := "denied by the whoami test policy"
`

// BenchmarkDecision splits the cost of one allowed request: the OPA round trip alone, the
// plugin compiled, and the plugin interpreted by Yaegi as in Traefik.
func BenchmarkDecision(b *testing.B) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	startOPA(b, opaBinary(b), addr, "../opa")
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	interpreted, err := plugin(b)(next, "bench@file", canary, "http://"+addr, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	cfg := acl.CreateConfig()
	cfg.Policy = canary
	cfg.OPAURL = "http://" + addr
	compiled, err := acl.New(b.Context(), next, cfg, "bench@file")
	if err != nil {
		b.Fatal(err)
	}

	serve := func(h http.Handler) func(*testing.B) {
		return func(b *testing.B) {
			for b.Loop() {
				req := httptest.NewRequest("GET", "https://whoami.hopopops.com/acl", nil)
				req.RemoteAddr = "192.168.1.2:4242"
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != 200 {
					b.Fatalf("status %d", rec.Code)
				}
			}
		}
	}
	b.Run("opa", func(b *testing.B) {
		body := []byte(`{"input":{"middleware":"bench@file","request":{"method":"GET","scheme":"https","host":"whoami.hopopops.com","path":"/acl","query":{},"protocol":"HTTP/1.1","headers":{},"client_ip":"192.168.1.2"}}}`)
		// The id the plugin derives for "bench@file".
		sum := sha256.Sum256([]byte("bench@file"))
		url := "http://" + addr + "/v1/data/mw/p_bench_file_" + hex.EncodeToString(sum[:4])
		for b.Loop() {
			resp, err := http.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
	// 32 clients at once, the shape that exhausts the transport's idle connections.
	parallel := func(h http.Handler) func(*testing.B) {
		return func(b *testing.B) {
			b.SetParallelism(32 / runtime.GOMAXPROCS(0))
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req := httptest.NewRequest("GET", "https://whoami.hopopops.com/acl", nil)
					req.RemoteAddr = "192.168.1.2:4242"
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					if rec.Code != 200 {
						b.Errorf("status %d", rec.Code)
						return
					}
				}
			})
		}
	}
	socket := "unix://" + filepath.Join(b.TempDir(), "opa.sock")
	startOPA(b, opaBinary(b), socket, "../opa")
	unix, err := plugin(b)(next, "bench@file", canary, socket, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("compiled", serve(compiled))
	b.Run("yaegi", serve(interpreted))
	b.Run("compiled-parallel", parallel(compiled))
	b.Run("yaegi-parallel", parallel(interpreted))
	b.Run("yaegi-unix", serve(unix))
	b.Run("yaegi-unix-parallel", parallel(unix))
}
