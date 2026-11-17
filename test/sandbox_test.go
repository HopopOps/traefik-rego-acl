package test

import (
	"context"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

func modules(t *testing.T, files ...string) []func(*rego.Rego) {
	var opts []func(*rego.Rego)
	for _, f := range files {
		b, err := os.ReadFile("../opa/" + f)
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, rego.Module(f, string(b)))
	}
	return opts
}

func set(t *testing.T, ref string) map[string]bool {
	rs, err := rego.New(append(modules(t, "system/builtins.rego"), rego.Query(ref))...).Eval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, v := range rs[0].Expressions[0].Value.([]any) {
		out[v.(string)] = true
	}
	return out
}

// An OPA upgrade adding a builtin fails here until it is put in one of the two sets.
func TestBuiltinsCoverCapabilities(t *testing.T) {
	allowed, denied := set(t, "data.system.sandbox.allowed_builtins"), set(t, "data.system.sandbox.denied_builtins")
	seen := map[string]bool{}
	for _, b := range ast.CapabilitiesForThisVersion().Builtins {
		seen[b.Name] = true
		if allowed[b.Name] == denied[b.Name] {
			t.Errorf("builtin %s must be in exactly one of allowed_builtins, denied_builtins", b.Name)
		}
	}
	for n := range allowed {
		if !seen[n] {
			t.Errorf("allowed builtin %s does not exist in this OPA version", n)
		}
	}
}

func TestSandbox(t *testing.T) {
	cases := []struct {
		name, source string
		ok           bool
	}{
		{"plain", `allow if input.request.host == "a"`, true},
		{"operators", `allow if { x := count(input.groups) + 1; x > 2; "admin" in input.groups; not input.blocked }`, true},
		{"some in", `allow if { some g in input.groups; startswith(g, "ops-") }`, true},
		{"every", `allow if every g in input.groups { g != "banned" }`, true},
		{"comprehension", `allow if count([g | some g in input.groups; endswith(g, "-admin")]) > 0`, true},
		{"cidr", `allow if net.cidr_contains("10.43.0.0/16", input.request.client_ip)`, true},
		{"template", `allow if $"{input.request.host}" == "a"`, true},
		{"self rule", "default allow := false\nallow if data.mw.x.helper\nhelper if true", true},
		{"local func", "allow if is_ops(input.groups)\nis_ops(gs) if \"ops\" in gs", true},
		{"lib", `allow if data.lib.jwt.claims(input.token, "a").sub == "a"`, true},
		{"lib import", "import data.lib.jwt\nallow if jwt.claims(input.token, \"a\").sub == \"a\"", true},
		{"jwt verify", `allow if { [ok, _, _] := io.jwt.decode_verify(input.token, {"cert": "x"}); ok }`, true},
		// A local rule shadows the builtin: the call resolves to the rule, never to http.send.
		{"shadow", "http.send(x) := 1\nallow if http.send({}) == 1", true},
		{"other mw", `allow if data.mw.y.allow`, false},
		{"import other", "import data.mw.y\nallow if y.allow", false},
		{"bare data", `allow if { x := data; x }`, false},
		{"dynamic data", `allow if { some k; data[k] }`, false},
		{"dynamic mw", `allow if { some k; data.mw[k].allow }`, false},
		{"walk data", `allow if walk(data, _)`, false},
		{"system", `allow if data.system.sandbox`, false},
		{"with other", "allow if data.mw.x.helper with data.mw.y.z as 1\nhelper if true", false},
		{"http.send", `allow if http.send({"method": "get", "url": "http://x"}).status_code == 200`, false},
		{"http.send nested", `allow if count(http.send({"method": "get", "url": "http://x"}).body) > 0`, false},
		{"opa.runtime", `allow if opa.runtime().env`, false},
		{"print", `allow if print("x")`, false},
	}
	q, err := rego.New(append(modules(t, "system/sandbox.rego", "system/builtins.rego"), rego.Query("data.system.sandbox.violations"))...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		rs, err := q.Eval(context.Background(), rego.EvalInput(map[string]any{"name": "x", "source": c.source}))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		v := rs[0].Expressions[0].Value.([]any)
		// Accepted means the server would also take the PUT: the module must compile next to lib.
		var cerr error
		if len(v) == 0 {
			_, cerr = rego.New(append(modules(t, "lib/jwt.rego"), rego.Module("p.rego", "package mw.x\n"+c.source), rego.Query("data.mw.x"))...).PrepareForEval(context.Background())
		}
		if ok := len(v) == 0 && cerr == nil; ok != c.ok {
			t.Errorf("%s: want ok=%v, got violations=%v compile=%v", c.name, c.ok, v, cerr)
		}
	}
}
