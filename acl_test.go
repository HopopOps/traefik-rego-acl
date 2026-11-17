package traefik_rego_acl

import (
	"net"
	"testing"
)

func TestClientIP(t *testing.T) {
	a := &acl{}
	for _, c := range []string{"10.43.13.0/24", "10.43.12.10/32"} {
		_, n, _ := net.ParseCIDR(c)
		a.trusted = append(a.trusted, n)
	}
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.7:4242", nil, "203.0.113.7"},
		{"203.0.113.7:4242", []string{"10.0.0.1"}, "203.0.113.7"},
		{"10.43.13.5:4242", []string{"198.51.100.9"}, "198.51.100.9"},
		{"10.43.13.5:4242", []string{"1.2.3.4, 198.51.100.9, 10.43.12.10"}, "198.51.100.9"},
		{"10.43.13.5:4242", []string{"1.2.3.4", "198.51.100.9,10.43.12.10"}, "198.51.100.9"},
		{"10.43.13.5:4242", []string{"10.43.12.10"}, "10.43.12.10"},
		{"10.43.13.5:4242", nil, "10.43.13.5"},
		{"10.43.13.5:4242", []string{"garbage"}, "garbage"},
	}
	for _, c := range cases {
		if got := a.clientIP(c.remote, c.xff); got != c.want {
			t.Errorf("clientIP(%q, %q) = %q, want %q", c.remote, c.xff, got, c.want)
		}
	}
}

func TestPolicyID(t *testing.T) {
	if policyID("a-b@kubernetescrd") == policyID("a_b@kubernetescrd") {
		t.Error("names sanitizing alike must not share an id")
	}
}
