# traefik-rego-acl

A Traefik middleware plugin that authorizes requests with a Rego policy. The policy lives in
the middleware itself; an OPA sidecar next to Traefik evaluates it.

It fills the gap between an authentication middleware, which says who the caller is, and
access rules that depend on the request: network, host, path, method, groups.

## How it works

```
Middleware (policy) -> plugin --validate, push, query--> OPA sidecar (127.0.0.1:8181)
```

- When Traefik builds the middleware, the plugin submits the policy to the sandbox check, then
  loads it into OPA under a package of its own, `data.mw.<id>`, `<id>` being derived from the
  middleware name.
- For each request it posts an input document to that package and applies the decision.
- OPA keeps policies in memory. When it restarts, the plugin notices the missing policy on
  the next request and loads it again.

The plugin is interpreted by Yaegi and uses the standard library only. OPA itself cannot run
in Yaegi, which is why it sits in a sidecar.

Failure modes, all closed:

| Situation | Outcome |
| --- | --- |
| Policy rejected by the sandbox or the Rego compiler | The middleware fails to build; routers using it are down, others are untouched |
| OPA unreachable when the middleware is built | The middleware builds, requests get `500` until the policy can be pushed |
| OPA unreachable or slower than `timeout` on a request | `500` |
| `allow` is not `true` | `denyStatus`, or the policy's own `status` |

## Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: admins-or-lab
spec:
  plugin:
    rego-acl:
      trustedProxies:
        - 10.43.12.10/32
      headers:
        - X-Forwarded-Proto
      policy: |
        default allow := false

        claims := data.lib.jwt.claims(input.token, "whoami")

        allow if {
          input.request.method == "GET"
          net.cidr_contains("10.43.0.0/16", input.request.client_ip)
        }

        allow if "admins" in claims.groups

        headers["X-User"] := claims.sub

        status := 401 if not input.token
```

| Key | Default | Meaning |
| --- | --- | --- |
| `policy` | required | Rego source, without a `package` line |
| `opaURL` | `http://127.0.0.1:8181` | OPA API, or `unix:///path/to/opa.sock` |
| `headers` | none | Request headers copied into the input |
| `trustedProxies` | none | CIDRs whose `X-Forwarded-For` entries are believed |
| `denyStatus` | `403` | Status of a denial |
| `timeout` | `1s` | Budget for the OPA calls of one request |

### Input

| Path | Content |
| --- | --- |
| `input.request.method`, `.scheme`, `.host`, `.path`, `.protocol` | `host` is lowercase, without port |
| `input.request.query` | Object of string arrays |
| `input.request.headers` | The configured headers only, names in lowercase |
| `input.request.client_ip` | Peer address, or the rightmost `X-Forwarded-For` entry that is not a trusted proxy |
| `input.token` | Bearer token of `Authorization`, unverified; absent without one |
| `input.middleware` | Middleware name |

### Decision

| Rule | Type | Effect |
| --- | --- | --- |
| `allow` | boolean | Anything but `true` denies |
| `headers` | object of strings | Set on the request passed upstream, on allow |
| `status` | 400-599 | Replaces `denyStatus` |
| `reason` | string | Body of the denial |

## Sandbox

A policy is checked by `opa/system/sandbox.rego` before it is loaded, and refused when it:

- references `data` outside its own package and `data.lib` (other middlewares, `data.system`,
  a bare or dynamic `data` reference);
- calls a builtin that is not in `allowed_builtins` (`opa/system/builtins.rego`). Network,
  runtime introspection, logging and key handling builtins are denied.

`test/sandbox_test.go` fails when a builtin of the OPA version in `test/go.mod` is in neither
list, so an OPA upgrade forces a decision on every new builtin.

The sandbox does not bound evaluation cost: an expensive policy slows the sidecar for every
middleware of that Traefik pod. `timeout` caps what a request waits.

### lib

`data.lib` is trusted code, loaded from files, callable by every policy:

- `data.lib.jwt.claims(token, aud)`: the payload of a token signed by an issuer listed in
  `data.lib.config.issuers` and issued for `aud`. Undefined otherwise.

`lib` may use denied builtins. A `lib` function must never take a URL or a host from its
caller or from unverified input: that would hand the network back to every policy.

## OPA sidecar

One per Traefik pod, never a shared Service: the policy store is per process.

```
opa run --server --addr 127.0.0.1:8181 --authorization=basic /policies
```

`/policies` holds the `opa/` tree of this repository plus the deployment's issuers, in
`/policies/lib/config/data.json`:

```json
{"issuers": {"https://accounts.example.com/realms/main": {"jwks_uri": "https://accounts.example.com/realms/main/protocol/openid-connect/certs"}}}
```

`opa/system/authz.rego` opens only what the plugin calls: `PUT /v1/policies/mw/<id>`,
`POST /v1/data/mw/<id>`, the sandbox check and `GET /health`. The OPA version must be the one
pinned in `test/go.mod`, since the builtin lists are checked against it.

Over a Unix socket in a volume the two containers share, nothing Traefik proxies can reach
OPA and `system.authz`, about 40% of a decision's round trip, is no longer needed. Both
containers must run as the same user:

```
opa run --server --addr unix:///run/opa/opa.sock --unix-socket-perm 600 /policies
```

with `opaURL: unix:///run/opa/opa.sock` on each middleware.

A removed middleware leaves its policy in the sidecar until it restarts.

## Image

`code.hopopops.com/kubernetes/traefik-rego-acl:<tag>` is a file tree, not a program: `/plugin`
holds the plugin source and `/opa` the policy tree, so both come from the same tested commit.
It is meant to be mounted as an image volume, `/plugin` into Traefik at
`/plugins-local/src/code.hopopops.com/kubernetes/traefik-rego-acl` and `/opa` into the sidecar.

## Tests

```
go test .                 # plugin unit tests
(cd test && go test .)    # sandbox cases, then the plugin under Yaegi against a real opa server
```

`test/` is a module of its own so that OPA and Yaegi stay out of the plugin's `go.mod`.
