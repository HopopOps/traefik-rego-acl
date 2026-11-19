# traefik-rego-acl

> Canonical repository: [code.hopopops.com/kubernetes/traefik-rego-acl](https://code.hopopops.com/kubernetes/traefik-rego-acl).
> The GitHub repository is a read-only mirror; issues and pull requests opened there are not watched.

A Traefik middleware plugin that authorizes requests with a Rego policy. The policy lives in
the middleware itself; an OPA sidecar next to Traefik evaluates it.

It fills the gap between an authentication middleware, which says who the caller is, and
access rules that depend on the request: network, host, path, method, groups.

## How it works

```
Middleware (policy) -> plugin --validate, push, query--> OPA sidecar (Unix socket)
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
      issuers:
        - issuer: https://accounts.example.com/realms/main
          jwksURI: https://accounts.example.com/realms/main/protocol/openid-connect/certs
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
| `opaURL` | `unix:///run/opa/opa.sock` | Unix socket of the OPA sidecar; nothing else is accepted |
| `headers` | none | Request headers copied into the input |
| `trustedProxies` | none | CIDRs whose `X-Forwarded-For` entries are believed |
| `issuers` | none | `issuer` and `jwksURI` of each token issuer `data.lib.jwt.claims` accepts |
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
| `input.issuers` | The `issuers` of the middleware, issuer to JWKS URL; absent without any |

### Client address

A plugin sees the request and nothing else: Traefik keeps no client address of its own that
it could read. `client_ip` is therefore derived the way Traefik's entrypoints do it:
`X-Forwarded-For` is read only when the TCP peer is in `trustedProxies`, walking from the
right and stopping at the first address that is not. Entries a client prepends sit left of
the one its first trusted proxy appended and are never reached.

- Set `trustedProxies` to the entrypoint's `forwardedHeaders.trustedIPs`, and to nothing on
  an entrypoint that clients reach directly. The entrypoint strips `X-Forwarded-For` from an
  untrusted peer anyway; the plugin's own list guards against an entrypoint left on
  `forwardedHeaders.insecure`.
- Never base a decision on `X-Forwarded-For` or `X-Real-Ip` copied through `headers`: from a
  trusted peer, Traefik passes `X-Real-Ip` through as that proxy sent it.
- To drop headers altogether, put PROXY protocol between the front proxy and Traefik
  (`entryPoints.<name>.proxyProtocol.trustedIPs`): Traefik then rewrites the peer address
  itself and `trustedProxies` stays empty. The front proxy has to pass TCP through rather
  than terminate HTTP.

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
- uses `with`, which can substitute any function, a denied builtin included, for an allowed one;
- calls a builtin that is not in `allowed_builtins` (`opa/system/builtins.rego`). Network,
  runtime introspection, logging and key handling builtins are denied.

`test/sandbox_test.go` fails when a builtin of the OPA version in `test/go.mod` is in neither
list, so an OPA upgrade forces a decision on every new builtin.

The sandbox does not bound evaluation cost: an expensive policy slows the sidecar for every
middleware of that Traefik pod. `timeout` caps what a request waits.

### lib

`data.lib` is trusted code, loaded from files, callable by every policy:

- `data.lib.jwt.claims(token, aud)`: the payload of a token signed by an issuer listed in the
  middleware's `issuers` and issued for `aud`. Undefined otherwise. The JWKS is fetched on the
  first token of an issuer and cached for an hour, keyed by URL.

`lib` may use denied builtins. A `lib` function must never take a URL or a host from its
caller or from unverified input: that would hand the network back to every policy.

A `jwksURI` is fetched by the sidecar from inside the Traefik pod. Whoever can write a
Middleware can therefore make it issue GET requests to any address that pod reaches, response
unseen. Limit the pod's egress with a NetworkPolicy to the backends Traefik routes to and the
identity providers' addresses. The sidecar shares the pod's network namespace, so the policy
cannot tell OPA's traffic from Traefik's: what Traefik must reach, OPA can reach too.

## OPA sidecar

One per Traefik pod, never a shared Service: the policy store is per process.

```
opa run --server --addr unix:///run/opa/opa.sock --unix-socket-perm 600 --diagnostic-addr :8282 /policies
```

The socket lives in a volume the two containers share, and both run as the same user: only
Traefik can open it, and nothing Traefik proxies can reach OPA. The socket is the only
transport: OPA on a TCP port is reachable by anything sharing the pod's network namespace.
`/health` and `/metrics` are served on the diagnostic port.

`/policies` holds the `opa/` tree of this repository, nothing else. OPA must trust the CA of
every `jwksURI`.

The OPA version must be the one pinned in `test/go.mod`, since the builtin lists are checked
against it.

A removed middleware leaves its policy in the sidecar until it restarts.

## Tracing

Two sources, both OTLP, neither needing anything from the plugin's configuration:

- Traefik wraps the plugin in a `Plugin` span carrying `traefik.middleware.name`, once the
  entrypoint or the router has `observability.traceVerbosity: detailed`. Its duration is the
  whole cost of the middleware, OPA round trip included.
- OPA exports its own spans when started with a `distributed_tracing` configuration:

  ```
  opa run ... --set distributed_tracing.type=grpc --set distributed_tracing.address=<collector>:4317
  ```

The plugin forwards `traceparent` and `tracestate` to OPA, so OPA's spans join the trace of a
caller that sent one. They cannot be attached to the trace Traefik starts itself: that span
lives in the request context and Traefik writes it to the headers only when it proxies, after
the middlewares. Without a caller trace, OPA's spans form a trace of their own.

## Deployment

`quay.io/hopopops/traefik-rego-acl:<tag>` (also on `docker.io/hopopops`) is a file tree, not a
program: `/plugin` holds the plugin source and `/opa` the policy tree, so both come from the
same tested commit. It is mounted as an image volume, which needs the `ImageVolume` feature in
the cluster and a runtime that supports it.

Values for the [Traefik Helm chart](https://github.com/traefik/traefik-helm-chart): the plugin
is loaded from the image as a local plugin, OPA runs as a native sidecar (an init container
with `restartPolicy: Always`, so it is up before Traefik builds the middlewares) and listens on
a socket in a volume the two containers share.

```yaml
experimental:
  localPlugins:
    rego-acl:
      type: localPath
      moduleName: github.com/HopopOps/traefik-rego-acl
      volumeName: rego-acl
      mountPath: /plugins-local/src/github.com/HopopOps/traefik-rego-acl
      subPath: plugin

additionalVolumeMounts:
  - name: opa-socket
    mountPath: /run/opa

deployment:
  additionalVolumes:
    - name: rego-acl
      image:
        reference: quay.io/hopopops/traefik-rego-acl:v0.5.0
        pullPolicy: IfNotPresent
    - name: opa-socket
      emptyDir: {}
  initContainers:
    - name: opa
      # The version pinned in test/go.mod: the builtin allowlist is checked against it.
      image: docker.io/openpolicyagent/opa:1.22.4-static
      restartPolicy: Always
      args:
        - run
        - --server
        - --addr=unix:///run/opa/opa.sock
        - --unix-socket-perm=600
        - --diagnostic-addr=:8282
        - --log-format=json
        - --log-level=error
        - /policies
      ports:
        - name: opa-diag
          containerPort: 8282
      startupProbe:
        httpGet:
          path: /health
          port: opa-diag
        periodSeconds: 1
        failureThreshold: 30
      livenessProbe:
        httpGet:
          path: /health
          port: opa-diag
      resources:
        requests:
          cpu: 50m
          memory: 64Mi
        limits:
          memory: 128Mi
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: rego-acl
          mountPath: /policies
          subPath: opa
          readOnly: true
        - name: opa-socket
          mountPath: /run/opa
```

Both containers run as the chart's default user (65532), which `--unix-socket-perm=600`
relies on. The socket path is the plugin's default `opaURL`. If a `jwksURI` is
served under a private CA, mount its bundle into the `opa` container too.

From the [plugin catalog](https://plugins.traefik.io) instead, replace `experimental.localPlugins`
with the block below; the image volume stays, for the sidecar's `/opa`, at the same version:

```yaml
experimental:
  plugins:
    rego-acl:
      moduleName: github.com/HopopOps/traefik-rego-acl
      version: v0.5.0
```

## Tests

```
go test .                 # plugin unit tests
(cd test && go test .)    # sandbox cases, then the plugin under Yaegi against a real opa server
```

`test/` is a module of its own so that OPA and Yaegi stay out of the plugin's `go.mod`.

## License

Copyright 2026 HopopOps.

Licensed under the Apache License, Version 2.0, see [LICENSE](LICENSE).
