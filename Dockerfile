# Not a runnable image: a file tree mounted into the Traefik pod as an image volume.
# /plugin is the plugin source Traefik loads, /opa the policy tree of the OPA sidecar.
FROM scratch
COPY .traefik.yml go.mod acl.go /plugin/
COPY opa /opa
