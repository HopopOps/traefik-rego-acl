package system.authz

# The API surface the plugin needs, nothing else: system.* and lib.* stay file-loaded.

default allow := false

allow if {
	input.method == "PUT"
	count(input.path) == 4
	array.slice(input.path, 0, 3) == ["v1", "policies", "mw"]
}

allow if {
	input.method == "POST"
	count(input.path) == 4
	array.slice(input.path, 0, 3) == ["v1", "data", "mw"]
}

allow if {
	input.method == "POST"
	input.path == ["v1", "data", "system", "sandbox", "violations"]
}

allow if {
	input.method == "GET"
	input.path == ["health"]
}
