package system.sandbox

allowed_prefixes := [["mw", input.name], ["lib"]]

module := rego.parse_module("policy.rego", concat("\n", [sprintf("package mw.%s", [input.name]), input.source]))

# Names a call may resolve to without being a builtin: the policy's own rules, and import aliases
# (whose targets are checked by the data rule below).
local_heads contains rule.head.ref[0].value if some rule in module.rules

local_heads contains imp_alias(imp) if some imp in module.imports

imp_alias(imp) := imp.alias if imp.alias

imp_alias(imp) := imp.path.value[count(imp.path.value) - 1].value if not imp.alias

violations contains msg if {
	walk(module, [path, node])
	path[0] != "package"
	node == {"type": "var", "value": "data"}
	not compliant_data_ref(path)
	msg := sprintf("reference to data outside mw.%s or lib", [input.name])
}

violations contains msg if {
	some op in operators
	op.type == "ref"
	op.value[0].type == "var"
	not local_heads[op.value[0].value]
	op.value[0].value != "data"
	name := ref_name(op.value)
	not allowed_builtins[name]
	msg := sprintf("builtin %s is not allowed", [name])
}

# with replaces data, input or a function, builtins included: `count(x) with count as http.send`
# calls a denied builtin under an allowed name.
violations contains "with is not allowed" if {
	walk(module, [_, node])
	node["with"]
}

violations contains "unsupported call expression" if {
	some op in operators
	op.type != "ref"
}

# Operator position of an expression call (a == b, f(x)) and of a call term (count(f(x))).
operators contains node.terms[0] if {
	walk(module, [_, node])
	is_array(node.terms)
}

operators contains node.value[0] if {
	walk(module, [_, node])
	node.type == "call"
}

ref_name(terms) := concat(".", [t.value | some t in terms]) if {
	every t in array.slice(terms, 1, count(terms)) {
		t.type == "string"
	}
}

ref_name(terms) := "<dynamic>" if {
	some t in array.slice(terms, 1, count(terms))
	t.type != "string"
}

compliant_data_ref(path) if {
	count(path) >= 2
	path[count(path) - 1] == 0
	parent := object.get(module, array.slice(path, 0, count(path) - 2), null)
	parent.type == "ref"
	some prefix in allowed_prefixes
	count(parent.value) > count(prefix)
	every i, p in prefix {
		parent.value[i + 1] == {"type": "string", "value": p}
	}
}
