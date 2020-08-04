# If a Service is defined with selectors, ensure that there exists a Pod with labels that the Service matches.
package main

deny[msg] {
    resources := input[_][_]
    resources.kind == "Service"

    not selectors_match(resources.metadata.namespace, resources.spec.selector)

    msg := sprintf("%v/%v: Contains Pod selectors that do not match any Pods", [resources.kind, resources.metadata.name])
}

selectors_match(namespace, selectors) {
    resources := input[_][_]
    resources.metadata.namespace == namespace

    matches := {k: v | v := selectors[k]; resources.spec.template.metadata.labels[k] == v}

    count(selectors) == count(matches)
}
