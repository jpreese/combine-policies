# Deployments and DaemonSets need to be able to select their own Pods
package main

deny[msg] {
    resources := input[_][_]

    valid_resources := ["DaemonSet", "Deployment"]
    resources.kind == valid_resources[_]

    not selectors_match(resources.metadata.namespace, resources.spec.selector.matchLabels)

    msg := sprintf("%v/%v: Does not match its Pod selectors", [resources.kind, resources.metadata.name])
}

selectors_match(namespace, matchLabels) {
    resources := input[_][_]
    resources.metadata.namespace == namespace

    matches := {k: v | v := matchLabels[k]; resources.spec.template.metadata.labels[k] == v}

    count(matchLabels) == count(matches)
}
