# The matchLabels selector is an immutable field and can cause deployment issues during an in-place upgrade.
package main

deny[msg] {
    some previous
    previous_resources := input[previous][_]
    contains(previous, "releases")

    match_label_resources := ["Deployment", "DaemonSet"]
    previous_resources.kind == match_label_resources[_]

    current_resources := input["-"][_]
    current_resources.kind == previous_resources.kind
    current_resources.metadata.name == previous_resources.metadata.name
    current_resources.metadata.namespace == previous_resources.metadata.namespace

    not current_resources.spec.selector.matchLabels == previous_resources.spec.selector.matchLabels

    msg := sprintf("%v/%v has different match labels. Was: %v", [previous_resources.kind, previous_resources.metadata.name, previous_resources.spec.selector.matchLabels])
}
