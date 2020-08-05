# @title Workloads must be able to match their Pods
#
# Workloads that define a selector must be able to select the pods
# that they create.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet
package main

import data.lib.combine

deny[msg] {
    resource := combine.resources[_]

    valid_resources := ["DaemonSet", "Deployment", "StatefulSet"]
    resource.kind == valid_resources[_]

    not selectors_match(resource.metadata.namespace, resource.spec.selector.matchLabels)

    msg := sprintf("%v/%v: Does not match its Pod selectors", [resource.kind, resource.metadata.name])
}

selectors_match(namespace, matchLabels) {
    resource := combine.resources[_]
    resource.metadata.namespace == namespace

    combine.is_subset(matchLabels, resource.spec.template.metadata.labels)
}
