# @title Services must be able to match their selectors
#
# Services that define selectors must be able to match a resource.
#
# @kinds core/Service
package main

import data.lib.combine

deny[msg] {
    resource := combine.resources[_]
    resource.kind == "Service"

    not selectors_match(resource.metadata.namespace, resource.spec.selector)

    msg := sprintf("%v/%v: Contains Pod selectors that do not match any Pods", [resource.kind, resource.metadata.name])
}

selectors_match(namespace, selectors) {
    resource := combine.resources[_]

    resource.metadata.namespace == namespace
    combine.is_subset(selectors, resource.spec.template.metadata.labels)
}
