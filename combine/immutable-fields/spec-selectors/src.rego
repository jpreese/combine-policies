# @title Workloads cannot change their selectors
#
# If a Workload has been deployed, its selector cannot change.
# The selector field is immutable.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet
package main

deny[msg] {

    # The previous release will come from a file in the releases directory.
    # Set the previous resource to the Job that comes from releases.
    some key
    previous := input[key][_]
    contains(key, "releases")
    kinds := ["Deployment", "DaemonSet", "StatefulSet"]
    previous.kind == kinds[_]

    latest := input[_][_]
    latest.kind == previous.kind
    latest.metadata.name == previous.metadata.name
    latest.metadata.namespace == previous.metadata.namespace

    not latest.spec.selector == previous.spec.selector

    msg := sprintf("%v/%v has changed its selector. \nWas: %v\n\nNow: %v", [previous.kind, previous.metadata.name, previous.spec.selector, latest.spec.selector])
}
