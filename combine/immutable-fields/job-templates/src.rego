# @title Job templates cannot change their templates
#
# If a Job has been deployed, its template cannot change.
# The template field is immutable.
#
# @kinds batchv1/Job
package main

deny[msg] {

    # The previous release will come from a file in the releases directory.
    # Set the previous resource to the Job that comes from releases.
    some key
    previous := input[key][_]
    contains(key, "releases")
    previous.kind == "Job"

    latest := input[_][_]
    latest.kind == previous.kind
    latest.metadata.name == previous.metadata.name
    latest.metadata.namespace == previous.metadata.namespace

    not latest.spec.template == previous.spec.template

    msg := sprintf("%v/%v has changed its template. \nWas: %v\n\nNow: %v", [previous.kind, previous.metadata.name, previous.spec.template, latest.spec.template])
}
