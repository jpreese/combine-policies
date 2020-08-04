# If a ServiceMonitor is defined with selectors, ensure that there exists a Service with labels that the ServiceMonitor matches.
package main

deny[msg] {
    resources := input[_][_]
    resources.kind == "ServiceMonitor"

    # Do not consider the kube-system namespace for evaluation.
    # These Services are created by Rancher.
    resources.metadata.namespace != "kube-system"

    not excluded_monitor(resources)
    not service_labels_exist(resources.metadata.namespace, resources.spec.selector.matchLabels)

    msg := sprintf("%v/%v: Contains Service selectors that do not match any Services", [resources.kind, resources.metadata.name])
}

service_labels_exist(namespace, matchLabels) {
    resources := input[_][_]
    resources.kind == "Service"
    resources.metadata.namespace == namespace

    matches := {k: v | v := matchLabels[k]; resources.metadata.labels[k] == v}

    count(matchLabels) == count(matches)
}

# Both the prometheus and the alertmanager ServiceMonitors reference Services that
# are created by the Prometheus Operator and do not exist in the platform.
excluded_monitor(monitor) {
    monitor.metadata.namespace == "monitoring"

    excluded_monitors := ["prometheus", "alertmanager"]
    monitor.metadata.name == excluded_monitors[_]
}
