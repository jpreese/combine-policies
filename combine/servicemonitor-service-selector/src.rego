# @title ServiceMonitors must be able to match their Services
#
# ServiceMonitors that define selectors must be able to match a Service.
#
# @kinds monitoring.coreos.com/ServiceMonitor
package main

import data.lib.combine

deny[msg] {
    resource := combine.resources[_]
    resource.kind == "ServiceMonitor"

    # Do not consider the kube-system namespace for evaluation.
    # These Services are created by Rancher.
    resource.metadata.namespace != "kube-system"

    not excluded_monitor(resource)
    not service_labels_exist(resource.metadata.namespace, resource.spec.selector.matchLabels)

    msg := sprintf("%v/%v: Contains Service selectors that do not match any Services", [resource.kind, resource.metadata.name])
}

service_labels_exist(namespace, matchLabels) {
    resource := combine.resources[_]

    resource.kind == "Service"
    resource.metadata.namespace == namespace
    combine.is_subset(matchLabels, resource.metadata.labels)
}

# Both the prometheus and the alertmanager ServiceMonitors reference Services that
# are created by the Prometheus Operator and do not exist in the platform.
excluded_monitor(monitor) {
    monitor.metadata.namespace == "monitoring"

    excluded_monitors := ["prometheus", "alertmanager"]
    monitor.metadata.name == excluded_monitors[_]
}
