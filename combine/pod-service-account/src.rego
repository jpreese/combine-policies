# @title Dependent ServiceAccount exists
#
# If a resource depends on a ServiceAccount by setting the
# template.spec.serviceAccountName field, the named ServiceAccount must exist.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package main

import data.lib.combine

deny[msg] {
    resource := combine.resources[_]
    serviceAccount := resource.spec.template.spec.serviceAccountName

    not service_account_exists(resource.metadata.namespace, serviceAccount)

    msg := sprintf("%v/%v: References ServiceAccount %v/%v which was not found", [resource.kind, resource.metadata.name, resource.metadata.namespace, serviceAccount])
}

service_account_exists(namespace, serviceAccount) {
    resource := combine.resources[_]

    resource.kind == "ServiceAccount"
    resource.metadata.namespace == namespace
    resource.metadata.name == serviceAccount
}
