# If a resource depends on a ServiceAccount, ensure that the ServiceAccount exists.
package main

deny[msg] {
    resources := input[_][_]
    serviceAccount := resources.spec.template.spec.serviceAccountName

    not service_account_exists(resources.metadata.namespace, serviceAccount)

    msg := sprintf("%v/%v: References ServiceAccount %v/%v which was not found", [resources.kind, resources.metadata.name, resources.metadata.namespace, serviceAccount])
}

service_account_exists(namespace, serviceAccount) {
    resources := input[_][_]
    resources.kind == "ServiceAccount"

    resources.metadata.namespace == namespace
    resources.metadata.name == serviceAccount
}
