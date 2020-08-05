package lib.combine

default is_multidocument = false

is_multidocument {
    input[_][_].kind
}

resources[resource] {
    is_multidocument
    resource = input[_][_]
}

resources[resource] {
    resource = input[_]
}

is_subset(subset, set) {
    matches := {k: v | v := subset[k]; set[k] == v}
    count(subset) == count(matches)
}
