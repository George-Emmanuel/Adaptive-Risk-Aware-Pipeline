package main

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.containers[_].securityContext.runAsNonRoot
  msg := "Containers must run as non-root"
}

deny[msg] {
  input.kind == "Deployment"
  some c
  c := input.spec.template.spec.containers[_]
  c.securityContext.allowPrivilegeEscalation
  msg := "Privilege escalation must be disabled"
}

deny[msg] {
  input.kind == "Deployment"
  not input.metadata.labels["data-classification"]
  msg := "data-classification label is required"
}
