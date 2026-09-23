# rw-discovery-codecollection

RunWhen CodeCollection for infrastructure discovery -- a **capability image**, built on the
`runwhen_capability` SDK and its `rwtask` task host, not a Robot codebundle collection.

Ships the `k8s-discovery` capability: it enumerates a Kubernetes cluster's resources, sanitizes
them at the source, and pushes them to papi's resource inventory. See `capabilities/k8s-discovery/`
once it lands on `resources-design` for the manifest, tasks and pack.
