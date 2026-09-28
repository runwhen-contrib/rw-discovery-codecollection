"""rwdiscovery -- the Python core behind the `k8s-discovery` capability.

Everything here is a plain library: enumerate the cluster's API, page through
objects, sanitize them, build their identity chain, compute rollups over
ephemeral objects, and push the result to papi's resource-sync API. The
`capabilities/k8s-discovery/tasks.py` module is a thin `@setup`/`@task`
wrapper over this package, per the RunWhen capability manifest format.
"""

__version__ = "0.1.0"
