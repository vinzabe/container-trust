"""ctrust — a container admission gate that refuses untraceable images.

The supply-chain question for a running container is simple to ask and hard to
enforce: can this image be traced to a signed build from source you trust? An
admission gate that answers "no, block" is easy to write and a great way to take
down production the first time a legitimate image lacks an attestation.

This gate makes failing closed *safe*: staged enforcement (audit -> warn ->
block), per-namespace policy so you roll out gradually, and an explicit
break-glass path with a mandatory reason that is always recorded. The decision is
pure and fully testable; a real deployment wires it to a Kubernetes
ValidatingAdmissionWebhook or a registry gate.
"""
__version__ = "1.0.0"
