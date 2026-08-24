# container-trust

**A container-provenance admission gate that refuses images it can't trace to a signed build — and fails closed without taking production down.**

The supply-chain question for a running container is easy to ask: *can this image be traced to a signed build from source you trust?* An admission gate that answers "no → block" is trivial to write and a great way to cause your first outage, the moment a legitimate image lacks an attestation.

`container-trust` makes failing closed **safe**:

- **Staged enforcement** — `audit` (record only) → `warn` (admit + flag) → `block` (deny). Sit in warn while you find the images without provenance.
- **Per-namespace mode** — keep `production` in `block` while a new namespace rolls out in `warn`.
- **Break-glass with a mandatory, recorded reason** — an emergency bypass that leaves an audit trail, because a bypass with no record is not a control.

```
$ ctrust admit ghcr.io/vinzabe/app:1.0 sha256:aaaa... --config policy.json --namespace production
DENY ghcr.io/vinzabe/app:1.0
  - no provenance attestation for this digest

$ ctrust admit ... --namespace production --break-glass "incident-42 hotfix"
ADMIT ghcr.io/vinzabe/app:1.0  (BREAK-GLASS — recorded)
```

## What "trusted" means

An image is admitted under `block` only if its digest has an attestation that: matches the digest, is signature-verified, names a **trusted builder**, and points to a **trusted source prefix** — from a **trusted registry**. Anything less is a listed, human-readable reason.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/container-trust && cd container-trust
python -m pip install -e ".[dev]"

# 1. record a build's provenance (a CI step would do this)
ctrust attest sha256:aaaa... --builder github-actions@ci.example.com \
    --source https://github.com/vinzabe/app --signed

# 2. gate admission (prod is block, staging is warn — per policy.json)
ctrust admit ghcr.io/vinzabe/app:1.0 sha256:aaaa... --config policy.json --namespace production

# 3. audit what's deployed, and every break-glass use
ctrust audit
ctrust audit --break-glass
```

`admit` exit codes: `0` admitted, `2` denied, `1` error — so a webhook or CI job gates on it.

## Wiring it up

The decision (`gate.evaluate`) is **pure and fully tested**. A real deployment wires it to:
- a Kubernetes `ValidatingAdmissionWebhook` (deny = reject the pod), or
- a registry-promotion gate (deny = don't promote to the prod registry).

The attestation store also answers the incident-time question *"what is deployed and where did it come from?"* — `ctrust audit` lists every admitted image by digest and namespace.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=ctrust      # 25 tests, ~91% coverage
mypy --strict src/ctrust # clean
ruff check src tests     # clean
```

## License

MIT © vinzabe
