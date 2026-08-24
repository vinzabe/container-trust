"""CLI: register attestations, evaluate admission, and audit.

`admit` exit codes: 0 admitted, 2 denied, 1 error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .gate import evaluate
from .model import Attestation, Image
from .policy_loader import load_config
from .store import Store

EXIT_ADMIT, EXIT_ERROR, EXIT_DENY = 0, 1, 2


def cmd_attest(a: argparse.Namespace) -> int:
    with Store(a.store) as st:
        st.put_attestation(Attestation(
            digest=a.digest, builder=a.builder, source_repo=a.source,
            signature_verified=a.signed))
    print(f"recorded attestation for {a.digest}")
    return EXIT_ADMIT


def cmd_admit(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    image = Image(reference=a.reference, digest=a.digest, namespace=a.namespace)
    mode = cfg.mode_for(a.namespace)
    with Store(a.store) as st:
        att = st.get_attestation(a.digest)
        decision = evaluate(image, att, cfg.policy, mode,
                            break_glass_reason=a.break_glass)
        st.record_decision(
            reference=a.reference, digest=a.digest, namespace=a.namespace,
            admitted=decision.admitted, mode=mode.value,
            reasons=list(decision.reasons),
            break_glass_reason=a.break_glass)
    if a.json:
        print(json.dumps({
            "admitted": decision.admitted, "mode": mode.value,
            "compliant": decision.compliant, "break_glass": decision.break_glass,
            "reasons": list(decision.reasons)}, indent=2))
    else:
        verb = "ADMIT" if decision.admitted else "DENY"
        note = ""
        if decision.break_glass:
            note = "  (BREAK-GLASS — recorded)"
        elif decision.reasons and decision.admitted:
            note = f"  ({mode.value}: violations not enforced)"
        print(f"{verb} {a.reference}{note}")
        for r in decision.reasons:
            print(f"  - {r}")
    return EXIT_ADMIT if decision.admitted else EXIT_DENY


def cmd_audit(a: argparse.Namespace) -> int:
    with Store(a.store) as st:
        if a.break_glass:
            uses = st.break_glass_uses()
            print(json.dumps(uses, indent=2) if a.json
                  else _fmt_break_glass(uses))
        else:
            imgs = st.deployed_images()
            print(json.dumps(imgs, indent=2) if a.json
                  else "\n".join(f"  {i['namespace']}/{i['reference']} "
                                 f"@ {i['digest'][:19]}" for i in imgs)
                  or "no admitted images recorded")
    return EXIT_ADMIT


def _fmt_break_glass(uses: list[dict[str, object]]) -> str:
    if not uses:
        return "no break-glass admissions recorded"
    out = [f"{len(uses)} break-glass admission(s):"]
    for u in uses:
        out.append(f"  {u['at']}  {u['namespace']}/{u['reference']}")
        out.append(f"      reason: {u['break_glass_reason']}")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ctrust", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--store", default="ctrust.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    at = sub.add_parser("attest", help="record a provenance attestation")
    at.add_argument("digest")
    at.add_argument("--builder", required=True)
    at.add_argument("--source", required=True)
    at.add_argument("--signed", action="store_true")
    at.set_defaults(func=cmd_attest)

    ad = sub.add_parser("admit", help="evaluate an image for admission")
    ad.add_argument("reference")
    ad.add_argument("digest")
    ad.add_argument("--config", required=True)
    ad.add_argument("--namespace", default="default")
    ad.add_argument("--break-glass", metavar="REASON",
                    help="force admission WITH a recorded reason")
    ad.add_argument("--json", action="store_true")
    ad.set_defaults(func=cmd_admit)

    au = sub.add_parser("audit", help="list admitted images or break-glass uses")
    au.add_argument("--break-glass", action="store_true")
    au.add_argument("--json", action="store_true")
    au.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
