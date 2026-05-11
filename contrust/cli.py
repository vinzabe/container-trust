"""contrust CLI."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .advisor import LLMRemediationAdvisor
from .pipeline import TrustPipeline
from .policy import Policy, PolicyDecision
from .risk import RiskModel
from .scanner import TrivyConfig, TrivyScanner


def _build_pipeline(args: argparse.Namespace) -> TrustPipeline:
    cfg = TrivyConfig(
        skip_db_update=args.skip_db_update,
        offline=args.offline,
    )
    scanner = TrivyScanner(cfg)
    advisor = LLMRemediationAdvisor() if args.llm else None
    policy = Policy(
        max_critical=args.max_critical,
        max_high=args.max_high,
        deny_secrets=not args.allow_secrets,
        score_warn=args.score_warn,
        score_fail=args.score_fail,
    )
    return TrustPipeline(
        scanner=scanner,
        risk_model=RiskModel(),
        policy=policy,
        advisor=advisor,
        enable_llm=args.llm,
    )


def _cmd_image(args):
    pipeline = _build_pipeline(args)
    result = pipeline.run_image(args.image)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0 if result.decision != PolicyDecision.FAIL else 1


def _cmd_fs(args):
    pipeline = _build_pipeline(args)
    result = pipeline.run_fs(args.path)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0 if result.decision != PolicyDecision.FAIL else 1


def _cmd_replay(args):
    pipeline = TrustPipeline(
        scanner=None,
        policy=Policy(
            max_critical=args.max_critical,
            max_high=args.max_high,
            deny_secrets=not args.allow_secrets,
            score_warn=args.score_warn,
            score_fail=args.score_fail,
        ),
        advisor=LLMRemediationAdvisor() if args.llm else None,
        enable_llm=args.llm,
    )
    result = pipeline.run_from_json(args.json)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0 if result.decision != PolicyDecision.FAIL else 1


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--llm", action="store_true", help="ask LLM for remediation plan")
    p.add_argument("--max-critical", type=int, default=0)
    p.add_argument("--max-high", type=int, default=5)
    p.add_argument("--allow-secrets", action="store_true",
                   help="don't fail policy on secret findings")
    p.add_argument("--score-warn", type=float, default=35.0)
    p.add_argument("--score-fail", type=float, default=70.0)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="contrust")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_img = sub.add_parser("image", help="scan a container image")
    p_img.add_argument("image", help="image ref (e.g. docker.io/library/nginx:1.25)")
    p_img.add_argument("--skip-db-update", action="store_true")
    p_img.add_argument("--offline", action="store_true")
    _add_common(p_img)
    p_img.set_defaults(func=_cmd_image)

    p_fs = sub.add_parser("fs", help="scan a filesystem path")
    p_fs.add_argument("path")
    p_fs.add_argument("--skip-db-update", action="store_true")
    p_fs.add_argument("--offline", action="store_true")
    _add_common(p_fs)
    p_fs.set_defaults(func=_cmd_fs)

    p_rep = sub.add_parser("replay", help="re-run analysis on saved trivy JSON")
    p_rep.add_argument("--json", required=True)
    _add_common(p_rep)
    p_rep.set_defaults(func=_cmd_replay)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
