"""
Striga AI evaluation layer.

Wire into the framework:

    from evaluation.ai import build_evaluator, is_ai_enabled, load_results_dir, render

    if is_ai_enabled(config.get("llm", {}), cli_override=args.ai_eval):
        evaluator = build_evaluator(config["llm"])
        findings  = load_results_dir("/etc/striga", scan_id, target, enrich=my_cve_lookup)
        results   = evaluator.evaluate(findings)
        print(render(results, config["llm"].get("output_format", "markdown"), source=findings))

`is_ai_enabled` resolves precedence CLI > config (`llm.enabled`, default True).
`cli_override` is True/False from a --ai-eval/--no-ai-eval flag, or None if unset.

Or feed your own in-memory RawFinding list from the enumeration modules directly
into evaluator.evaluate(...).
"""

from __future__ import annotations

from typing import Any

from .client import LLMClient
from .evaluator import EvalConfig, Evaluator, load_results_dir, render
from .schema import Classification, EvaluatedFinding, RawFinding, Severity

__all__ = [
    "build_evaluator",
    "is_ai_enabled",
    "Evaluator",
    "EvalConfig",
    "LLMClient",
    "RawFinding",
    "EvaluatedFinding",
    "Classification",
    "Severity",
    "load_results_dir",
    "render",
]


def is_ai_enabled(llm_cfg: dict[str, Any] | None, cli_override: bool | None = None) -> bool:
    """Resolve whether the AI eval runs. CLI flag wins over config; default on."""
    if cli_override is not None:
        return cli_override
    return bool((llm_cfg or {}).get("enabled", True))


def _read_key(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def build_evaluator(llm_cfg: dict[str, Any]) -> Evaluator:
    """Construct an Evaluator from the `llm:` section of config.yaml."""
    llm_cfg = llm_cfg or {}
    client = LLMClient(
        provider=llm_cfg.get("provider", "ollama"),
        model=llm_cfg.get("model", "qwen2.5:14b-instruct"),
        base_url=llm_cfg.get("base_url", "http://127.0.0.1:11434"),
        api_key=_read_key(llm_cfg.get("api_key_file")),
        timeout=int(llm_cfg.get("timeout", 120)),
        temperature=float(llm_cfg.get("temperature", 0.0)),
        retries=int(llm_cfg.get("retries", 2)),
        options=llm_cfg.get("options") or {},
    )
    return Evaluator(client, EvalConfig.from_dict(llm_cfg))


def _main() -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(description="Striga AI evaluation (standalone)")
    p.add_argument("--results-dir", default="/etc/striga")
    p.add_argument("--scan-id", required=True)
    p.add_argument("--target", default="unknown")
    p.add_argument("--provider", default="ollama")
    p.add_argument("--model", default="qwen2.5:14b-instruct")
    p.add_argument("--base-url", default="http://127.0.0.1:11434")
    p.add_argument("--api-key-file", default=None)
    p.add_argument("--format", default="markdown", choices=["markdown", "json", "table"])
    p.add_argument("--max-input-chars", type=int, default=12000)
    p.add_argument("--drop-below-confidence", type=float, default=None,
                   help="opt-in noise floor; findings below this confidence are deleted")
    # enable/disable this run
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--ai-eval", dest="ai_eval", action="store_true", default=None,
                     help="force-enable AI evaluation for this run")
    grp.add_argument("--no-ai-eval", dest="ai_eval", action="store_false",
                     help="force-disable AI evaluation for this run")
    args = p.parse_args()

    if not is_ai_enabled({}, cli_override=args.ai_eval):
        print("[i] AI evaluation disabled for this run (--no-ai-eval)", file=sys.stderr)
        return 0

    evaluator = build_evaluator(
        {
            "provider": args.provider,
            "model": args.model,
            "base_url": args.base_url,
            "api_key_file": args.api_key_file,
            "max_input_chars": args.max_input_chars,
            "drop_below_confidence": args.drop_below_confidence,
        }
    )
    if not evaluator.client.health():
        print(f"[!] LLM backend unreachable at {args.base_url}", file=sys.stderr)
        return 2
    findings = load_results_dir(args.results_dir, args.scan_id, args.target)
    if not findings:
        print("[!] no results found", file=sys.stderr)
        return 1
    print(render(evaluator.evaluate(findings), args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
