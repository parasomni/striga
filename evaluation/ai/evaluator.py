"""
The evaluation orchestrator.

Pipeline:
    RawFinding[]
      -> chunk oversized output (with overlap so findings aren't split; capped)
      -> LLM classify per chunk
      -> deterministic post-processing:
             * verify evidence actually appears in the raw output
             * ground CVEs against context / raw (drop invented ones)
             * derive severity from CVSS when context provides a score
             * flag low-confidence / high-FP items for review (never silently drop)
      -> policy (optional opt-in hard drop of true noise)
      -> dedup / sort
      -> render (with coverage: which modules ran clean)

Nothing here is bound to a specific tool; a module is just (service, module, text).
The LLM produces judgement; every judgement is cross-checked against the data.

Known residual limit (not solvable deterministically): evidence verification
proves the quoted snippet exists in the output, not that it justifies the finding.
That gap is what `review_required` and a human/second pass are for.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .client import LLMClient
from .prompts import OUTPUT_SCHEMA, build_system, build_user
from .schema import Classification, EvaluatedFinding, RawFinding, Severity

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


@dataclass
class EvalConfig:
    # Applies to the raw output only; leave headroom below the model's context
    # window for the system prompt + template overhead.
    max_input_chars: int = 12000
    chunk_overlap_chars: int = 400
    # Bound worst-case work per module output (huge/hostile output -> many calls).
    # None = unlimited. When exceeded, the surplus is dropped with a visible notice.
    max_chunks_per_finding: int | None = 20
    # Below/above these, a finding is FLAGGED for review -- not deleted.
    review_min_confidence: float = 0.5
    review_max_fp: float = 0.5
    # Opt-in hard noise floor. None = never delete a finding automatically.
    drop_below_confidence: float | None = None
    dedup: bool = True

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "EvalConfig":
        d = d or {}
        drop = d.get("drop_below_confidence", None)
        cap = d.get("max_chunks_per_finding", 20)
        return EvalConfig(
            max_input_chars=int(d.get("max_input_chars", 12000)),
            chunk_overlap_chars=int(d.get("chunk_overlap_chars", 400)),
            max_chunks_per_finding=(None if cap is None else int(cap)),
            # accept legacy keys min_confidence / max_fp_likelihood as fallbacks
            review_min_confidence=float(d.get("review_min_confidence", d.get("min_confidence", 0.5))),
            review_max_fp=float(d.get("review_max_fp", d.get("max_fp_likelihood", 0.5))),
            drop_below_confidence=(None if drop is None else float(drop)),
            dedup=bool(d.get("dedup", True)),
        )


class Evaluator:
    def __init__(self, client: LLMClient, config: EvalConfig | None = None):
        self.client = client
        self.config = config or EvalConfig()

    # -- main entry ---------------------------------------------------------

    def evaluate(self, findings: Iterable[RawFinding]) -> list[EvaluatedFinding]:
        out: list[EvaluatedFinding] = []
        for finding in findings:
            chunks = self._chunk(finding)
            cap = self.config.max_chunks_per_finding
            truncated = cap is not None and len(chunks) > cap
            if truncated:
                chunks = chunks[:cap]
            for chunk in chunks:
                out.extend(self._evaluate_chunk(chunk))
            if truncated:
                out.append(EvaluatedFinding(
                    raw=finding,
                    error=(f"output truncated to {cap} chunks "
                           f"(~{cap * self.config.max_input_chars} chars) for evaluation"),
                ))
        out = [self._postprocess(f) for f in out]
        out = self._apply_policy(out)
        return self._dedup(out) if self.config.dedup else self._sort(out)

    # -- LLM step -----------------------------------------------------------

    def _evaluate_chunk(self, finding: RawFinding) -> list[EvaluatedFinding]:
        if not finding.raw.strip():
            return []
        try:
            data = self.client.complete_json(build_system(), build_user(finding), OUTPUT_SCHEMA)
        except Exception as exc:  # noqa: BLE001 - keep the run going, surface per-item
            return [EvaluatedFinding(raw=finding, error=str(exc))]
        classifications = [Classification.from_model(x) for x in data.get("findings", [])]
        return [EvaluatedFinding(raw=finding, classification=c) for c in classifications]

    # -- deterministic cross-checks (the trust layer) -----------------------

    def _postprocess(self, ef: EvaluatedFinding) -> EvaluatedFinding:
        c = ef.classification
        if c is None:
            return ef
        raw_norm = _WS_RE.sub(" ", ef.raw.raw).strip().lower()

        # 1) evidence verification: the quoted snippet must exist in the output
        ev = _WS_RE.sub(" ", c.evidence).strip().lower()
        if len(ev) < 8:
            c.evidence_verified = False
            c.notes.append("evidence too short to verify")
        else:
            c.evidence_verified = ev in raw_norm or self._loose_contains(raw_norm, ev)
        if not c.evidence_verified:
            c.notes.append("evidence not found verbatim in tool output")
            c.review_required = True
            c.confidence = round(c.confidence * 0.5, 3)
            c.false_positive_likelihood = round(min(1.0, c.false_positive_likelihood + 0.3), 3)

        # 2) CVE grounding: keep only CVEs backed by context or literally in output
        allowed = {x.upper() for x in ef.raw.context.get("cve_ids", []) if str(x).strip()}
        in_raw = {m.upper() for m in _CVE_RE.findall(ef.raw.raw)}
        grounded, invented = [], []
        for cve in c.cve_ids:
            (grounded if (cve in allowed or cve in in_raw) else invented).append(cve)
        if invented:
            c.notes.append("dropped ungrounded CVE(s): " + ", ".join(sorted(set(invented))))
            c.review_required = True
        c.cve_ids = grounded

        # 3) severity grounding: when context carries a CVSS score, it is
        #    authoritative over the model's severity guess.
        self._ground_severity(c, ef.raw.context)
        return ef

    @staticmethod
    def _ground_severity(c: Classification, context: dict[str, Any]) -> None:
        """If context provides CVSS, derive severity from it deterministically.

        context["cvss"] may be:
          - a dict keyed by CVE id  -> {"CVE-2016-6210": 5.3, ...}
          - a bare number/string    -> 9.8   (applies to any CVE-bearing finding)
        """
        cvss = context.get("cvss")
        if cvss is None or not c.cve_ids:
            return
        scores: list[float] = []
        if isinstance(cvss, dict):
            for cve in c.cve_ids:
                v = cvss.get(cve) or cvss.get(cve.upper()) or cvss.get(cve.lower())
                if v is not None:
                    try:
                        scores.append(float(v))
                    except (TypeError, ValueError):
                        pass
        else:
            try:
                scores.append(float(cvss))
            except (TypeError, ValueError):
                pass
        if not scores:
            return
        band = _cvss_band(max(scores))
        if band != c.severity:
            c.notes.append(
                f"severity aligned to CVSS ({max(scores):.1f} -> {band.value}; model said {c.severity.value})"
            )
            c.severity = band

    @staticmethod
    def _loose_contains(haystack: str, needle: str) -> bool:
        probe = needle[:50]
        return len(probe) >= 12 and probe in haystack

    def _apply_policy(self, findings: list[EvaluatedFinding]) -> list[EvaluatedFinding]:
        kept: list[EvaluatedFinding] = []
        for f in findings:
            c = f.classification
            if c is None:
                kept.append(f)  # keep error/notice rows visible
                continue
            if c.confidence < self.config.review_min_confidence:
                c.review_required = True
                c.notes.append(f"low confidence ({c.confidence:.2f})")
            if c.false_positive_likelihood > self.config.review_max_fp:
                c.review_required = True
                c.notes.append(f"high FP likelihood ({c.false_positive_likelihood:.2f})")
            floor = self.config.drop_below_confidence
            if floor is not None and c.confidence < floor:
                continue  # opt-in: only place a finding is ever deleted
            kept.append(f)
        return kept

    # -- chunking -----------------------------------------------------------

    def _chunk(self, finding: RawFinding) -> list[RawFinding]:
        raw = finding.raw
        limit = self.config.max_input_chars
        if len(raw) <= limit:
            return [finding]
        overlap = max(0, min(self.config.chunk_overlap_chars, limit // 2))
        chunks: list[str] = []
        buf: list[str] = []
        size = 0
        for line in raw.splitlines(keepends=True):
            if size + len(line) > limit and buf:
                chunks.append("".join(buf))
                # seed the next buffer with the tail of the flushed one (overlap)
                tail: list[str] = []
                tsize = 0
                for prev in reversed(buf):
                    if tsize + len(prev) > overlap:
                        break
                    tail.insert(0, prev)
                    tsize += len(prev)
                buf, size = list(tail), tsize
            buf.append(line)
            size += len(line)
        if buf:
            chunks.append("".join(buf))
        return [
            RawFinding(finding.scan_id, finding.target, finding.service, finding.module, c, dict(finding.context))
            for c in chunks
        ]

    # -- dedup / sort -------------------------------------------------------

    def _dedup(self, findings: list[EvaluatedFinding]) -> list[EvaluatedFinding]:
        best: dict[tuple[str, str, str], EvaluatedFinding] = {}
        passthrough: list[EvaluatedFinding] = []
        for f in findings:
            if f.classification is None:
                passthrough.append(f)
                continue
            k = (f.raw.target, f.raw.service, f.classification.title.lower())
            cur = best.get(k)
            if cur is None or f.classification.confidence > cur.classification.confidence:  # type: ignore[union-attr]
                best[k] = f
        return self._sort(list(best.values()) + passthrough)

    @staticmethod
    def _sort(findings: list[EvaluatedFinding]) -> list[EvaluatedFinding]:
        findings.sort(
            key=lambda f: (
                f.classification.severity.rank if f.classification else -1,
                1 if (f.classification and not f.classification.review_required) else 0,
                f.classification.confidence if f.classification else 0.0,
            ),
            reverse=True,
        )
        return findings


def _cvss_band(score: float) -> Severity:
    """CVSS v3.x qualitative severity bands."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


# -- loaders ---------------------------------------------------------------

_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
    ".pcap", ".pcapng", ".bin", ".gz", ".zip", ".tar", ".7z", ".so", ".o", ".exe",
}


def load_results_dir(
    results_dir: str,
    scan_id: str,
    target: str = "unknown",
    enrich: Callable[[RawFinding], dict[str, Any]] | None = None,
) -> list[RawFinding]:
    """
    Read saved tool outputs into RawFindings. Adjust the glob/derivation to match
    your on-disk layout under /etc/striga. Default assumption:
        {results_dir}/{scan_id}/{service}/{module}.*
    Falls back to {results_dir}/{scan_id}/{module}.* (flat) if no service dir.

    Binary files are skipped (by extension and by NUL-byte sniff).

    `enrich` is an optional callback to attach grounded context per finding, e.g.
    look up CVE ids / CVSS from cve_mappings.json or vulners and return a dict that
    is merged into RawFinding.context. This is what makes CVE and severity grounding
    effective (return {"cve_ids": [...], "cvss": {cve: score, ...}}).
    """
    findings: list[RawFinding] = []
    base = os.path.join(results_dir, scan_id)
    for path in sorted(glob.glob(os.path.join(base, "**", "*"), recursive=True)):
        if not os.path.isfile(path):
            continue
        if os.path.splitext(path)[1].lower() in _BINARY_EXTS:
            continue
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        if b"\x00" in blob[:8192]:  # looks binary
            continue
        raw = blob.decode("utf-8", "replace")
        if not raw.strip():
            continue
        rel = os.path.relpath(path, base)
        parts = rel.split(os.sep)
        service = parts[0] if len(parts) > 1 else "unknown"
        module = os.path.splitext(parts[-1])[0]
        rf = RawFinding(scan_id=scan_id, target=target, service=service, module=module, raw=raw)
        if enrich:
            try:
                rf.context.update(enrich(rf) or {})
            except Exception:  # noqa: BLE001 - enrichment must never break loading
                pass
        findings.append(rf)
    return findings


# -- rendering -------------------------------------------------------------


def render(findings: list[EvaluatedFinding], fmt: str = "markdown",
           source: Iterable[RawFinding] | None = None) -> str:
    """Render results. Pass `source` (the RawFindings you evaluated) to also
    report coverage: which evaluated modules produced no findings (ran clean)."""
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)
    if fmt == "table":
        return _render_table(findings)
    return _render_markdown(findings, source)


_SEV_ICON = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def _render_table(findings: list[EvaluatedFinding]) -> str:
    rows = ["SEV     CONF  FP    RV  V  SERVICE/MODULE            TITLE"]
    for f in findings:
        c = f.classification
        if c is None:
            continue
        rows.append(
            f"{_SEV_ICON.get(c.severity.value, '[????]')}  "
            f"{c.confidence:0.2f}  {c.false_positive_likelihood:0.2f}  "
            f"{'!' if c.review_required else ' '}   {'v' if c.evidence_verified else 'x'}  "
            f"{(f.raw.service + '/' + f.raw.module):<24.24}  {c.title}"
        )
    return "\n".join(rows)


def _render_markdown(findings: list[EvaluatedFinding], source: Iterable[RawFinding] | None = None) -> str:
    lines: list[str] = ["# Striga AI Evaluation", ""]
    counts: dict[str, int] = {}
    review = 0
    for f in findings:
        if f.classification:
            counts[f.classification.severity.value] = counts.get(f.classification.severity.value, 0) + 1
            review += 1 if f.classification.review_required else 0
    if counts:
        summary = ", ".join(
            f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda kv: -Severity.coerce(kv[0]).rank)
        )
        lines += [f"**Summary:** {summary}  |  flagged for review: {review}", ""]

    # coverage: modules that were evaluated but produced no findings
    if source is not None:
        evaluated = {(r.service, r.module) for r in source}
        produced = {(f.raw.service, f.raw.module) for f in findings if f.classification}
        clean = sorted(evaluated - produced)
        if clean:
            lines += ["**Clean (evaluated, no findings):** "
                      + ", ".join(f"{s}/{m}" for s, m in clean), ""]

    for f in findings:
        c = f.classification
        if c is None:
            if f.error:
                lines += [f"- _notice on {f.raw.service}/{f.raw.module}: {f.error}_"]
            continue
        flag = " :warning: REVIEW" if c.review_required else ""
        lines += [
            f"## {_SEV_ICON.get(c.severity.value, '')} {c.title}{flag}",
            f"- **Severity:** {c.severity.value}  |  **Confidence:** {c.confidence:0.2f}  "
            f"|  **FP likelihood:** {c.false_positive_likelihood:0.2f}  "
            f"|  **Evidence verified:** {c.evidence_verified}",
            f"- **Target/Service:** {f.raw.target} / {f.raw.service} ({f.raw.module})",
            f"- **Category:** {c.category}",
        ]
        if c.cve_ids:
            lines.append(f"- **CVE:** {', '.join(c.cve_ids)}")
        lines += [
            f"- **Evidence:** `{c.evidence[:400]}`",
            f"- **Remediation:** {c.remediation}",
        ]
        if c.notes:
            lines.append(f"- **Notes:** {'; '.join(c.notes)}")
        if c.references:
            lines.append(f"- **References:** {', '.join(c.references)}")
        lines.append("")
    return "\n".join(lines)
