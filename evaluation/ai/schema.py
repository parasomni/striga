"""
Data model for the AI evaluation layer.

Everything here is tool- and provider-agnostic on purpose: a RawFinding is just
"some output from some module against some target", and the LLM turns it into
zero or more Classification objects. No tool-specific fields, so any module you
add to Striga later is covered without touching this file.

The verification-related fields on Classification (evidence_verified,
review_required, notes) are NOT set by the model. They are filled by the
deterministic post-processing stage in evaluator.py, which cross-checks the
model's output against the raw tool data.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class RawFinding:
    """One unit of tool output handed to the evaluator."""
    scan_id: str
    target: str
    service: str          # web, smb, dns, ... (or "unknown")
    module: str           # nmap, nikto, sqlmap, ... (whatever produced it)
    raw: str              # the tool output (may be a chunk of a larger file)
    context: dict[str, Any] = field(default_factory=dict)
    # context carries *grounded* hints from deterministic sources, e.g.
    # {"cve_ids": [...], "cvss": {...}, "ports": [...], "versions": {...}}

    def key(self) -> str:
        return f"{self.target}:{self.service}:{self.module}"


@dataclass
class Classification:
    """One evaluated, classified issue derived from a RawFinding."""
    # --- fields the model provides ---
    title: str
    severity: Severity
    confidence: float                 # model certainty the issue is real, 0..1
    category: str                     # misconfiguration | cve | exposure | weak-cred | info-leak | ...
    false_positive_likelihood: float  # 0..1
    evidence: str                     # verbatim snippet from the tool output
    remediation: str
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # --- fields the deterministic post-processing sets (never the model) ---
    evidence_verified: bool = False   # evidence string actually found in raw output
    review_required: bool = False     # something needs a human before trusting this
    notes: list[str] = field(default_factory=list)  # why review is required / what was changed

    @staticmethod
    def from_model(d: dict[str, Any]) -> "Classification":
        def num(x, default=0.0):
            try:
                return max(0.0, min(1.0, float(x)))
            except (TypeError, ValueError):
                return default
        return Classification(
            title=str(d.get("title", "")).strip() or "untitled finding",
            severity=Severity.coerce(d.get("severity", "info")),
            confidence=num(d.get("confidence"), 0.0),
            category=str(d.get("category", "unknown")).strip().lower(),
            false_positive_likelihood=num(d.get("false_positive_likelihood"), 0.5),
            evidence=str(d.get("evidence", "")).strip(),
            remediation=str(d.get("remediation", "")).strip(),
            cve_ids=[str(c).strip().upper() for c in d.get("cve_ids", []) if str(c).strip()],
            references=[str(r).strip() for r in d.get("references", []) if str(r).strip()],
        )


@dataclass
class EvaluatedFinding:
    raw: RawFinding
    classification: Classification | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "target": self.raw.target,
            "service": self.raw.service,
            "module": self.raw.module,
            "scan_id": self.raw.scan_id,
        }
        if self.classification is not None:
            c = asdict(self.classification)
            c["severity"] = self.classification.severity.value
            out.update(c)
        if self.error:
            out["error"] = self.error
        return out
