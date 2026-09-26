"""The SentinelX alert priority score (docs/risk-model.md, ADR-0005).

A project-specific, additive score (0–100) that orders the alert queue. It is not an industry
standard. Every factor is listed with its input and its points, so an analyst can recompute
the number by hand. Pure: no database, no clock.

Changing any weight or band edge means bumping RISK_MODEL_VERSION (a test fails otherwise).
The version is stored with every score, so old scores stay explainable.
"""

from dataclasses import dataclass
from typing import Any

RISK_MODEL_VERSION = "1"

SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 40, "critical": 55}
CONFIDENCE_POINTS = {"low": 0, "medium": 8, "high": 15}
ASSET_POINTS = {"low": 0, "medium": 5, "high": 10, "critical": 15}
UNKNOWN_ASSET_POINTS = 5  # not in the inventory: neither reassuring nor alarming
PRIVILEGED_IDENTITY_POINTS = 10
VOLUME_POINTS = 5  # evidence at least VOLUME_FACTOR times the rule's threshold
VOLUME_FACTOR = 2
MAX_SCORE = 100
# Lowest score of each band, highest band first.
BANDS = (("critical", 75), ("high", 50), ("medium", 25), ("low", 0))


@dataclass(frozen=True)
class AssetContext:
    hostname: str
    criticality: str


@dataclass(frozen=True)
class IdentityContext:
    username: str
    privileged: bool


@dataclass(frozen=True)
class Factor:
    name: str
    value: str  # the input, as shown to the analyst
    points: int


@dataclass(frozen=True)
class Priority:
    score: int
    band: str
    factors: tuple[Factor, ...]
    version: str = RISK_MODEL_VERSION

    def breakdown(self) -> list[dict[str, Any]]:
        return [{"factor": f.name, "value": f.value, "points": f.points} for f in self.factors]

    def summary(self) -> str:
        """`severity high +40 · confidence medium +8 · ... = 48 (medium)`"""
        parts = " · ".join(f"{f.name} {f.value} +{f.points}" for f in self.factors)
        return f"{parts} = {self.score} ({self.band})"


def band(score: int) -> str:
    return next(name for name, lowest in BANDS if score >= lowest)


def alert_priority(
    *,
    severity: str,
    confidence: str,
    asset: AssetContext | None,
    identity: IdentityContext | None,
    peak_count: int,
    threshold: int | None,
) -> Priority:
    """`asset` is the most critical known asset among the evidence (None: none is in the
    inventory); `identity` a privileged actor if there is one, else any known actor.
    `peak_count` is the largest evidence count (events, or distinct values for distinct
    rules) of one detection; `threshold` the rule's threshold (None for kinds without one)."""
    factors = [
        Factor("severity", severity, SEVERITY_POINTS[severity]),
        Factor("confidence", confidence, CONFIDENCE_POINTS[confidence]),
    ]
    if asset is None:
        factors.append(Factor("asset", "not in inventory", UNKNOWN_ASSET_POINTS))
    else:
        factors.append(
            Factor(
                "asset", f"{asset.hostname} {asset.criticality}", ASSET_POINTS[asset.criticality]
            )
        )
    if identity is not None and identity.privileged:
        factors.append(
            Factor("identity", f"{identity.username} privileged", PRIVILEGED_IDENTITY_POINTS)
        )
    if threshold is not None and peak_count >= VOLUME_FACTOR * threshold:
        factors.append(
            Factor(
                "evidence",
                f"{peak_count} (≥ {VOLUME_FACTOR}× threshold {threshold})",
                VOLUME_POINTS,
            )
        )
    score = min(MAX_SCORE, sum(f.points for f in factors))
    return Priority(score=score, band=band(score), factors=tuple(factors))


def weights() -> dict[str, Any]:
    """Every number the score depends on (for the version check)."""
    return {
        "severity": SEVERITY_POINTS,
        "confidence": CONFIDENCE_POINTS,
        "asset": ASSET_POINTS,
        "unknown_asset": UNKNOWN_ASSET_POINTS,
        "privileged_identity": PRIVILEGED_IDENTITY_POINTS,
        "volume": [VOLUME_POINTS, VOLUME_FACTOR],
        "max": MAX_SCORE,
        "bands": BANDS,
    }
