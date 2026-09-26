"""The SentinelX priority score: every factor, the band edges, and the version guard."""

import hashlib
import json

import pytest

from app.risk import priority
from app.risk.priority import AssetContext, IdentityContext, alert_priority, band

# The weights each model version stands for. Changing a weight without bumping
# RISK_MODEL_VERSION (and adding its fingerprint here) fails the test below: old scores are
# stored with their version and must stay explainable.
WEIGHTS_BY_VERSION = {"1": "8ed872d86dc7"}


def fingerprint() -> str:
    canonical = json.dumps(priority.weights(), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def test_weights_changes_bump_the_model_version() -> None:
    assert WEIGHTS_BY_VERSION.get(priority.RISK_MODEL_VERSION) == fingerprint(), (
        "weights changed: bump RISK_MODEL_VERSION and record the new fingerprint"
    )


def score(**changes: object) -> priority.Priority:
    values: dict[str, object] = {
        "severity": "medium",
        "confidence": "medium",
        "asset": None,
        "identity": None,
        "peak_count": 5,
        "threshold": 5,
    }
    values.update(changes)
    return alert_priority(**values)  # type: ignore[arg-type]


def test_a_documented_example_adds_up() -> None:
    result = score(
        severity="high",
        confidence="medium",
        asset=AssetContext("web-01", "critical"),
        identity=IdentityContext("deploy", privileged=True),
    )
    assert result.summary() == (
        "severity high +40 · confidence medium +8 · asset web-01 critical +15 · "
        "identity deploy privileged +10 = 73 (high)"
    )
    assert result.score == sum(f["points"] for f in result.breakdown())


@pytest.mark.parametrize(
    ("severity", "points"), [("low", 10), ("medium", 25), ("high", 40), ("critical", 55)]
)
def test_severity_points(severity: str, points: int) -> None:
    assert score(severity=severity, confidence="low").factors[0].points == points


@pytest.mark.parametrize(("confidence", "points"), [("low", 0), ("medium", 8), ("high", 15)])
def test_confidence_points(confidence: str, points: int) -> None:
    assert score(confidence=confidence).factors[1].points == points


@pytest.mark.parametrize(
    ("criticality", "points"), [("low", 0), ("medium", 5), ("high", 10), ("critical", 15)]
)
def test_asset_points(criticality: str, points: int) -> None:
    factor = score(asset=AssetContext("db-01", criticality)).factors[2]
    assert (factor.value, factor.points) == (f"db-01 {criticality}", points)


def test_an_asset_missing_from_the_inventory_counts_a_little() -> None:
    factor = score().factors[2]
    assert (factor.value, factor.points) == ("not in inventory", 5)


def test_only_a_privileged_identity_adds_points() -> None:
    assert score(identity=IdentityContext("alice", privileged=False)).score == score().score
    assert score(identity=IdentityContext("root", privileged=True)).score == score().score + 10


@pytest.mark.parametrize(
    ("peak", "threshold", "bonus"),
    [(9, 5, 0), (10, 5, 5), (40, 20, 5), (39, 20, 0), (100, None, 0)],
)
def test_evidence_volume_needs_twice_the_threshold(
    peak: int, threshold: int | None, bonus: int
) -> None:
    base = score(peak_count=1, threshold=threshold).score
    assert score(peak_count=peak, threshold=threshold).score - base == bonus


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "low"),
        (24, "low"),
        (25, "medium"),
        (49, "medium"),
        (50, "high"),
        (74, "high"),
        (75, "critical"),
        (100, "critical"),
    ],
)
def test_band_edges(value: int, expected: str) -> None:
    assert band(value) == expected


def test_the_score_is_capped_at_100() -> None:
    result = score(
        severity="critical",
        confidence="high",
        asset=AssetContext("dc-01", "critical"),
        identity=IdentityContext("admin", privileged=True),
        peak_count=100,
    )
    assert sum(f.points for f in result.factors) == 100
    assert result.score == 100 and result.band == "critical"


def test_the_lowest_possible_score() -> None:
    result = score(severity="low", confidence="low", asset=AssetContext("x", "low"))
    assert (result.score, result.band) == (10, "low")
