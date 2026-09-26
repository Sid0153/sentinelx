"""What the rule format refuses: bad conditions, inconsistent rules, a broken library. And
exclusions, including the look-alike names that must not match an allowlist entry."""

import string
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from app.detection.conditions import LOWERCASE_COLUMNS, All, Any_, Condition, Not, Predicate
from app.detection.evaluators.common import excluded
from app.detection.library import ATTACK_FILE, RULES_DIR, LibraryError, load_library
from app.detection.model import Exclusion, Rule
from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from tests.detection_helpers import ev, rule

ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
CONDITION: TypeAdapter[All | Any_ | Not | Predicate] = TypeAdapter(Condition)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"field": "password", "op": "eq", "value": "x"}, "unknown field"),
        ({"field": "attributes.Bad-Key", "op": "eq", "value": "x"}, "unknown field"),
        ({"field": "target_account", "op": "eq", "value": "x"}, "unknown field"),  # derived
        ({"field": "username", "op": "like", "value": "x"}, "Input should be"),
        ({"field": "username", "op": "exists", "value": "yes"}, "exists takes"),
        ({"field": "username", "op": "in", "value": []}, "list of 1 to 200"),
        ({"field": "username", "op": "in", "value": "root"}, "list of 1 to 200"),
        ({"field": "username", "op": "gt", "value": 3}, "numeric field"),
        ({"field": "source_port", "op": "gt", "value": "3"}, "numeric field"),
        ({"field": "username", "op": "cidr", "value": "10.0.0.0/8"}, "cidr needs an IP"),
        ({"field": "source_ip", "op": "cidr", "value": "10.0.0.300/8"}, "does not appear"),
        ({"field": "message", "op": "matches", "value": "x" * 513}, "at most 512"),
        ({"field": "message", "op": "matches", "value": "(unclosed"}, "invalid pattern"),
        ({"field": "username", "op": "eq", "value": ["root"]}, "single value"),
        ({"field": "username", "op": "eq"}, "single value"),
        ({"field": "username", "op": "eq", "value": "x", "extra": 1}, "Extra inputs"),
        ({"all": []}, "at least 1 item"),
    ],
)
def test_invalid_conditions_are_refused(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CONDITION.validate_python(raw)


def base(**changes: Any) -> dict[str, Any]:
    data = rule("AUTH-001").model_dump(mode="json", by_alias=True)
    data.update(changes)
    return data


PREDICATE = {"field": "username", "op": "eq", "value": "root"}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (base(id="auth-1"), "rule IDs look like"),
        (base(threshold=None), "needs threshold"),
        (base(kind="distinct"), "needs distinct_field"),
        (base(kind="sequence"), "needs steps"),
        (base(steps=[{"name": "a", "match": PREDICATE}] * 2), "only sequence rules have steps"),
        (
            base(kind="sequence", steps=[{"name": "a", "match": PREDICATE}]),
            "2 to 5 steps",
        ),
        (
            base(kind="sequence", steps=[{"name": "a", "match": PREDICATE}] * 2),
            "filters with its steps",
        ),
        (
            base(indicators=rule("PROC-001").model_dump(mode="json", by_alias=True)["indicators"]),
            "only single-event rules",
        ),
        (base(group_by=["password"]), "unknown field"),
        (base(mitre=[]), "at least one ATT&CK"),
        (base(mitre=[{"technique": "T99", "reason": "a reason long enough"}]), "look like T1110"),
        (base(match={"not": {"not": {"not": {"not": PREDICATE}}}}), "at most 4 levels"),
        (base(threshold=1), "default threshold is outside"),
        (base(time_window="48h"), "default time window is outside"),
        (base(explanation="Hello $password"), "unknown placeholder \\$password"),
        (base(time_window="soon"), "duration"),
    ],
)
def test_inconsistent_rules_are_refused(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Rule.model_validate(data)


def test_attribute_placeholders_are_allowed() -> None:
    Rule.model_validate(base(explanation="Seen $count times ($attr_method)."))


# ---------- the library ----------


def copy_rules(tmp_path: Path, *names: str) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    for name in names:
        (directory / name).write_bytes((RULES_DIR / name).read_bytes())
    return directory


def test_the_shipped_library_loads() -> None:
    library = load_library()
    assert len(library.rules) == 9 and library.attack.attack_version == "19.2"


def test_a_rule_file_must_be_named_after_its_rule(tmp_path: Path) -> None:
    directory = copy_rules(tmp_path, "AUTH-001.yaml")
    (directory / "AUTH-001.yaml").rename(directory / "AUTH-009.yaml")
    with pytest.raises(LibraryError, match="file name must be the rule ID"):
        load_library(directory)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("id: [unclosed", "cannot be read as YAML"),
        ("id: AUTH-001\nkind: threshold\n", "AUTH-001.yaml: "),
    ],
)
def test_an_invalid_rule_file_names_the_file(tmp_path: Path, content: str, message: str) -> None:
    directory = copy_rules(tmp_path)
    (directory / "AUTH-001.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(LibraryError, match=message):
        load_library(directory)


def test_a_bad_pattern_in_a_rule_file_is_a_library_error(tmp_path: Path) -> None:
    directory = copy_rules(tmp_path, "PRIV-001.yaml")
    text = (directory / "PRIV-001.yaml").read_text(encoding="utf-8")
    pattern = "value: '^(?:/usr)?"
    assert pattern in text
    (directory / "PRIV-001.yaml").write_text(text.replace(pattern, "value: '(^"), "utf-8")
    with pytest.raises(LibraryError, match="PRIV-001.yaml: (.|\n)*invalid pattern"):
        load_library(directory)


def test_techniques_must_be_in_the_pinned_attack_reference(tmp_path: Path) -> None:
    directory = copy_rules(tmp_path, "AUTH-001.yaml")
    text = (directory / "AUTH-001.yaml").read_text(encoding="utf-8")
    (directory / "AUTH-001.yaml").write_text(text.replace("T1110.001", "T1999"), "utf-8")
    with pytest.raises(LibraryError, match="T1999 are not in"):
        load_library(directory)


def test_an_empty_library_or_broken_reference_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(LibraryError, match="no rules found"):
        load_library(copy_rules(tmp_path))
    broken = tmp_path / "attack.yaml"
    broken.write_text("attack_version: 19.2\n", encoding="utf-8")
    with pytest.raises(LibraryError, match="attack.yaml"):
        load_library(RULES_DIR, broken)
    assert ATTACK_FILE.exists()


# ---------- exclusions ----------


@pytest.mark.parametrize(
    ("field", "value", "event_fields", "is_excluded"),
    [
        ("source_ip", "203.0.113.0/24", {}, True),
        ("source_ip", "198.51.100.0/24", {}, False),
        ("source_ip", "::/0", {}, False),  # an IPv6 network never contains an IPv4 address
        ("source_ip", "10.0.0.0/8", {"source_ip": None}, False),
        ("source_ip", "10.0.0.0/8", {"source_ip": "not-an-ip"}, False),
        ("username", "ROOT", {}, True),
        ("username", "svc", {"username": "svc"}, True),
        # Look-alikes: Unicode case folding would turn these into "svc" and "kiosk".
        ("username", "svc", {"username": "ſvc"}, False),
        ("username", "kiosk", {"username": "Kiosk"}, False),
        ("host", "web-01", {}, True),
    ],
)
def test_exclusions(
    field: str, value: str, event_fields: dict[str, Any], is_excluded: bool
) -> None:
    exclusion = Exclusion.model_validate({"field": field, "value": value})
    assert excluded(ev(**event_fields), [exclusion]) is is_excluded


def test_columns_compared_without_folding_are_stored_without_capitals() -> None:
    """The prefilter compares LOWERCASE_COLUMNS directly (so indexes work). That is only exact
    if the normalizer never stores an ASCII capital in them."""
    shouting = "WEB-01.CORP.EXAMPLE"
    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 25, tzinfo=UTC),
        source_type=SourceType.LINUX_AUTH,
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon",
        event_outcome=EventOutcome.FAILURE,
        **{  # type: ignore[arg-type]  # every value is a string; mypy cannot tell
            name: shouting
            for name in LOWERCASE_COLUMNS
            if name in NormalizedEvent.model_fields
            and name not in ("source_type", "event_category", "event_action", "event_outcome")
        },
    ).model_dump(mode="json")
    for name in LOWERCASE_COLUMNS & set(event):
        value = event[name]
        assert value is None or value == value.translate(ASCII_LOWER), name
    # Set at enrichment from fixed enums (IpScope, Criticality), not by the normalizer.
    assert LOWERCASE_COLUMNS - set(event) == {"source_ip_scope", "asset_criticality"}
