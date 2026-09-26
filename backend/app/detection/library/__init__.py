"""The rule library shipped with SentinelX: YAML files validated at startup.

`load_library()` fails loudly (the application refuses to start) if any rule file is invalid,
if a file name does not match its rule ID, if two rules share an ID, or if a rule refers to an
ATT&CK technique missing from the pinned reference file. A broken library is a deployment
error, not something to discover when the first detection run silently skips a rule.
"""

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.detection.model import TECHNIQUE_ID, Rule

LIBRARY_DIR = Path(__file__).resolve().parent
RULES_DIR = LIBRARY_DIR / "rules"
ATTACK_FILE = LIBRARY_DIR / "attack_techniques.yaml"


class LibraryError(Exception):
    """The shipped rule library is invalid. The message says which file and why."""


class Technique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=TECHNIQUE_ID.pattern)
    name: str = Field(min_length=3, max_length=200)
    tactics: list[str] = Field(min_length=1)

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


class AttackReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attack_version: str
    checked_on: str
    source: str
    techniques: list[Technique]

    def by_id(self) -> dict[str, Technique]:
        return {t.id: t for t in self.techniques}


@dataclass(frozen=True)
class Library:
    rules: dict[str, Rule]
    hashes: dict[str, str]  # rule ID -> fingerprint of its definition
    attack: AttackReference


def fingerprint(rule: Rule) -> str:
    canonical = json.dumps(rule.model_dump(mode="json", by_alias=True), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _read_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LibraryError(f"{path.name}: cannot be read as YAML ({type(exc).__name__})") from exc


def load_library(rules_dir: Path = RULES_DIR, attack_file: Path = ATTACK_FILE) -> Library:
    try:
        attack = AttackReference.model_validate(_read_yaml(attack_file))
    except ValidationError as exc:
        raise LibraryError(f"{attack_file.name}: {exc}") from exc
    known = attack.by_id()
    rules: dict[str, Rule] = {}
    for path in sorted(rules_dir.glob("*.yaml")):
        try:
            rule = Rule.model_validate(_read_yaml(path))
        except ValidationError as exc:
            raise LibraryError(f"{path.name}: {exc}") from exc
        if path.stem != rule.id:
            raise LibraryError(f"{path.name}: the file name must be the rule ID ({rule.id})")
        if rule.id in rules:
            raise LibraryError(f"{path.name}: rule ID {rule.id} is used twice")
        unknown = sorted(rule.techniques() - set(known))
        if unknown:
            raise LibraryError(
                f"{path.name}: techniques {', '.join(unknown)} are not in {attack_file.name}"
            )
        rules[rule.id] = rule
    if not rules:
        raise LibraryError(f"no rules found in {rules_dir}")
    return Library(
        rules=rules, hashes={rule_id: fingerprint(r) for rule_id, r in rules.items()}, attack=attack
    )


@lru_cache
def get_library() -> Library:
    return load_library()
