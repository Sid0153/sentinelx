"""docs/deployment.md documents every way SentinelX is configured (Phase 15): every backend
setting, every variable the Compose files read, every entry of .env.example. A new setting
without documentation fails here instead of surprising an operator."""

import re
from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[3]
DEPLOYMENT = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
DOCUMENTED = set(re.findall(r"^\| `([A-Z][A-Z0-9_]*)` \|", DEPLOYMENT, flags=re.MULTILINE))


def test_every_backend_setting_is_documented() -> None:
    settings = {name.upper() for name in Settings.model_fields}
    assert settings - DOCUMENTED == set()


def test_every_compose_variable_is_documented() -> None:
    used: set[str] = set()
    for name in ("docker-compose.yml", "docker-compose.prod.yml"):
        used |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", (ROOT / name).read_text(encoding="utf-8")))
    entrypoint = (ROOT / "backend" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    used |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", entrypoint))
    assert len(used) > 10  # the files were read
    assert used - DOCUMENTED == set()


def test_every_env_example_entry_is_documented() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    entries = set(re.findall(r"^#? ?([A-Z][A-Z0-9_]*)=", example, flags=re.MULTILINE))
    assert {"SECRET_KEY", "SITE_PORT"} <= entries
    assert entries - DOCUMENTED == set()


def test_nothing_documented_that_does_not_exist() -> None:
    """The reverse: a removed setting must leave the tables too."""
    known = {name.upper() for name in Settings.model_fields}
    for name in ("docker-compose.yml", "docker-compose.prod.yml", ".env.example"):
        known |= set(re.findall(r"[A-Z][A-Z0-9_]{2,}", (ROOT / name).read_text(encoding="utf-8")))
    entrypoint = (ROOT / "backend" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    known |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", entrypoint))  # PORT, DEMO_AUTOLOAD, ...
    known |= {"COMPOSE_FILE"}  # the shell variable Compose reads
    assert DOCUMENTED - known == set()
