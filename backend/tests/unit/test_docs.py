"""The documentation matches the code (Phase 17): links resolve, and every route, command,
script and rule the docs name exists. A stale document fails here instead of misleading a
reader. (docs/openapi.json and docs/deployment.md have their own tests.)"""

import json
import re
from pathlib import Path

import pytest

from app import cli
from app.detection.library import get_library

ROOT = Path(__file__).resolve().parents[3]
DOCS = sorted([ROOT / "README.md", *(ROOT / "docs").rglob("*.md")])
TEXT = {path: path.read_text(encoding="utf-8") for path in DOCS}

LINK = re.compile(r"\]\(([^)\s]+)\)")
FENCE = re.compile(r"```.*?```", re.DOTALL)


def _anchors(markdown: str) -> set[str]:
    """GitHub's heading anchors: lowercase, punctuation dropped, spaces to hyphens."""
    anchors = set()
    for heading in re.findall(r"^#{1,6} (.+)$", FENCE.sub("", markdown), flags=re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")
        anchors.add(slug)
    return anchors


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


@pytest.mark.parametrize("doc", DOCS, ids=_relative)
def test_relative_links_resolve(doc: Path) -> None:
    broken = []
    for target in LINK.findall(FENCE.sub("", TEXT[doc])):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        file_part, _, anchor = target.partition("#")
        linked = (doc.parent / file_part).resolve() if file_part else doc
        if not linked.exists():
            broken.append(target)
        elif (
            anchor
            and linked.suffix == ".md"
            and anchor not in _anchors(linked.read_text(encoding="utf-8"))
        ):
            broken.append(target)
    assert broken == []


def _openapi_routes() -> set[tuple[str, str]]:
    spec = json.loads((ROOT / "docs" / "openapi.json").read_text(encoding="utf-8"))
    return {
        (method.upper(), path)
        for path, operations in spec["paths"].items()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    }


def _shape(path: str) -> str:
    """/api/alerts/{alert_id} and /api/alerts/{id} are the same route."""
    return re.sub(r"\{[^}]+\}", "{}", path.split("?")[0].rstrip("/"))


def test_every_path_in_the_api_doc_exists() -> None:
    api = (ROOT / "docs" / "api.md").read_text(encoding="utf-8")
    documented = {_shape(p) for p in re.findall(r"`(/api/[^`\s]*)`", api)}
    real = {_shape(path) for _, path in _openapi_routes()} | {"/api/docs"}  # the docs page itself
    assert len(documented) > 40
    assert documented - real == set()


def test_every_route_is_in_the_api_doc() -> None:
    api = (ROOT / "docs" / "api.md").read_text(encoding="utf-8")
    documented = {_shape(p) for p in re.findall(r"`(/api/[^`\s]*)`", api)}
    missing = {path for _, path in _openapi_routes() if _shape(path) not in documented}
    assert missing == set()


def _cli_commands() -> set[str]:
    parser = cli.build_parser()
    subcommands = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    return set(subcommands.choices)  # type: ignore[arg-type]


def test_every_cli_command_named_in_the_docs_exists() -> None:
    commands = _cli_commands()
    assert {"demo-load", "create-admin", "verify-audit"} <= commands
    named = {
        name
        for text in TEXT.values()
        for name in re.findall(r"(?:app\.cli|\bcli) ([a-z]+(?:-[a-z]+)+|[a-z]{4,})\b", text)
    }
    assert named - commands == set()


def test_every_script_named_in_the_docs_exists() -> None:
    named = {
        name
        for text in TEXT.values()
        for name in re.findall(r"\bscripts/([\w.-]+\.(?:sh|py|mjs))", text)
    }
    assert {"backup.sh", "demo_reset.sh"} <= named
    assert {n for n in named if not (ROOT / "scripts" / n).exists()} == set()


def test_every_rule_named_in_the_docs_exists() -> None:
    rules = set(get_library().rules)
    named = {
        rule
        for text in TEXT.values()
        for rule in re.findall(r"\b(?:AUTH|PRIV|ACCT|PROC|NET)-\d{3}\b", text)
    }
    assert named and named - rules == set()
