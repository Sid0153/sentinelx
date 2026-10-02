"""The module boundaries in docs/architecture.md, enforced (Phase 18 review): pure cores do no
I/O and read no clock, and each kind of record has exactly one writer."""

import ast
import importlib
from pathlib import Path

import pytest

from app.database.base import Base

APP = Path(__file__).resolve().parents[2] / "app"

# Plain data in, plain data out: no database, no web framework, no clock.
PURE = [
    *sorted((APP / "ingestion" / "parsers").glob("*.py")),
    APP / "ingestion" / "normalize.py",
    *sorted((APP / "detection" / "evaluators").glob("*.py")),
    APP / "detection" / "evaluate.py",
    APP / "detection" / "explain.py",
    APP / "correlation" / "scoring.py",
    *sorted((APP / "risk").glob("*.py")),
    APP / "alerts" / "workflow.py",
    APP / "incidents" / "workflow.py",
    APP / "demo" / "scenarios.py",
    APP / "demo" / "environment.py",
]
# Pure evaluation, plus one documented use of SQLAlchemy each, never a session or the clock:
# conditions compile to SQL expressions (to_sql); enrichment loads its inventory snapshot once
# per batch (load_snapshot), then looks up without I/O.
PURE_WITH_SQL = [APP / "detection" / "conditions.py", APP / "ingestion" / "enrich.py"]

FORBIDDEN = ("sqlalchemy", "fastapi", "starlette", "app.database", "app.models", "app.api")
CLOCK = {("datetime", "now"), ("datetime", "utcnow"), ("datetime", "today"), ("time", "time")}


def _relative(path: Path) -> str:
    return path.relative_to(APP).as_posix()


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _clock_reads(tree: ast.Module) -> list[str]:
    reads = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (node.func.value.id, node.func.attr) in CLOCK
        ):
            reads.append(f"line {node.lineno}: {node.func.value.id}.{node.func.attr}()")
    return reads


def _model_imports(tree: ast.Module) -> list[tuple[str, str]]:
    return [
        (node.module, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.models")
        for alias in node.names
    ]


@pytest.mark.parametrize("path", PURE, ids=_relative)
def test_pure_cores_import_no_database_or_framework(path: Path) -> None:
    tree = _tree(path)
    bad = {
        name
        for name in _imports(tree)
        if name.startswith(FORBIDDEN) and not name.startswith("app.models")
    }
    assert bad == set()
    # From the model modules, only enums and constants (the shared vocabulary), never a
    # mapped class: a pure core cannot query or build rows.
    for module, name in _model_imports(tree):
        value = getattr(importlib.import_module(module), name)
        assert not (isinstance(value, type) and issubclass(value, Base)), f"{module}.{name}"


@pytest.mark.parametrize("path", PURE_WITH_SQL, ids=_relative)
def test_the_two_sql_aware_cores_hold_no_session_except_to_load(path: Path) -> None:
    imports = _imports(_tree(path))
    assert not {n for n in imports if n.startswith(("fastapi", "starlette", "app.database"))}
    sessions = [
        node.name
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(arg.annotation, ast.Name) and arg.annotation.id == "Session"
            for arg in node.args.args
        )
    ]
    assert sessions in ([], ["load_snapshot"])


@pytest.mark.parametrize("path", PURE + PURE_WITH_SQL, ids=_relative)
def test_pure_cores_take_the_time_as_a_parameter(path: Path) -> None:
    assert _clock_reads(_tree(path)) == []


# Each kind of record is constructed in one place only.
WRITERS = {
    "RawEvent": {"events/store.py"},
    "Event": {"events/store.py"},
    "Alert": {"alerts/service.py"},
    "Incident": {"incidents/records.py"},
    "AuditLog": {"audit/service.py"},
}


def test_each_record_has_one_writer() -> None:
    found: dict[str, set[str]] = {name: set() for name in WRITERS}
    for path in APP.rglob("*.py"):
        for node in ast.walk(_tree(path)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in WRITERS
            ):
                found[node.func.id].add(_relative(path))
    assert found == WRITERS
