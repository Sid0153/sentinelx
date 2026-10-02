"""render.yaml (the free public deployment) stays consistent with the code: the static site
proxies to the API service, CORS names the static site, every variable is one the backend
reads, and no secret value is written in the file."""

import re
from pathlib import Path
from typing import Any

import yaml

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[3]
BLUEPRINT: dict[str, Any] = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
SERVICES = {service["name"]: service for service in BLUEPRINT["services"]}
API = next(s for s in SERVICES.values() if s["runtime"] == "docker")
SITE = next(s for s in SERVICES.values() if s["runtime"] == "static")
ENV = {item["key"]: item for item in API["envVars"]}


def test_the_site_proxies_api_calls_to_the_api_service() -> None:
    rewrite = next(r for r in SITE["routes"] if r["source"] == "/api/*")
    assert rewrite["destination"] == f"https://{API['name']}.onrender.com/api/*"
    assert SITE["routes"][-1] == {"type": "rewrite", "source": "/*", "destination": "/index.html"}


def test_cors_allows_exactly_the_site() -> None:
    assert ENV["CORS_ORIGINS"]["value"] == f"https://{SITE['name']}.onrender.com"


def test_every_variable_is_one_the_backend_reads() -> None:
    entrypoint = (ROOT / "backend" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    known = {name.upper() for name in Settings.model_fields}
    known |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", entrypoint))
    assert set(ENV) - known == set()


def test_no_secret_is_written_in_the_file() -> None:
    for key in ("SECRET_KEY", "APP_DB_PASSWORD"):
        assert ENV[key] == {"key": key, "generateValue": True}
    assert ENV["MIGRATION_DATABASE_URL"] == {"key": "MIGRATION_DATABASE_URL", "sync": False}
    assert "DATABASE_URL" not in ENV  # derived from the owner's URL and the app role


def test_production_settings_and_the_safe_demo() -> None:
    assert ENV["APP_ENV"]["value"] == "production"
    assert ENV["DEMO_AUTOLOAD"]["value"] == "true"
    assert ENV["GUEST_EMAIL"]["value"].endswith(".example")  # never a real mailbox
    assert API["autoDeployTrigger"] == SITE["autoDeployTrigger"] == "checksPass"
    Settings(  # the values given in the file pass the backend's own validation
        _env_file=None,  # type: ignore[call-arg]
        database_url="postgresql+psycopg://u:p@h/d",
        secret_key="a-generated-value-0123456789abcdef",
        **{key.lower(): item["value"] for key, item in ENV.items() if "value" in item},
    )


def test_the_site_sends_the_same_security_headers_as_nginx() -> None:
    nginx = (ROOT / "frontend" / "nginx" / "app.conf").read_text(encoding="utf-8")
    sent = dict(re.findall(r'add_header ([\w-]+) "([^"]+)" always;', nginx))
    configured = {h["name"]: h["value"] for h in SITE["headers"] if h["path"] == "/*"}
    assert configured == sent
