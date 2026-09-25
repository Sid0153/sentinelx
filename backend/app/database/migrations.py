"""Which schema revision the code expects, and which one the database has."""

from functools import lru_cache
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))


@lru_cache
def expected_revision() -> str | None:
    """The head revision of the migrations shipped with this code."""
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(db: Session) -> str | None:
    """The revision recorded in the database, or None if it was never migrated."""
    if not inspect(db.connection()).has_table("alembic_version"):
        return None
    return db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
