"""Assets and identities: the context that turns "host web-01" into "a critical production
server owned by the platform team". Maintained by admins; read by enrichment and risk."""

import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.events.schema import Criticality


class AssetType(enum.StrEnum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    OTHER = "other"


class Environment(enum.StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class AssetStatus(enum.StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"  # kept, because past events and incidents still point to it


class PrivilegeLevel(enum.StrEnum):
    STANDARD = "standard"
    PRIVILEGED = "privileged"  # administrators, sudoers, domain admins
    SERVICE = "service"  # non-human accounts


class IdentityStatus(enum.StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


def _check_in(column: str, values: type[enum.StrEnum]) -> str:
    return f"{column} IN ({', '.join(repr(v.value) for v in values)})"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        sa.CheckConstraint(_check_in("asset_type", AssetType), name="asset_type_valid"),
        sa.CheckConstraint(_check_in("environment", Environment), name="environment_valid"),
        sa.CheckConstraint(_check_in("criticality", Criticality), name="criticality_valid"),
        sa.CheckConstraint(_check_in("status", AssetStatus), name="status_valid"),
        sa.CheckConstraint("hostname = lower(hostname)", name="hostname_lowercase"),
        sa.Index("ix_assets_ip_addresses", "ip_addresses", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(sa.String(253), unique=True)
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(INET), default=list, server_default="{}")
    asset_type: Mapped[str] = mapped_column(sa.String(32))
    environment: Mapped[str] = mapped_column(sa.String(16))
    criticality: Mapped[str] = mapped_column(sa.String(16), index=True)
    owner: Mapped[str | None] = mapped_column(sa.String(128))
    description: Mapped[str | None] = mapped_column(sa.String(500))
    tags: Mapped[list[str]] = mapped_column(ARRAY(sa.String(32)), default=list, server_default="{}")
    status: Mapped[str] = mapped_column(sa.String(16), default=AssetStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )


class Identity(Base):
    """A person or service account as it appears in logs (not a SentinelX user)."""

    __tablename__ = "identities"
    __table_args__ = (
        sa.CheckConstraint(
            _check_in("privilege_level", PrivilegeLevel), name="privilege_level_valid"
        ),
        sa.CheckConstraint(_check_in("status", IdentityStatus), name="status_valid"),
        sa.CheckConstraint("username = lower(username)", name="username_lowercase"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(sa.String(256), unique=True)
    display_name: Mapped[str | None] = mapped_column(sa.String(128))
    department: Mapped[str | None] = mapped_column(sa.String(128))
    title: Mapped[str | None] = mapped_column(sa.String(128))  # job role, e.g. "DBA"
    privilege_level: Mapped[str] = mapped_column(sa.String(16), index=True)
    status: Mapped[str] = mapped_column(sa.String(16), default=IdentityStatus.ACTIVE)
    tags: Mapped[list[str]] = mapped_column(ARRAY(sa.String(32)), default=list, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )
