import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.hunting.query import HuntQuery, TimeRange
from app.hunting.service import Definition
from app.schemas.ingestion import EventPublic


class HuntField(BaseModel):
    field: str
    kind: str  # text | ip | number | boolean | attribute
    operators: list[str]


class HuntFields(BaseModel):
    fields: list[HuntField]
    attribute_operators: list[str]  # for `attributes.<key>`
    max_filters: int
    max_range_days: int


class HuntRunRequest(HuntQuery):
    cursor: str | None = Field(default=None, max_length=200)


class HuntResult(BaseModel):
    items: list[EventPublic]
    next_cursor: str | None
    total: int
    total_capped: bool  # more matches than `total` (the count stops at a cap)
    start: datetime = Field(serialization_alias="from")
    end: datetime = Field(serialization_alias="to")
    limit: int


class TemplateParam(BaseModel):
    name: str
    description: str
    default: int
    minimum: int
    maximum: int


class TemplateColumn(BaseModel):
    key: str
    label: str
    kind: str


class TemplateInfo(BaseModel):
    id: str
    name: str
    question: str
    technique: str
    mirrors_rule: str | None
    params: list[TemplateParam]
    columns: list[TemplateColumn]


class TemplateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: dict[str, Any] = Field(default_factory=dict)
    time_range: TimeRange


class TemplateResult(BaseModel):
    template_id: str
    columns: list[TemplateColumn]
    rows: list[dict[str, Any]]
    truncated: bool  # more rows than shown
    start: datetime = Field(serialization_alias="from")
    end: datetime = Field(serialization_alias="to")


class SavedHuntCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    definition: Definition
    shared: bool = False


class SavedHuntUpdate(BaseModel):
    """PATCH: only the fields sent change. `description: null` clears it."""

    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    definition: Definition | None = None
    shared: bool | None = None

    @model_validator(mode="after")
    def _something(self) -> "SavedHuntUpdate":
        if not self.model_fields_set:
            raise ValueError("provide at least one field to change")
        for field in self.model_fields_set - {"description"}:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be empty")
        return self


class SavedHuntPublic(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    kind: str
    definition: dict[str, Any]
    shared: bool
    owner_id: uuid.UUID
    owner_email: str | None
    is_owner: bool
    valid: bool  # false: saved by an older version and no longer runnable
    problem: str | None
    created_at: datetime
    updated_at: datetime
