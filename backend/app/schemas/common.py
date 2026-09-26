from typing import Any

from pydantic import BaseModel


class Page[T](BaseModel):
    """One page of a list. `total` counts every matching row, not just this page."""

    items: list[T]
    total: int
    limit: int
    offset: int


class ErrorDetail(BaseModel):
    loc: list[str | int]
    msg: str
    type: str


class ErrorInfo(BaseModel):
    code: str
    message: str
    request_id: str | None
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    """The shape of every error response (app/core/errors.py)."""

    error: ErrorInfo


_DESCRIPTIONS = {
    400: "Request not allowed in the current state",
    401: "Not signed in, or the session expired",
    403: "Signed in, but the role does not allow this",
    404: "Not found",
    409: "Conflicts with existing data",
    413: "Request body or record count over the limit",
    415: "Unsupported content type",
    422: "Request validation failed",
    429: "Too many requests; see Retry-After",
}


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """OpenAPI documentation for the error statuses a route can return."""
    return {
        code: {"model": ErrorResponse, "description": _DESCRIPTIONS.get(code, "Error")}
        for code in codes
    }
