"""Parser registry: one parser per source type. Adding a source means one module here, its
fixtures and tests; detection and correlation do not change (ADR-0003)."""

import logging

from pydantic import ValidationError

from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.parsers import (
    app_json,
    generic_json,
    http_access,
    linux_auth,
    windows_security,
)
from app.ingestion.parsers.base import ParseContext, ParseFailure, Parser, Skipped

logger = logging.getLogger(__name__)

PARSERS: dict[SourceType, Parser] = {
    SourceType.LINUX_AUTH: linux_auth.parse,
    SourceType.WINDOWS_SECURITY: windows_security.parse,
    SourceType.HTTP_ACCESS: http_access.parse,
    SourceType.APP_JSON: app_json.parse,
    SourceType.GENERIC_JSON: generic_json.parse,
}


def parse_record(
    source_type: SourceType, raw: bytes, context: ParseContext
) -> NormalizedEvent | Skipped | ParseFailure:
    """Runs the source's parser and turns every way of failing into a ParseFailure value.

    Parsers must never crash the batch. A field that passes the parser but not the
    normalized model (for example a hostname with a space) fails the record as
    invalid_field; any other unexpected exception is reported as parser_error so a parser
    bug shows up in batch reports instead of aborting ingestion.
    """
    try:
        return PARSERS[source_type](raw, context)
    except ParseFailure as failure:
        return failure
    except ValidationError:
        return ParseFailure("invalid_field")
    except Exception as exc:  # a parser bug must not stop the batch
        # Only the exception type: its message could contain text from the record.
        logger.error(
            "ingest.parser_error",
            extra={"fields": {"source_type": str(source_type), "error": type(exc).__name__}},
        )
        return ParseFailure("parser_error")


__all__ = ["PARSERS", "ParseContext", "ParseFailure", "Skipped", "parse_record"]
