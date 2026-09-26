"""Safe JSON decoding for the JSON-based parsers."""

import json
from typing import Any

from app.ingestion.parsers.base import ParseFailure, decode_utf8


def load_object(raw: bytes) -> dict[str, Any]:
    """One JSON object. Anything else (array, number, invalid, too deeply nested) fails.

    json.loads raises RecursionError on pathological nesting instead of consuming memory
    without bound; that is caught and reported as invalid_json like any other bad input.
    """
    text = decode_utf8(raw)
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise ParseFailure("invalid_json") from None
    if not isinstance(value, dict):
        raise ParseFailure("not_a_json_object")
    return value
