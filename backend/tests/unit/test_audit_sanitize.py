from app.audit.service import MAX_ITEMS, MAX_TEXT, sanitize


def test_secret_looking_keys_are_dropped_at_any_depth() -> None:
    cleaned = sanitize(
        {
            "email": "a@example.com",
            "password": "hunter2",
            "nested": {"refresh_token": "abc", "api-key": "k", "ok": 1},
            "Cookie": "sx_refresh=xyz",
        }
    )
    assert cleaned == {"email": "a@example.com", "nested": {"ok": 1}}


def test_secrets_inside_values_are_redacted() -> None:
    cleaned = sanitize({"note": "sent Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"})
    assert "eyJ" not in cleaned["note"]


def test_long_strings_and_lists_are_capped() -> None:
    cleaned = sanitize({"text": "x" * 10_000, "items": list(range(1000))})
    assert len(cleaned["text"]) == MAX_TEXT
    assert len(cleaned["items"]) == MAX_ITEMS


def test_deep_nesting_is_truncated() -> None:
    assert sanitize({"a": {"b": {"c": {"d": {"e": 1}}}}}) == {
        "a": {"b": {"c": {"d": "[truncated]"}}}
    }


def test_non_json_values_become_strings() -> None:
    assert sanitize({"when": object()})["when"].startswith("<object")
