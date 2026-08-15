"""Keep credential material out of the audit trail.

An audit record is read by operators during an incident, exported for review,
and retained far longer than a request log. A token that lands in one is a token
that outlives every control built to contain it. Redaction is therefore applied
to *every* write, not left to the discretion of each caller.

The approach is deny-by-default on names, plus a shape check on values:

* **Key match** — any key whose name contains a sensitive fragment is replaced,
  whatever its value. Substring rather than exact match, so `refresh_token`,
  `authorization_header`, and `client_secret` are all caught without
  enumerating every variation someone might invent.
* **Value shape** — a value that *looks* like a credential is replaced even
  under an innocent key, because `{"detail": "Bearer eyJhbGci..."}` is exactly
  how these leak in practice.

Redaction replaces rather than removes. A missing key is ambiguous during an
investigation; `"[redacted]"` says a value existed and was withheld deliberately.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[redacted]"

#: Substrings that mark a key as carrying credential material.
SENSITIVE_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "token",
        "password",
        "passwd",
        "secret",
        "authorization",
        "cookie",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "signing_key",
        "jwt",
        "bearer",
        "session_key",
        "access_key",
        "refresh",
        "hash",
    }
)

#: A compact JWT — three base64url segments. Catches ID and access tokens even
#: when stored under a harmless key.
_JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")

#: An explicit scheme prefix is a credential regardless of the key it sits under.
_AUTH_SCHEME_PATTERN = re.compile(r"^(bearer|basic|token)\s+\S+", re.IGNORECASE)

#: Depth limit. Audit metadata is not a place for deep structures, and an
#: unbounded walk over caller-supplied data is a denial-of-service waiting to
#: happen. Anything deeper is dropped rather than trusted.
MAX_DEPTH = 6


def is_sensitive_key(key: str) -> bool:
    """Whether a key name marks its value as credential material."""
    lowered = key.casefold()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def looks_like_credential(value: str) -> bool:
    """Whether a string has the shape of a token, regardless of its key."""
    stripped = value.strip()
    return bool(_JWT_PATTERN.match(stripped) or _AUTH_SCHEME_PATTERN.match(stripped))


def redact(payload: Any, *, _depth: int = 0) -> Any:
    """Return a copy of `payload` with credential material replaced.

    Recurses through dicts, lists, and tuples. Never mutates the input — a
    caller's dictionary being silently rewritten as a side effect of logging
    would be its own bug.
    """
    if _depth >= MAX_DEPTH:
        return REDACTED

    if isinstance(payload, dict):
        result: dict[str, Any] = {}
        for key, value in payload.items():
            name = str(key)
            if is_sensitive_key(name):
                result[name] = REDACTED
            else:
                result[name] = redact(value, _depth=_depth + 1)
        return result

    if isinstance(payload, (list, tuple)):
        return [redact(item, _depth=_depth + 1) for item in payload]

    if isinstance(payload, str) and looks_like_credential(payload):
        return REDACTED

    return payload
