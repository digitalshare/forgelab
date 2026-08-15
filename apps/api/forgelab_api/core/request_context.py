"""Per-request correlation identifier.

One user action can produce several audit events across authentication,
authorization, and the handler itself. Without a shared identifier those rows
can only be tied together by timestamp — and `created_at` defaults to
PostgreSQL `now()`, which returns transaction-start time, so rows written in one
transaction are indistinguishable by time. The request identifier is what makes
"show me everything that happened during that request" answerable.

An inbound `X-Request-ID` is honoured so a trace started at the edge carries
through, but it is validated first: the value reaches the database and is echoed
to the client, so accepting arbitrary caller input would be both a storage and a
header-injection concern.
"""

from __future__ import annotations

import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

REQUEST_ID_HEADER = "X-Request-ID"

#: Conservative on purpose: identifiers, not free text.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _clean(candidate: str | None) -> str | None:
    if candidate and _VALID_REQUEST_ID.match(candidate):
        return candidate
    return None


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request identifier to every request and echo it back."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = _clean(request.headers.get(REQUEST_ID_HEADER)) or uuid.uuid4().hex
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


def get_request_id(request: Request) -> str | None:
    """Read the identifier attached by the middleware.

    Returns None when the middleware is absent — a caller assembling an audit
    record should still write it, just without correlation.
    """
    return getattr(request.state, "request_id", None)
