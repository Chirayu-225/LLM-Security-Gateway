"""
Fix for: "no cost protection... /redteam/run is unauthenticated and fires
multiple paid LLM calls per request. Nothing limits request rate or
prompt length" — OWASP LLM10, Unbounded Consumption (2025 list).

Deliberately simple: an in-memory fixed-window counter per client
identity (API key if present, else caller IP). Good enough for a
single-process portfolio deployment; a real multi-instance deployment
would move this to Redis so limits are shared across processes.

Also enforces a hard prompt-length cap, since an unbounded prompt is its
own cost/DoS vector independent of request count.
"""

import time
from collections import defaultdict
from fastapi import HTTPException, Request

MAX_PROMPT_CHARS = 4000

_WINDOW_SECONDS = 60
_LIMITS = {
    "/chat": 30,
    "/redteam/run": 3,       # expensive: fires many paid LLM calls per hit
}

_hits: dict[str, list[float]] = defaultdict(list)


def _client_key(request: Request) -> str:
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"key:{api_key}"
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}"


def enforce_rate_limit(request: Request, route: str):
    limit = _LIMITS.get(route)
    if limit is None:
        return

    key = f"{route}:{_client_key(request)}"
    now = time.time()
    window_start = now - _WINDOW_SECONDS

    recent = [t for t in _hits[key] if t > window_start]
    if len(recent) >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for {route}: {limit} requests per "
                   f"{_WINDOW_SECONDS}s. Try again shortly.",
        )

    recent.append(now)
    _hits[key] = recent


def enforce_prompt_length(prompt: str):
    if len(prompt) > MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"Prompt exceeds max length of {MAX_PROMPT_CHARS} characters.",
        )
