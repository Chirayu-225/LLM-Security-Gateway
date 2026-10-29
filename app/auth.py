"""
Fix for: "/stats serves recent prompts with no authentication" and
"/redteam/run is unauthenticated and fires multiple paid LLM calls per
request" (review findings).

Deliberately simple — a single shared API key checked via a header. This
is proportionate to a portfolio project; a real production deployment
would use per-client keys or OAuth, but "no auth at all on an endpoint
that serves logged prompts and one that spends money" is the actual bug
being fixed here, not the sophistication of the auth scheme.

Set GATEWAY_API_KEY in your .env. If it's unset, these endpoints refuse
to serve traffic rather than silently running open — fail closed, not
open, matching the same philosophy as the enforcer fix.
"""

import os
import secrets
from fastapi import Header, HTTPException


def require_api_key(x_api_key: str = Header(default=None)):
    configured_key = os.environ.get("GATEWAY_API_KEY")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="Server misconfiguration: GATEWAY_API_KEY is not set. "
                   "Refusing to serve this endpoint unauthenticated.",
        )

    if not x_api_key or not secrets.compare_digest(x_api_key, configured_key):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")

    return True
