"""
LLM Security Gateway — main API surface.

Endpoints:
  GET  /                    health check
  POST /chat                the actual gateway: input guardrail -> LLM -> output guardrail
  POST /agent/check-tool-call   enforce an agent manifest against a proposed tool call
  POST /redteam/run          replay the held-out attack suite against the gateway, score it
  GET  /stats                aggregated data for the Streamlit dashboard

Single-provider (Groq) by design — see app/pipeline.py for why.

SECURITY FIXES (review findings):

  - High: manifest_path (an arbitrary client-supplied filesystem path
    passed straight to open()) is REMOVED. Callers now reference a
    manifest by ID from a fixed, server-side allowlist
    (MANIFEST_ALLOWLIST below) — a caller can no longer probe the
    filesystem or read arbitrary files by manipulating a path string.
  - High/Medium: /agent/check-tool-call, /redteam/run, and /stats now
    require the X-API-Key header (app/auth.py). /stats previously served
    recent prompts with no authentication at all; /redteam/run
    previously let anyone fire paid LLM calls with no auth or rate limit.
  - Medium (LLM10, Unbounded Consumption): /chat and /redteam/run are now
    rate-limited (app/rate_limit.py), and /chat enforces a hard prompt
    length cap.
"""

from dotenv import load_dotenv
load_dotenv()

import os
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional

from app.pipeline import process_chat, PROVIDER_NAME
from app.agent_audit.manifest import load_manifest
from app.agent_audit.enforcer import check_tool_call
from app.redteam.runner import run_redteam_suite
from app.db.models import init_db
from app.db import logger as db_logger
from app.auth import require_api_key
from app.rate_limit import enforce_rate_limit, enforce_prompt_length

app = FastAPI(title="LLM Security Gateway", version="0.4.0")

init_db()

# --- Manifest allowlist ----------------------------------------------------
# Fix for the manifest-path-injection bypass: callers reference a manifest
# by a fixed ID, never by a raw filesystem path. Add new manifests here,
# not by accepting arbitrary paths from a request.
_MANIFESTS_DIR = os.path.join(os.path.dirname(__file__), "..", "manifests")
MANIFEST_ALLOWLIST = {
    "research_assistant_agent": os.path.join(_MANIFESTS_DIR, "example_agent.yaml"),
}


# ---------------------------------------------------------------- /chat --
class ChatRequest(BaseModel):
    prompt: str
    # Optional: pass the same session_id across turns of one conversation
    # to enable multi-turn erosion detection (app/guardrails/session_tracker.py).
    # Omit it and each request is evaluated independently, as before.
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    provider: str = PROVIDER_NAME
    blocked: bool
    blocked_stage: Optional[str] = None
    blocked_category: Optional[str] = None
    reason: str
    response: Optional[str] = None
    error: bool = False


@app.get("/")
def health_check():
    return {"status": "ok", "message": "LLM Security Gateway is running", "provider": PROVIDER_NAME}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest, http_request: Request):
    enforce_rate_limit(http_request, "/chat")
    enforce_prompt_length(request.prompt)

    result = process_chat(request.prompt, session_id=request.session_id)
    return ChatResponse(
        blocked=result.blocked,
        blocked_stage=result.blocked_stage,
        blocked_category=result.blocked_category,
        reason=result.reason,
        response=result.response,
        error=result.error,
    )


# ----------------------------------------------------- /agent/check-tool-call --
class ToolCallRequest(BaseModel):
    manifest_id: str             # e.g. "research_assistant_agent" — NOT a filesystem path
    tool_name: str
    scope: Optional[str] = None
    # Audit-only: never trusted for the authorization decision itself.
    # The server derives the real required permission from
    # app/agent_audit/tool_registry.py. Kept so a mismatch between what
    # the caller CLAIMS and what's actually required is visible in logs —
    # a useful signal for spotting a compromised or misbehaving agent.
    requested_permission: Optional[str] = None


class ToolCallResponse(BaseModel):
    allowed: bool
    reason: str
    effective_permission: Optional[str] = None


@app.post("/agent/check-tool-call", response_model=ToolCallResponse)
def agent_check_tool_call(request: ToolCallRequest, _auth: bool = Depends(require_api_key)):
    manifest_path = MANIFEST_ALLOWLIST.get(request.manifest_id)
    if manifest_path is None:
        raise HTTPException(status_code=404, detail=f"Unknown manifest_id: {request.manifest_id!r}")

    try:
        manifest = load_manifest(manifest_path)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Allowlisted manifest file is missing on disk.")

    verdict = check_tool_call(
        manifest, request.tool_name, request.requested_permission, request.scope,
    )

    if not verdict.allowed:
        db_logger.log_tool_violation(
            agent_name=manifest.agent_name,
            tool_name=request.tool_name,
            reason=verdict.reason,
        )

    return ToolCallResponse(
        allowed=verdict.allowed, reason=verdict.reason,
        effective_permission=verdict.effective_permission,
    )


# ------------------------------------------------------------ /redteam/run --
@app.post("/redteam/run")
def redteam_run(http_request: Request, _auth: bool = Depends(require_api_key)):
    enforce_rate_limit(http_request, "/redteam/run")
    return run_redteam_suite()


# ----------------------------------------------------------------- /stats --
@app.get("/stats")
def stats(_auth: bool = Depends(require_api_key)):
    recent_requests = db_logger.get_recent_requests(limit=50)
    recent_violations = db_logger.get_recent_violations(limit=50)
    latest_run = db_logger.get_latest_redteam_run()
    history = db_logger.get_redteam_history(limit=20)

    return {
        "provider": PROVIDER_NAME,
        "recent_requests": [
            {
                "timestamp": r.timestamp.isoformat(),
                "provider": r.provider,
                "prompt": r.prompt,
                "blocked": r.blocked,
                "blocked_stage": r.blocked_stage,
                "blocked_category": r.blocked_category,
                "reason": r.reason,
            }
            for r in recent_requests
        ],
        "recent_violations": [
            {
                "timestamp": v.timestamp.isoformat(),
                "agent_name": v.agent_name,
                "tool_name": v.tool_name,
                "reason": v.reason,
            }
            for v in recent_violations
        ],
        "latest_redteam_run": (
            {
                "timestamp": latest_run.timestamp.isoformat(),
                "total_prompts": latest_run.total_prompts,
                "blocked_count": latest_run.blocked_count,
                "block_rate": latest_run.block_rate,
                "category_breakdown": latest_run.category_breakdown_json,
            }
            if latest_run else None
        ),
        "redteam_history": [
            {
                "timestamp": r.timestamp.isoformat(),
                "block_rate": r.block_rate,
                "total_prompts": r.total_prompts,
            }
            for r in history
        ],
    }
