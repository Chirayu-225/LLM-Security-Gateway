"""
LLM Security Gateway — main API surface.

Endpoints:
  GET  /                    health check
  POST /chat                the actual gateway: input guardrail -> LLM -> output guardrail
  POST /agent/check-tool-call   enforce an agent manifest against a proposed tool call
  POST /redteam/run          replay the held-out attack suite against the gateway, score it
  GET  /stats                aggregated data for the Streamlit dashboard

Single-provider (Groq) by design — see app/pipeline.py for why.
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.pipeline import process_chat, PROVIDER_NAME
from app.agent_audit.manifest import load_manifest
from app.agent_audit.enforcer import check_tool_call
from app.redteam.runner import run_redteam_suite
from app.db.models import init_db
from app.db import logger as db_logger

app = FastAPI(title="LLM Security Gateway", version="0.3.0")

init_db()


# ---------------------------------------------------------------- /chat --
class ChatRequest(BaseModel):
    prompt: str


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
def chat(request: ChatRequest):
    result = process_chat(request.prompt)
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
    manifest_path: str          # e.g. "manifests/example_agent.yaml"
    tool_name: str
    requested_permission: str   # "read_only" | "write" | "execute"
    scope: Optional[str] = None


class ToolCallResponse(BaseModel):
    allowed: bool
    reason: str


@app.post("/agent/check-tool-call", response_model=ToolCallResponse)
def agent_check_tool_call(request: ToolCallRequest):
    try:
        manifest = load_manifest(request.manifest_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Manifest not found: {request.manifest_path}")

    verdict = check_tool_call(
        manifest, request.tool_name, request.requested_permission, request.scope,
    )

    if not verdict.allowed:
        db_logger.log_tool_violation(
            agent_name=manifest.agent_name,
            tool_name=request.tool_name,
            reason=verdict.reason,
        )

    return ToolCallResponse(allowed=verdict.allowed, reason=verdict.reason)


# ------------------------------------------------------------ /redteam/run --
@app.post("/redteam/run")
def redteam_run():
    return run_redteam_suite()


# ----------------------------------------------------------------- /stats --
@app.get("/stats")
def stats():
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
