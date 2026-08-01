"""
Small helper functions so the rest of the app never writes raw SQLAlchemy
session code inline — main.py and redteam/runner.py just call these.
"""

import json
from sqlalchemy.orm import sessionmaker
from app.db.models import RequestLog, ToolViolation, RedTeamRun, get_engine

_Session = sessionmaker(bind=get_engine())


def log_request(
    provider: str,
    prompt: str,
    response: str = None,
    blocked: bool = False,
    blocked_stage: str = None,
    blocked_category: str = None,
    reason: str = None,
):
    session = _Session()
    try:
        entry = RequestLog(
            provider=provider,
            prompt=prompt,
            response=response,
            blocked=blocked,
            blocked_stage=blocked_stage,
            blocked_category=blocked_category,
            reason=reason,
        )
        session.add(entry)
        session.commit()
    finally:
        session.close()


def log_tool_violation(agent_name: str, tool_name: str, reason: str):
    session = _Session()
    try:
        entry = ToolViolation(agent_name=agent_name, tool_name=tool_name, reason=reason)
        session.add(entry)
        session.commit()
    finally:
        session.close()


def log_redteam_run(total_prompts: int, blocked_count: int, category_breakdown: dict):
    session = _Session()
    try:
        entry = RedTeamRun(
            total_prompts=total_prompts,
            blocked_count=blocked_count,
            block_rate=round(blocked_count / total_prompts, 3) if total_prompts else 0.0,
            category_breakdown_json=json.dumps(category_breakdown),
        )
        session.add(entry)
        session.commit()
    finally:
        session.close()


def get_recent_requests(limit: int = 50):
    session = _Session()
    try:
        return (
            session.query(RequestLog)
            .order_by(RequestLog.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def get_recent_violations(limit: int = 50):
    session = _Session()
    try:
        return (
            session.query(ToolViolation)
            .order_by(ToolViolation.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def get_latest_redteam_run():
    session = _Session()
    try:
        return (
            session.query(RedTeamRun)
            .order_by(RedTeamRun.timestamp.desc())
            .first()
        )
    finally:
        session.close()


def get_redteam_history(limit: int = 20):
    session = _Session()
    try:
        return (
            session.query(RedTeamRun)
            .order_by(RedTeamRun.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()
