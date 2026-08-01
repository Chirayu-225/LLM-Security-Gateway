"""
Storage schema. SQLite is intentional here — zero setup, single file,
plenty for a portfolio-scale project. Swap to Postgres later by changing
only the engine URL in logger.py if this ever needs to scale.
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, Float
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    provider = Column(String)
    prompt = Column(Text)
    response = Column(Text, nullable=True)
    blocked = Column(Boolean, default=False)
    blocked_stage = Column(String, nullable=True)   # "input" | "output" | None
    blocked_category = Column(String, nullable=True)  # OWASP LLM Top 10 ID
    reason = Column(Text, nullable=True)


class ToolViolation(Base):
    __tablename__ = "tool_violations"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_name = Column(String)
    tool_name = Column(String)
    reason = Column(Text)


class RedTeamRun(Base):
    __tablename__ = "redteam_runs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_prompts = Column(Integer)
    blocked_count = Column(Integer)
    block_rate = Column(Float)
    category_breakdown_json = Column(Text)  # JSON string: {"LLM01": {"total": .., "blocked": ..}, ...}


_engine = create_engine("sqlite:///gateway.db", connect_args={"check_same_thread": False})


def init_db():
    Base.metadata.create_all(_engine)


def get_engine():
    return _engine
