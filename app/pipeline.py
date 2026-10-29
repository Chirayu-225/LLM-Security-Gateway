"""
The single shared pipeline both /chat (real traffic) and the red-team
runner (simulated attacks) run through. Keeping this in one place means
the red-team engine is testing the EXACT same code path real users hit —
not a re-implementation that could drift out of sync with production
behavior.

Pipeline stages, in order:
  1. Input guardrail  (app/guardrails/input_filter.py)
  2. LLM call         (app/llm_clients/groq_client.py)
  3. Output guardrail (app/guardrails/output_filter.py)
  4. Logging          (app/db/logger.py)

Single-provider by design: this gateway targets Groq only. Two
interchangeable providers added complexity without adding coverage — the
guardrails are provider-agnostic logic, so testing them against one real
backend is sufficient. We specifically want attack prompts to reach OUR
guardrails rather than being pre-filtered upstream by a provider's own
safety layer, so a red-team run measures our own defenses, not the
underlying model's.

SECURITY FIX (review finding, High — "PII is written in plaintext to the
log you built to prevent leaks"): every response written to the log is
now passed through OutputGuardrail.redact() first, regardless of whether
the response was blocked or allowed. Previously, a response blocked FOR
containing PII was still logged with the raw, unredacted text — meaning
the very act of detecting and blocking a leak created a second, quieter
copy of it in the database. The client-facing response is unaffected:
blocked responses are still never returned to the client at all, and
allowed responses are still returned to the client exactly as generated —
only the LOGGED COPY is redacted.
"""

from dataclasses import dataclass
from typing import Optional

from app.guardrails.input_filter import InputGuardrail
from app.guardrails.output_filter import OutputGuardrail
from app.guardrails import session_tracker
from app.llm_clients import groq_client
from app.db import logger as db_logger
from app.system_prompt import SYSTEM_PROMPT_LEAK_MARKER

# Instantiated once at import time (module-level singletons) so the
# embedding model and Presidio analyzer load ONCE, not on every request —
# loading them per-request would make every call painfully slow.
_input_guardrail = InputGuardrail()
_output_guardrail = OutputGuardrail(system_prompt_fragment=SYSTEM_PROMPT_LEAK_MARKER)

PROVIDER_NAME = "groq"


@dataclass
class PipelineResult:
    blocked: bool
    blocked_stage: Optional[str]      # "input" | "output" | "session" | "provider_error" | None
    blocked_category: Optional[str]   # OWASP LLM Top 10 ID
    reason: str
    response: Optional[str] = None
    error: bool = False               # True if the LLM call itself failed/refused —
                                       # distinct from "blocked" (our guardrails firing)


def process_chat(prompt: str, log: bool = True, session_id: Optional[str] = None) -> PipelineResult:
    # --- Stage 1: input guardrail ---
    input_verdict = _input_guardrail.check(prompt)

    # --- Stage 1b: multi-turn session risk (extension — see
    # app/guardrails/session_tracker.py). Runs even when the single turn
    # wasn't individually blocked, since the whole point is catching
    # erosion attacks spread across several below-threshold turns. ---
    session_verdict = None
    if session_id and input_verdict.similarity_score is not None:
        session_verdict = session_tracker.record_turn(session_id, input_verdict.similarity_score)

    if input_verdict.blocked:
        result = PipelineResult(
            blocked=True,
            blocked_stage="input",
            blocked_category=input_verdict.category,
            reason=input_verdict.reason,
        )
        if log:
            db_logger.log_request(
                provider=PROVIDER_NAME, prompt=prompt, response=None,
                blocked=True, blocked_stage="input",
                blocked_category=input_verdict.category, reason=input_verdict.reason,
            )
        return result

    if session_verdict and session_verdict.blocked:
        result = PipelineResult(
            blocked=True,
            blocked_stage="session",
            blocked_category="LLM01",  # still fundamentally a prompt-injection pattern, spread across turns
            reason=session_verdict.reason,
        )
        if log:
            db_logger.log_request(
                provider=PROVIDER_NAME, prompt=prompt, response=None,
                blocked=True, blocked_stage="session",
                blocked_category="LLM01", reason=session_verdict.reason,
            )
        return result

    # --- Stage 2: forward to Groq ---
    try:
        raw_response = groq_client.generate(prompt)
    except Exception as e:
        result = PipelineResult(
            blocked=False, blocked_stage="provider_error", blocked_category=None,
            reason=f"LLM provider error: {e}", response=None, error=True,
        )
        if log:
            db_logger.log_request(
                provider=PROVIDER_NAME, prompt=prompt, response=None,
                blocked=False, blocked_stage="provider_error", reason=result.reason,
            )
        return result

    # --- Stage 3: output guardrail ---
    output_verdict = _output_guardrail.check(raw_response)
    if output_verdict.blocked:
        result = PipelineResult(
            blocked=True,
            blocked_stage="output",
            blocked_category=output_verdict.category or "LLM05",
            reason=output_verdict.reason,
            response=None,  # never return the flagged content to the client
        )
        if log:
            db_logger.log_request(
                provider=PROVIDER_NAME, prompt=prompt,
                # Log the REDACTED copy, never the raw text — see module
                # docstring. This response was already withheld from the
                # client; it should not persist unredacted in the DB either.
                response=_output_guardrail.redact(raw_response),
                blocked=True, blocked_stage="output",
                blocked_category=output_verdict.category or "LLM05",
                reason=output_verdict.reason,
            )
        return result

    # --- Clean end to end ---
    result = PipelineResult(
        blocked=False, blocked_stage=None, blocked_category=None,
        reason="Passed all checks.", response=raw_response,
    )
    if log:
        db_logger.log_request(
            provider=PROVIDER_NAME, prompt=prompt,
            # Redact before logging even on the ALLOWED path — an allowed
            # response can still legitimately contain a single low-risk
            # soft entity (an IP, an email) that the output guardrail
            # correctly chose not to block on, but that still shouldn't
            # sit in plaintext in a log table.
            response=_output_guardrail.redact(raw_response),
            blocked=False, reason="Passed all checks.",
        )
    return result
