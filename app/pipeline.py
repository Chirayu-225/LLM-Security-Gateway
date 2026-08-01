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
backend is sufficient, and Groq's models are less aggressively filtered
by their OWN safety layer than Gemini's, which means attack prompts
actually reach OUR guardrails instead of being pre-filtered upstream.
That matters here specifically: this project is testing our defenses, not
the underlying model's.
"""

from dataclasses import dataclass
from typing import Optional

from app.guardrails.input_filter import InputGuardrail
from app.guardrails.output_filter import OutputGuardrail
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
    blocked_stage: Optional[str]      # "input" | "output" | "provider_error" | None
    blocked_category: Optional[str]   # OWASP LLM Top 10 ID
    reason: str
    response: Optional[str] = None
    error: bool = False               # True if the LLM call itself failed/refused —
                                       # distinct from "blocked" (our guardrails firing)


def process_chat(prompt: str, log: bool = True) -> PipelineResult:
    # --- Stage 1: input guardrail ---
    input_verdict = _input_guardrail.check(prompt)
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
            blocked_category=output_verdict.category or "LLM06",
            reason=output_verdict.reason,
            response=None,  # never return the flagged content to the client
        )
        if log:
            db_logger.log_request(
                provider=PROVIDER_NAME, prompt=prompt, response=raw_response,
                blocked=True, blocked_stage="output",
                blocked_category=output_verdict.category or "LLM06",
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
            provider=PROVIDER_NAME, prompt=prompt, response=raw_response,
            blocked=False, reason="Passed all checks.",
        )
    return result
