"""
Output guardrail: checks what the LLM is ABOUT to send back to the client,
before it leaves the gateway. Three concerns:

  1. PII/sensitive-data leakage (LLM02 — Sensitive Information Disclosure,
     2025 list) — the model might echo back something sensitive.
  2. System prompt leakage (LLM07 — its own category in the 2025 list) —
     the model complying with an extraction attempt the input guardrail
     didn't catch (defense in depth).
  3. Dangerous / destructive code in the response (LLM05 — Improper Output
     Handling, 2025 list) — the model producing a command that would
     cause real damage if actually run.

Uses Presidio for PII detection; hand-rolled regex for dangerous code.

SECURITY FIXES (review findings, Medium severity — "blocking any
subprocess.run(, os.system(, email, or IP address makes the gateway
unusable for coding or IT support"):

  - PII entities are now TIERED, not one flat blocklist. CREDIT_CARD,
    US_SSN, IBAN_CODE, and CRYPTO are unambiguous, high-confidence
    identifiers with essentially no legitimate reason to appear in a
    support-bot response — any single high-confidence hit still blocks.
    EMAIL_ADDRESS, PHONE_NUMBER, and IP_ADDRESS are common in entirely
    legitimate IT-support and coding answers ("set the server's IP to
    10.0.0.1", "format is name@example.com"), so a SINGLE instance no
    longer blocks. They only trigger a block when TWO OR MORE distinct
    soft entities appear together — the actual pattern of a real PII
    leak (a name + an email + a phone number clustered together) looks
    very different from one incidental IP address in a config example.
  - Dangerous-code detection is now split into HARD-block patterns
    (unambiguously destructive regardless of context: rm -rf, DROP
    TABLE, a fork bomb, etc.) and REVIEW-only patterns (bare
    os.system(/subprocess.*(/exec(/eval( calls, which are completely
    normal in ordinary coding-help responses and were previously
    blocking the gateway from being usable for that purpose at all).
    Review-only hits are still recorded in the verdict for visibility,
    but don't block the response by themselves.
"""

import re
from dataclasses import dataclass, field
from typing import List

from presidio_analyzer import AnalyzerEngine
from app.guardrails.text_normalize import normalize_for_matching
from app.guardrails.code_patterns import check_dangerous_code

_analyzer = AnalyzerEngine()

# --- PII entity tiers -----------------------------------------------------
_HARD_BLOCK_ENTITIES = {"CREDIT_CARD", "US_SSN", "IBAN_CODE", "CRYPTO"}
_SOFT_ENTITIES = {"EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"}
_SOFT_ENTITY_BLOCK_THRESHOLD = 2  # need 2+ distinct soft entities together to block


@dataclass
class OutputVerdict:
    blocked: bool
    flagged_entities: List[str] = field(default_factory=list)
    system_prompt_leak_suspected: bool = False
    dangerous_code_labels: List[str] = field(default_factory=list)      # hard-blocked labels
    reviewed_code_labels: List[str] = field(default_factory=list)       # flagged but not blocking
    category: str = ""      # OWASP LLM Top 10 ID (2025 numbering) the block maps to, if any
    reason: str = ""


class OutputGuardrail:
    def __init__(self, system_prompt_fragment: str = ""):
        self._system_prompt_fragment = system_prompt_fragment.strip()

    def check(self, response_text: str) -> OutputVerdict:
        normalized = normalize_for_matching(response_text)

        # --- PII / sensitive entity check (LLM02), tiered ---
        results = _analyzer.analyze(text=response_text, language="en")
        detected = {r.entity_type for r in results if r.score >= 0.5}

        hard_hits = sorted(detected & _HARD_BLOCK_ENTITIES)
        soft_hits = sorted(detected & _SOFT_ENTITIES)
        pii_blocks = bool(hard_hits) or len(soft_hits) >= _SOFT_ENTITY_BLOCK_THRESHOLD
        all_flagged = sorted(set(hard_hits) | set(soft_hits))

        # --- System prompt leak check (LLM07) ---
        leak_suspected = bool(
            self._system_prompt_fragment
            and len(self._system_prompt_fragment) > 15
            and self._system_prompt_fragment.lower() in normalized.lower()
        )

        # --- Dangerous code check (LLM05) ---
        hard_code_labels, review_code_labels = check_dangerous_code(response_text)

        blocked = pii_blocks or leak_suspected or bool(hard_code_labels)

        reason_parts = []
        category = ""
        if hard_hits:
            reason_parts.append(f"Detected high-confidence sensitive entities: {', '.join(hard_hits)}")
            category = "LLM02"
        elif soft_hits and pii_blocks:
            reason_parts.append(
                f"Detected {len(soft_hits)} co-occurring PII-adjacent entities: {', '.join(soft_hits)}"
            )
            category = "LLM02"
        elif soft_hits:
            reason_parts.append(f"(not blocking) low-risk single instance of: {', '.join(soft_hits)}")
        if leak_suspected:
            reason_parts.append("Response appears to echo the system prompt.")
            category = "LLM07"
        if hard_code_labels:
            reason_parts.append(f"Detected dangerous code pattern(s): {', '.join(hard_code_labels)}")
            category = "LLM05"
        if review_code_labels:
            reason_parts.append(
                f"(flagged for review, not blocked) code pattern(s): {', '.join(review_code_labels)}"
            )

        return OutputVerdict(
            blocked=blocked,
            flagged_entities=all_flagged,
            system_prompt_leak_suspected=leak_suspected,
            dangerous_code_labels=hard_code_labels,
            reviewed_code_labels=review_code_labels,
            category=category,
            reason="; ".join(reason_parts) if reason_parts else "No sensitive data detected.",
        )

    def redact(self, response_text: str) -> str:
        """Returns a copy of response_text with every detected PII entity
        span replaced by an [ENTITY_TYPE] placeholder. Used for LOGGING
        only, never for the response actually sent to the client (a
        blocked response is never sent at all; an allowed response is
        sent as-is and only the LOGGED COPY is redacted) — see the fix in
        app/pipeline.py for why the previous version logged raw PII."""
        results = _analyzer.analyze(text=response_text, language="en")
        # Replace from the end of the string backwards so earlier offsets
        # in `results` stay valid as we mutate the string.
        redacted = response_text
        for r in sorted(results, key=lambda r: r.start, reverse=True):
            if r.score >= 0.5:
                redacted = redacted[: r.start] + f"[{r.entity_type}]" + redacted[r.end :]
        return redacted
