"""
Output guardrail: checks what the LLM is ABOUT to send back to the client,
before it leaves the gateway. Three concerns now, all real production risks:

  1. PII/sensitive-data leakage (LLM06) — the model might echo back
     something sensitive (from context, from training data memorization,
     or from a poorly-scoped RAG retrieval upstream of this gateway).
  2. System prompt leakage (LLM06) — the model complying with an
     extraction attempt that the input guardrail didn't catch (defense in
     depth: this is a SECOND chance to catch what layer 1 missed).
  3. Dangerous / destructive code in the response (LLM02 — Insecure Output
     Handling) — the model producing a command or script that would cause
     real damage if a downstream system (or a copy-pasting human) actually
     ran it. This is the category that was previously NOT checked at all.

Uses Presidio (Microsoft's open-source PII detection library) rather than
hand-rolled regex for PII, since Presidio already covers a wide, well-
maintained set of entity types (emails, phone numbers, credit cards, SSNs,
IP addresses, etc.) with confidence scoring. Dangerous-code detection uses
hand-rolled regex on purpose — these are syntactic patterns (a bash
recursive delete, a SQL DROP/TRUNCATE, a Python filesystem wipe) with very
low false-positive risk, which is exactly what regex is good at, versus
PII's fuzzier "does this look like a real phone number" problem which is
what Presidio's built for.
"""

import re
from dataclasses import dataclass, field
from typing import List

from presidio_analyzer import AnalyzerEngine

_analyzer = AnalyzerEngine()

# Entity types we consider serious enough to block on. Presidio detects
# more than this (e.g. PERSON, LOCATION) but those alone are often too
# noisy/low-risk to block a response outright — tune this list as you
# observe real traffic.
_BLOCKING_ENTITY_TYPES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "CRYPTO",
    "IP_ADDRESS",
}

# Destructive / dangerous code patterns — LLM02: Insecure Output Handling.
# Each tuple is (compiled pattern, human-readable label). Deliberately
# narrow and high-precision: these patterns are almost never legitimate in
# a chatbot response, so false positives should be rare.
_DANGEROUS_CODE_PATTERNS = [
    (re.compile(r"rm\s+-rf\s+[/~]", re.I), "recursive filesystem delete (rm -rf)"),
    (re.compile(r"shutil\.rmtree\s*\(", re.I), "recursive filesystem delete (shutil.rmtree)"),
    (re.compile(r"os\.system\s*\(", re.I), "raw shell execution (os.system)"),
    (re.compile(r"subprocess\.(run|call|Popen)\s*\(", re.I), "raw subprocess execution"),
    (re.compile(r"\bDROP\s+TABLE\b", re.I), "destructive SQL (DROP TABLE)"),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", re.I), "destructive SQL (TRUNCATE TABLE)"),
    (re.compile(r"\bDELETE\s+FROM\s+\w+\s*(;|$)", re.I), "unscoped destructive SQL (DELETE FROM, no WHERE)"),
    (re.compile(r"del\s+/f\s*/s\s*/q", re.I), "recursive Windows delete (del /f /s /q)"),
    (re.compile(r"format\s+[a-zA-Z]:\s*(/y)?", re.I), "drive format command"),
    (re.compile(r"\bexec\s*\(\s*['\"]", re.I), "arbitrary code execution (exec)"),
    (re.compile(r"\beval\s*\(\s*['\"]", re.I), "arbitrary code execution (eval)"),
    (re.compile(r":\(\)\{\s*:\|:&\s*\};:", re.I), "fork bomb"),
]


@dataclass
class OutputVerdict:
    blocked: bool
    flagged_entities: List[str] = field(default_factory=list)
    system_prompt_leak_suspected: bool = False
    dangerous_code_labels: List[str] = field(default_factory=list)
    category: str = ""      # OWASP LLM Top 10 ID the block maps to, if any
    reason: str = ""


class OutputGuardrail:
    def __init__(self, system_prompt_fragment: str = ""):
        # If you set a real system prompt for your LLM calls, pass a
        # distinctive fragment of it here so this guardrail can detect
        # the model echoing it back (a classic extraction-attack tell).
        self._system_prompt_fragment = system_prompt_fragment.strip()

    def check(self, response_text: str) -> OutputVerdict:
        # --- PII / sensitive entity check (LLM06) ---
        results = _analyzer.analyze(text=response_text, language="en")
        flagged = sorted({
            r.entity_type for r in results
            if r.entity_type in _BLOCKING_ENTITY_TYPES and r.score >= 0.5
        })

        # --- System prompt leak check (LLM06) ---
        leak_suspected = bool(
            self._system_prompt_fragment
            and len(self._system_prompt_fragment) > 15
            and self._system_prompt_fragment.lower() in response_text.lower()
        )

        # --- Dangerous code check (LLM02) ---
        dangerous_labels = [
            label for pattern, label in _DANGEROUS_CODE_PATTERNS
            if pattern.search(response_text)
        ]

        blocked = bool(flagged) or leak_suspected or bool(dangerous_labels)

        reason_parts = []
        category = ""
        if flagged:
            reason_parts.append(f"Detected sensitive entities: {', '.join(flagged)}")
            category = "LLM06"
        if leak_suspected:
            reason_parts.append("Response appears to echo the system prompt.")
            category = "LLM06"
        if dangerous_labels:
            reason_parts.append(f"Detected dangerous code pattern(s): {', '.join(dangerous_labels)}")
            category = "LLM02"  # takes priority in the category field if both fire

        return OutputVerdict(
            blocked=blocked,
            flagged_entities=flagged,
            system_prompt_leak_suspected=leak_suspected,
            dangerous_code_labels=dangerous_labels,
            category=category,
            reason="; ".join(reason_parts) if reason_parts else "No sensitive data detected.",
        )
