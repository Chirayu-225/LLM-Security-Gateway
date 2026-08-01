"""
Input guardrail: the first line of defense (Chapter 3.1 territory — this
is the INPUT half of "input/output guardrails").

Two layers, checked in order because they have very different cost/recall
tradeoffs:

  1. Regex layer — cheap, instant, catches known exact phrasings
     ("ignore previous instructions", "developer mode", etc.). High
     precision, low recall (easy to evade with paraphrasing).

  2. Embedding similarity layer — embeds the incoming prompt and compares
     it against ATTACK_CORPUS using cosine similarity. Catches paraphrased
     or reworded attacks that regex would miss (semantic match, not exact
     string match). Higher recall, costs a bit of latency (one embedding
     call), and needs a similarity threshold tuned to avoid false positives.

Returns a structured verdict, not just True/False, because the gateway
needs to know WHY something was blocked (for the dashboard, the logs,
and the red-team scoring).
"""

import re
from dataclasses import dataclass
from typing import Optional

from sentence_transformers import SentenceTransformer, util
from app.guardrails.attack_patterns import ATTACK_CORPUS

# --- Layer 1: regex rules -----------------------------------------------
# Deliberately simple, readable patterns. Add to this list as you discover
# new exact-phrase attacks in the wild — this is meant to be a living file.
_REGEX_RULES = [
    (re.compile(r"ignore (all )?previous instructions", re.I), "LLM01"),
    (re.compile(r"disregard (everything|all) (above|prior)", re.I), "LLM01"),
    (re.compile(r"system\s*override", re.I), "LLM01"),
    (re.compile(r"developer mode", re.I), "LLM01"),
    (re.compile(r"\bDAN\b.*(unfiltered|no restrictions|no rules)", re.I), "LLM01"),
    (re.compile(r"(reveal|print|show|output).{0,20}(system prompt|api key|password|config)", re.I), "LLM06"),
    (re.compile(r"repeat everything above", re.I), "LLM06"),
    (re.compile(r"base64|rot13|pig ?latin|reversed text", re.I), "LLM01"),
]


@dataclass
class GuardrailVerdict:
    blocked: bool
    stage: str            # "regex" | "embedding" | "clean"
    category: Optional[str] = None      # OWASP LLM Top 10 ID
    matched_technique: Optional[str] = None
    similarity_score: Optional[float] = None
    reason: str = ""


class InputGuardrail:
    def __init__(self, similarity_threshold: float = 0.72):
        # all-MiniLM-L6-v2 is small (~80MB), CPU-friendly, and good enough
        # for this kind of short-text similarity task — no GPU required,
        # which matters given the 4GB VRAM constraint this project targets.
        self._model = SentenceTransformer("all-MiniLM-L6-v2")
        self._threshold = similarity_threshold

        # Pre-compute embeddings for the entire attack corpus ONCE at
        # startup, not on every request — this is the expensive part,
        # and it never changes unless ATTACK_CORPUS changes.
        self._corpus_texts = [item["text"] for item in ATTACK_CORPUS]
        self._corpus_meta = ATTACK_CORPUS
        self._corpus_embeddings = self._model.encode(
            self._corpus_texts, convert_to_tensor=True
        )

    def check(self, prompt: str) -> GuardrailVerdict:
        # --- Layer 1: regex first, it's nearly free ---
        for pattern, category in _REGEX_RULES:
            if pattern.search(prompt):
                return GuardrailVerdict(
                    blocked=True,
                    stage="regex",
                    category=category,
                    reason=f"Matched known attack pattern: /{pattern.pattern}/",
                )

        # --- Layer 2: embedding similarity against the attack corpus ---
        prompt_embedding = self._model.encode(prompt, convert_to_tensor=True)
        similarities = util.cos_sim(prompt_embedding, self._corpus_embeddings)[0]
        best_idx = int(similarities.argmax())
        best_score = float(similarities[best_idx])

        if best_score >= self._threshold:
            matched = self._corpus_meta[best_idx]
            return GuardrailVerdict(
                blocked=True,
                stage="embedding",
                category=matched["category"],
                matched_technique=matched["technique"],
                similarity_score=round(best_score, 3),
                reason=(
                    f"Semantically similar (score={best_score:.3f}) to known "
                    f"'{matched['technique']}' attack pattern."
                ),
            )

        # --- Clean ---
        return GuardrailVerdict(
            blocked=False,
            stage="clean",
            similarity_score=round(best_score, 3),
            reason="No known attack pattern matched.",
        )
