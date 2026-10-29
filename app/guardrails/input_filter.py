"""
Input guardrail: the first line of defense.

Two layers, checked in order because they have very different cost/recall
tradeoffs:

  1. Regex layer — cheap, instant, catches known exact phrasings.
     High precision, low recall (easy to evade with paraphrasing) — so it
     is intentionally kept NARROW. A broad regex here doesn't add real
     security (the embedding layer already catches paraphrases), it only
     adds false positives.

  2. Embedding similarity layer — embeds the incoming prompt and compares
     it against ATTACK_CORPUS using cosine similarity. Catches paraphrased
     or reworded attacks that regex would miss.

Returns a structured verdict, not just True/False, because the gateway
needs to know WHY something was blocked.

SECURITY FIXES (review findings, Medium severity):

  - Both layers now run on Unicode-normalized text (NFKC + zero-width
    stripping) via app/guardrails/text_normalize.py, closing the
    zero-width-space and homoglyph bypasses. The regex layer additionally
    runs on a leet-folded copy, closing the "1gnore" bypass.
  - Fixed the "ignore all prior instructions" miss: the old regex only
    matched "previous", not "prior".
  - Removed the standalone `developer mode` and `base64|rot13|pig
    ?latin|reversed text` regex rules. These were the source of BOTH a
    false-positive problem (blocking "how do I enable developer mode on
    my Android phone?", "how do I decode a base64 string in Python?") AND
    an evaluation-leakage problem (the held-out red-team set contains a
    literal Pig Latin attack that the regex layer catches by matching the
    ENCODING'S NAME, not by detecting the actual evasion attempt — which
    inflates the block-rate metric without proving anything about the
    embedding layer's real generalization). Evasion-by-encoding attempts
    are still caught by the embedding layer, since ATTACK_CORPUS already
    contains several worked examples of that technique — semantic
    matching is the right tool for "requests an unusual encoding to slip
    past a filter", not a keyword-matching regex on encoding names that
    have countless legitimate everyday uses.
  - "developer mode" and "revealing configuration" rules now require
    CO-OCCURRING intent words (bypass/unrestricted/no rules/etc.), not
    just the bare phrase, so ordinary tech-support questions pass.
"""

from dataclasses import dataclass
from typing import Optional

from sentence_transformers import SentenceTransformer, util
from app.guardrails.attack_patterns import ATTACK_CORPUS
from app.guardrails.text_normalize import normalize_for_matching, normalize_and_fold_leet
from app.guardrails.regex_rules import check_regex_rules


@dataclass
class GuardrailVerdict:
    blocked: bool
    stage: str            # "regex" | "embedding" | "clean"
    category: Optional[str] = None      # OWASP LLM Top 10 ID (2025 numbering)
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
        # startup, not on every request.
        self._corpus_texts = [item["text"] for item in ATTACK_CORPUS]
        self._corpus_meta = ATTACK_CORPUS
        self._corpus_embeddings = self._model.encode(
            self._corpus_texts, convert_to_tensor=True
        )

    def check(self, prompt: str) -> GuardrailVerdict:
        # --- Normalize first: strips zero-width chars, folds Unicode,
        # collapses whitespace. The regex layer gets an additional
        # leetspeak fold on top of this. ---
        normalized = normalize_for_matching(prompt)
        leet_folded = normalize_and_fold_leet(prompt)

        # --- Layer 1: regex, on both the normalized and leet-folded text ---
        regex_hit = check_regex_rules(normalized, leet_folded)
        if regex_hit:
            category, pattern_str = regex_hit
            return GuardrailVerdict(
                blocked=True,
                stage="regex",
                category=category,
                reason=f"Matched known attack pattern: /{pattern_str}/",
            )

        # --- Layer 2: embedding similarity against the attack corpus ---
        prompt_embedding = self._model.encode(normalized, convert_to_tensor=True)
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
