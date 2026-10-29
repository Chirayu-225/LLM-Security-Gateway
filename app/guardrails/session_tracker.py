"""
Extension #4 from the review: "Add multi-turn and conversation-level
defenses. Your corpus already has 'false memory' attacks, but the
pipeline is single-turn. Tracking risk across a whole session is a real
open problem, even a simple version stands out."

Idea: a single prompt might sit BELOW the embedding similarity threshold
(not blocked) while still being somewhat attack-like — a "near miss".
Multi-turn erosion attacks work by spreading a jailbreak across several
turns, each individually below the block threshold. This tracks a
cumulative risk score per session and blocks once that accumulation
crosses a threshold, even if no single turn would have been blocked
alone.

Deliberately simple (in-memory, fixed time window) to match the scale of
the rest of this project — a production version would move this to
Redis/a shared store so it works across multiple gateway instances.
"""

import time
from collections import defaultdict
from dataclasses import dataclass

_SESSION_WINDOW_SECONDS = 600          # risk decays out of consideration after this
_SESSION_BLOCK_THRESHOLD = 1.4         # cumulative risk score that triggers a block
_NEAR_MISS_LOW = 0.45                  # below this, a turn contributes ~nothing
_NEAR_MISS_HIGH = 0.72                 # at/above this, input_filter already blocks it outright

_session_risk: dict = defaultdict(list)   # session_id -> [(timestamp, risk_contribution), ...]


@dataclass
class SessionVerdict:
    blocked: bool
    cumulative_risk: float
    reason: str = ""


def _risk_contribution(similarity_score: float) -> float:
    """A near-miss similarity score contributes risk proportional to how
    close it got to the block threshold. Anything below _NEAR_MISS_LOW
    contributes ~nothing (it's genuinely unrelated to the attack corpus);
    anything at/above _NEAR_MISS_HIGH would already be blocked outright
    by input_filter.py on its own, so this function is only meaningful in
    the near-miss band between the two."""
    if similarity_score < _NEAR_MISS_LOW:
        return 0.0
    if similarity_score >= _NEAR_MISS_HIGH:
        return 1.0  # already blocked on its own; record it, but it never reaches this path in practice
    span = _NEAR_MISS_HIGH - _NEAR_MISS_LOW
    return round((similarity_score - _NEAR_MISS_LOW) / span, 3)


def record_turn(session_id: str, similarity_score: float) -> SessionVerdict:
    """Call once per turn (from process_chat) with the input guardrail's
    similarity_score, even for turns that weren't individually blocked.
    Returns whether the SESSION should now be considered compromised."""
    now = time.time()
    window_start = now - _SESSION_WINDOW_SECONDS

    history = [(t, r) for t, r in _session_risk[session_id] if t > window_start]
    contribution = _risk_contribution(similarity_score)
    history.append((now, contribution))
    _session_risk[session_id] = history

    cumulative = round(sum(r for _, r in history), 3)

    if cumulative >= _SESSION_BLOCK_THRESHOLD:
        return SessionVerdict(
            blocked=True,
            cumulative_risk=cumulative,
            reason=(
                f"Session risk threshold exceeded ({cumulative} >= "
                f"{_SESSION_BLOCK_THRESHOLD}) — several individually-below-"
                f"threshold turns in this session were each somewhat "
                f"similar to known attack patterns, consistent with a "
                f"multi-turn erosion attempt."
            ),
        )

    return SessionVerdict(blocked=False, cumulative_risk=cumulative)


def reset_session(session_id: str):
    """Mainly for tests — clears a session's accumulated risk."""
    _session_risk.pop(session_id, None)
