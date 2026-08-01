"""
Runs the held-out attack suite through the SAME pipeline real traffic
uses (app/pipeline.py), records whether each attack got blocked, scores
the results by OWASP category, and persists the run to the database so
the dashboard can show trend history over time.

Note: log=False when calling process_chat here — we don't want red-team
traffic polluting the "real request" log used for the Live Traffic tab.
Red-team runs get their own table (RedTeamRun) instead.
"""

from app.pipeline import process_chat
from app.redteam.attack_suite import get_attack_suite
from app.redteam.scorer import score_results
from app.db import logger as db_logger


def run_redteam_suite() -> dict:
    suite = get_attack_suite()
    results = []

    for attack in suite:
        outcome = process_chat(attack["text"], log=False)
        results.append({
            "prompt": attack["text"],
            "category": attack["category"],
            "technique": attack["technique"],
            "blocked": outcome.blocked,
            "blocked_stage": outcome.blocked_stage,
            "reason": outcome.reason,
        })

    scored = score_results(results)
    scored["raw_results"] = results

    db_logger.log_redteam_run(
        total_prompts=scored["overall"]["total"],
        blocked_count=scored["overall"]["blocked"],
        category_breakdown=scored["by_category"],
    )

    return scored
