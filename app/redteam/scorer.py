"""
Takes raw per-prompt results from a red-team run and aggregates them into
a category-level breakdown — this is what turns "we ran 40 prompts" into
"here's exactly where the gateway is weak", which is the actually useful
output of a red-team exercise.
"""

from collections import defaultdict


def score_results(results: list[dict]) -> dict:
    """
    results: list of dicts like:
      {"category": "LLM01", "technique": "...", "prompt": "...", "blocked": True}

    Returns:
      {
        "overall": {"total": N, "blocked": N, "block_rate": 0.x},
        "by_category": {
          "LLM01": {"total": .., "blocked": .., "block_rate": ..},
          ...
        }
      }
    """
    by_category = defaultdict(lambda: {"total": 0, "blocked": 0})

    for r in results:
        cat = r["category"]
        by_category[cat]["total"] += 1
        if r["blocked"]:
            by_category[cat]["blocked"] += 1

    for cat, stats in by_category.items():
        stats["block_rate"] = round(stats["blocked"] / stats["total"], 3) if stats["total"] else 0.0

    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])

    return {
        "overall": {
            "total": total,
            "blocked": blocked,
            "block_rate": round(blocked / total, 3) if total else 0.0,
        },
        "by_category": dict(by_category),
    }
