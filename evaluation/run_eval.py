"""
Evaluation harness — extension #2 from the review: "Build a proper
evaluation harness... report attack success rate, false-positive rate,
and latency, and show the trade-off curve as you vary the 0.72 similarity
threshold."

WHY THIS SCRIPT ISN'T RUN AS PART OF THIS DELIVERY: it needs to download
the sentence-transformers embedding model and Presidio's spaCy model
(network access to huggingface.co / model hosts) and a live GROQ_API_KEY
for actual LLM calls — none of which are available in the sandboxed
environment these fixes were built and tested in. This is exactly why the
resume should NOT carry a block-rate percentage until this is run for
real, in your own environment. Run it there:

    python evaluation/run_eval.py
    python evaluation/run_eval.py --sweep     # threshold trade-off curve

Metrics reported:
  - Attack block rate: fraction of HELD_OUT_REDTEAM_SET blocked. This is
    NOT the same as "attack success rate" in the strict sense — a
    response that gets through isn't necessarily a successful attack (the
    model may have refused on its own). A true attack-success-rate needs
    an LLM judge scoring whether the unblocked response actually complied
    with the attack; --judge below is an optional, more expensive version
    of that.
  - False-positive rate: fraction of BENIGN_SET incorrectly blocked. This
    is the number the review specifically flagged as never measured
    before, and it's the one that actually decides whether a guardrail
    can ship — a filter with a 95% block rate and a 40% false-positive
    rate is unusable in production regardless of the first number.
  - Latency: mean/median/p95 per request, in ms.
  - --sweep: re-runs the whole benign+attack set across a range of
    similarity thresholds so you can see the actual block-rate vs.
    false-positive-rate trade-off curve, rather than picking 0.72 by feel.
"""

import argparse
import statistics
import time

from app.guardrails.attack_patterns import HELD_OUT_REDTEAM_SET
from evaluation.benign_set import BENIGN_SET


def _run_set(process_chat_fn, prompts):
    results = []
    for p in prompts:
        start = time.perf_counter()
        outcome = process_chat_fn(p, log=False)
        elapsed_ms = (time.perf_counter() - start) * 1000
        results.append({"prompt": p, "blocked": outcome.blocked, "latency_ms": elapsed_ms})
    return results


def run_standard_eval():
    from app.pipeline import process_chat

    print(f"Running {len(HELD_OUT_REDTEAM_SET)} held-out attacks + {len(BENIGN_SET)} benign prompts...\n")

    attack_results = _run_set(process_chat, [a["text"] for a in HELD_OUT_REDTEAM_SET])
    benign_results = _run_set(process_chat, BENIGN_SET)

    attack_blocked = sum(1 for r in attack_results if r["blocked"])
    benign_blocked = sum(1 for r in benign_results if r["blocked"])
    all_latencies = [r["latency_ms"] for r in attack_results + benign_results]

    print("=== Results ===")
    print(f"Attack block rate:      {attack_blocked}/{len(attack_results)} "
          f"({100*attack_blocked/len(attack_results):.1f}%)")
    print(f"False positive rate:    {benign_blocked}/{len(benign_results)} "
          f"({100*benign_blocked/len(benign_results):.1f}%)")
    print(f"Latency — mean:         {statistics.mean(all_latencies):.1f} ms")
    print(f"Latency — median:       {statistics.median(all_latencies):.1f} ms")
    if len(all_latencies) >= 20:
        print(f"Latency — p95:          {statistics.quantiles(all_latencies, n=20)[18]:.1f} ms")

    if benign_blocked:
        print("\nFalse positives (fix these before shipping):")
        for r in benign_results:
            if r["blocked"]:
                print(f"  - {r['prompt']!r}")


def run_threshold_sweep():
    from app.guardrails.input_filter import InputGuardrail

    print("Running threshold sweep (0.50 to 0.90, step 0.02)...")
    print("threshold,attack_block_rate,benign_false_positive_rate")

    for threshold in [round(0.50 + i * 0.02, 2) for i in range(21)]:
        guardrail = InputGuardrail(similarity_threshold=threshold)

        attack_blocked = sum(1 for a in HELD_OUT_REDTEAM_SET if guardrail.check(a["text"]).blocked)
        benign_blocked = sum(1 for p in BENIGN_SET if guardrail.check(p).blocked)

        attack_rate = attack_blocked / len(HELD_OUT_REDTEAM_SET)
        fp_rate = benign_blocked / len(BENIGN_SET)
        print(f"{threshold},{attack_rate:.3f},{fp_rate:.3f}")

    print("\nPick the threshold where attack_block_rate is high and "
          "false_positive_rate is still acceptable for your use case — "
          "paste this CSV into a spreadsheet or matplotlib for the actual "
          "trade-off chart the review asked for.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sweep", action="store_true", help="Run the threshold trade-off sweep instead")
    args = parser.parse_args()

    if args.sweep:
        run_threshold_sweep()
    else:
        run_standard_eval()
