"""
Tests the dangerous-code regex split (hard-block vs review-only) directly
against the compiled pattern lists, without instantiating OutputGuardrail
(which needs Presidio's spaCy model — a network download not available in
every environment). Run: python3 tests/test_output_filter_code_patterns.py
"""
import sys, os, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import the module but only touch the pattern lists, not the class (which
# instantiates AnalyzerEngine at class-definition... actually at __init__,
# so importing the module alone is safe).
from app.guardrails.code_patterns import HARD_BLOCK_CODE_PATTERNS as _HARD_BLOCK_CODE_PATTERNS, REVIEW_ONLY_CODE_PATTERNS as _REVIEW_ONLY_CODE_PATTERNS


def hard_blocks(text):
    return any(p.search(text) for p, _ in _HARD_BLOCK_CODE_PATTERNS)


def review_flags(text):
    return any(p.search(text) for p, _ in _REVIEW_ONLY_CODE_PATTERNS)


# Previously blocked ordinary coding-help responses — must NOT hard-block now
ORDINARY_CODING_HELP = [
    "You can run it with subprocess.run(['ls', '-la'], capture_output=True)",
    "Use os.system('echo hello') for a quick shell call in a script.",
    "The eval('2 + 2') pattern is generally discouraged, but here's how it works.",
    "You'd call exec('print(1)') to dynamically run that snippet.",
]

# Genuinely destructive — must still hard-block
STILL_DANGEROUS = [
    "Run this to wipe everything: rm -rf /",
    "import shutil; shutil.rmtree('/home/user')",
    "DROP TABLE users;",
    "DELETE FROM users;",
    "os.system('rm -rf /important_data')",
]


def run():
    failed = 0
    for t in ORDINARY_CODING_HELP:
        blocked = hard_blocks(t)
        flagged = review_flags(t)
        ok = (not blocked) and flagged
        print(f"{'PASS' if ok else 'FAIL'} (should flag-not-block): {t!r} -> hard={blocked} review={flagged}")
        failed += 0 if ok else 1

    for t in STILL_DANGEROUS:
        ok = hard_blocks(t)
        print(f"{'PASS' if ok else 'FAIL'} (should hard-block): {t!r}")
        failed += 0 if ok else 1

    print(f"\n{'ALL PASS' if failed == 0 else f'{failed} FAILED'}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    run()
