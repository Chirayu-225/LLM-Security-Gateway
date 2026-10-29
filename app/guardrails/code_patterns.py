"""
Dangerous-code regex patterns, split into their own dependency-free module
(no Presidio/spaCy import) so they can be unit-tested in isolation. See
output_filter.py's module docstring for the hard-block vs review-only
rationale.
"""

import re

# HARD-block: unambiguously destructive even without surrounding context.
HARD_BLOCK_CODE_PATTERNS = [
    (re.compile(r"rm\s+-rf\s+[/~]", re.I), "recursive filesystem delete (rm -rf)"),
    (re.compile(r"shutil\.rmtree\s*\(", re.I), "recursive filesystem delete (shutil.rmtree)"),
    (re.compile(r"\bDROP\s+TABLE\b", re.I), "destructive SQL (DROP TABLE)"),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", re.I), "destructive SQL (TRUNCATE TABLE)"),
    (re.compile(r"\bDELETE\s+FROM\s+\w+\s*(;|$)", re.I), "unscoped destructive SQL (DELETE FROM, no WHERE)"),
    (re.compile(r"del\s+/f\s*/s\s*/q", re.I), "recursive Windows delete (del /f /s /q)"),
    (re.compile(r"format\s+[a-zA-Z]:\s*(/y)?", re.I), "drive format command"),
    (re.compile(r":\(\)\{\s*:\|:&\s*\};:", re.I), "fork bomb"),
    (re.compile(r"(os\.system|subprocess\.(run|call|Popen))\s*\(\s*['\"].{0,60}(rm\s+-rf|del\s+/f|format\s+[a-zA-Z]:)", re.I | re.S),
     "shell execution wrapping a destructive command"),
]

# REVIEW-only: ordinary in legitimate coding-help/IT-support responses —
# flagged for visibility, never blocks by itself.
REVIEW_ONLY_CODE_PATTERNS = [
    (re.compile(r"os\.system\s*\(", re.I), "raw shell execution (os.system)"),
    (re.compile(r"subprocess\.(run|call|Popen)\s*\(", re.I), "raw subprocess execution"),
    (re.compile(r"\bexec\s*\(\s*['\"]", re.I), "code execution (exec)"),
    (re.compile(r"\beval\s*\(\s*['\"]", re.I), "code execution (eval)"),
]


def check_dangerous_code(text: str):
    """Returns (hard_labels, review_labels) — lists of matched pattern
    labels for each tier."""
    hard = [label for pattern, label in HARD_BLOCK_CODE_PATTERNS if pattern.search(text)]
    review = [label for pattern, label in REVIEW_ONLY_CODE_PATTERNS if pattern.search(text)]
    return hard, review
