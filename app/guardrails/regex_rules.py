"""
The regex layer's rules, split into their own module (no ML/network
dependency) so they can be unit-tested and reasoned about in isolation
from the embedding model that input_filter.py also loads. See
input_filter.py's module docstring for the full rationale behind each fix
here.
"""

import re

_JAILBREAK_INTENT_WORDS = r"(unrestricted|no rules|no restrictions|unfiltered|bypass|disable|override|ignore your (rules|guidelines|instructions))"

REGEX_RULES = [
    (re.compile(r"ignore (all )?(previous|prior) instructions", re.I), "LLM01"),
    (re.compile(r"disregard (everything|all) (above|prior)", re.I), "LLM01"),
    (re.compile(r"system\s*override", re.I), "LLM01"),
    (re.compile(rf"developer mode.{{0,40}}{_JAILBREAK_INTENT_WORDS}", re.I), "LLM01"),
    (re.compile(rf"{_JAILBREAK_INTENT_WORDS}.{{0,40}}developer mode", re.I), "LLM01"),
    (re.compile(r"\bDAN\b.*(unfiltered|no restrictions|no rules)", re.I), "LLM01"),
    (re.compile(r"(reveal|print|show|output).{0,20}(system prompt|internal config(uration)?)", re.I), "LLM07"),
    (re.compile(r"(reveal|print|show|output).{0,20}(api key|password|credential)", re.I), "LLM02"),
    (re.compile(r"repeat everything above", re.I), "LLM07"),
]


def check_regex_rules(normalized_text: str, leet_folded_text: str):
    """Returns (category, pattern_str) for the first matching rule, or
    None if nothing matches either the normalized or leet-folded text."""
    for pattern, category in REGEX_RULES:
        if pattern.search(normalized_text) or pattern.search(leet_folded_text):
            return category, pattern.pattern
    return None
