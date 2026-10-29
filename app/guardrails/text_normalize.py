"""
Fix for: "there's no Unicode normalization (NFKC, zero-width stripping,
homoglyph folding) before either [filter] layer" (review finding).

Without this, trivial evasions slip straight past regex matching:
  - a zero-width space inside "ignore all previous instructions"
  - full-width or accented lookalike characters
  - light leetspeak ("1gnore" instead of "ignore")
  - doubled/irregular whitespace breaking a fixed phrase match

This module is intentionally cheap (no ML, no network) since it runs on
every request before either the regex or the embedding layer.
"""

import re
import unicodedata

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")
_WHITESPACE_RE = re.compile(r"\s+")

# Minimal, conservative leetspeak fold — only digits/symbols with an
# unambiguous single-letter meaning. Deliberately NOT folding things like
# '5'->'s' or '7'->'t', which collide too often with legitimate numbers
# and would just trade one false-positive problem for another.
_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "@": "a"})


def normalize_for_matching(text: str) -> str:
    """Returns a normalized copy of `text` for regex/embedding matching.
    Never used for anything shown back to a user or logged — matching
    only."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def normalize_and_fold_leet(text: str) -> str:
    """Stronger normalization used specifically for the cheap regex layer,
    where a leetspeak or zero-width evasion would otherwise slip a known
    exact-phrase rule entirely. The embedding layer runs on the
    non-leet-folded text (normalize_for_matching), since folding digits to
    letters can distort semantic embeddings more than it helps."""
    return normalize_for_matching(text).lower().translate(_LEET_MAP)
