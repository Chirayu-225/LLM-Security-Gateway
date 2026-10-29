"""
Fix for two of the review's High-severity bypasses:

  1. `kb://public_docs_internal_hr` passing a `startswith("kb://public_docs")`
     check — that's STRING prefix matching, not PATH matching, so any scope
     that happens to start with the same characters slips through.
  2. `kb://public_docs/../private/salaries` passing because paths were never
     normalized, so `..` traversal just works.

Both are the same underlying bug: treating a scope string as an opaque
string instead of a structured path. This module treats it as a path.
"""

import posixpath
from typing import Optional


def normalize_scope(scope: str) -> str:
    """Collapses '..' and '.' segments and redundant slashes, the same way
    a filesystem would resolve them, so a caller can't smuggle a traversal
    past a naive string check."""
    if "://" in scope:
        prefix, _, rest = scope.partition("://")
        return f"{prefix}://{posixpath.normpath(rest).lstrip('/')}"
    return posixpath.normpath(scope)


def is_within_scope(requested_scope: Optional[str], declared_scope: Optional[str]) -> bool:
    """True only if `requested_scope` resolves to a path that is the
    declared scope itself, or a proper sub-path of it — matched on whole
    path SEGMENTS, never on raw string prefix.

    Deny-by-default: if the manifest declares a scope restriction at all,
    an omitted or empty requested_scope does NOT pass. The old code only
    checked the scope when both `declared.data_scope` and `scope` were
    truthy — meaning an agent could bypass the entire scope check just by
    not sending one. Fail-closed instead.
    """
    if declared_scope is None:
        # Tool has no scope restriction at all — nothing to check.
        return True

    if not requested_scope:
        # A scope restriction IS declared, but the caller didn't say what
        # they want to access. Refuse to guess — deny.
        return False

    norm_requested = normalize_scope(requested_scope)
    norm_declared = normalize_scope(declared_scope)

    if norm_requested == norm_declared:
        return True

    # Segment-wise prefix check, not string prefix. "public_docs_internal"
    # must NOT match a declared scope of "public_docs" just because the
    # characters happen to line up.
    req_segments = norm_requested.split("/")
    decl_segments = norm_declared.split("/")

    if len(req_segments) < len(decl_segments):
        return False

    return req_segments[: len(decl_segments)] == decl_segments
