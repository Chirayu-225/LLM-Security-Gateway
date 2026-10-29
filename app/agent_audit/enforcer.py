"""
Runtime enforcement: given a manifest (what the agent SHOULD be able to
do) and an actual tool call (what the agent is TRYING to do right now),
decide whether to allow it.

This is deliberately kept separate from the LLM guardrails — permission
enforcement is a policy/authorization problem, not a content-detection
problem, so it doesn't need embeddings or NLP, just a straightforward
allow-list check plus an escalation check.

SECURITY FIXES (see review findings, all High severity):

  1. Permission level is no longer taken from the caller. The old code
     accepted `requested_permission` from the request body — a compromised
     agent could simply claim "read_only" for a tool that writes or
     executes. Now the enforcer looks up the tool's REAL required
     permission in app/agent_audit/tool_registry.py, a server-side source
     of truth the caller can't influence. A `requested_permission` field
     is still accepted for logging/audit purposes only — it is never
     trusted for the authorization decision itself.
  2. An unregistered tool is denied, same as a tool missing from the
     manifest. Both checks must pass independently.
  3. Scope checks now use segment-aware, normalized path matching
     (app/agent_audit/scope_utils.py) instead of raw string startswith(),
     closing both the "public_docs_internal_hr" prefix-collision bypass
     and the "../private/salaries" traversal bypass.
  4. Scope checks are deny-by-default: if the manifest declares a scope
     restriction and the caller omits a scope, that is now a denial, not
     a skipped check. The old code only enforced scope when the caller
     ALSO supplied one, so omitting it bypassed the restriction entirely.

Maps to OWASP LLM06 (Excessive Agency, 2025 list) — an agent's actual
runtime permissions should never exceed what its stated task requires,
and that boundary needs to be enforced server-side, not self-declared.
"""

from dataclasses import dataclass
from typing import Optional

from app.agent_audit.manifest import AgentManifest
from app.agent_audit.scope_utils import is_within_scope
from app.agent_audit.tool_registry import get_required_permission

_PERMISSION_RANK = {"read_only": 0, "write": 1, "execute": 2}


@dataclass
class EnforcementVerdict:
    allowed: bool
    reason: str
    # The permission level actually used for the decision (server-derived),
    # surfaced so a mismatch with the caller's claim is visible in logs —
    # useful for spotting a compromised or misbehaving agent.
    effective_permission: Optional[str] = None


def check_tool_call(
    manifest: AgentManifest,
    tool_name: str,
    requested_permission: Optional[str] = None,  # audit-only, never trusted
    scope: Optional[str] = None,
) -> EnforcementVerdict:
    # --- Step 1: is this even a known, registered tool? Deny by default. ---
    required_permission = get_required_permission(tool_name)
    if required_permission is None:
        return EnforcementVerdict(
            allowed=False,
            reason=f"Tool '{tool_name}' is not a recognized/registered tool. Denied by default.",
        )

    # --- Step 2: is this tool in the agent's declared manifest at all? ---
    declared = manifest.get_permission(tool_name)
    if declared is None:
        return EnforcementVerdict(
            allowed=False,
            reason=f"Tool '{tool_name}' is not in {manifest.agent_name}'s declared manifest at all.",
            effective_permission=required_permission,
        )

    # --- Step 3: escalation check, using the SERVER-DERIVED permission ---
    # level for this tool — not whatever the caller claims it needs.
    required_rank = _PERMISSION_RANK.get(required_permission, 99)
    declared_rank = _PERMISSION_RANK.get(declared.permission_level, -1)
    if required_rank > declared_rank:
        return EnforcementVerdict(
            allowed=False,
            reason=(
                f"Permission escalation: '{tool_name}' actually requires "
                f"'{required_permission}' but the agent's manifest only "
                f"declares '{declared.permission_level}'."
            ),
            effective_permission=required_permission,
        )

    if requested_permission and requested_permission != required_permission:
        # Not a denial by itself (the server-derived value already governed
        # the decision above) — but worth flagging: the caller's claim
        # didn't match reality, which is exactly the kind of signal that's
        # worth alerting on for a compromised agent.
        audit_note = (
            f" [audit: caller claimed '{requested_permission}', "
            f"actual requirement is '{required_permission}']"
        )
    else:
        audit_note = ""

    # --- Step 4: scope check — normalized, segment-aware, deny-by-default ---
    if not is_within_scope(scope, declared.data_scope):
        return EnforcementVerdict(
            allowed=False,
            reason=(
                f"Scope violation: '{tool_name}' is restricted to "
                f"'{declared.data_scope}' but was invoked on "
                f"'{scope!r}'."
            ),
            effective_permission=required_permission,
        )

    return EnforcementVerdict(
        allowed=True,
        reason="Within declared permissions." + audit_note,
        effective_permission=required_permission,
    )
