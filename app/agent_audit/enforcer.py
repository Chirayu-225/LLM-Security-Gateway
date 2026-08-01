"""
Runtime enforcement: given a manifest (what the agent SHOULD be able to
do) and an actual tool call (what the agent is TRYING to do right now),
decide whether to allow it.

This is deliberately kept separate from the LLM guardrails — permission
enforcement is a policy/authorization problem, not a content-detection
problem, so it doesn't need embeddings or NLP, just a straightforward
allow-list check plus an escalation check (asking for a HIGHER permission
level than declared, e.g. a read_only tool being invoked to write).
"""

from dataclasses import dataclass
from typing import Optional
from app.agent_audit.manifest import AgentManifest

_PERMISSION_RANK = {"read_only": 0, "write": 1, "execute": 2}


@dataclass
class EnforcementVerdict:
    allowed: bool
    reason: str


def check_tool_call(
    manifest: AgentManifest,
    tool_name: str,
    requested_permission: str,
    scope: Optional[str] = None,
) -> EnforcementVerdict:
    declared = manifest.get_permission(tool_name)

    if declared is None:
        return EnforcementVerdict(
            allowed=False,
            reason=f"Tool '{tool_name}' is not in {manifest.agent_name}'s declared manifest at all.",
        )

    # Escalation check: is the agent asking to do MORE than it's scoped for?
    requested_rank = _PERMISSION_RANK.get(requested_permission, 99)
    declared_rank = _PERMISSION_RANK.get(declared.permission_level, -1)
    if requested_rank > declared_rank:
        return EnforcementVerdict(
            allowed=False,
            reason=(
                f"Permission escalation: '{tool_name}' is declared as "
                f"'{declared.permission_level}' but was invoked requesting "
                f"'{requested_permission}'."
            ),
        )

    # Scope check: if the manifest restricts scope (e.g. a specific
    # directory or table), the requested scope must fall within it.
    if declared.data_scope and scope and not scope.startswith(declared.data_scope):
        return EnforcementVerdict(
            allowed=False,
            reason=(
                f"Scope violation: '{tool_name}' is restricted to "
                f"'{declared.data_scope}' but was invoked on '{scope}'."
            ),
        )

    return EnforcementVerdict(allowed=True, reason="Within declared permissions.")
