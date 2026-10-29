"""
Fix for: "the enforcer trusts requested_permission from the caller" (review
finding, High).

Previously, /agent/check-tool-call accepted requested_permission directly
from the request body — a compromised or malicious agent could simply
claim "read_only" for a tool that actually writes or executes, and the
enforcer had no way to know better. That's the agent grading its own
homework.

The fix: permission level is an intrinsic property of the TOOL, not a
claim the caller gets to make. This registry is the single source of
truth for "what does invoking this tool actually do" — the enforcer
looks a tool up here, not at whatever the request body says.

Unknown tools are NOT in this registry on purpose: enforcer.py treats
"not found in the tool registry" as deny-by-default, same as "not in the
agent's manifest". Both checks must pass.
"""

from typing import Optional

# tool_name -> the REAL permission level that invoking this tool requires,
# regardless of what any caller claims. Add every tool your agent loop can
# actually call here — anything missing is denied automatically.
TOOL_REGISTRY = {
    "knowledge_base_search": "read_only",
    "calendar_read": "read_only",
    "draft_email": "write",       # drafts are saved but not sent — still a write
    "send_email": "write",
    "file_read": "read_only",
    "file_write": "write",
    "run_shell_command": "execute",
    "delete_resource": "execute",
}


def get_required_permission(tool_name: str) -> Optional[str]:
    """Returns the tool's real required permission level, or None if the
    tool isn't registered at all (treat None as deny-by-default)."""
    return TOOL_REGISTRY.get(tool_name)
