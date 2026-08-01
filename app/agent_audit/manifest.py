"""
Defines the schema for an "agent manifest" — a declared, least-privilege
statement of what an agent is ALLOWED to do. This is the artifact that
enforcer.py checks real tool calls against.

The core idea (OWASP LLM08 - Excessive Agency): an agent's actual runtime
permissions should never exceed what its stated task requires. Declaring
that requirement explicitly, in a file, is what makes it enforceable and
auditable rather than an informal assumption.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel
import yaml


class ToolPermission(BaseModel):
    tool_name: str
    permission_level: Literal["read_only", "write", "execute"]
    # Optional scope restriction, e.g. a file-access tool might be scoped
    # to a specific directory, or a DB tool scoped to specific tables.
    data_scope: Optional[str] = None


class AgentManifest(BaseModel):
    agent_name: str
    description: str
    allowed_tools: List[ToolPermission]

    def get_permission(self, tool_name: str) -> Optional[ToolPermission]:
        for tool in self.allowed_tools:
            if tool.tool_name == tool_name:
                return tool
        return None


def load_manifest(path: str) -> AgentManifest:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return AgentManifest(**raw)
