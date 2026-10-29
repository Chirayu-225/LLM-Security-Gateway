"""
Regression tests for the four High-severity permission-enforcer bypasses
found in the security review. Every one of these MUST return allowed=False.
Run: pytest tests/test_enforcer_bypasses.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.agent_audit.manifest import load_manifest
from app.agent_audit.enforcer import check_tool_call

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "manifests", "example_agent.yaml")


def _manifest():
    return load_manifest(MANIFEST_PATH)


def test_bypass_1_prefix_collision_denied():
    """kb://public_docs_internal_hr must NOT pass a scope of kb://public_docs
    just because the string happens to start with it."""
    v = check_tool_call(
        _manifest(), "knowledge_base_search", "read_only",
        scope="kb://public_docs_internal_hr",
    )
    assert v.allowed is False, "prefix-collision bypass is still open"


def test_bypass_2_path_traversal_denied():
    """kb://public_docs/../private/salaries must not escape the declared
    scope via traversal."""
    v = check_tool_call(
        _manifest(), "knowledge_base_search", "read_only",
        scope="kb://public_docs/../private/salaries",
    )
    assert v.allowed is False, "path traversal bypass is still open"


def test_bypass_3_missing_scope_denied():
    """Omitting scope entirely, when the manifest declares a scope
    restriction, must fail CLOSED, not open."""
    v = check_tool_call(
        _manifest(), "knowledge_base_search", "read_only", scope=None,
    )
    assert v.allowed is False, "missing-scope fail-open bypass is still open"


def test_bypass_4_draft_email_traversal_denied():
    """drafts_folder/../sent must not escape the declared scope."""
    v = check_tool_call(
        _manifest(), "draft_email", "write",
        scope="drafts_folder/../sent",
    )
    assert v.allowed is False, "second traversal bypass is still open"


def test_caller_cannot_self_declare_permission():
    """A caller claiming read_only for a tool that actually requires write
    must not be trusted — the server-side tool_registry decides, not the
    request body."""
    v = check_tool_call(
        _manifest(), "send_email", "read_only", scope=None,
    )
    # send_email isn't even in the manifest, so this should be denied
    # regardless — but critically, it must NOT be allowed just because the
    # caller claimed a low permission level.
    assert v.allowed is False


def test_legitimate_call_still_works():
    """Sanity check: the fixes above shouldn't break a legitimate, in-scope
    call."""
    v = check_tool_call(
        _manifest(), "knowledge_base_search", "read_only",
        scope="kb://public_docs",
    )
    assert v.allowed is True
    v2 = check_tool_call(
        _manifest(), "knowledge_base_search", "read_only",
        scope="kb://public_docs/onboarding/faq.md",
    )
    assert v2.allowed is True


def test_unregistered_tool_denied():
    """A tool that isn't in the server-side tool_registry at all must be
    denied, even if somehow present in a manifest."""
    v = check_tool_call(_manifest(), "totally_made_up_tool", "read_only")
    assert v.allowed is False


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
