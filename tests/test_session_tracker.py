"""
Tests the multi-turn session risk tracker in isolation — pure logic, no
network needed. Run: python3 tests/test_session_tracker.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.guardrails.session_tracker import record_turn, reset_session

failed = 0

# Single below-threshold turn should not trip a session block.
reset_session("s1")
v = record_turn("s1", similarity_score=0.5)
ok = not v.blocked
print(f"{'PASS' if ok else 'FAIL'}: one near-miss turn alone does not block session")
failed += 0 if ok else 1

# Several near-miss turns in a row (simulating erosion) SHOULD eventually block.
reset_session("s2")
last = None
for i in range(6):
    last = record_turn("s2", similarity_score=0.65)
ok = last.blocked
print(f"{'PASS' if ok else 'FAIL'}: repeated near-miss turns eventually block the session (cumulative={last.cumulative_risk})")
failed += 0 if ok else 1

# Genuinely unrelated low-similarity turns should never accumulate meaningfully.
reset_session("s3")
last = None
for i in range(10):
    last = record_turn("s3", similarity_score=0.1)
ok = not last.blocked
print(f"{'PASS' if ok else 'FAIL'}: many genuinely benign turns do not accumulate risk (cumulative={last.cumulative_risk})")
failed += 0 if ok else 1

# Sessions are isolated from each other.
reset_session("s4a")
reset_session("s4b")
for i in range(6):
    record_turn("s4a", similarity_score=0.65)
v_b = record_turn("s4b", similarity_score=0.1)
ok = not v_b.blocked
print(f"{'PASS' if ok else 'FAIL'}: one session's risk does not leak into another session")
failed += 0 if ok else 1

print(f"\n{'ALL PASS' if failed == 0 else f'{failed} FAILED'}")
sys.exit(1 if failed else 0)
