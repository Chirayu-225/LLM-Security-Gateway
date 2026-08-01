"""
The red-team engine tests the gateway against the HELD_OUT_REDTEAM_SET,
NOT the same corpus the input guardrail was built from. This matters:
scoring against your own reference set would just tell you the lookup
table works, not whether the defense generalizes to attacks it hasn't
seen verbatim before — which is the actual question a red-team exercise
is supposed to answer.
"""

from app.guardrails.attack_patterns import HELD_OUT_REDTEAM_SET

def get_attack_suite():
    return HELD_OUT_REDTEAM_SET
