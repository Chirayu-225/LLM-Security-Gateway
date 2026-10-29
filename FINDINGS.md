# I attacked my own guardrail: what got through, and how I fixed it

This project went through an external security review after its first
build. Every High and Medium finding is documented here with the actual
bypass, the root cause, the fix, and the regression test proving it's
closed. Read `README.md` for setup; this is the "how it actually held up"
story.

## High severity

### 1. The permission enforcer could be bypassed four ways

Tested against `manifests/example_agent.yaml`, all four of these
previously returned `allowed=True`:

- `kb://public_docs_internal_hr` passed a scope check against declared
  scope `kb://public_docs`, because the check was `str.startswith()` —
  string prefix matching, not path matching. Any scope whose characters
  happened to line up passed.
- `kb://public_docs/../private/salaries` passed, because paths were never
  normalized — `..` traversal just worked.
- Omitting `scope` entirely passed, because the old code only ran the
  scope check when the caller supplied one. The check failed *open*.
- `drafts_folder/../sent` passed — the same traversal bug in a second
  place.

**The deeper problem** wasn't any one of these — it was that
`requested_permission` was supplied by the *caller*. A compromised agent
could simply claim `read_only` for a tool that actually writes or
executes, and the enforcer had no way to know better. The agent was
grading its own homework.

**Fix:** `app/agent_audit/tool_registry.py` is a new, server-side source
of truth mapping every real tool to its actual required permission level.
The enforcer looks a tool up there — it no longer trusts anything the
caller claims. `requested_permission` is still accepted, but only for
audit logging (so a caller lying about it is now a visible signal, not an
exploit). Scope checks moved to `app/agent_audit/scope_utils.py`, which
normalizes paths and matches whole path *segments*, closing both the
prefix-collision and traversal bugs, and fails **closed** when a scope
restriction exists but the caller didn't supply one.

`tests/test_enforcer_bypasses.py` replays all four bypasses plus two
additional checks (unregistered tools, caller-claimed-low-permission) —
7/7 pass.

### 2. The manifest path was attacker-controlled

`/agent/check-tool-call` passed `manifest_path` straight to `open()`. A
404 meant the file didn't exist; a 500 meant it existed but wasn't a
valid manifest — enough to probe the filesystem from an unauthenticated
endpoint.

**Fix:** `manifest_path` is gone. Callers reference a manifest by
`manifest_id`, checked against `MANIFEST_ALLOWLIST` in `app/main.py` — a
fixed dict of known-good IDs to known-good paths. No caller-supplied
string ever reaches `open()`.

### 3. PII was logged in plaintext by the system built to prevent leaks

When the output guardrail blocked a response for containing PII,
`pipeline.py` still wrote the raw, unredacted `raw_response` to SQLite.
`/stats` then served recent prompts with no authentication at all —
meaning the very act of detecting and blocking a leak created a second,
quieter, publicly-readable copy of it.

**Fix:** `OutputGuardrail.redact()` (new method) replaces every detected
PII span with an `[ENTITY_TYPE]` placeholder. `pipeline.py` now logs the
redacted copy on *every* path — blocked and allowed — never the raw text.
The client-facing response is unaffected: a blocked response was never
sent to the client before and still isn't; an allowed response is still
returned to the client exactly as generated. Only the logged copy
changed. `/stats`, along with `/agent/check-tool-call` and `/redteam/run`,
now also require the `X-API-Key` header (`app/auth.py`), and refuse to
serve traffic at all if `GATEWAY_API_KEY` isn't configured — fail closed,
not open.

## Medium severity

### 4. The input filter had both high false positives and easy bypasses

Tested directly against the regex layer:

- **False positives:** blocked "How do I enable developer mode on my
  Android phone?", "How do I decode a base64 string in Python?", "How do
  I show the config of my nginx server?" — the `developer mode` and
  `base64|rot13|pig ?latin|reversed text` rules were far too broad.
- **Misses:** a zero-width space inside "Ignore all previous
  instructions", leetspeak ("1gnore"), a double space, and "ignore all
  prior instructions" (the regex only matched "previous").

**Fix:** `app/guardrails/text_normalize.py` strips zero-width characters
and applies NFKC + a conservative leetspeak fold before matching, closing
the misses. The `developer mode` rule now requires a co-occurring
jailbreak-intent word (bypass/unrestricted/disable/etc.) within 40
characters, and the standalone encoding-name rule
(`base64|rot13|pig latin|reversed text`) was removed entirely — it was
also the source of an **evaluation-leakage bug**: the held-out red-team
set contains a literal Pig Latin attack, so that regex was catching its
own test case by matching the *name of the encoding*, not by detecting
an actual evasion attempt. That inflated the block-rate metric without
proving the embedding layer generalizes to anything. Encoding-evasion
attempts are still caught by the embedding layer's semantic matching,
which is the right tool for this — not a keyword rule on format names
that have countless legitimate everyday uses.

`tests/test_input_filter_regex.py`: 9/9 pass, covering every miss and
every false positive listed above, verbatim.

### 5. The evaluation couldn't support its own metric

The held-out set had 6 prompts (each moves the block rate ~17 points),
there was no benign set (so false-positive rate was never measured — the
number that actually decides whether a guardrail can ship), and "not
blocked" was being treated as "attack succeeded" with no distinction from
"the model refused on its own."

**Fix:** `evaluation/benign_set.py` (~40 prompts, several deliberately
targeting the exact false positives above) and `evaluation/run_eval.py`
(block rate, false-positive rate, latency, and a `--sweep` mode charting
the trade-off across similarity thresholds). The held-out attack set also
grew from 6 to 9. **Honesty note:** this harness needs network access
(to download the embedding model) and a live `GROQ_API_KEY`, neither
available in the environment these fixes were built in — it has not been
run yet, and no block-rate number appears on the resume until it has.
Run it yourself with `python evaluation/run_eval.py`.

### 6. Bare `os.system(`, `subprocess.*(`, `eval(`, `exec(` and any single
email/phone/IP made the gateway unusable for coding or IT-support answers

Any response mentioning these — completely normal in ordinary technical
help — was blocked outright.

**Fix:** `app/guardrails/code_patterns.py` splits dangerous-code patterns
into a **hard-block** tier (unambiguous regardless of context: `rm -rf`,
`DROP TABLE`, a fork bomb, etc.) and a **review-only** tier (bare
`os.system(`/`subprocess.*(`/`eval(`/`exec(` — flagged for visibility,
never blocks alone). PII entities are similarly tiered in
`output_filter.py`: `CREDIT_CARD`/`US_SSN`/`IBAN_CODE`/`CRYPTO` still
hard-block on a single hit; `EMAIL_ADDRESS`/`PHONE_NUMBER`/`IP_ADDRESS`
now need **two or more** to appear together, matching what a real PII
leak actually looks like (clustered personal data) versus one incidental
IP in a config example.

`tests/test_output_filter_code_patterns.py`: 9/9 pass — every previously
blocked ordinary response now flags-but-passes, every genuinely
destructive one still hard-blocks.

### 7. No cost protection

`/redteam/run` was unauthenticated and fired several paid LLM calls per
hit; nothing limited request rate or prompt length (LLM10, Unbounded
Consumption).

**Fix:** `app/rate_limit.py` — a 4000-character prompt cap, plus
per-client rate limits (30/min on `/chat`, 3/min on `/redteam/run`,
since that one is the expensive one). `/redteam/run` also now requires
auth, so it's no longer reachable by an anonymous caller at all.

## Low severity (quick fixes)

- OWASP category IDs updated throughout to the 2025 numbering: Sensitive
  Information Disclosure is now LLM02, Improper Output Handling is
  LLM05, Excessive Agency is LLM06, and System Prompt Leakage is its own
  category, LLM07 (previously all lumped under the 2023 list's LLM06).
- `system_prompt.py`'s comment claiming the canary approach "catches
  paraphrased leaks" was inaccurate — it only catches verbatim echoes.
  Corrected, and left as a documented open gap rather than silently
  wrong.
- `.env.example` added (previously referenced in setup steps but missing
  from the repo).
- `gemini_client.py` and the `google-generativeai` dependency removed —
  unused, and referenced an outdated model name.
- Tutorial leftovers removed (a stray "Chapter 3.1" comment, a
  personal-venv-name comment in `.gitignore`).
- The README's "Known gaps" section, which claimed the system-prompt-leak
  fragment was unset, was itself stale (`pipeline.py` does set it) —
  corrected.

## Extensions built beyond the fixes

Ranked by portfolio impact in the original review, all implemented:

1. **A real agent loop** (`app/agent_loop/`) — a document poisoned with a
   hidden instruction tries to get the agent to silently email an
   internal spreadsheet to an external address (indirect prompt
   injection via retrieved content, not anything the user typed), and
   the permission enforcer denies the resulting tool call before it ever
   executes. Runs in both a live mode (real Groq function-calling) and an
   offline mode (no API key needed) — this is the demo that shows the
   enforcer stopping something, not just filtering text.
2. **The evaluation harness** described in finding #5.
3. **An automated attacker** (`app/redteam/mutator.py`) — rule-based
   (zero-width injection, leetspeak, double-spacing, random case,
   base64-wrapping, sentence-splitting), deliberately not LLM-based so it
   needs no API key and can run in CI on every commit. Reports an
   evasion rate per mutation type, which is a real, growing feedback
   signal for the attack corpus over time.
4. **Multi-turn session risk tracking** (`app/guardrails/session_tracker.py`)
   — several individually below-threshold "near miss" turns in one
   session now accumulate risk and can trigger a block even when no
   single turn would have, a first pass at defending against the
   erosion-style attacks already represented in `ATTACK_CORPUS`.
5. **Production hardening**: API keys, rate limiting, a pytest-style
   regression suite (deliberately split from the heavier ML-dependent
   code so it needs no network or API key to run), and CI
   (`.github/workflows/tests.yml`) that runs that suite on every push.
6. This write-up.
