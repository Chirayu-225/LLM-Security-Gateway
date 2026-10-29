"""
Streamlit dashboard for the LLM Security Gateway — "SOC console" visual
direction: deep navy panels, amber for blocked/alert states, teal for
passed/safe states, violet for category/informational accents.

IMPORTANT implementation note (read before editing HTML blocks below):
Every chunk of raw HTML passed to st.markdown(..., unsafe_allow_html=True)
is built as a SINGLE flat string with NO embedded newlines/indentation,
and passed in ONE st.markdown() call per logical component (never split
an opening tag and its content/closing tag across separate calls).

Two real bugs came from violating these rules earlier:
  1. Splitting a wrapping <div> across multiple st.markdown() calls —
     each call is its own independent element, so the browser silently
     auto-closes the "open" div immediately, producing an empty styled
     box with the real content dumped, unstyled, right after it.
  2. Building HTML inside an indented Python loop left leading
     whitespace on each generated line. Markdown treats 4+ spaces of
     indentation as a literal code block, so those lines rendered as
     raw escaped text instead of being parsed as HTML.
Building everything as flat, single-line strings sidesteps both issues
entirely, regardless of Streamlit's markdown parser internals.

Run with:
  streamlit run dashboard/app.py
Assumes the FastAPI server is already running on http://127.0.0.1:8000
"""

import html
import pandas as pd
import requests
import streamlit as st

API_BASE = "http://127.0.0.1:8000"
PROVIDER_LABEL = "Llama 3.1 8B — via Groq"

st.set_page_config(page_title="LLM Security Gateway", page_icon="🛡️", layout="wide")

for key in ("last_chat_result", "last_tool_check", "last_redteam_result"):
    if key not in st.session_state:
        st.session_state[key] = None

# ----------------------------------------------------------------------
# THEME
# ----------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --ink: #0B1220;
  --panel: #121B2E;
  --panel-raised: #16223A;
  --hairline: #22304A;
  --text: #E8ECF4;
  --text-muted: #7C8AA5;
  --amber: #F2A94D;
  --amber-soft: rgba(242, 169, 77, 0.14);
  --teal: #4FD1C5;
  --teal-soft: rgba(79, 209, 197, 0.14);
  --violet: #8B7FE8;
  --violet-soft: rgba(139, 127, 232, 0.14);
  --rose: #E8593A;
  --rose-soft: rgba(232, 89, 58, 0.14);
}

.stApp { background: var(--ink); font-family: 'Inter', sans-serif; color: var(--text); }
h1, h2, h3 { font-family: 'Space Grotesk', sans-serif !important; color: var(--text) !important; }
p, span, div, label { font-family: 'Inter', sans-serif; }
code, .mono { font-family: 'JetBrains Mono', monospace !important; }

.gw-header { display: flex; align-items: center; justify-content: space-between; padding-bottom: 4px; margin-bottom: 4px; }
.gw-brand { display: flex; align-items: center; gap: 14px; }
.gw-logo { width: 42px; height: 42px; border-radius: 10px; background: linear-gradient(135deg, var(--violet), var(--teal)); display: flex; align-items: center; justify-content: center; font-size: 20px; flex-shrink: 0; }
.gw-title { font-family: 'Space Grotesk', sans-serif; font-size: 26px; font-weight: 700; margin: 0; letter-spacing: -0.02em; }
.gw-subtitle { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-muted); margin-top: 2px; }
.gw-live { display: flex; align-items: center; gap: 7px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--teal); background: var(--teal-soft); border: 1px solid rgba(79,209,197,0.3); padding: 6px 12px; border-radius: 20px; }
.gw-live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--teal); animation: gw-pulse 1.8s ease-in-out infinite; }
@keyframes gw-pulse { 0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(79,209,197,0.5); } 50% { opacity: 0.6; box-shadow: 0 0 0 5px rgba(79,209,197,0); } }

.gw-pulse-wrap { background: var(--panel); border: 1px solid var(--hairline); border-radius: 12px; padding: 14px 18px; margin: 18px 0 22px 0; }
.gw-pulse-label { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px; }
.gw-pulse-row { display: flex; gap: 4px; flex-wrap: wrap; align-items: center; }
.gw-pulse-dot { width: 10px; height: 22px; border-radius: 3px; flex-shrink: 0; transition: transform 0.15s ease; display: inline-block; }
.gw-pulse-dot.blocked { background: var(--amber); }
.gw-pulse-dot.passed { background: var(--teal); opacity: 0.55; }
.gw-pulse-empty { color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 12px; }

.gw-kpi-row { display: flex; gap: 14px; margin-bottom: 22px; }
.gw-kpi { flex: 1; background: var(--panel); border: 1px solid var(--hairline); border-radius: 12px; padding: 18px 20px; border-top: 3px solid var(--hairline); }
.gw-kpi.accent-teal { border-top-color: var(--teal); }
.gw-kpi.accent-amber { border-top-color: var(--amber); }
.gw-kpi.accent-violet { border-top-color: var(--violet); }
.gw-kpi-label { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
.gw-kpi-value { font-family: 'Space Grotesk', sans-serif; font-size: 32px; font-weight: 700; line-height: 1; }

.gw-pill { display: inline-flex; align-items: center; gap: 5px; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 500; padding: 3px 10px; border-radius: 20px; white-space: nowrap; }
.gw-pill.blocked { background: var(--amber-soft); color: var(--amber); border: 1px solid rgba(242,169,77,0.35); }
.gw-pill.passed { background: var(--teal-soft); color: var(--teal); border: 1px solid rgba(79,209,197,0.35); }
.gw-pill.category { background: var(--violet-soft); color: var(--violet); border: 1px solid rgba(139,127,232,0.35); }
.gw-pill.none { background: rgba(124,138,165,0.1); color: var(--text-muted); border: 1px solid var(--hairline); }

.gw-table { width: 100%; border-collapse: collapse; margin-top: 4px; }
.gw-table th { text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; padding: 8px 12px; border-bottom: 1px solid var(--hairline); }
.gw-table td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid var(--hairline); vertical-align: middle; color: var(--text); }
.gw-table tr.row-blocked td:first-child { border-left: 3px solid var(--amber); }
.gw-table tr.row-passed td:first-child { border-left: 3px solid var(--teal); }
.gw-table .cell-mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-muted); }
.gw-table .cell-prompt { font-family: 'JetBrains Mono', monospace; font-size: 12.5px; max-width: 420px; }

.gw-catbar-row { margin-bottom: 12px; }
.gw-catbar-head { display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 12px; margin-bottom: 5px; }
.gw-catbar-track { background: var(--panel-raised); border-radius: 6px; height: 10px; overflow: hidden; }
.gw-catbar-fill { height: 100%; border-radius: 6px; background: linear-gradient(90deg, var(--amber), var(--teal)); display: block; }

.gw-result { border-radius: 12px; padding: 18px 20px; margin-top: 14px; border: 1px solid; }
.gw-result.blocked { background: var(--amber-soft); border-color: rgba(242,169,77,0.35); }
.gw-result.passed { background: var(--teal-soft); border-color: rgba(79,209,197,0.35); }
.gw-result.error { background: var(--rose-soft); border-color: rgba(232,89,58,0.35); }
.gw-result-title { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 15px; margin-bottom: 8px; }
.gw-result-body { font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--text); line-height: 1.6; white-space: pre-wrap; }

.gw-empty { background: var(--panel); border: 1px dashed var(--hairline); border-radius: 12px; padding: 28px; text-align: center; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 13px; }

.stButton > button { background: var(--panel-raised) !important; color: var(--text) !important; border: 1px solid var(--hairline) !important; border-radius: 8px !important; font-family: 'Inter', sans-serif !important; font-weight: 500 !important; }
.stButton > button:hover { border-color: var(--violet) !important; color: var(--violet) !important; }
.stTextArea textarea, .stTextInput input { background: var(--panel) !important; color: var(--text) !important; border: 1px solid var(--hairline) !important; font-family: 'JetBrains Mono', monospace !important; }
.stSelectbox > div > div { background: var(--panel) !important; border: 1px solid var(--hairline) !important; }
[data-testid="stTabs"] button { font-family: 'Space Grotesk', sans-serif !important; font-weight: 600 !important; }
hr { border-color: var(--hairline) !important; }
</style>
""", unsafe_allow_html=True)


def pill(kind: str, label: str) -> str:
    return f'<span class="gw-pill {kind}">{html.escape(str(label))}</span>'


def _auth_headers() -> dict:
    key = st.session_state.get("gateway_api_key", "")
    return {"X-API-Key": key} if key else {}


def fetch_stats():
    try:
        resp = requests.get(f"{API_BASE}/stats", headers=_auth_headers(), timeout=5)
        if resp.status_code == 401:
            st.warning("Enter your Gateway API key in the sidebar to load stats (set as GATEWAY_API_KEY in .env).")
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        st.error(f"Could not reach the gateway API at {API_BASE}. Is it running? ({e})")
        return None


with st.sidebar:
    st.markdown("##### Gateway API Key")
    st.caption("Required for Agent Violations, Red-Team Report, and Live Traffic — must match GATEWAY_API_KEY in the server's .env.")
    st.text_input("X-API-Key", type="password", key="gateway_api_key")


# ----------------------------------------------------------------------
# HEADER  (single flat string, single call — logo/title/subtitle/live badge)
# ----------------------------------------------------------------------
header_html = (
    '<div class="gw-header">'
    '<div class="gw-brand">'
    '<div class="gw-logo">🛡️</div>'
    '<div>'
    '<p class="gw-title">LLM Security Gateway</p>'
    f'<p class="gw-subtitle">{html.escape(PROVIDER_LABEL)}</p>'
    '</div></div>'
    '<div class="gw-live"><span class="gw-live-dot"></span>LIVE</div>'
    '</div>'
)
st.markdown(header_html, unsafe_allow_html=True)

_, col_refresh = st.columns([9, 1])
with col_refresh:
    if st.button("🔄 Refresh"):
        st.rerun()

stats = fetch_stats()

# ----------------------------------------------------------------------
# SIGNATURE ELEMENT: traffic pulse strip (built + rendered as ONE block)
# ----------------------------------------------------------------------
if stats and stats["recent_requests"]:
    recent = list(reversed(stats["recent_requests"]))[-30:]
    dots = "".join(
        f'<div class="gw-pulse-dot {"blocked" if r["blocked"] else "passed"}" '
        f'title="{html.escape(r["prompt"][:80])}"></div>'
        for r in recent
    )
    pulse_inner = f'<div class="gw-pulse-row">{dots}</div>'
else:
    pulse_inner = '<div class="gw-pulse-empty">No traffic yet — send a prompt via Try It / Attack It.</div>'

pulse_html = (
    '<div class="gw-pulse-wrap">'
    '<div class="gw-pulse-label">Traffic Pulse — last 30 requests</div>'
    f'{pulse_inner}'
    '</div>'
)
st.markdown(pulse_html, unsafe_allow_html=True)

tab_live, tab_agent, tab_redteam, tab_manual = st.tabs(
    ["Live Traffic", "Agent Violations", "Red-Team Report", "Try It / Attack It"]
)

# ------------------------------------------------------------ Live Traffic --
with tab_live:
    if stats and stats["recent_requests"]:
        df = pd.DataFrame(stats["recent_requests"])
        total = len(df)
        blocked = int(df["blocked"].sum())
        rate = f"{(blocked/total*100):.1f}%" if total else "0%"

        kpi_html = (
            '<div class="gw-kpi-row">'
            f'<div class="gw-kpi accent-violet"><div class="gw-kpi-label">Total Requests</div><div class="gw-kpi-value">{total}</div></div>'
            f'<div class="gw-kpi accent-amber"><div class="gw-kpi-label">Blocked</div><div class="gw-kpi-value">{blocked}</div></div>'
            f'<div class="gw-kpi accent-teal"><div class="gw-kpi-label">Block Rate</div><div class="gw-kpi-value">{rate}</div></div>'
            '</div>'
        )
        st.markdown(kpi_html, unsafe_allow_html=True)

        rows_html = ""
        for r in stats["recent_requests"]:
            row_class = "row-blocked" if r["blocked"] else "row-passed"
            status_pill = pill("blocked", "BLOCKED") if r["blocked"] else pill("passed", "PASSED")
            cat_pill = pill("category", r["blocked_category"]) if r["blocked_category"] else pill("none", "—")
            prompt_short = html.escape(r["prompt"][:90] + ("…" if len(r["prompt"]) > 90 else ""))
            reason_txt = r["reason"] or ""
            reason_short = html.escape(reason_txt[:70] + ("…" if len(reason_txt) > 70 else ""))
            rows_html += (
                f'<tr class="{row_class}">'
                f'<td class="cell-mono">{r["timestamp"][11:19]}</td>'
                f'<td class="cell-prompt">{prompt_short}</td>'
                f'<td>{status_pill}</td>'
                f'<td class="cell-mono">{r["blocked_stage"] or "—"}</td>'
                f'<td>{cat_pill}</td>'
                f'<td class="cell-mono">{reason_short}</td>'
                f'</tr>'
            )

        table_html = (
            '<table class="gw-table">'
            '<tr><th>Time</th><th>Prompt</th><th>Status</th><th>Stage</th><th>Category</th><th>Reason</th></tr>'
            f'{rows_html}</table>'
        )
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.markdown('<div class="gw-empty">No requests logged yet. Send a prompt via the Try It tab.</div>', unsafe_allow_html=True)

# --------------------------------------------------------- Agent Violations --
with tab_agent:
    st.markdown("##### Tool Permission Violations")
    if stats and stats["recent_violations"]:
        rows_html = ""
        for v in stats["recent_violations"]:
            rows_html += (
                '<tr class="row-blocked">'
                f'<td class="cell-mono">{v["timestamp"][11:19]}</td>'
                f'<td>{html.escape(v["agent_name"])}</td>'
                f'<td class="cell-mono">{html.escape(v["tool_name"])}</td>'
                f'<td class="cell-mono">{html.escape(v["reason"])}</td>'
                f'</tr>'
            )
        table_html = (
            '<table class="gw-table"><tr><th>Time</th><th>Agent</th><th>Tool</th><th>Reason</th></tr>'
            f'{rows_html}</table>'
        )
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.markdown('<div class="gw-empty">No agent permission violations logged yet.</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("##### Test a Tool Call Against a Manifest")
    manifest_id = st.text_input("Manifest ID", value="research_assistant_agent",
                                 help="Not a filesystem path — must match a key in main.py's MANIFEST_ALLOWLIST.")
    c1, c2, c3 = st.columns(3)
    with c1:
        tool_name = st.text_input("Tool name", value="draft_email")
    with c2:
        permission = st.selectbox("Claimed permission (audit-only)", ["read_only", "write", "execute"],
                                   help="No longer trusted for the decision — the server derives the real "
                                        "required permission from app/agent_audit/tool_registry.py. This is "
                                        "logged for comparison only.")
    with c3:
        scope = st.text_input("Scope (optional)", value="")

    if st.button("Check tool call"):
        try:
            resp = requests.post(
                f"{API_BASE}/agent/check-tool-call",
                headers=_auth_headers(),
                json={
                    "manifest_id": manifest_id,
                    "tool_name": tool_name,
                    "requested_permission": permission,
                    "scope": scope or None,
                },
                timeout=5,
            )
            st.session_state.last_tool_check = resp.json() if resp.status_code != 401 else {"request_error": "401 Unauthorized — check your API key in the sidebar."}
        except requests.RequestException as e:
            st.session_state.last_tool_check = {"request_error": str(e)}
        st.rerun()

    if st.session_state.last_tool_check:
        result = st.session_state.last_tool_check
        if "request_error" in result:
            st.markdown(f'<div class="gw-result error"><div class="gw-result-title">Request failed</div><div class="gw-result-body">{html.escape(result["request_error"])}</div></div>', unsafe_allow_html=True)
        elif result["allowed"]:
            st.markdown(f'<div class="gw-result passed"><div class="gw-result-title">✅ Allowed</div><div class="gw-result-body">{html.escape(result["reason"])}</div></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="gw-result blocked"><div class="gw-result-title">🚫 Blocked</div><div class="gw-result-body">{html.escape(result["reason"])}</div></div>', unsafe_allow_html=True)

# ------------------------------------------------------------ Red-Team Report --
with tab_redteam:
    st.markdown("##### Run Red-Team Suite")
    st.caption(f"Replays a held-out attack set against the live gateway ({PROVIDER_LABEL}).")

    if st.button("▶ Run red-team suite now"):
        with st.spinner("Replaying attack suite against the gateway..."):
            try:
                resp = requests.post(f"{API_BASE}/redteam/run", headers=_auth_headers(), timeout=120)
                st.session_state.last_redteam_result = resp.json() if resp.status_code not in (401, 429) else {"request_error": f"{resp.status_code} — check your API key or wait for the rate limit to reset."}
            except requests.RequestException as e:
                st.session_state.last_redteam_result = {"request_error": str(e)}
        st.rerun()

    if st.session_state.last_redteam_result:
        result = st.session_state.last_redteam_result
        if "request_error" in result:
            st.markdown(f'<div class="gw-result error"><div class="gw-result-title">Request failed</div><div class="gw-result-body">{html.escape(result["request_error"])}</div></div>', unsafe_allow_html=True)
        else:
            ov = result["overall"]
            kpi_html = (
                '<div class="gw-kpi-row">'
                f'<div class="gw-kpi accent-violet"><div class="gw-kpi-label">Prompts Tested</div><div class="gw-kpi-value">{ov["total"]}</div></div>'
                f'<div class="gw-kpi accent-amber"><div class="gw-kpi-label">Blocked</div><div class="gw-kpi-value">{ov["blocked"]}</div></div>'
                f'<div class="gw-kpi accent-teal"><div class="gw-kpi-label">Block Rate</div><div class="gw-kpi-value">{ov["block_rate"]*100:.1f}%</div></div>'
                '</div>'
            )
            st.markdown(kpi_html, unsafe_allow_html=True)

            st.markdown("###### Breakdown by OWASP Category")
            bars_html = ""
            for cat, cs in result["by_category"].items():
                pct = cs["block_rate"] * 100
                bars_html += (
                    '<div class="gw-catbar-row">'
                    f'<div class="gw-catbar-head"><span>{html.escape(cat)}</span>'
                    f'<span style="color:var(--text-muted)">{cs["blocked"]}/{cs["total"]} blocked ({pct:.0f}%)</span></div>'
                    f'<div class="gw-catbar-track"><div class="gw-catbar-fill" style="width:{pct}%"></div></div>'
                    '</div>'
                )
            st.markdown(bars_html, unsafe_allow_html=True)

            with st.expander("Raw per-prompt results"):
                st.dataframe(pd.DataFrame(result["raw_results"]), use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)
    if stats and stats["redteam_history"] and len(stats["redteam_history"]) > 1:
        st.markdown("###### Block Rate Over Time")
        hist_df = pd.DataFrame(stats["redteam_history"]).sort_values("timestamp")
        st.line_chart(hist_df.set_index("timestamp")["block_rate"])

# --------------------------------------------------------------- Try It --
with tab_manual:
    st.markdown("##### Send a Prompt Through the Gateway")
    st.caption(f"Every prompt runs through the full pipeline: input guardrail → {PROVIDER_LABEL} → output guardrail.")
    prompt = st.text_area("Prompt", height=120, placeholder="Try a normal question, or a known attack pattern...", label_visibility="collapsed")

    if st.button("▶ Send"):
        try:
            resp = requests.post(f"{API_BASE}/chat", json={"prompt": prompt}, timeout=30)
            st.session_state.last_chat_result = resp.json()
        except requests.RequestException as e:
            st.session_state.last_chat_result = {"request_error": str(e)}
        st.rerun()

    if st.session_state.last_chat_result:
        data = st.session_state.last_chat_result
        if "request_error" in data:
            st.markdown(f'<div class="gw-result error"><div class="gw-result-title">Request failed</div><div class="gw-result-body">{html.escape(data["request_error"])}</div></div>', unsafe_allow_html=True)
        elif data.get("blocked"):
            st.markdown(
                f'<div class="gw-result blocked"><div class="gw-result-title">🚫 BLOCKED — {html.escape(str(data["blocked_stage"]))} stage · {html.escape(str(data["blocked_category"]))}</div>'
                f'<div class="gw-result-body">{html.escape(data["reason"])}</div></div>',
                unsafe_allow_html=True,
            )
        elif data.get("error"):
            st.markdown(
                f'<div class="gw-result error"><div class="gw-result-title">⚠️ No response — LLM call failed or refused</div>'
                f'<div class="gw-result-body">{html.escape(data["reason"])}</div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="gw-result passed"><div class="gw-result-title">✅ Passed</div>'
                f'<div class="gw-result-body">{html.escape(data["response"] or "")}</div></div>',
                unsafe_allow_html=True,
            )
