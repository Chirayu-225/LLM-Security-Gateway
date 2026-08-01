"""
Thin wrapper around Google's Gemini API.

Why a wrapper at all? So the rest of our gateway (main.py, guardrails, etc.)
never needs to know HOW we talk to Gemini specifically. It just calls
`generate(prompt)` and gets text back. Later, if Google changes their SDK,
we only fix this one file.
"""

import os
import google.generativeai as genai
from app.system_prompt import SYSTEM_PROMPT

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Passing system_instruction here means every call through this client is
# genuinely subject to the same system prompt the output guardrail's leak
# detector is checking for — not a prompt that only exists in a comment.
_model = genai.GenerativeModel(
    "gemini-1.5-flash",
    system_instruction=SYSTEM_PROMPT,
)


def generate(prompt: str) -> str:
    """
    Send a prompt to Gemini (with our system prompt applied) and return
    its text response as a plain string.
    """
    response = _model.generate_content(prompt)
    return response.text
