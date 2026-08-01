"""
Thin wrapper around Groq's API (they host fast, free open models like
Llama 3.1 and Mixtral). One function, `generate(prompt)`, that hides the SDK details from the rest of the app.
"""

import os
from groq import Groq
from app.system_prompt import SYSTEM_PROMPT

_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

_MODEL_NAME = "llama-3.1-8b-instant"


def generate(prompt: str) -> str:
    """
    Send a prompt to Groq's chat completion endpoint (with our system
    prompt applied as the first message) and return the assistant's
    reply as plain text.
    """
    completion = _client.chat.completions.create(
        model=_MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return completion.choices[0].message.content
