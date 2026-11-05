"""Person 2 test: one LLM request with tool calling (Groq, OpenAI-compatible).

    python scripts/check_llm.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
from openai import OpenAI  # noqa: E402
from agent import BASE_URL, MODEL, TOOLS  # noqa: E402

client = OpenAI(api_key=os.getenv("LLM_API_KEY"), base_url=BASE_URL)
resp = client.chat.completions.create(
    model=MODEL, max_tokens=300, tools=TOOLS,
    messages=[{"role": "user", "content": "Use the tool to verify requests version 2.32.0."}],
)
msg = resp.choices[0].message
if msg.tool_calls:
    tc = msg.tool_calls[0]
    print("OK: tool call returned ->", tc.function.name, tc.function.arguments)
else:
    print("No tool call. Reply was:", msg.content)