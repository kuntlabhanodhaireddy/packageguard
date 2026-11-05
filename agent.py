"""Person 2: LLM agent (step 3). Uses any OpenAI-compatible provider (default: Groq, free tier).

The LLM writes plain-English explanations and may call verify_package() before it
recommends a replacement. It never decides verdicts: those come from checks.py.
Without LLM_API_KEY, or if the API fails, explain_results() falls back to offline text.
"""
from __future__ import annotations

import json
import os

from dotenv import load_dotenv

from checks import check_package
from result_format import PackageResult

load_dotenv()
BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
MAX_TOOL_ROUNDS = 5

SYSTEM = """You explain dependency scan results to a developer in plain English.
Rules:
1. Use only the facts in the evidence JSON you are given. Do not invent CVE ids, dates or numbers.
2. Never call a package safe unless its verdict is Safe.
3. If you suggest a replacement version, call verify_package first. Recommend it only if the result is Safe.
4. Write 2 to 3 short sentences per package.
5. When finished, reply with only a JSON object: {"explanations": {"<package name>": "<text>"}}"""

TOOLS = [{
    "type": "function",
    "function": {
        "name": "verify_package",
        "description": "Run PackageGuard's real checks on one package version and return its verdict, confidence and reasons.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "version": {"type": "string"}},
            "required": ["name", "version"],
        },
    },
}]


def _summary(r: PackageResult) -> dict:
    return {"name": r.name, "version": r.version, "verdict": r.verdict,
            "confidence": r.confidence, "reasons": r.reasons, "fix": r.fix}


def _run_tool(name: str, args: dict) -> str:
    if name != "verify_package":
        return json.dumps({"error": f"unknown tool {name}"})
    r = check_package(args["name"], args["version"])
    return json.dumps({"verdict": r.verdict, "confidence": r.confidence, "reasons": r.reasons[:3]})


def _offline_one(r: PackageResult) -> str:
    text = f"{r.verdict}: " + " ".join(r.reasons)
    if r.fix:
        text += f" Suggested fix: {r.fix}."
    return text


def _ask_llm(results: list[PackageResult], key: str) -> dict[str, str]:
    from openai import OpenAI  # imported here so the app runs without the SDK

    client = OpenAI(api_key=key, base_url=BASE_URL)
    payload = json.dumps([_summary(r) for r in results], indent=2)
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"Scan results:\n{payload}\n\nExplain each package, then reply with the JSON object."},
    ]

    for _ in range(MAX_TOOL_ROUNDS):
        resp = client.chat.completions.create(model=MODEL, messages=messages, tools=TOOLS, max_tokens=1500)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            text = msg.content or ""
            data = json.loads(text[text.find("{"): text.rfind("}") + 1])
            expl = data.get("explanations", {})
            return {r.name: expl.get(r.name) or _offline_one(r) for r in results}
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [tc.model_dump() for tc in msg.tool_calls],
        })
        for tc in msg.tool_calls:
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": _run_tool(tc.function.name, json.loads(tc.function.arguments)),
            })
    raise RuntimeError("LLM did not finish within the tool-call limit")


def explain_results(results: list[PackageResult]) -> tuple[dict[str, str], str]:
    """Return ({package name: explanation}, source). Source is 'AI' or 'offline (...)'."""
    key = os.getenv("LLM_API_KEY")
    if not key:
        return {r.name: _offline_one(r) for r in results}, "offline (no LLM_API_KEY)"
    try:
        return _ask_llm(results, key), "AI"
    except Exception as err:
        return {r.name: _offline_one(r) for r in results}, f"offline (API error: {err})"