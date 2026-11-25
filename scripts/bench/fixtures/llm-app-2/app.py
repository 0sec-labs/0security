"""The research assistant: a tool loop and an HTML page. Planted flaws are intentional."""
import html
import json

from llm import client
from rag import build_system_prompt, build_user_message
from tools import TOOL_SPECS, TOOL_TABLE


def answer(question: str) -> str:
    messages = [{"role": "system", "content": build_system_prompt()}, build_user_message(question)]
    for _ in range(6):
        reply = client.complete(messages, tools=TOOL_SPECS)
        call = reply.get("tool_call")
        if not call:
            return reply["content"]
        args = json.loads(call["arguments"])
        result = TOOL_TABLE[call["name"]](**args)
        messages.append({"role": "tool", "name": call["name"], "content": result})
    return "stopped after six tool calls"


def render_page(question: str) -> str:
    text = answer(question)
    return "<main><h1>Answer</h1><div class='answer'>" + text + "</div></main>"


def render_title(question: str) -> str:
    return "<title>" + html.escape(question[:80]) + "</title>"
