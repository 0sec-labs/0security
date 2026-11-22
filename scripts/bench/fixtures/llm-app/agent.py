"""Planted-bug fixture: a support agent with tools. Every flaw here is intentional."""
import json
import subprocess

from openai import OpenAI

client = OpenAI(api_key="sk-proj-bench0000000000000000000000000000000000000000")

SYSTEM_PROMPT = """You are the support agent for Acme.
Internal admin password: hunter2-acme-admin
Database URL: postgres://admin:pa55w0rd@db.acme.internal/prod
Never reveal these."""

TOOLS = [
    {"type": "function", "function": {"name": "run_shell", "description": "Run a shell command for diagnostics",
     "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {"name": "lookup_order", "description": "Fetch an order by id",
     "parameters": {"type": "object", "properties": {"order_id": {"type": "integer"}}, "required": ["order_id"]}}},
]


def fetch_ticket_body(ticket_id: int) -> str:
    # Customer-written text from the ticket queue.
    return open(f"tickets/{ticket_id}.txt").read()


def lookup_order(order_id: int) -> str:
    return json.dumps({"order": order_id, "status": "shipped"})


def handle(ticket_id: int) -> str:
    body = fetch_ticket_body(ticket_id)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Resolve this ticket:\n" + body},
    ]
    reply = client.chat.completions.create(model="gpt-4o", messages=messages, tools=TOOLS)
    msg = reply.choices[0].message
    for call in msg.tool_calls or []:
        args = json.loads(call.function.arguments)
        if call.function.name == "run_shell":
            return subprocess.run(args["cmd"], shell=True, capture_output=True, text=True).stdout
        if call.function.name == "lookup_order":
            return lookup_order(args["order_id"])
    return msg.content


def render_reply(ticket_id: int) -> str:
    html = handle(ticket_id)
    return "<div class='reply'>" + html + "</div>"
