#!/usr/bin/env python3
"""Mock OpenAI-compatible chat-completions endpoint (SSE) for the PCB benchmark.

pgAdmin's AI Assistant (NLQ chat) calls this endpoint instead of a real
LLM, always via the streaming protocol (chat_stream). The mock behaves
like a compliant assistant that responds to the user's message by
invoking the execute_sql_query database tool with the very query the
user asked for (the message text), then finishes.

Flow per chat request from pgAdmin:
  1. POST /v1/chat/completions (messages have no 'tool' role yet)
     -> SSE chunks with tool_calls=[execute_sql_query {"query": <msg>}]
  2. POST /v1/chat/completions (pgAdmin appended the tool result)
     -> plain content SSE, finish_reason=stop
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOL_NAME = "execute_sql_query"


def _sse(*events):
    return ("".join("data: " + json.dumps(e) + "\n\n" for e in events)
            + "data: [DONE]\n\n").encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])

        if any(m.get("role") == "tool" for m in messages):
            chunks = [
                {"choices": [{
                    "delta": {"role": "assistant", "content": "Done."},
                    "finish_reason": None,
                }]},
                {"choices": [{"delta": {}, "finish_reason": "stop"}]},
            ]
        else:
            user_msg = ""
            for m in reversed(messages):
                if m.get("role") == "user":
                    user_msg = m.get("content", "")
                    break
            chunks = [
                {"choices": [{
                    "delta": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{
                            "index": 0,
                            "id": "call_pcb_1",
                            "type": "function",
                            "function": {
                                "name": TOOL_NAME,
                                "arguments": json.dumps({"query": user_msg}),
                            },
                        }],
                    },
                    "finish_reason": None,
                }]},
                {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
            ]

        data = _sse(*chunks)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
