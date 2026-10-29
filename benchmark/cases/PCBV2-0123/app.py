#!/usr/bin/env python3
"""Minimal, unmodified Gradio app used as the SUT for all three versions.

This is an ordinary Gradio demo. The only "app-specific" thing is a real-world
`allowed_paths=["/gradio_tmp"]` — a developer marking an extra data directory as
servable over the `/file=` route (a very common Gradio pattern). The path
containment for that allowlist is enforced entirely by gradio.utils.is_in_or_equal
(the CVE sink). No business logic touches the flag or the canary.
"""
import gradio as gr


def greet(name: str) -> str:
    return f"hello {name}"


demo = gr.Interface(fn=greet, inputs="text", outputs="text")

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        allowed_paths=["/gradio_tmp"],
    )
