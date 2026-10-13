"""Record an agent's model calls from outside the agent, whatever it is written in.

    mnestiq proxy evidence/agent.jsonl --agent support-bot --signer

Point the agent's model client at the proxy instead of the provider::

    OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1
    ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic

Each request is passed on unchanged with the agent's own API key, and the answer comes back
unchanged, streamed as it arrives. Every model call becomes an ``llm_call`` record in a signed
evidence file, the same as the recorder writes inside an agent, so ``mnestiq verify``, the
dashboard and the findings work on it as they are.

What it sees: what the model was told (system prompt, the user's words, the tool results the
agent handed back, labelled untrusted unless a tool is configured as trusted) and what the model
asked for (tool calls, answers). What it does not see: whether a tool really ran, and anything the
agent did besides calling the model. Pair it with network logs, and allow only the proxy to reach
the provider, so an agent cannot go around it.

The API key passes through and is never written down. The proxy listens on this machine only
unless told otherwise, and forwards only to the providers it was configured with.
"""

from .server import DEFAULT_UPSTREAMS, ModelProxy, Upstream

__all__ = ["DEFAULT_UPSTREAMS", "ModelProxy", "Upstream"]
