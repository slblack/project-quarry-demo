"""Model adapters for Quarry's ``model("judge").score(...)``.

* ``DemoJudgeAdapter``  - offline and deterministic, used by scripted replays. It is a simple
  keyword heuristic standing in for a real model, so replays need no key and always give the
  same result. The UI labels it as such.
* ``LiveJudgeAdapter``  - asks the configured OpenAI model, used in live mode.

Quarry builds the judge prompt itself (the ``constitution`` message builder): a system message
with a one-token "1"/"0" contract, the policy text, and the conversation wrapped in boundary
tags as untrusted data. The adapter only transports it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .guard import judge_context

_INTENT = {
    "send_email": r"\b(e-?mail|send (me|it|a copy)|copy of|receipt|confirm(ation)? to)\b",
    "issue_refund": r"refund|money back|return|reimburs|damaged|broken|faulty|never (arrived|got|received)",
    "update_shipping_address": r"(change|update|new|different)\b.{0,40}\baddress|deliver (it )?to|ship (it )?to|send it to",
    "create_discount_code": r"discount|coupon|voucher|promo|deal|code",
}


def _parts_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                out.append(str(part.get("text", "")))
        return "\n".join(out)
    return ""


def _conversation_turns(messages: list) -> list[tuple[str, str]]:
    """Recover (original_role, text) pairs from Quarry's constitution-built messages."""
    turns = []
    for m in messages:
        content = m.get("content") if isinstance(m, dict) else None
        if not isinstance(content, list) or not content:
            continue
        first = content[0].get("text", "") if isinstance(content[0], dict) else ""
        try:
            role = json.loads(first).get("original_role")
        except (ValueError, AttributeError):
            continue
        rest = []
        for part in content[1:]:
            if isinstance(part, dict) and part.get("type") == "text":
                rest.append(str(part.get("text", "")))
        turns.append((role, "\n".join(rest)))
    return turns


def demo_score(messages: list) -> float:
    turns = _conversation_turns(messages)
    user_text = " ".join(t for r, t in turns if r == "user").lower()
    pending = None
    for role, text in turns:
        if role == "assistant" and '"tool_calls"' in text:
            for match in re.finditer(r'"name":\s*"([a-z_]+)"', text):
                pending = match.group(1)
    if pending is None or pending not in _INTENT:
        return 0.05
    return 0.06 if re.search(_INTENT[pending], user_text) else 0.94


class DemoJudgeAdapter:
    async def score(self, _config, messages, *, timeout=None):  # noqa: D401 - Quarry adapter API
        ctx = judge_context.get()
        value = demo_score(list(messages))
        if ctx is not None:
            ctx.calls += 1
            ctx.last_score = value
        return value


class LiveJudgeAdapter:
    """Scores with the OpenAI Chat Completions API using the run's key and judge model."""

    def __init__(self, client) -> None:
        self._client = client

    async def score(self, _config, messages, *, timeout=None):
        import asyncio

        ctx = judge_context.get()
        if ctx is None or not ctx.api_key:
            raise RuntimeError("Live judge has no OpenAI key for this run.")
        ctx.calls += 1
        wire = []
        for m in messages:
            role = m.get("role", "user")
            text = _parts_text(m.get("content"))
            wire.append({"role": role if role in ("system", "user", "assistant") else "user", "content": text})
        result = await asyncio.to_thread(
            self._client.chat, ctx.api_key, ctx.model, wire, None, 1024, ctx
        )
        if not result.ok:
            ctx.errors.append(result.error.public() if result.error else {"code": "judge_error"})
            raise RuntimeError(result.error.message if result.error else "Judge call failed.")
        text = (result.message.get("content") or "").strip()
        token = text[:1]
        if token not in ("0", "1"):
            m = re.search(r"\b([01])\b", text)
            token = m.group(1) if m else ""
        if token not in ("0", "1"):
            ctx.errors.append({"code": "judge_unparseable", "message": "Judge did not answer 1 or 0."})
            raise RuntimeError("Judge did not answer 1 or 0.")
        value = 1.0 if token == "1" else 0.0
        ctx.last_score = value
        return value
