"""OpenAI client for the live agent and the AI judge, over ``requests``.

Two OpenAI APIs are supported; the rest of the app always speaks Chat Completions-shaped messages
(``role``/``content``/``tool_calls`` and ``role: tool`` results) and this module translates.

* ``responses`` (default) - the Responses API, the same API the Northstar demo uses. Newer models
  such as the GPT-6 family support function calling here.
* ``chat`` - Chat Completions. Set ``QUARRY_DEMO_OPENAI_API=chat`` for models or OpenAI-compatible
  endpoints that only offer it.

Plain HTTPS keeps dependencies short and lets the same trust settings as the AI Defense client
apply (extra CA certificates via ``REQUESTS_CA_BUNDLE``; opt-in relaxed strict X.509 via
``QUARRY_DEMO_TLS_RELAX_X509_STRICT``). Verification is never disabled. Redirects are not
followed, so the key never leaves the configured host.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

import requests
from requests.adapters import HTTPAdapter

from ..tls import relaxed_strict_context
from .errors import ProviderError, find_tls_error, tls_message

DEFAULT_BASE_URL = "https://api.openai.com/v1"
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 90.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_SAFE_DETAIL = re.compile(r"[^\w\s.,:;'\"()\[\]/_\-+=<>@%]")


def base_url() -> str:
    return (os.environ.get("QUARRY_DEMO_OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def api_style() -> str:
    value = (os.environ.get("QUARRY_DEMO_OPENAI_API") or "responses").strip().lower()
    return "chat" if value in ("chat", "chat_completions", "chat-completions") else "responses"


class _RelaxedAdapter(HTTPAdapter):
    def __init__(self, ctx, *args, **kwargs):
        self._ctx = ctx
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().init_poolmanager(*args, **kwargs)


def default_session() -> requests.Session:
    session = requests.Session()
    ctx = relaxed_strict_context()
    if ctx is not None:
        session.mount("https://", _RelaxedAdapter(ctx))
    return session


@dataclass
class ChatResult:
    ok: bool
    message: dict = field(default_factory=dict, repr=False)
    finish_reason: Optional[str] = None
    usage: Optional[dict] = None
    duration_ms: int = 0
    error: Optional[ProviderError] = None


def _provider_detail(body: Any) -> str:
    """OpenAI's own error text (e.g. "Unsupported parameter: 'x'"), shortened and stripped of odd
    characters. These messages describe the request, not the key, so they are safe to show."""
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        err = body["error"]
        msg = err.get("message") if isinstance(err.get("message"), str) else ""
        param = err.get("param") if isinstance(err.get("param"), str) else ""
        text = msg + (f" (parameter: {param})" if param and param not in msg else "")
        text = _SAFE_DETAIL.sub("", re.sub(r"sk-[A-Za-z0-9_\-]{6,}", "sk-…", text)).strip()
        return text[:300]
    return ""


def _status_error(status: int, body: Any) -> ProviderError:
    code = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        code = body["error"].get("code")
    detail = _provider_detail(body)
    suffix = f" OpenAI said: {detail}" if detail else ""
    if status == 401:
        return ProviderError("authentication", "OpenAI rejected the API key. Enter a valid key in Setup.", 401)
    if status == 403:
        return ProviderError("model_access", "The OpenAI key is not permitted to use this model or project." + suffix, 403)
    if status == 404:
        return ProviderError("model_access", "The configured model was not found or is not available to this key." + suffix, 404)
    if status == 429:
        if code == "insufficient_quota":
            return ProviderError("quota", "OpenAI reports insufficient quota or credit for this key.", 429)
        return ProviderError("rate_limit", "OpenAI rate limit reached. Wait a moment and try again.", 429)
    if status == 400:
        return ProviderError("bad_request", "OpenAI rejected the request (400)." + (suffix or
                             " The model may not support function calling; choose another model in Setup."), 400)
    if 300 <= status < 400:
        return ProviderError("redirect", "OpenAI returned a redirect, which is not followed.", status)
    return ProviderError("provider_error", f"OpenAI returned HTTP {status}." + suffix, status)


# --------------------------------------------------------------------------- translation
def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict) and "text" in p)
    return ""


def to_responses_input(messages: Sequence[dict]) -> list[dict]:
    """Chat-shaped messages -> Responses API input items."""
    items: list[dict] = []
    for m in messages:
        role = m.get("role")
        if role in ("system", "developer", "user"):
            items.append({"role": role, "content": _text(m.get("content"))})
        elif role == "assistant":
            text = _text(m.get("content"))
            if text.strip():
                items.append({"role": "assistant", "content": text})
            for call in m.get("tool_calls") or []:
                fn = call.get("function") or {}
                items.append({"type": "function_call", "call_id": call.get("id", ""),
                              "name": fn.get("name", ""), "arguments": fn.get("arguments") or "{}"})
        elif role == "tool":
            items.append({"type": "function_call_output", "call_id": m.get("tool_call_id", ""),
                          "output": _text(m.get("content"))})
    return items


def to_responses_tools(tools: Optional[list]) -> list[dict]:
    out = []
    for t in tools or []:
        fn = t.get("function") or {}
        out.append({"type": "function", "name": fn.get("name"), "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {"type": "object", "properties": {}})})
    return out


def from_responses_output(body: dict) -> tuple[dict, Optional[dict], Optional[str]]:
    """Responses API body -> (chat-shaped assistant message, usage, finish reason)."""
    texts, calls = [], []
    for item in body.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") in ("output_text", "text"):
                    texts.append(str(part.get("text", "")))
        elif item.get("type") == "function_call":
            calls.append({"id": item.get("call_id") or item.get("id") or "", "type": "function",
                          "function": {"name": item.get("name", ""), "arguments": item.get("arguments") or "{}"}})
    message: dict = {"role": "assistant", "content": "\n".join(t for t in texts if t) or None}
    if calls:
        message["tool_calls"] = calls
    usage = None
    if isinstance(body.get("usage"), dict):
        u = body["usage"]
        usage = {"prompt_tokens": u.get("input_tokens") or 0, "completion_tokens": u.get("output_tokens") or 0}
    reason = "tool_calls" if calls else body.get("status")
    return message, usage, reason


# --------------------------------------------------------------------------- client
class OpenAIChatClient:
    def __init__(self, session_factory: Callable[[], requests.Session] = default_session,
                 style: Optional[str] = None) -> None:
        self._session_factory = session_factory
        self._style = style
        self.timeout = (CONNECT_TIMEOUT, READ_TIMEOUT)

    @property
    def style(self) -> str:
        return self._style or api_style()

    def _request(self, method: str, path: str, api_key: str, payload: Optional[dict] = None):
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        with self._session_factory() as session:
            resp = session.request(
                method, base_url() + path, headers=headers, json=payload,
                timeout=self.timeout, allow_redirects=False,
            )
            return resp.status_code, resp.content[: MAX_RESPONSE_BYTES + 1]

    def _transport_error(self, exc: BaseException) -> ProviderError:
        if isinstance(exc, requests.exceptions.Timeout):
            return ProviderError("timeout", "OpenAI did not respond before the timeout. Try again shortly.")
        if find_tls_error(exc) or isinstance(exc, requests.exceptions.SSLError):
            return ProviderError("tls", tls_message("OpenAI", exc))
        if isinstance(exc, requests.exceptions.ConnectionError):
            return ProviderError("connectivity", "Could not reach OpenAI. Check network access, proxy and firewall.")
        return ProviderError("provider_error", "Unexpected error while calling OpenAI.")

    def chat(
        self,
        api_key: str,
        model: str,
        messages: Sequence[dict],
        tools: Optional[list] = None,
        max_completion_tokens: int = 2000,
        _ctx: Any = None,
    ) -> ChatResult:
        if self.style == "chat":
            path = "/chat/completions"
            payload: dict = {"model": model, "messages": list(messages), "max_completion_tokens": max_completion_tokens}
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
        else:
            path = "/responses"
            payload = {"model": model, "input": to_responses_input(messages),
                       "max_output_tokens": max_completion_tokens, "store": False}
            if tools:
                payload["tools"] = to_responses_tools(tools)
                payload["tool_choice"] = "auto"
        start = time.perf_counter()
        try:
            status, content = self._request("POST", path, api_key, payload)
        except requests.exceptions.RequestException as exc:
            return ChatResult(False, duration_ms=_ms(start), error=self._transport_error(exc))
        try:
            body = json.loads(content.decode("utf-8")) if content and len(content) <= MAX_RESPONSE_BYTES else None
        except (UnicodeDecodeError, ValueError):
            body = None
        if status != 200:
            return ChatResult(False, duration_ms=_ms(start), error=_status_error(status, body))
        if not isinstance(body, dict):
            return ChatResult(False, duration_ms=_ms(start),
                              error=ProviderError("malformed", "OpenAI returned an unexpected response format."))
        if self.style == "chat":
            try:
                choice = body["choices"][0]
                message = choice["message"]
                assert isinstance(message, dict)
            except (TypeError, KeyError, IndexError, AssertionError):
                return ChatResult(False, duration_ms=_ms(start),
                                  error=ProviderError("malformed", "OpenAI returned an unexpected response format."))
            usage = body.get("usage") if isinstance(body.get("usage"), dict) else None
            return ChatResult(True, message=message, finish_reason=choice.get("finish_reason"),
                              usage=usage, duration_ms=_ms(start))
        message, usage, reason = from_responses_output(body)
        if not message.get("content") and not message.get("tool_calls"):
            details = body.get("incomplete_details") if isinstance(body.get("incomplete_details"), dict) else {}
            why = details.get("reason") if isinstance(details.get("reason"), str) else body.get("status")
            return ChatResult(False, duration_ms=_ms(start), usage=usage, error=ProviderError(
                "empty", f"The model returned no text or tool call ({why or 'no output'}). "
                         "Try raising OPENAI_MAX_OUTPUT_TOKENS or choose another model."))
        return ChatResult(True, message=message, finish_reason=reason, usage=usage, duration_ms=_ms(start))

    def verify(self, api_key: str, model: str) -> dict:
        """Authenticate, then make one tiny function-calling request with this model."""
        try:
            status, content = self._request("GET", f"/models/{model}", api_key)
        except requests.exceptions.RequestException as exc:
            err = self._transport_error(exc)
            return {"ok": False, "outcome": err.code, "message": err.message}
        if status == 404:
            return {"ok": False, "outcome": "model_unavailable",
                    "message": "Key authenticated, but this model is not available to it."}
        if status != 200:
            err = _status_error(status, None)
            return {"ok": False, "outcome": err.code, "message": err.message}
        probe_tool = [{"type": "function", "function": {
            "name": "ping", "description": "Reply to a ping.",
            "parameters": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}}}]
        res = self.chat(api_key, model, [{"role": "user", "content": "Call the ping tool with ok=true."}], probe_tool, 400)
        if not res.ok and res.error and res.error.code != "empty":
            return {"ok": False, "outcome": res.error.code,
                    "message": f"Key authenticated, but a tool-calling test failed. {res.error.message}"}
        api = "Responses API" if self.style == "responses" else "Chat Completions"
        return {"ok": True, "outcome": "authenticated",
                "message": f"Key authenticated and the model accepted a tool-calling request ({api}). "
                           "This does not guarantee credit or rate limits."}


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
