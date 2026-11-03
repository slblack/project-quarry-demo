"""The real HTTP client against a local fake OpenAI server (no internet), for both APIs."""

from __future__ import annotations

import threading

import pytest
from flask import Flask, jsonify, redirect, request
from werkzeug.serving import make_server

from quarry_demo.providers.openai_chat import OpenAIChatClient, to_responses_input

TOOLS = [{"type": "function", "function": {"name": "lookup_order", "description": "d",
                                           "parameters": {"type": "object", "properties": {}}}}]


def _error_for(model):
    if model == "bad-key":
        return jsonify({"error": {"code": "invalid_api_key", "message": "Incorrect API key"}}), 401
    if model == "no-quota":
        return jsonify({"error": {"code": "insufficient_quota"}}), 429
    if model == "bad-param":
        return jsonify({"error": {"message": "Unsupported parameter: 'max_completion_tokens' is not supported with this model.",
                                  "param": "max_completion_tokens"}}), 400
    if model == "redirect":
        return redirect("http://127.0.0.1:1/elsewhere", 307)
    return None


@pytest.fixture
def fake_openai(monkeypatch):
    app = Flask("fake")
    seen = []

    @app.post("/v1/responses")
    def responses():
        body = request.get_json()
        seen.append({"path": "responses", "auth": request.headers.get("Authorization"), "body": body})
        err = _error_for(body["model"])
        if err:
            return err
        if body["model"] == "empty":
            return jsonify({"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
                            "output": [{"type": "reasoning", "id": "rs_1", "summary": []}]})
        if any(i.get("type") == "function_call_output" for i in body["input"]):
            return jsonify({"status": "completed", "output": [
                {"type": "reasoning", "id": "rs_2", "summary": []},
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Your order is on its way."}]}],
                "usage": {"input_tokens": 50, "output_tokens": 9}})
        return jsonify({"status": "completed", "output": [
            {"type": "reasoning", "id": "rs_1", "summary": []},
            {"type": "function_call", "id": "fc_1", "call_id": "call_abc", "name": "lookup_order",
             "arguments": "{\"order_id\":\"NS-1\"}"}],
            "usage": {"input_tokens": 12, "output_tokens": 3}})

    @app.post("/v1/chat/completions")
    def chat():
        body = request.get_json()
        seen.append({"path": "chat", "auth": request.headers.get("Authorization"), "body": body})
        err = _error_for(body["model"])
        if err:
            return err
        return jsonify({"choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "lookup_order",
                                                                                     "arguments": "{\"order_id\":\"NS-1\"}"}}]}}],
                        "usage": {"prompt_tokens": 12, "completion_tokens": 3}})

    @app.get("/v1/models/<name>")
    def model(name):
        return (jsonify({}), 404) if name == "nope" else (jsonify({"id": name}), 200)

    server = make_server("127.0.0.1", 0, app)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("QUARRY_DEMO_OPENAI_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.delenv("QUARRY_DEMO_OPENAI_API", raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    yield seen
    server.shutdown()


def test_responses_is_default_and_round_trips_tool_calls(fake_openai):
    client = OpenAIChatClient()
    res = client.chat("sk-x", "m", [{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}], TOOLS, 500)
    assert res.ok and fake_openai[0]["path"] == "responses"
    body = fake_openai[0]["body"]
    assert body["store"] is False and body["max_output_tokens"] == 500
    assert body["tools"][0] == {"type": "function", "name": "lookup_order", "description": "d",
                                "parameters": {"type": "object", "properties": {}}}
    call = res.message["tool_calls"][0]
    assert call["id"] == "call_abc" and call["function"]["name"] == "lookup_order"
    assert res.usage == {"prompt_tokens": 12, "completion_tokens": 3}

    # Feed the call and its result back the way the agent does.
    convo = [{"role": "user", "content": "hi"}, res.message,
             {"role": "tool", "tool_call_id": "call_abc", "content": "{\"status\":\"shipped\"}"}]
    res2 = client.chat("sk-x", "m", convo, TOOLS)
    assert res2.ok and res2.message["content"] == "Your order is on its way."
    sent = fake_openai[1]["body"]["input"]
    assert {"type": "function_call", "call_id": "call_abc", "name": "lookup_order",
            "arguments": "{\"order_id\":\"NS-1\"}"} in sent
    assert {"type": "function_call_output", "call_id": "call_abc", "output": "{\"status\":\"shipped\"}"} in sent


def test_translation_skips_empty_assistant_text():
    items = to_responses_input([{"role": "assistant", "content": None,
                                 "tool_calls": [{"id": "c", "function": {"name": "n", "arguments": "{}"}}]}])
    assert items == [{"type": "function_call", "call_id": "c", "name": "n", "arguments": "{}"}]


def test_empty_output_is_reported(fake_openai):
    res = OpenAIChatClient().chat("sk-x", "empty", [{"role": "user", "content": "hi"}])
    assert not res.ok and res.error.code == "empty" and "max_output_tokens" in res.error.message


def test_chat_completions_style(fake_openai, monkeypatch):
    monkeypatch.setenv("QUARRY_DEMO_OPENAI_API", "chat")
    res = OpenAIChatClient().chat("sk-x", "m", [{"role": "user", "content": "hi"}], TOOLS, 500)
    assert res.ok and fake_openai[0]["path"] == "chat"
    body = fake_openai[0]["body"]
    assert fake_openai[0]["auth"] == "Bearer sk-x"
    assert body["max_completion_tokens"] == 500 and body["tool_choice"] == "auto"
    assert res.message["tool_calls"][0]["function"]["name"] == "lookup_order"


@pytest.mark.parametrize("model,code", [("bad-key", "authentication"), ("no-quota", "quota"),
                                        ("redirect", "redirect"), ("bad-param", "bad_request")])
def test_errors_are_mapped(fake_openai, model, code):
    res = OpenAIChatClient().chat("sk-x", model, [{"role": "user", "content": "hi"}])
    assert not res.ok and res.error.code == code


def test_400_shows_openai_reason(fake_openai):
    res = OpenAIChatClient().chat("sk-x", "bad-param", [{"role": "user", "content": "hi"}])
    assert "Unsupported parameter" in res.error.message and "max_completion_tokens" in res.error.message


def test_verify_makes_a_tool_calling_probe(fake_openai):
    out = OpenAIChatClient().verify("sk-x", "ok-model")
    assert out["ok"] and "Responses API" in out["message"]
    assert fake_openai[-1]["body"]["tools"][0]["name"] == "ping"
    assert OpenAIChatClient().verify("sk-x", "nope")["outcome"] == "model_unavailable"
    bad = OpenAIChatClient().verify("sk-x", "bad-param")
    assert not bad["ok"] and "Unsupported parameter" in bad["message"]


def test_unreachable(monkeypatch):
    monkeypatch.setenv("QUARRY_DEMO_OPENAI_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    res = OpenAIChatClient().chat("sk-x", "m", [{"role": "user", "content": "hi"}])
    assert not res.ok and res.error.code == "connectivity"
