"""Shared fixtures. Fake providers only: no real keys, no network, no paid calls."""

from __future__ import annotations

import json
import re
import threading

import pytest

from quarry_demo.app import create_app
from quarry_demo.config import ConfigStore
from quarry_demo.providers.ai_defense import InspectionResult
from quarry_demo.providers.openai_chat import ChatResult

HOST = "127.0.0.1:5075"
FAKE_OPENAI_KEY = "sk-test-FAKEOPENAIKEY-0000000000"


def _call(cid, name, args):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


class FakeChat:
    """Plays a fixed tool plan for the agent and answers judge prompts.

    ``plan`` is a list of (tool name, args) the agent will request one per round, then ``final``.
    Judge prompts (no tools offered) are answered "1" when ``judge_flags`` appears in them.
    """

    def __init__(self, plan=None, final="All done.", judge_flags=("verify@trailtalk", "Harbour Trading"),
                 judge_reply=None):
        self.plan = plan or []
        self.final = final
        self.judge_flags = judge_flags
        self.judge_reply = judge_reply
        self.calls: list[dict] = []
        self.judge_calls = 0
        self._lock = threading.Lock()

    def chat(self, api_key, model, messages, tools=None, max_completion_tokens=1200, _ctx=None):
        with self._lock:
            self.calls.append({"api_key": api_key, "model": model, "messages": json.loads(json.dumps(messages)),
                               "tools": bool(tools)})
        if not tools:
            self.judge_calls += 1
            if self.judge_reply is not None:
                return self.judge_reply
            text = json.dumps(messages)
            flagged = any(f in text for f in self.judge_flags)
            return ChatResult(True, message={"role": "assistant", "content": "1" if flagged else "0"})
        done = sum(1 for m in messages if m.get("role") == "tool")
        if done < len(self.plan):
            name, args = self.plan[done]
            return ChatResult(True, message={"role": "assistant", "content": None,
                                             "tool_calls": [_call(f"call_{done}", name, args)]},
                              usage={"prompt_tokens": 100, "completion_tokens": 20})
        return ChatResult(True, message={"role": "assistant", "content": self.final},
                          usage={"prompt_tokens": 100, "completion_tokens": 20})

    def verify(self, api_key, model):
        return {"ok": True, "outcome": "authenticated", "message": "fake ok"}


class FakeAIDefense:
    def __init__(self, decision="allow"):
        self.decision = decision
        self.calls = []

    def inspect(self, api_key, base_url, messages, transaction_id):
        self.calls.append({"messages": list(messages), "txid": transaction_id})
        return InspectionResult(decision=self.decision, raw_action=self.decision.title())

    def verify(self, api_key, base_url, transaction_id):
        return {"ok": True, "outcome": "usable_decision", "message": "fake"}


@pytest.fixture
def store(tmp_path):
    return ConfigStore(tmp_path / "data", env={}, dotenv_path=None)


@pytest.fixture
def fake_chat():
    return FakeChat()


@pytest.fixture
def fake_aid():
    return FakeAIDefense()


@pytest.fixture
def app(store, fake_chat, fake_aid):
    return create_app(config_store=store, chat_client=fake_chat, ai_defense=fake_aid)


@pytest.fixture
def client(app):
    c = app.test_client()
    page = c.get("/", headers={"Host": HOST})
    token = re.search(r'name="csrf-token" content="([^"]+)"', page.get_data(as_text=True)).group(1)
    c.environ_base["HTTP_HOST"] = HOST
    c.csrf = token
    return c


def post(client, path, body):
    return client.post(path, json=body, headers={"X-CSRF-Token": client.csrf})


def get(client, path):
    return client.get(path, headers={"X-CSRF-Token": client.csrf})


def wait_run(client, run_id, timeout=60):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        data = get(client, f"/api/run/{run_id}").get_json()["run"]
        if data["done"]:
            return data
        time.sleep(0.05)
    raise AssertionError("run did not finish")
