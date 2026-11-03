"""HTTP surface: hardening, bootstrap, scripted runs, rules API and settings."""

from __future__ import annotations

from tests.conftest import FAKE_OPENAI_KEY, HOST, get, post, wait_run


def test_rejects_foreign_host(app):
    c = app.test_client()
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_api_requires_csrf(client):
    r = client.post("/api/run", json={"mode": "scripted", "scenario_id": "order-status"})
    assert r.status_code == 403


def test_bootstrap(client):
    data = get(client, "/api/bootstrap").get_json()
    assert len(data["scenarios"]) == 9 and len(data["rules"]) == 9
    assert data["config"]["openai_configured"] is False
    assert "Content-Security-Policy" in client.get("/").headers


def test_scripted_run_via_api(client):
    r = post(client, "/api/run", {"mode": "scripted", "scenario_id": "refund-over-limit", "speed": "instant"})
    run = wait_run(client, r.get_json()["run_id"])
    assert run["paths"]["unprotected"]["damage"]["refunded_gbp"] == 420
    assert run["paths"]["guarded"]["damage"]["refunded_gbp"] == 0


def test_toggle_rule_changes_outcome(client):
    for rid in ("04_refund_over_limit",):
        assert post(client, "/api/rules/toggle", {"id": rid, "enabled": False}).status_code == 200
    run = wait_run(client, post(client, "/api/run", {"mode": "scripted", "scenario_id": "refund-over-limit",
                                                     "speed": "instant"}).get_json()["run_id"])
    assert run["paths"]["guarded"]["damage"]["refunded_gbp"] == 420
    post(client, "/api/rules/reset", {})
    rules = get(client, "/api/rules").get_json()["rules"]
    assert all(r["enabled"] for r in rules)


def test_rule_test_and_add(client):
    src = ('rule "Date of birth in an outgoing email"\nmetadata:\n    enforce = "tool_call"\nstrings:\n'
           '    $dob = "(DOB|date of birth)[^0-9]{0,12}[0-9]{4}-[0-9]{2}-[0-9]{2}" nocase regex\ncondition:\n'
           '    any mail in get_tool_calls("send_email") where mail.response == null and $dob in mail.arguments.body\n')
    res = post(client, "/api/rules/test", {"source": src}).get_json()["result"]
    hits = {s["id"]: s["hits"] for s in res["scenarios"]}
    assert hits["injection-exfil"] and not hits["legit-refund-email"]
    bad = post(client, "/api/rules/test", {"source": 'rule "x"\ncondition:\n    nonsense(\n'}).get_json()["result"]
    assert bad["compiled"] is False
    rules = post(client, "/api/rules/add", {"source": src}).get_json()["rules"]
    assert any(r["name"] == "Date of birth in an outgoing email" and not r["builtin"] for r in rules)


def test_settings_never_return_keys(client):
    r = post(client, "/api/config", {"openai_api_key": FAKE_OPENAI_KEY, "openai_model": "gpt-test"})
    body = r.get_data(as_text=True)
    assert FAKE_OPENAI_KEY not in body
    cfg = r.get_json()["config"]
    assert cfg["openai_configured"] and cfg["judge_model"] == "gpt-test"


def test_unknown_run(client):
    assert get(client, "/api/run/" + "a" * 32).status_code == 404
