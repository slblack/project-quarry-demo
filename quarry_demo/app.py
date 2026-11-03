"""Flask application for the Project Quarry agent-guard demo."""

from __future__ import annotations

import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import __version__, security
from .agent import (
    LiveSettings,
    RunRegistry,
    load_scenarios,
    private_run,
    run_live_path,
    run_scripted_path,
    scenario_by_id,
    store_overview,
)
from .config import AI_DEFENSE_REGION_HOSTS, ConfigError, ConfigStore, validate_key, validate_model, validate_region
from .guard import MAX_RULE_CHARS, GuardEngine, JudgeContext, judge_context, parse_rule_info
from .judge import DemoJudgeAdapter, LiveJudgeAdapter
from .providers.ai_defense import AIDefenseClient
from .providers.openai_chat import OpenAIChatClient
from .tools import TOOL_DEFINITIONS

log = logging.getLogger("quarry_demo")

MAX_REQUEST_BYTES = 64 * 1024
MAX_MESSAGE_CHARS = 2000
MAX_ACTIVE_RUNS = 2
SPEEDS = {"slow": 1.4, "normal": 0.8, "fast": 0.3, "instant": 0.0}


def default_data_dir() -> Path:
    env = os.environ.get("QUARRY_DEMO_DATA_DIR")
    return Path(env) if env else Path(__file__).resolve().parent.parent / "data"


def default_dotenv() -> Path:
    return Path(__file__).resolve().parent.parent / ".env"


class BadInput(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _json_body(allowed: set[str]) -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BadInput("Request body must be a JSON object.")
    if set(data) - allowed:
        raise BadInput("Request contains unsupported fields.")
    for value in data.values():
        if value is not None and not isinstance(value, (str, bool)):
            raise BadInput("Fields must be strings or booleans.")
    return data


def _text(data: dict, key: str, limit: int, required: bool = True) -> str:
    value = data.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise BadInput(f"'{key}' must be text.")
    if "\x00" in value:
        raise BadInput("Text contains a null byte.")
    value = value.replace("\r\n", "\n").strip()
    if required and not value:
        raise BadInput(f"'{key}' is required.")
    if len(value) > limit:
        raise BadInput(f"'{key}' must be at most {limit} characters.")
    return value


def create_app(
    config_store: Optional[ConfigStore] = None,
    chat_client: Optional[OpenAIChatClient] = None,
    ai_defense: Optional[AIDefenseClient] = None,
    extra_hosts: tuple[str, ...] = (),
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.json.sort_keys = False

    store = config_store or ConfigStore(default_data_dir(), dotenv_path=default_dotenv())
    chat = chat_client or OpenAIChatClient()
    aid = ai_defense or AIDefenseClient()
    engine = GuardEngine({"demo_judge": DemoJudgeAdapter(), "live_judge": LiveJudgeAdapter(chat)})
    registry = RunRegistry()
    executor = ThreadPoolExecutor(max_workers=MAX_ACTIVE_RUNS * 2 + 2, thread_name_prefix="quarry-run")
    start_lock = threading.Lock()
    verify_slots = threading.BoundedSemaphore(2)
    csrf_token = security.install(app, extra_hosts)
    app.extensions["quarry_demo"] = {"store": store, "engine": engine, "registry": registry}

    # ------------------------------------------------------------------ errors
    @app.errorhandler(BadInput)
    def _bad_input(exc: BadInput):
        return jsonify({"ok": False, "error": {"code": "invalid_input", "message": exc.message}}), exc.status

    @app.errorhandler(ConfigError)
    def _config_error(exc: ConfigError):
        return jsonify({"ok": False, "error": {"code": "invalid_input", "message": str(exc)}}), 400

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        messages = {413: "Request too large.", 404: "Not found.", 405: "Method not allowed."}
        msg = messages.get(exc.code or 500, "Request could not be processed.")
        if request.path.startswith("/api/") or exc.code in (413, 405):
            return jsonify({"ok": False, "error": {"code": f"http_{exc.code}", "message": msg}}), exc.code
        return Response(msg, status=exc.code, mimetype="text/plain")

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        ref = uuid.uuid4().hex[:12]
        log.error("Unhandled error ref=%s type=%s", ref, type(exc).__name__)
        return jsonify({"ok": False, "error": {"code": "internal", "message": f"Internal error (ref {ref})."}}), 500

    # ------------------------------------------------------------------ pages
    @app.get("/")
    def index():
        return render_template("index.html", csrf_token=csrf_token, version=__version__,
                               max_chars=MAX_MESSAGE_CHARS)

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "version": __version__})

    # ------------------------------------------------------------------ catalogue
    @app.get("/api/bootstrap")
    def bootstrap():
        scenarios = [
            {k: s[k] for k in ("id", "title", "kind", "headline", "talk_track")}
            | {"user_messages": [t["user"] for t in s["turns"] if "user" in t]}
            for s in load_scenarios()
        ]
        return jsonify({
            "ok": True,
            "version": __version__,
            "scenarios": scenarios,
            "rules": _rules_view(),
            "store": store_overview(),
            "tools": [t["function"] for t in TOOL_DEFINITIONS],
            "config": store.public_view(),
        })

    def _rules_view() -> list[dict]:
        return [dict(r.public(), enabled=r.rule_id not in engine.disabled) for r in engine.all_rules()]

    # ------------------------------------------------------------------ rules
    @app.get("/api/rules")
    def rules():
        return jsonify({"ok": True, "rules": _rules_view()})

    @app.post("/api/rules/toggle")
    def rules_toggle():
        data = _json_body({"id", "enabled"})
        rid = _text(data, "id", 100)
        try:
            engine.set_enabled(rid, bool(data.get("enabled")))
        except KeyError:
            raise BadInput("Unknown rule.", 404)
        return jsonify({"ok": True, "rules": _rules_view()})

    @app.post("/api/rules/reset")
    def rules_reset():
        _json_body(set())
        engine.reset()
        return jsonify({"ok": True, "rules": _rules_view()})

    @app.post("/api/rules/compile")
    def rules_compile():
        source = _text(_json_body({"source"}), "source", MAX_RULE_CHARS)
        return jsonify({"ok": True, "result": engine.compile_check(source)})

    @app.post("/api/rules/test")
    def rules_test():
        """Replay every scenario with ONLY this rule active and report where it would act."""
        source = _text(_json_body({"source"}), "source", MAX_RULE_CHARS)
        check = engine.compile_check(source)
        if not check["ok"]:
            return jsonify({"ok": True, "result": {"compiled": False, "errors": check["errors"]}})
        info = parse_rule_info("candidate", source, builtin=False)
        rows = []
        for sc in load_scenarios():
            run = private_run()
            run_scripted_path(run, "guarded", sc, engine, 0.0, rules=[info])
            hits = []
            for ev in run.paths["guarded"].events:
                d = ev.get("decision") or {}
                for r in d.get("rules", []) + d.get("alerts", []):
                    hits.append({"step": ev.get("tool") or ev["type"], "action": d.get("action"),
                                 "witness": r.get("witness", []), "captured_value": r.get("captured_value")})
                if d.get("fail_closed_reason"):
                    hits.append({"step": ev.get("tool") or ev["type"], "action": d.get("action"),
                                 "error": d["fail_closed_reason"]})
            rows.append({"id": sc["id"], "title": sc["title"], "kind": sc["kind"], "hits": hits})
        return jsonify({"ok": True, "result": {"compiled": True, "rule": info.public(), "scenarios": rows}})

    @app.post("/api/rules/add")
    def rules_add():
        source = _text(_json_body({"source"}), "source", MAX_RULE_CHARS)
        try:
            engine.add_custom(source)
        except ValueError as exc:
            raise BadInput(str(exc)[:600])
        return jsonify({"ok": True, "rules": _rules_view()})

    @app.post("/api/rules/remove")
    def rules_remove():
        rid = _text(_json_body({"id"}), "id", 100)
        engine.remove_custom(rid)
        return jsonify({"ok": True, "rules": _rules_view()})

    # ------------------------------------------------------------------ config
    @app.get("/api/config")
    def get_config():
        return jsonify({"ok": True, "config": store.public_view()})

    @app.post("/api/config")
    def save_config():
        data = _json_body({"openai_api_key", "ai_defense_api_key", "openai_model", "judge_model",
                           "ai_defense_region", "ai_defense_connection_name"})
        mapping = {
            "openai_api_key": "OPENAI_API_KEY",
            "ai_defense_api_key": "AI_DEFENSE_API_KEY",
            "openai_model": "OPENAI_MODEL",
            "judge_model": "JUDGE_MODEL",
            "ai_defense_region": "AI_DEFENSE_REGION",
            "ai_defense_connection_name": "AI_DEFENSE_CONNECTION_NAME",
        }
        updates = {name: data[f] for f, name in mapping.items() if isinstance(data.get(f), str)}
        store.save(updates)
        log.info("Settings saved (fields=%s)", ",".join(sorted(k for k, v in updates.items() if str(v).strip())))
        return jsonify({"ok": True, "config": store.public_view()})

    @app.post("/api/verify/openai")
    def verify_openai():
        data = _json_body({"api_key", "model"})
        snap = store.snapshot()
        key = (data.get("api_key") or "").strip()
        key = validate_key(key, "OpenAI API key") if key else snap.openai_api_key
        model = validate_model(data["model"]) if (data.get("model") or "").strip() else snap.openai_model
        if not key:
            return jsonify({"ok": True, "result": {"ok": False, "outcome": "not_configured",
                                                   "message": "No OpenAI key entered or saved."}})
        if not verify_slots.acquire(blocking=False):
            raise BadInput("Another verification is running. Try again shortly.", 429)
        try:
            result = chat.verify(key, model)
        finally:
            verify_slots.release()
        return jsonify({"ok": True, "result": result, "model": model})

    @app.post("/api/verify/ai-defense")
    def verify_ai_defense():
        data = _json_body({"api_key", "region"})
        snap = store.snapshot()
        key = (data.get("api_key") or "").strip()
        key = validate_key(key, "AI Defense API key") if key else snap.ai_defense_api_key
        region = validate_region(data["region"]) if (data.get("region") or "").strip() else snap.region
        if not key:
            return jsonify({"ok": True, "result": {"ok": False, "outcome": "not_configured",
                                                   "message": "No AI Defense key entered or saved."}})
        if not verify_slots.acquire(blocking=False):
            raise BadInput("Another verification is running. Try again shortly.", 429)
        try:
            result = aid.verify(key, AI_DEFENSE_REGION_HOSTS[region], f"verify-{uuid.uuid4().hex}")
        finally:
            verify_slots.release()
        return jsonify({"ok": True, "result": result, "region": region})

    # ------------------------------------------------------------------ runs
    @app.post("/api/run")
    def start_run():
        data = _json_body({"mode", "scenario_id", "message", "speed", "use_ai_defense"})
        mode = data.get("mode")
        with start_lock:
            if registry.active() >= MAX_ACTIVE_RUNS:
                raise BadInput("Another run is still in progress. Wait for it to finish.", 429)
            if mode == "scripted":
                sc = scenario_by_id(_text(data, "scenario_id", 100))
                if sc is None:
                    raise BadInput("Unknown scenario.", 404)
                pace = SPEEDS.get(str(data.get("speed") or "normal"), SPEEDS["normal"])
                run = registry.create("scripted", sc["title"], {"scenario_id": sc["id"], "kind": sc["kind"]})
                for path in ("unprotected", "guarded"):
                    executor.submit(run_scripted_path, run, path, sc, engine, pace)
            elif mode == "live":
                message = _text(data, "message", MAX_MESSAGE_CHARS)
                snap = store.snapshot()
                if not snap.openai_configured:
                    raise BadInput("Live mode needs an OpenAI API key. Open Setup.")
                use_aid = bool(data.get("use_ai_defense")) and snap.ai_defense_configured
                run = registry.create("live", message[:80], {"model": snap.openai_model,
                                                              "judge_model": snap.judge_model,
                                                              "ai_defense": use_aid})

                def inspect(stage: str, messages: list, _run=run, _snap=snap):
                    wire = [{"role": m["role"], "content": m["content"]} for m in messages
                            if m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str)
                            and m["content"].strip()]
                    return aid.inspect(_snap.ai_defense_api_key, _snap.ai_defense_base_url, wire,
                                       f"{_run.run_id}-{stage}")

                settings = LiveSettings(api_key=snap.openai_api_key, model=snap.openai_model,
                                        judge_model=snap.judge_model, max_tokens=snap.max_output_tokens,
                                        ai_defense=inspect if use_aid else None)
                for path in ("unprotected", "guarded"):
                    executor.submit(run_live_path, run, path, message, engine, chat, settings)
            else:
                raise BadInput("mode must be 'scripted' or 'live'.")
        log.info("run=%s mode=%s started", run.run_id, mode)
        return jsonify({"ok": True, "run_id": run.run_id})

    @app.get("/api/run/<run_id>")
    def poll_run(run_id: str):
        if len(run_id) != 32 or not run_id.isalnum():
            raise BadInput("Unknown run.", 404)
        run = registry.get(run_id)
        if run is None:
            raise BadInput("Unknown run.", 404)
        since = {p: request.args.get(p, "0") for p in ("unprotected", "guarded")}
        return jsonify({"ok": True, "run": run.snapshot(since)})

    return app
