"""Cisco AI Defense chat inspection client.

API reference (checked 2026-10-14):
  POST {region host}/api/v1/inspect/chat
  Header: X-Cisco-AI-Defense-API-Key
  Body:   {"messages": [{"role", "content"}], "metadata": {"client_transaction_id", ...}}

Enforcement is read from the response ``action`` field ("Allow" / "Block"), as modelled by
Cisco's official ``cisco-aidefense-sdk`` (``aidefense.runtime.models.Action``). The REST
reference page lists ``is_safe``, ``classifications``, ``rules`` etc. but not ``action``;
the SDK's own sample shows ``is_safe: false`` together with ``action: "Allow"`` (a
monitor-only policy), so ``is_safe`` is never used as a decision here.

No ``config.enabled_rules`` is sent: the policy attached to the customer's inspection
connection (identified by the API key) decides.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

import requests

from ..config import AI_DEFENSE_REGION_HOSTS
from .errors import ProviderError, find_tls_error, tls_message

INSPECT_PATH = "/api/v1/inspect/chat"
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 256 * 1024

_CLASSIFICATIONS = {"SECURITY_VIOLATION", "PRIVACY_VIOLATION", "SAFETY_VIOLATION", "RELEVANCE_VIOLATION",
                    "NONE_VIOLATION"}
_SEVERITIES = {"NONE_SEVERITY", "LOW", "MEDIUM", "HIGH"}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9 &_\-./()]{1,80}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.:]{1,100}$")


@dataclass
class InspectionResult:
    decision: str  # "allow" | "block" | "error"
    duration_ms: int = 0
    http_status: Optional[int] = None
    raw_action: Optional[str] = None
    is_safe: Optional[bool] = None
    classifications: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    severity: Optional[str] = None
    attack_technique: Optional[str] = None
    event_id: Optional[str] = None
    client_transaction_id: Optional[str] = None
    error: Optional[ProviderError] = None

    def public(self) -> dict:
        data = {
            "decision": self.decision,
            "duration_ms": self.duration_ms,
            "action": self.raw_action,
            "is_safe": self.is_safe,
            "classifications": self.classifications,
            "rules": self.rules,
            "severity": self.severity,
            "attack_technique": self.attack_technique,
            "event_id": self.event_id,
            "client_transaction_id": self.client_transaction_id,
        }
        if self.error is not None:
            data["error"] = self.error.public()
        return data


def _safe_label(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _SAFE_LABEL.match(value) else None


def _safe_id(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _SAFE_ID.match(value) else None


def parse_inspection_body(body: Any) -> InspectionResult:
    """Turn a decoded 200 response into a decision. Anything unusable fails closed."""
    if not isinstance(body, dict):
        return InspectionResult(
            decision="error", error=ProviderError("malformed", "AI Defense returned an unexpected response format.")
        )
    raw_action = body.get("action")
    action_text = raw_action.strip().lower() if isinstance(raw_action, str) else None
    result = InspectionResult(decision="error")
    result.raw_action = _safe_label(raw_action) if isinstance(raw_action, str) else None
    result.is_safe = body.get("is_safe") if isinstance(body.get("is_safe"), bool) else None
    result.classifications = [c for c in (body.get("classifications") or []) if c in _CLASSIFICATIONS][:10] \
        if isinstance(body.get("classifications"), list) else []
    rules = []
    if isinstance(body.get("rules"), list):
        for rule in body["rules"][:20]:
            if not isinstance(rule, dict):
                continue
            rules.append(
                {
                    "rule_name": _safe_label(rule.get("rule_name")),
                    "rule_id": rule.get("rule_id") if isinstance(rule.get("rule_id"), int) else None,
                    "classification": rule.get("classification")
                    if rule.get("classification") in _CLASSIFICATIONS
                    else None,
                }
            )
    result.rules = rules
    result.severity = body.get("severity") if body.get("severity") in _SEVERITIES else None
    result.attack_technique = _safe_label(body.get("attack_technique"))
    result.event_id = _safe_id(body.get("event_id"))
    result.client_transaction_id = _safe_id(body.get("client_transaction_id"))

    if action_text == "allow":
        result.decision = "allow"
    elif action_text == "block":
        result.decision = "block"
    elif raw_action is None:
        result.error = ProviderError(
            "no_decision",
            "AI Defense responded without an enforcement action. Check that an enabled policy is attached "
            "to this inspection connection.",
        )
    else:
        result.error = ProviderError("unknown_action", "AI Defense returned an unrecognised enforcement action.")
    return result


class AIDefenseClient:
    def __init__(
        self,
        connect_timeout: float = CONNECT_TIMEOUT,
        read_timeout: float = READ_TIMEOUT,
        session_factory: Callable[[], requests.Session] = requests.Session,
    ) -> None:
        self.timeout = (connect_timeout, read_timeout)
        self._session_factory = session_factory

    @staticmethod
    def endpoint_for(base_url: str) -> str:
        if base_url not in AI_DEFENSE_REGION_HOSTS.values():
            raise ValueError("AI Defense host is not one of the documented regional hosts.")
        return base_url + INSPECT_PATH

    def inspect(
        self, api_key: str, base_url: str, messages: Sequence[dict], transaction_id: str
    ) -> InspectionResult:
        url = self.endpoint_for(base_url)
        payload = {
            "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
            "metadata": {"client_transaction_id": transaction_id, "src_app": "project-quarry-demo"},
        }
        headers = {
            "X-Cisco-AI-Defense-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        start = time.perf_counter()

        def done(result: InspectionResult) -> InspectionResult:
            result.duration_ms = int((time.perf_counter() - start) * 1000)
            return result

        try:
            with self._session_factory() as session:
                response = session.post(
                    url, json=payload, headers=headers, timeout=self.timeout, allow_redirects=False
                )
                status = response.status_code
                content = response.content[: MAX_RESPONSE_BYTES + 1]
        except requests.exceptions.Timeout:
            return done(InspectionResult("error", error=ProviderError("timeout", "AI Defense inspection timed out.")))
        except requests.exceptions.SSLError as exc:
            msg = tls_message("AI Defense", exc) if find_tls_error(exc) else "TLS error while contacting AI Defense."
            return done(InspectionResult("error", error=ProviderError("tls", msg)))
        except requests.exceptions.ConnectionError:
            return done(
                InspectionResult(
                    "error",
                    error=ProviderError("unreachable", "Could not reach AI Defense. Check network, proxy and region."),
                )
            )
        except requests.exceptions.RequestException:
            return done(InspectionResult("error", error=ProviderError("request_failed", "AI Defense request failed.")))

        if status in (401, 403):
            return done(
                InspectionResult(
                    "error",
                    http_status=status,
                    error=ProviderError(
                        "authentication",
                        "AI Defense rejected the API key (check the key and that the region matches your tenant).",
                        status,
                    ),
                )
            )
        if status == 429:
            return done(
                InspectionResult(
                    "error", http_status=status, error=ProviderError("rate_limit", "AI Defense rate limit reached.", 429)
                )
            )
        if 300 <= status < 400:
            return done(
                InspectionResult(
                    "error",
                    http_status=status,
                    error=ProviderError("redirect", "AI Defense returned a redirect, which is not followed.", status),
                )
            )
        if status != 200:
            return done(
                InspectionResult(
                    "error",
                    http_status=status,
                    error=ProviderError("provider_error", f"AI Defense returned HTTP {status}.", status),
                )
            )
        if len(content) > MAX_RESPONSE_BYTES:
            return done(
                InspectionResult("error", http_status=status, error=ProviderError("malformed", "AI Defense response too large."))
            )
        try:
            import json

            body = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return done(
                InspectionResult(
                    "error", http_status=status, error=ProviderError("malformed", "AI Defense returned invalid JSON.")
                )
            )
        result = parse_inspection_body(body)
        result.http_status = status
        return done(result)

    def verify(self, api_key: str, base_url: str, transaction_id: str) -> dict:
        """Benign inspection request. Never claims a policy works just because the key was accepted."""
        result = self.inspect(
            api_key,
            base_url,
            [{"role": "user", "content": "Hello, what is the return window for unused items?"}],
            transaction_id,
        )
        if result.decision in ("allow", "block"):
            return {
                "ok": True,
                "outcome": "usable_decision",
                "message": f"Key accepted and the service returned a usable enforcement decision "
                f"({result.raw_action}) for a benign test question. This confirms connectivity and a decision, "
                "not that your custom policy rules behave as intended.",
                "decision": result.decision,
            }
        err = result.error or ProviderError("unknown", "Verification failed.")
        outcome = {
            "authentication": "rejected",
            "timeout": "unreachable",
            "unreachable": "unreachable",
            "tls": "tls",
            "no_decision": "authenticated_no_policy_decision",
            "unknown_action": "authenticated_no_policy_decision",
        }.get(err.code, err.code)
        message = err.message
        if outcome == "authenticated_no_policy_decision":
            message = (
                "Key accepted, but the response had no usable enforcement decision. Attach and enable a policy "
                "on this inspection connection in your AI Defense tenant."
            )
        return {"ok": False, "outcome": outcome, "message": message}
