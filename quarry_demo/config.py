"""Configuration and secret storage for the Project Quarry demo.

Precedence (highest first) for every setting:

1. Values saved from the Setup dialog (``settings.json`` in the data directory).
2. Variables in the process environment (for example ``docker run -e``).
3. Values in a project-local ``.env`` file.
4. Built-in defaults.

Saving from Setup therefore wins over inherited environment values, so a restart
never silently reverts a change made in the UI.

``settings.json`` is written atomically (temporary file + ``os.replace``) and
restricted to the current OS user (mode 0600 on POSIX). Secrets are never
returned by any public method other than :meth:`ConfigStore.snapshot`, which the
server uses internally to call providers.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

DEFAULT_OPENAI_MODEL = "gpt-6-luna"
DEFAULT_REGION = "us"
DEFAULT_MAX_OUTPUT_TOKENS = 2000

# Documented Cisco AI Defense inspection hosts (developer.cisco.com getting-started).
# Only these HTTPS hosts can ever receive the AI Defense key.
AI_DEFENSE_REGION_HOSTS: Mapping[str, str] = {
    "us": "https://us.api.inspect.aidefense.security.cisco.com",
    "eu": "https://eu.api.inspect.aidefense.security.cisco.com",
    "ap": "https://ap.api.inspect.aidefense.security.cisco.com",
}

SECRET_FIELDS = ("OPENAI_API_KEY", "AI_DEFENSE_API_KEY")
PLAIN_FIELDS = ("OPENAI_MODEL", "JUDGE_MODEL", "AI_DEFENSE_REGION", "AI_DEFENSE_CONNECTION_NAME")
ALL_FIELDS = SECRET_FIELDS + PLAIN_FIELDS

MAX_KEY_LENGTH = 512
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,99}$")
# Printable ASCII without spaces: real provider keys never contain anything else.
KEY_RE = re.compile(r"^[\x21-\x7e]{8,%d}$" % MAX_KEY_LENGTH)
CONNECTION_NAME_RE = re.compile(r"^[\w .:/()\-]{0,80}$")


class ConfigError(ValueError):
    """Raised for invalid configuration input. Messages never contain values."""


def validate_key(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be text.")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ConfigError(f"{label} must not contain newlines or null bytes.")
    value = value.strip()
    if len(value) > MAX_KEY_LENGTH:
        raise ConfigError(f"{label} is unreasonably long.")
    if not KEY_RE.match(value):
        raise ConfigError(f"{label} contains unexpected characters or is too short.")
    return value


def validate_model(value: str) -> str:
    if not isinstance(value, str):
        raise ConfigError("Model identifier must be text.")
    value = value.strip()
    if not MODEL_RE.match(value):
        raise ConfigError(
            "Model identifier must be 1–100 characters of letters, digits, '.', '_', ':' or '-'."
        )
    return value


def validate_region(value: str) -> str:
    if not isinstance(value, str) or value.strip().lower() not in AI_DEFENSE_REGION_HOSTS:
        raise ConfigError("AI Defense region must be one of: us, eu, ap.")
    return value.strip().lower()


def validate_connection_name(value: str) -> str:
    if not isinstance(value, str):
        raise ConfigError("Connection name must be text.")
    value = value.strip()
    if "\x00" in value or "\n" in value or "\r" in value or not CONNECTION_NAME_RE.match(value):
        raise ConfigError("Connection name may contain up to 80 letters, digits, spaces and . : / ( ) - _")
    return value


def parse_dotenv(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE parser (no interpolation, no command execution)."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key in ALL_FIELDS:
            values[key] = value
    return values


@dataclass(frozen=True)
class ConfigSnapshot:
    """Immutable configuration captured once per paired run."""

    openai_api_key: str = field(repr=False)
    ai_defense_api_key: str = field(repr=False)
    openai_model: str
    judge_model: str
    region: str
    connection_name: str
    max_output_tokens: int

    @property
    def ai_defense_base_url(self) -> str:
        return AI_DEFENSE_REGION_HOSTS[self.region]

    @property
    def openai_configured(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def ai_defense_configured(self) -> bool:
        return bool(self.ai_defense_api_key)


class ConfigStore:
    def __init__(
        self,
        data_dir: Path,
        env: Mapping[str, str] | None = None,
        dotenv_path: Path | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.settings_path = self.data_dir / "settings.json"
        self._env = dict(os.environ if env is None else env)
        self._dotenv = parse_dotenv(dotenv_path) if dotenv_path else {}
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- reading
    def _read_saved(self) -> dict[str, Any]:
        try:
            with open(self.settings_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            # Corrupt or unreadable: treat as empty but never overwrite silently;
            # save() refuses to proceed (see _load_for_update).
            return {}
        return data if isinstance(data, dict) else {}

    def _resolve(self, saved: Mapping[str, Any], name: str, default: str = "") -> tuple[str, str]:
        value = saved.get(name)
        if isinstance(value, str) and value != "":
            return value, "saved"
        value = self._env.get(name, "")
        if value:
            return value, "environment"
        value = self._dotenv.get(name, "")
        if value:
            return value, ".env"
        return default, "default"

    def _max_tokens(self) -> int:
        raw = self._env.get("OPENAI_MAX_OUTPUT_TOKENS") or self._dotenv.get("OPENAI_MAX_OUTPUT_TOKENS", "")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return DEFAULT_MAX_OUTPUT_TOKENS
        return min(max(value, 64), 4000)

    def snapshot(self) -> ConfigSnapshot:
        with self._lock:
            saved = self._read_saved()
        okey, _ = self._resolve(saved, "OPENAI_API_KEY")
        akey, _ = self._resolve(saved, "AI_DEFENSE_API_KEY")
        model, _ = self._resolve(saved, "OPENAI_MODEL", DEFAULT_OPENAI_MODEL)
        judge, _ = self._resolve(saved, "JUDGE_MODEL", "")
        region, _ = self._resolve(saved, "AI_DEFENSE_REGION", DEFAULT_REGION)
        conn, _ = self._resolve(saved, "AI_DEFENSE_CONNECTION_NAME")
        try:
            model = validate_model(model)
        except ConfigError:
            model = DEFAULT_OPENAI_MODEL
        try:
            judge = validate_model(judge) if judge else model
        except ConfigError:
            judge = model
        try:
            region = validate_region(region)
        except ConfigError:
            region = DEFAULT_REGION
        return ConfigSnapshot(
            openai_api_key=okey.strip(),
            ai_defense_api_key=akey.strip(),
            openai_model=model,
            judge_model=judge,
            region=region,
            connection_name=conn,
            max_output_tokens=self._max_tokens(),
        )

    def public_view(self) -> dict[str, Any]:
        """Configuration safe to send to the browser: booleans and non-secret values only."""
        with self._lock:
            saved = self._read_saved()
        snap = self.snapshot()
        return {
            "openai_configured": snap.openai_configured,
            "ai_defense_configured": snap.ai_defense_configured,
            "openai_key_source": self._resolve(saved, "OPENAI_API_KEY")[1] if snap.openai_configured else None,
            "ai_defense_key_source": self._resolve(saved, "AI_DEFENSE_API_KEY")[1]
            if snap.ai_defense_configured
            else None,
            "openai_model": snap.openai_model,
            "judge_model": snap.judge_model,
            "judge_model_saved": self._resolve(saved, "JUDGE_MODEL")[0],
            "ai_defense_region": snap.region,
            "ai_defense_regions": sorted(AI_DEFENSE_REGION_HOSTS),
            "ai_defense_connection_name": snap.connection_name,
            "max_output_tokens": snap.max_output_tokens,
            "settings_saved": self.settings_path.exists(),
        }

    # ----------------------------------------------------------------- writing
    def _load_for_update(self) -> dict[str, Any]:
        if not self.settings_path.exists():
            return {}
        try:
            with open(self.settings_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ConfigError(
                "The saved settings file is unreadable; it was left untouched. "
                "Fix or remove it before saving again."
            ) from exc
        if not isinstance(data, dict):
            raise ConfigError("The saved settings file has an unexpected format; it was left untouched.")
        return data

    def save(self, updates: Mapping[str, str]) -> None:
        """Validate and persist updates. Blank secret values are ignored (keys preserved)."""
        clean: dict[str, str] = {}
        for name, value in updates.items():
            if name not in ALL_FIELDS:
                raise ConfigError("Unknown setting.")
            if name in SECRET_FIELDS:
                if value is None or (isinstance(value, str) and value.strip() == ""):
                    continue  # blank preserves the existing key
                label = "OpenAI API key" if name == "OPENAI_API_KEY" else "AI Defense API key"
                clean[name] = validate_key(value, label)
            elif name == "OPENAI_MODEL":
                clean[name] = validate_model(value)
            elif name == "JUDGE_MODEL":
                clean[name] = validate_model(value) if str(value).strip() else ""
            elif name == "AI_DEFENSE_REGION":
                clean[name] = validate_region(value)
            elif name == "AI_DEFENSE_CONNECTION_NAME":
                clean[name] = validate_connection_name(value)
        if not clean:
            return
        with self._lock:
            current = self._load_for_update()
            current.update(clean)  # preserves unrelated settings
            self._atomic_write(current)

    def _atomic_write(self, data: Mapping[str, Any]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=self.data_dir)
        try:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.settings_path)
            try:
                os.chmod(self.settings_path, 0o600)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
