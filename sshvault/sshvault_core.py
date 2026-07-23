"""Storage, validation, secret handling, and safe connection helpers for SSHVault.

This module deliberately has no Tk dependencies so its behavior can be tested
without a display or a live SSH server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, cast
from uuid import uuid4

SCHEMA_VERSION = 2
DEFAULT_PORT = 22
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SECRET_RE = re.compile(r"(?i)(password|passphrase|private[ _-]?key|token|secret)\s*([=:])\s*([^\s,;]+)")
_AUTHORIZATION_RE = re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.+?-----END [^-]*PRIVATE KEY-----", re.DOTALL)
_ALLOWED_FIELDS = {
    "id",
    "name",
    "host",
    "port",
    "user",
    "auth_method",
    "key_path",
    "proxy_jump",
    "tags",
    "notes",
    "startup_directory",
    "startup_command",
    "timeout",
    "compression",
    "password",
}
_SETTINGS_ALLOWED = {
    "scrollback_limit",
    "connection_timeout",
    "download_directory",
    "confirm_multiline_paste",
    "confirm_delete",
    "confirm_overwrite",
}
DEFAULT_SETTINGS = {
    "scrollback_limit": 5000,
    "connection_timeout": 15,
    "download_directory": "",
    "confirm_multiline_paste": True,
    "confirm_delete": True,
    "confirm_overwrite": True,
}


@dataclass
class MigrationReport:
    """Outcome of loading or migrating a profile vault for UI presentation."""

    migrated_profiles: int = 0
    skipped_profiles: int = 0
    secrets_moved: int = 0
    secrets_not_moved: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    backup_path: Path | None = None


class ProfileError(ValueError):
    """Raised when a profile cannot safely be stored or used."""


@dataclass
class ImportSummary:
    imported: int = 0
    renamed: int = 0
    replaced: int = 0
    skipped: int = 0
    failed: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class RestorePreview:
    """Secret-free restore validation information suitable for a UI preview."""

    schema_version: int
    profile_count: int
    valid_profiles: int = 0
    invalid_profiles: int = 0
    conflicts: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class RestoreSummary:
    restored: int = 0
    skipped: int = 0
    failed: int = 0
    backup_path: Path | None = None


@dataclass
class ImportPreviewRow:
    index: int
    profile: dict[str, Any] | None
    status: str
    error: str = ""
    decision: str = ""


def build_import_preview(raw_profiles: list[Any], existing: list[dict[str, Any]]) -> list[ImportPreviewRow]:
    rows = []
    for index, raw in enumerate(raw_profiles):
        if not isinstance(raw, dict) or any(
            any(word in str(k).casefold() for word in ("password", "passphrase", "token", "private"))
            for k in (raw if isinstance(raw, dict) else {})
        ):
            rows.append(ImportPreviewRow(index, None, "Invalid", "Secret or unsupported profile data."))
            continue
        try:
            profile = validate_profile(raw)
        except ProfileError as exc:
            rows.append(ImportPreviewRow(index, None, "Invalid", str(exc)))
            continue
        collision = any(
            p["name"].casefold() == profile["name"].casefold() or profile_identity(p) == profile_identity(profile)
            for p in existing
        )
        rows.append(
            ImportPreviewRow(
                index, profile, "Collision" if collision else "Ready", decision="" if collision else "import"
            )
        )
    return rows


def import_decisions_valid(rows: list[ImportPreviewRow], decisions: dict[int, str]) -> bool:
    return all(
        row.status != "Collision" or decisions.get(row.index, "skip") in {"skip", "rename", "replace"} for row in rows
    )


@dataclass
class ImportDecisionModel:
    rows: list[ImportPreviewRow]
    existing: list[dict[str, Any]]
    decisions: dict[int, str] = field(default_factory=dict)
    rename_names: dict[int, str] = field(default_factory=dict)
    replace_targets: dict[int, str] = field(default_factory=dict)

    def __post_init__(self):
        for row in self.rows:
            if row.status == "Collision":
                self.decisions.setdefault(row.index, "skip")

    def default_rename(self, row: ImportPreviewRow) -> str:
        base = (row.profile or {}).get("name", "Connection")
        name = f"{base} Imported"
        n = 2
        used = {p["name"].casefold() for p in self.existing}
        used.update(value.casefold() for key, value in self.rename_names.items() if key != row.index and value.strip())
        while name.casefold() in used:
            name = f"{base} Imported {n}"
            n += 1
        return name

    def collision_targets(self, row: ImportPreviewRow) -> list[dict[str, Any]]:
        """Return the existing profiles that conflict with one preview row."""
        if not row.profile:
            return []
        return [
            profile
            for profile in self.existing
            if profile["name"].casefold() == row.profile["name"].casefold()
            or profile_identity(profile) == profile_identity(row.profile)
        ]

    def errors(self) -> dict[int, str]:
        result = {}
        names = {p["name"].casefold() for p in self.existing}
        identities = {profile_identity(p) for p in self.existing}
        for row in self.rows:
            if row.status == "Invalid":
                continue
            action = self.decisions.get(row.index, "import" if row.status == "Ready" else "skip")
            if row.status == "Collision" and action == "skip":
                continue
            if row.status == "Collision" and action == "replace":
                targets = {profile.get("id", "") for profile in self.collision_targets(row)}
                if self.replace_targets.get(row.index) not in targets:
                    result[row.index] = "Choose the profile that will be replaced."
                continue
            if row.status == "Collision" and action != "rename":
                result[row.index] = "Choose Skip, Rename, or Replace."
                continue
            name = (
                self.rename_names.get(row.index, "").strip()
                if action == "rename"
                else (row.profile or {}).get("name", "")
            )
            if not name:
                result[row.index] = "Enter a unique name."
                continue
            if name.casefold() in names:
                result[row.index] = "Connection names must be unique."
                continue
            names.add(name.casefold())
            p = dict(row.profile or {}, name=name)
            if profile_identity(p) in identities:
                result[row.index] = "A connection with the same host, port, and username already exists."
            identities.add(profile_identity(p))
        return result

    def mapping(self) -> dict[int, str]:
        return {row.index: self.decisions.get(row.index, "import") for row in self.rows if row.status != "Invalid"}

    def to_import_mapping(self) -> dict[int, str]:
        return self.mapping()

    def rename_mapping(self) -> dict[int, str]:
        return {
            index: name.strip()
            for index, name in self.rename_names.items()
            if self.decisions.get(index) == "rename" and name.strip()
        }

    def replace_mapping(self) -> dict[int, str]:
        return {
            index: target for index, target in self.replace_targets.items() if self.decisions.get(index) == "replace"
        }

    def eligible_count(self) -> int:
        return sum(
            row.status == "Ready"
            or (row.status == "Collision" and self.decisions.get(row.index) in {"rename", "replace"})
            for row in self.rows
        )

    def summary(self) -> ImportSummary:
        s = ImportSummary()
        for row in self.rows:
            if row.status == "Invalid":
                s.failed += 1
            elif row.status == "Ready":
                s.imported += 1
            elif self.decisions.get(row.index) == "rename":
                s.renamed += 1
            elif self.decisions.get(row.index) == "replace":
                s.replaced += 1
            else:
                s.skipped += 1
        return s


def validate_settings(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProfileError("Unsupported settings data.")
    if any(
        any(word in str(key).casefold() for word in ("password", "passphrase", "token", "secret", "private"))
        for key in raw
    ):
        raise ProfileError("Settings cannot contain credentials or secrets.")
    try:
        scrollback = int(raw.get("scrollback_limit", 5000))
        timeout = int(raw.get("connection_timeout", 15))
    except (TypeError, ValueError) as exc:
        raise ProfileError("Scrollback and timeout must be whole numbers.") from exc
    if not 100 <= scrollback <= 100000 or not 1 <= timeout <= 120:
        raise ProfileError("Settings values are outside the supported range.")
    result = {key: value for key, value in raw.items() if key not in _SETTINGS_ALLOWED}
    result.update(
        {
            "scrollback_limit": scrollback,
            "connection_timeout": timeout,
            "download_directory": str(raw.get("download_directory", "")).strip(),
            "confirm_multiline_paste": bool(raw.get("confirm_multiline_paste", True)),
            "confirm_delete": bool(raw.get("confirm_delete", True)),
            "confirm_overwrite": bool(raw.get("confirm_overwrite", True)),
            "theme": AppearanceState.normalize_theme(raw.get("theme", "system")),
            "application_font_size": AppearanceState.clamp_application_font(raw.get("application_font_size", 10)),
            "terminal_font_size": AppearanceState.clamp_terminal_font(raw.get("terminal_font_size", 10)),
        }
    )
    return result


@dataclass(frozen=True)
class AppearanceState:
    """UI-independent appearance preferences with bounded font sizes."""

    theme: str = "system"
    application_font_size: int = 10
    terminal_font_size: int = 10

    @staticmethod
    def normalize_theme(value: object) -> str:
        value = str(value).casefold()
        return value if value in {"system", "light", "dark"} else "system"

    @staticmethod
    def clamp_application_font(value: object) -> int:
        try:
            return max(8, min(24, int(str(value))))
        except (TypeError, ValueError):
            return 10

    @staticmethod
    def clamp_terminal_font(value: object) -> int:
        try:
            return max(8, min(32, int(str(value))))
        except (TypeError, ValueError):
            return 10

    @classmethod
    def from_settings(cls, settings: dict[str, Any] | None) -> "AppearanceState":
        settings = settings if isinstance(settings, dict) else {}
        return cls(
            cls.normalize_theme(settings.get("theme", "system")),
            cls.clamp_application_font(settings.get("application_font_size", 10)),
            cls.clamp_terminal_font(settings.get("terminal_font_size", 10)),
        )

    def to_settings(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "application_font_size": self.application_font_size,
            "terminal_font_size": self.terminal_font_size,
        }

    def palette(self) -> dict[str, str]:
        """Return semantic colors shared by the Tk theme controller."""
        if self.theme == "dark":
            return {
                "background": "#1e1e2e",
                "panel": "#2a2a3e",
                "foreground": "#cdd6f4",
                "muted": "#9399b2",
                "accent": "#89b4fa",
                "error": "#f38ba8",
                "terminal_background": "#11111b",
                "terminal_foreground": "#cdd6f4",
            }
        return {
            "background": "#f5f6f8",
            "panel": "#ffffff",
            "foreground": "#202124",
            "muted": "#5f6368",
            "accent": "#356ac3",
            "error": "#b3261e",
            "terminal_background": "#202124",
            "terminal_foreground": "#f1f3f4",
        }


def confirm_multiline_paste_enabled(settings: dict[str, Any] | None) -> bool:
    """Return the safe default when settings are absent or malformed."""
    if not isinstance(settings, dict) or not isinstance(settings.get("confirm_multiline_paste", True), bool):
        return True
    return cast(bool, settings["confirm_multiline_paste"])


def confirm_delete_enabled(settings: dict[str, Any] | None) -> bool:
    if not isinstance(settings, dict) or not isinstance(settings.get("confirm_delete", True), bool):
        return True
    return cast(bool, settings["confirm_delete"])


def confirm_overwrite_enabled(settings: dict[str, Any] | None) -> bool:
    if not isinstance(settings, dict) or not isinstance(settings.get("confirm_overwrite", True), bool):
        return True
    return cast(bool, settings["confirm_overwrite"])


def atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


@dataclass
class ProfileFormState:
    """UI-independent state for the connection editor.

    Passwords and passphrases are deliberately separate from ``profile`` so a
    caller cannot accidentally hand a secret to :class:`ProfileStore`.
    """

    profile: dict[str, Any] = field(default_factory=dict)
    password: str = ""
    passphrase: str = ""
    remove_password: bool = False

    def auth_field_visibility(self) -> dict[str, bool]:
        method = str(self.profile.get("auth_method", "agent")).lower()
        return {
            "password": method == "password",
            "key_path": method == "key",
            "passphrase": method == "key",
        }

    def clean_profile(self, *, check_key_exists: bool = True) -> dict[str, Any]:
        safe = {key: value for key, value in self.profile.items() if key not in {"password", "passphrase"}}
        return validate_profile(safe, check_key_exists=check_key_exists)

    def validation_error(self, *, check_key_exists: bool = True) -> str | None:
        try:
            self.clean_profile(check_key_exists=check_key_exists)
        except ProfileError as exc:
            return str(exc)
        return None

    @property
    def can_save(self) -> bool:
        return self.validation_error() is None


@dataclass
class ProfileSidebarState:
    """Display-free search, sort, selection, and action state for profiles."""

    profiles: list[dict[str, Any]] = field(default_factory=list)
    query: str = ""
    sort_by: str = "Name"
    selected_id: str | None = None

    def _matches(self, profile: dict[str, Any]) -> bool:
        needle = self.query.strip().casefold()
        if not needle:
            return True
        tags = profile.get("tags", [])
        tag_text = " ".join(tags) if isinstance(tags, list) else str(tags)
        haystack = " ".join(str(profile.get(key, "")) for key in ("name", "host", "user", "notes"))
        return needle in f"{haystack} {tag_text}".casefold()

    def visible_profiles(self) -> list[dict[str, Any]]:
        result = [profile for profile in self.profiles if self._matches(profile)]
        keys = {"Name": "name", "Hostname": "host", "Username": "user"}
        key = keys.get(self.sort_by, "name")
        return sorted(result, key=lambda profile: str(profile.get(key, "")).casefold())

    def selected_profile(self) -> dict[str, Any] | None:
        return next((profile for profile in self.profiles if profile.get("id") == self.selected_id), None)

    def action_enabled(self) -> dict[str, bool]:
        selected = self.selected_profile() is not None
        return {action: selected for action in ("connect", "edit", "duplicate", "delete", "export")}

    def empty_state(self) -> str:
        if not self.profiles:
            return "No saved profiles yet. Add a profile to begin."
        if not self.visible_profiles():
            return "No profiles match your search."
        return ""

    def duplicate_name(self, profile: dict[str, Any]) -> str:
        base = f"{str(profile.get('name') or profile.get('host') or 'Connection').strip()} Copy"
        names = {str(item.get("name", "")).casefold() for item in self.profiles}
        candidate, suffix = base, 2
        while candidate.casefold() in names:
            candidate = f"{base} {suffix}"
            suffix += 1
        return candidate

    def selected_differs_from(self, connected_profile: dict[str, Any] | None) -> bool:
        selected = self.selected_profile()
        return bool(selected and connected_profile and selected.get("id") != connected_profile.get("id"))


def application_shortcut_allowed(widget_class: str) -> bool:
    """Avoid stealing keystrokes from terminal and ordinary text input."""
    return widget_class not in {"Entry", "Text", "TEntry", "TCombobox", "TerminalWidget"}


@dataclass
class TunnelFormState:
    """UI-free tunnel validation and lifecycle state; never owns an SSH client."""

    kind: str = "Local"
    bind_host: str = "127.0.0.1"
    bind_port: object = 0
    destination_host: str = ""
    destination_port: object = ""
    status: str = "stopped"
    generation: int = 0

    def validate(self) -> str | None:
        if self.kind not in {"Local", "Remote", "Dynamic/SOCKS"}:
            return "Choose a tunnel type."
        try:
            validate_host(self.bind_host)
            validate_port(self.bind_port)
        except ProfileError as exc:
            return str(exc)
        if self.kind != "Dynamic/SOCKS":
            try:
                validate_host(self.destination_host)
                validate_port(self.destination_port)
            except ProfileError:
                return "Enter a valid destination host and port."
        return None

    @property
    def start_enabled(self) -> bool:
        return self.status == "stopped" and self.validate() is None

    @property
    def public_bind_warning(self) -> bool:
        return (
            self.bind_host.strip() in {"0.0.0.0", "::"}
            or not self.bind_host.strip().startswith("127.")
            and self.bind_host.strip() != "::1"
        )

    def endpoint(self) -> str:
        host = self.bind_host.strip()
        return f"[{host}]:{self.bind_port}" if ":" in host and not host.startswith("[") else f"{host}:{self.bind_port}"

    def transition(self, status: str, generation: int | None = None) -> bool:
        if generation is not None and generation != self.generation:
            return False
        allowed = {
            "stopped": {"starting"},
            "starting": {"active", "failed", "stopping"},
            "active": {"stopping", "connection lost", "failed"},
            "stopping": {"stopped"},
            "failed": {"stopped", "starting"},
            "connection lost": {"stopped"},
        }
        if status not in allowed.get(self.status, set()):
            return False
        self.status = status
        return True

    def visible_fields(self) -> dict[str, bool]:
        return {"bind": True, "destination": self.kind != "Dynamic/SOCKS"}


@dataclass
class TunnelRuntime:
    """Owns a tunnel listener/thread; stopping is bounded and idempotent."""

    listener: Any = None
    thread: Any = None
    stop_event: Any = field(default_factory=lambda: __import__("threading").Event())
    generation: int = 0
    closed: bool = False
    bytes_transferred: int | None = 0

    def stop(self, timeout: float = 0.25) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop_event.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except Exception:
                pass
        if self.thread is not None and getattr(self.thread, "is_alive", lambda: False)():
            self.thread.join(timeout)

    def accepts(self, generation: int) -> bool:
        return not self.closed and generation == self.generation

    def add_bytes(self, count: int | None) -> None:
        if count is None or self.bytes_transferred is None:
            self.bytes_transferred = None
        else:
            self.bytes_transferred += max(0, count)


@dataclass
class CommandExecutionState:
    """UI-free verified-client command lifecycle with stale-output rejection."""

    status: str = "idle"
    generation: int = 0

    def start(self) -> int | None:
        if self.status in {"running", "cancelling"}:
            return None
        self.generation += 1
        self.status = "running"
        return self.generation

    def accepts(self, generation: int) -> bool:
        return generation == self.generation and self.status in {"running", "cancelling"}

    def cancel(self, generation: int) -> bool:
        if not self.accepts(generation):
            return False
        self.status = "cancelling"
        return True

    def finish(self, generation: int, *, failed: bool = False, lost: bool = False) -> bool:
        if generation != self.generation:
            return False
        self.status = "connection lost" if lost else "failed" if failed else "completed"
        return True


@dataclass
class WorkspaceChromeState:
    """Display-free state machine for a connection workspace header."""

    status: str = "disconnected"
    message: str = "Disconnected. Connect to open terminal and tools."
    selected_tab: str = "Terminal"

    def transition(self, status: str, message: str = "") -> None:
        allowed = {
            "disconnected": {"connecting"},
            "connecting": {"connected", "failed", "disconnected", "disconnecting"},
            "connected": {"disconnecting", "failed"},
            "disconnecting": {"disconnected", "failed"},
            "failed": {"connecting", "disconnecting", "disconnected"},
        }
        if status not in allowed.get(self.status, set()):
            raise ValueError(f"Invalid workspace status transition: {self.status} -> {status}")
        self.status = status
        defaults = {
            "disconnected": "Disconnected. Connect to open terminal and tools.",
            "connecting": "Connecting securely…",
            "connected": "Connected.",
            "disconnecting": "Disconnecting…",
            "failed": "Connection failed. Check the profile and try again.",
        }
        self.message = redact_secrets(message or defaults[status])  # type: ignore[assignment]

    @property
    def connect_button(self) -> tuple[str, bool]:
        if self.status == "connecting" or self.status == "disconnecting":
            return ("Connecting…" if self.status == "connecting" else "Disconnecting…", False)
        return ("Disconnect", True) if self.status == "connected" else ("Connect", True)

    @property
    def connection_tools_enabled(self) -> bool:
        return self.status == "connected"


@dataclass(frozen=True)
class ConnectionLogEvent:
    """A safe, user-visible session event; secrets are always redacted."""

    message: str
    level: str = "info"

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", redact_secrets(str(self.message)))


@dataclass
class SessionDashboardState:
    """Display-free session dashboard data and bounded safe event history."""

    profile_name: str = ""
    host: str = ""
    port: int = 22
    username: str = ""
    auth_method: str = ""
    status: str = "disconnected"
    negotiated: dict[str, str] = field(default_factory=dict)
    events: list[ConnectionLogEvent] = field(default_factory=list)
    max_events: int = 200

    @property
    def identity(self) -> str:
        suffix = f":{self.port}" if self.port != 22 else ""
        return f"{self.username}@{self.host}{suffix}" if self.username else f"{self.host}{suffix}"

    def add_event(self, message: str, level: str = "info") -> None:
        self.events.append(ConnectionLogEvent(message, level))
        del self.events[: -self.max_events]

    def transition(self, status: str, event: str | None = None) -> None:
        self.status = status
        if event:
            self.add_event(event)


@dataclass
class SFTPPanelState:
    """Display-free state for safe two-pane SFTP presentation."""

    local_state: str = "loading"
    remote_state: str = "loading"
    transfer_state: str = "idle"
    transfer_name: str = ""
    transferred: int = 0
    total: int = 0
    message: str = ""
    started_at: float | None = None

    @staticmethod
    def format_size(value: int) -> str:
        size: float = float(max(0, int(value)))
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def folder_first(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(items, key=lambda item: (not bool(item.get("is_dir")), str(item.get("name", "")).casefold()))

    def progress(self, transferred: int, total: int, *, now: float | None = None) -> float:
        self.transferred, self.total = max(0, transferred), max(0, total)
        return (self.transferred / self.total * 100) if self.total else 0.0

    def start_transfer(self, name: str, *, now: float | None = None) -> None:
        self.transfer_state, self.transfer_name, self.message = "active", name, ""
        self.started_at = now

    def speed(self, *, now: float | None = None) -> float | None:
        if self.started_at is None or now is None or now <= self.started_at:
            return None
        return self.transferred / (now - self.started_at)

    def progress_text(self, *, now: float | None = None) -> str:
        total = self.format_size(self.total) if self.total else "unknown size"
        pct = f" ({self.transferred / self.total * 100:.0f}%)" if self.total else ""
        speed = self.speed(now=now)
        suffix = f" · {self.format_size(int(speed))}/s" if speed is not None else ""
        return f"{self.format_size(self.transferred)} / {total}{pct}{suffix}"

    def cancel(self) -> None:
        if self.transfer_state == "active":
            self.transfer_state, self.message = "cancelled", "Transfer cancelled. Partial data was kept safely."

    def fail(self, error: object) -> None:
        self.transfer_state, self.message = "failed", str(redact_secrets(error))

    def complete(self) -> None:
        self.transfer_state, self.message = "complete", "Transfer complete."

    def action_enabled(self, *, local_selected: bool, remote_selected: bool) -> dict[str, bool]:
        return {
            "upload": local_selected and self.transfer_state != "active",
            "download": remote_selected and self.transfer_state != "active",
            "cancel": self.transfer_state == "active",
        }


@dataclass
class DirectoryLoadState:
    """Generation-based stale-result suppression for an asynchronous pane."""

    generation: int = 0
    pending: bool = False
    closed: bool = False
    state: str = "idle"

    def request(self) -> int:
        if self.closed:
            return self.generation
        self.generation += 1
        self.state = "loading"
        if not self.pending:
            self.pending = True
        return self.generation

    def accepts(self, generation: int) -> bool:
        return not self.closed and generation == self.generation

    def finish(self, generation: int, *, success: bool) -> bool:
        self.pending = False
        if not self.accepts(generation):
            return False
        self.state = "ready" if success else "error"
        return True

    def close(self) -> None:
        self.closed = True
        self.pending = False

    def invalidate(self) -> None:
        """Invalidate in-flight work while keeping the pane reusable."""
        if self.closed:
            return
        self.generation += 1
        self.pending = False
        self.state = "idle"


@dataclass
class TerminalPanelState:
    """UI-free terminal lifecycle, scrollback, search, and paste policy."""

    status: str = "disconnected"
    generation: int = 0
    max_scrollback_lines: int = 5000
    follow_output: bool = True

    def begin(self, *, reconnecting: bool = False) -> int:
        self.generation += 1
        self.status = "reconnecting" if reconnecting else "connecting"
        return self.generation

    def connected(self, generation: int) -> bool:
        if generation != self.generation:
            return False
        self.status = "connected"
        return True

    def ended(self, generation: int, *, lost: bool = False) -> bool:
        if generation != self.generation:
            return False
        self.status = "connection lost" if lost else "session ended"
        return True

    def accepts_output(self, generation: int) -> bool:
        return generation == self.generation and self.status in {"connecting", "reconnecting", "connected"}

    def trim_scrollback(self, lines: list[str]) -> list[str]:
        return lines[-max(0, self.max_scrollback_lines) :]

    @staticmethod
    def requires_paste_confirmation(text: str) -> bool:
        return "\n" in text or "\r" in text

    @staticmethod
    def terminal_size(width: int, height: int, char_width: int, char_height: int) -> tuple[int, int]:
        return max(20, (max(0, width) - 8) // max(1, char_width)), max(5, (max(0, height) - 4) // max(1, char_height))


def redact_secrets(value: object) -> object:
    """Redact secrets recursively while retaining safe diagnostic fields.

    Mappings, lists, and tuples retain their shape; scalar inputs return text.
    """
    if isinstance(value, BaseException):
        return redact_secrets(str(value))
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(
                word in str(key).lower()
                for word in ("password", "passphrase", "token", "secret", "private_key", "authorization")
            )
            else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    text = str(value)
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", text)
    return _SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)} [REDACTED]", text)


def validate_host(host: str) -> str:
    host = host.strip()
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise ProfileError("Enter a hostname or IP address without spaces.")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not _HOST_RE.fullmatch(host) or ".." in host:
            raise ProfileError("Enter a valid hostname or IP address.")
    return host


def validate_port(value: object) -> int:
    if isinstance(value, (bool, float)):
        raise ProfileError("Port must be a whole number between 1 and 65535.")
    try:
        port = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ProfileError("Port must be a number between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise ProfileError("Port must be between 1 and 65535.")
    return port


def validate_profile(raw: dict[str, Any], *, check_key_exists: bool = True) -> dict[str, Any]:
    """Normalize and validate a profile without retaining plaintext secrets."""
    if not isinstance(raw, dict):
        raise ProfileError("Profile data must be an object.")
    unknown = set(raw) - _ALLOWED_FIELDS
    if unknown:
        raise ProfileError(f"Unsupported profile field(s): {', '.join(sorted(unknown))}.")
    host = validate_host(str(raw.get("host", "")))
    user = str(raw.get("user", "")).strip()
    if not user or any(char.isspace() for char in user) or len(user) > 128:
        raise ProfileError("Username is required and cannot contain spaces.")
    auth_method = str(raw.get("auth_method", "key" if raw.get("key_path") else "agent")).lower()
    if auth_method not in {"agent", "key", "password"}:
        raise ProfileError("Choose SSH agent, key file, or password authentication.")
    key_path = str(raw.get("key_path", "")).strip()
    if auth_method == "key":
        if not key_path:
            raise ProfileError("Choose an SSH private key file for key authentication.")
        expanded_key = Path(key_path).expanduser()
        if check_key_exists and not expanded_key.is_file():
            raise ProfileError("The selected SSH private key file does not exist.")
        key_path = str(expanded_key)
    tags = raw.get("tags", [])
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.split(",") if item.strip()]
    if not isinstance(tags, list):
        raise ProfileError("Tags must be a comma-separated list.")
    timeout = raw.get("timeout", 15)
    if isinstance(timeout, bool):
        raise ProfileError("Timeout must be a number between 1 and 120 seconds.")
    try:
        timeout = int(timeout)
    except (TypeError, ValueError) as exc:
        raise ProfileError("Timeout must be a number between 1 and 120 seconds.") from exc
    if not 1 <= timeout <= 120:
        raise ProfileError("Timeout must be between 1 and 120 seconds.")
    compression = raw.get("compression", False)
    if not isinstance(compression, bool):
        raise ProfileError("Compression must be enabled or disabled.")
    return {
        "id": str(raw.get("id") or uuid4()),
        "name": str(raw.get("name", "")).strip() or host,
        "host": host,
        "port": validate_port(raw.get("port", DEFAULT_PORT)),
        "user": user,
        "auth_method": auth_method,
        "key_path": key_path,
        "proxy_jump": str(raw.get("proxy_jump", "")).strip(),
        "tags": list(dict.fromkeys(str(item).strip() for item in tags if str(item).strip())),
        # Notes are free-form user content. Unlike connection parameters,
        # their whitespace can be meaningful and is preserved verbatim.
        "notes": str(raw.get("notes", "")),
        "startup_directory": str(raw.get("startup_directory", "")).strip(),
        "startup_command": str(raw.get("startup_command", "")).strip(),
        "timeout": timeout,
        "compression": compression,
    }


def profile_identity(profile: dict[str, Any]) -> tuple[str, int, str]:
    return (str(profile["host"]).lower(), int(profile["port"]), str(profile["user"]).lower())


def connection_kwargs(profile: dict[str, Any], password: str | None = None) -> dict[str, Any]:
    """Build Paramiko-safe connection keywords; no shell command is involved."""
    result: dict[str, Any] = {
        "hostname": profile["host"],
        "port": profile["port"],
        "username": profile["user"],
        "timeout": profile.get("timeout", 15),
        "compress": profile.get("compression", False),
        "allow_agent": profile.get("auth_method") == "agent",
        "look_for_keys": True,
    }
    if profile.get("auth_method") == "key":
        result["key_filename"] = profile["key_path"]
    elif profile.get("auth_method") == "password":
        if not password:
            raise ProfileError("No password is available in the system credential store.")
        result["password"] = password
        result["allow_agent"] = False
        result["look_for_keys"] = False
    return result


def friendly_connection_error(error: BaseException) -> str:
    """Translate common transport errors into actionable, non-secret UI text."""
    message = str(error).lower()
    if isinstance(error, TimeoutError) or "timed out" in message:
        return "The server did not respond. Check the hostname, port, VPN, or network connection."
    if "authentication" in message or "auth fail" in message:
        return "Authentication was rejected. Check the username and selected authentication method."
    if "host key" in message or "known_hosts" in message:
        return "The server identity could not be verified. Review its host-key warning before reconnecting."
    if "refused" in message:
        return "The server refused the connection. Confirm that SSH is running and the port is correct."
    if "not known" in message or "name or service" in message:
        return "The hostname could not be found. Check its spelling or DNS/VPN connection."
    return "Could not connect. Open the activity log for redacted technical details."


_DEFAULT_BACKEND = object()


class SecretStore:
    """Adapter for the OS credential store. It never falls back to a file."""

    SERVICE = "sshvault"

    def __init__(self, backend: Any = _DEFAULT_BACKEND) -> None:
        if backend is _DEFAULT_BACKEND:
            try:
                import keyring
            except ImportError:
                keyring_module: Any = None
            else:
                keyring_module = keyring
            backend = keyring_module
        self._keyring = backend

    @property
    def available(self) -> bool:
        return self._keyring is not None

    def get(self, profile_id: str) -> str | None:
        if not self._keyring:
            return None
        try:
            return cast(str | None, self._keyring.get_password(self.SERVICE, profile_id))
        except Exception as exc:
            raise ProfileError("The system credential store could not be read.") from exc

    def set(self, profile_id: str, secret: str) -> None:
        if not self._keyring:
            raise ProfileError("Password storage needs the optional 'keyring' package and a system credential store.")
        try:
            self._keyring.set_password(self.SERVICE, profile_id, secret)
        except Exception as exc:
            raise ProfileError("The system credential store could not save this password.") from exc

    def delete(self, profile_id: str) -> None:
        if self._keyring:
            try:
                self._keyring.delete_password(self.SERVICE, profile_id)
            except Exception:
                # A missing credential is harmless; a failed cleanup is never
                # escalated into writing the secret into a local file.
                pass


class ProfileStore:
    """Versioned JSON profile store with atomic writes and migration backups."""

    def __init__(self, path: Path, secret_store: SecretStore | None = None) -> None:
        self.path = path
        self.secret_store = secret_store or SecretStore()
        self.entries: list[dict[str, Any]] = []
        self.migration_notice = ""
        self.migration_report = MigrationReport()
        self._prepare_directory()
        self.load()

    def _prepare_directory(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass

    def _backup(self, reason: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = self.path.with_name(f"{self.path.stem}.{reason}.{stamp}.json")
        suffix = 1
        while target.exists():
            target = self.path.with_name(f"{self.path.stem}.{reason}.{stamp}-{suffix}.json")
            suffix += 1
        shutil.copy2(self.path, target)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return target

    def create_backup(self, reason: str = "backup") -> tuple[Path, int]:
        """Create a unique, versioned, credential-free backup of this vault."""
        backup_dir = self.path.parent / "backups"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = backup_dir / f"{self.path.stem}.{reason}.{stamp}.json"
        suffix = 1
        while target.exists():
            target = backup_dir / f"{self.path.stem}.{reason}.{stamp}-{suffix}.json"
            suffix += 1
        return target, self.export(target)

    @staticmethod
    def _restore_data(source: Path) -> tuple[int, list[Any]]:
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError("Could not read the selected backup file.") from exc
        if (
            not isinstance(data, dict)
            or data.get("version") != SCHEMA_VERSION
            or not isinstance(data.get("profiles"), list)
        ):
            raise ProfileError("Backups must use the current versioned profile format.")
        profiles = data["profiles"]
        for raw in profiles:
            if not isinstance(raw, dict) or any(
                any(word in str(key).casefold() for word in ("password", "passphrase", "token", "secret", "private"))
                for key in raw
            ):
                raise ProfileError("Backups containing credentials or unsupported profile data cannot be restored.")
        return SCHEMA_VERSION, profiles

    def preview_restore(self, source: Path) -> RestorePreview:
        """Validate a backup without changing this store or its credential store."""
        version, raw_profiles = self._restore_data(source)
        preview = RestorePreview(schema_version=version, profile_count=len(raw_profiles))
        names: set[str] = set()
        identities: set[tuple[str, int, str]] = set()
        for position, raw in enumerate(raw_profiles, start=1):
            try:
                profile = validate_profile(raw, check_key_exists=False)
            except ProfileError as exc:
                preview.invalid_profiles += 1
                preview.errors.append(f"Profile {position}: {exc}")
                continue
            identity = profile_identity(profile)
            if profile["name"].casefold() in names or identity in identities:
                preview.conflicts += 1
                preview.errors.append(f"Profile {position}: duplicates another profile in the backup.")
                continue
            names.add(profile["name"].casefold())
            identities.add(identity)
            preview.valid_profiles += 1
        return preview

    def restore_backup(self, source: Path) -> RestoreSummary:
        """Atomically replace profiles from a validated backup after taking a backup."""
        self._restore_data(source)  # Reject malformed, future, and secret-bearing files first.
        preview = self.preview_restore(source)
        _, raw_profiles = self._restore_data(source)
        candidates: list[dict[str, Any]] = []
        names: set[str] = set()
        identities: set[tuple[str, int, str]] = set()
        summary = RestoreSummary(skipped=preview.conflicts, failed=preview.invalid_profiles)
        for raw in raw_profiles:
            try:
                profile = validate_profile(raw, check_key_exists=False)
            except ProfileError:
                continue
            identity = profile_identity(profile)
            if profile["name"].casefold() in names or identity in identities:
                continue
            names.add(profile["name"].casefold())
            identities.add(identity)
            candidates.append(profile)
        # Do this after full validation, but before replacing the current vault.
        summary.backup_path, _ = self.create_backup("pre-restore")
        old_entries = self.entries
        self.entries = candidates
        try:
            self.save()
        except Exception:
            self.entries = old_entries
            raise
        old_ids = {str(profile.get("id", "")) for profile in old_entries}
        restored_ids = {str(profile.get("id", "")) for profile in candidates}
        for profile_id in old_ids | restored_ids:
            if profile_id:
                self.secret_store.delete(profile_id)
        summary.restored = len(candidates)
        return summary

    def load(self) -> None:
        if not self.path.exists():
            self.entries = []
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            backup = self._backup("corrupt")
            raise ProfileError(f"Could not read saved connections. A copy was preserved at {backup}.") from exc
        if isinstance(data, dict):
            try:
                version = int(data.get("version", SCHEMA_VERSION))
            except (TypeError, ValueError) as exc:
                raise ProfileError("Saved connections have an invalid schema version and were not changed.") from exc
            if version > SCHEMA_VERSION:
                raise ProfileError("This vault was created by a newer SSHVault version and was not changed.")
        raw_entries = data.get("profiles", []) if isinstance(data, dict) else data
        if not isinstance(raw_entries, list):
            raise ProfileError("Saved connections have an unsupported format.")
        migrated = isinstance(data, list) or (isinstance(data, dict) and data.get("version") != SCHEMA_VERSION)
        report = MigrationReport()
        entries: list[dict[str, Any]] = []
        for record_number, raw in enumerate(raw_entries, start=1):
            if not isinstance(raw, dict):
                report.skipped_profiles += 1
                report.warnings.append(
                    f"Profile {record_number} is not an object and was skipped; it remains in the backup."
                )
                migrated = True
                continue
            raw = dict(raw)
            legacy_password = str(raw.pop("password", ""))
            try:
                profile = validate_profile(raw, check_key_exists=False)
            except ProfileError as exc:
                report.skipped_profiles += 1
                report.warnings.append(f"Profile {record_number} was skipped: {exc}")
                migrated = True
                continue
            if legacy_password:
                if self.secret_store.available:
                    self.secret_store.set(profile["id"], legacy_password)
                    profile["auth_method"] = "password" if not profile.get("key_path") else profile["auth_method"]
                    report.secrets_moved += 1
                else:
                    report.secrets_not_moved += 1
                migrated = True
            entries.append(profile)
        self.entries = entries
        report.migrated_profiles = len(entries) if migrated else 0
        if migrated:
            backup = self._backup("pre-migration")
            self.save()
            report.backup_path = backup
            self.migration_notice = f"Saved connections were safely migrated. Backup: {backup.name}"
            if report.secrets_not_moved:
                self.migration_notice += (
                    f" {report.secrets_not_moved} password(s) could not be moved because the system credential store is unavailable; "
                    "they remain only in the backup for manual recovery."
                )
                report.warnings.append(self.migration_notice)
        self.migration_report = report

    def save(self) -> None:
        payload = json.dumps({"version": SCHEMA_VERSION, "profiles": self.entries}, indent=2, ensure_ascii=False) + "\n"
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _assert_unique(self, profile: dict[str, Any], except_id: str | None = None) -> None:
        identity = profile_identity(profile)
        if any(profile_identity(item) == identity and item["id"] != except_id for item in self.entries):
            raise ProfileError("A connection with the same host, port, and username already exists.")
        name = profile["name"].casefold()
        if any(item["name"].casefold() == name and item["id"] != except_id for item in self.entries):
            raise ProfileError("Connection names must be unique (case-insensitive).")

    def add(self, raw: dict[str, Any], password: str = "") -> dict[str, Any]:
        profile = validate_profile(raw)
        self._assert_unique(profile)
        try:
            if password:
                self.secret_store.set(profile["id"], password)
            self.entries.append(profile)
            self.save()
        except Exception:
            if self.entries and self.entries[-1] is profile:
                self.entries.pop()
            if password:
                self.secret_store.delete(profile["id"])
            raise
        return profile

    def update(
        self,
        index: int,
        raw: dict[str, Any],
        password: str | None = None,
        *,
        remove_password: bool = False,
    ) -> dict[str, Any]:
        old = self.entries[index]
        raw = dict(raw, id=old["id"])
        profile = validate_profile(raw)
        self._assert_unique(profile, old["id"])
        old_secret = self.secret_store.get(profile["id"])
        try:
            if password:
                self.secret_store.set(profile["id"], password)
            self.entries[index] = profile
            self.save()
        except Exception:
            self.entries[index] = old
            if password:
                if old_secret:
                    self.secret_store.set(profile["id"], old_secret)
                else:
                    self.secret_store.delete(profile["id"])
            raise
        if remove_password:
            self.secret_store.delete(profile["id"])
        return profile

    def delete(self, index: int) -> None:
        profile = self.entries.pop(index)
        self.secret_store.delete(profile["id"])
        self.save()

    def export(
        self, destination: Path, profiles: list[dict[str, Any]] | None = None, *, overwrite: bool = False
    ) -> int:
        """Atomically write a versioned, credential-free profile export.

        The conservative default rejects an existing target.  Callers that
        obtained explicit user approval may opt into an atomic replacement.
        """
        if destination.exists() and not overwrite:
            raise ProfileError("Export target already exists; choose a new filename.")
        source = self.entries if profiles is None else profiles
        safe_profiles = [
            validate_profile(
                {
                    key: value
                    for key, value in dict(profile).items()
                    if not any(
                        word in str(key).casefold() for word in ("password", "passphrase", "token", "secret", "private")
                    )
                },
                check_key_exists=False,
            )
            for profile in source
        ]
        atomic_json_write(destination, {"version": SCHEMA_VERSION, "profiles": safe_profiles})
        return len(safe_profiles)

    def import_profiles(
        self,
        source: Path,
        decisions: dict[int, str] | None = None,
        rename_names: dict[int, str] | None = None,
        replace_targets: dict[int, str] | None = None,
    ) -> ImportSummary:
        """Apply a versioned, secret-free import atomically after validation."""
        decisions = decisions or {}
        rename_names = rename_names or {}
        replace_targets = replace_targets or {}
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError("Could not read the import file.") from exc
        if (
            not isinstance(data, dict)
            or data.get("version") != SCHEMA_VERSION
            or not isinstance(data.get("profiles"), list)
        ):
            raise ProfileError("Import files must use the current versioned profile format.")
        candidate = [dict(item) for item in self.entries]
        summary = ImportSummary()
        replacing = False
        for index, raw in enumerate(data["profiles"]):
            if not isinstance(raw, dict) or any(
                any(word in str(k).casefold() for word in ("password", "passphrase", "token", "private")) for k in raw
            ):
                summary.failed += 1
                summary.warnings.append(f"Profile {index + 1} contains unsupported or secret data.")
                continue
            try:
                profile = validate_profile(raw)
            except ProfileError as exc:
                summary.failed += 1
                summary.warnings.append(f"Profile {index + 1}: {exc}")
                continue
            name_matches = [i for i, p in enumerate(candidate) if p["name"].casefold() == profile["name"].casefold()]
            identity_matches = [i for i, p in enumerate(candidate) if profile_identity(p) == profile_identity(profile)]
            matches = name_matches or identity_matches
            action = decisions.get(index, "skip") if matches else "import"
            if action == "skip":
                summary.skipped += 1
                continue
            if action == "rename":
                requested = rename_names.get(index, "").strip()
                if requested:
                    profile = validate_profile(dict(profile, name=requested))
                    if any(p["name"].casefold() == profile["name"].casefold() for p in candidate):
                        raise ProfileError("An imported renamed profile conflicts with an existing name.")
                    if any(profile_identity(p) == profile_identity(profile) for p in candidate):
                        raise ProfileError("An imported renamed profile conflicts with an existing connection.")
                else:
                    base = profile["name"]
                    n = 2
                    while any(p["name"].casefold() == profile["name"].casefold() for p in candidate):
                        profile["name"] = f"{base} {n}"
                        n += 1
                candidate.append(profile)
                summary.renamed += 1
                continue
            if action == "replace" and matches:
                requested_target = replace_targets.get(index)
                if requested_target:
                    target_index = next(
                        (i for i, item in enumerate(candidate) if item.get("id") == requested_target), None
                    )
                    if target_index is None or target_index not in matches:
                        raise ProfileError("The requested replacement target is no longer valid.")
                else:
                    target_index = matches[0]
                candidate[target_index] = dict(profile, id=candidate[target_index]["id"])
                summary.replaced += 1
                replacing = True
                continue
            if action == "import":
                candidate.append(profile)
                summary.imported += 1
                continue
            summary.skipped += 1
        if replacing:
            self._backup("pre-import")
        old = self.entries
        self.entries = candidate
        try:
            self.save()
        except Exception:
            self.entries = old
            raise
        return summary
