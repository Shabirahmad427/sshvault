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
import platform
import posixpath
import socket
import time
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Callable, cast
import threading
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
    "login_options",
    "terminal_options",
    "sftp_options",
    "tunnel_options",
    "connection_options",
    "launch_preferences",
}
_SETTINGS_ALLOWED = {
    "scrollback_limit",
    "connection_timeout",
    "download_directory",
    "confirm_multiline_paste",
    "confirm_delete",
    "confirm_overwrite",
    "maximum_sftp_transfers",
    "sftp_chunk_size",
    "show_transfer_manager_on_start",
    "transfer_manager_window",
}
DEFAULT_SETTINGS = {
    "scrollback_limit": 5000,
    "connection_timeout": 15,
    "download_directory": "",
    "confirm_multiline_paste": True,
    "confirm_delete": True,
    "confirm_overwrite": True,
    # One MiB amortizes SFTP round trips without allocating an unbounded buffer.
    "maximum_sftp_transfers": 3,
    "sftp_chunk_size": 1048576,
    "show_transfer_manager_on_start": True,
    "transfer_manager_window": {},
}
SFTP_TRANSFER_CHUNK_SIZES = (65536, 131072, 262144, 524288, 1048576, 2097152)
SFTP_SIDECAR_PROGRESS_BYTES = 16 * 1024 * 1024
SFTP_SIDECAR_PROGRESS_SECONDS = 5.0
SFTP_PROGRESS_INTERVAL = 0.25
SFTP_PREFETCH_DEPTHS = (4, 8, 16, 32)
SFTP_PREFETCH_WORKER_MEMORY_LIMIT = 32 * 1024 * 1024
SFTP_PREFETCH_TOTAL_MEMORY_LIMIT = 96 * 1024 * 1024


def bounded_prefetch_depth(chunk_size: int, requested_depth: int, workers: int = 1) -> int:
    """Return a tested prefetch depth that cannot exceed the memory budget."""
    if requested_depth not in SFTP_PREFETCH_DEPTHS:
        requested_depth = min(32, max(4, requested_depth))
    safe_workers = max(1, workers)
    budget = min(SFTP_PREFETCH_WORKER_MEMORY_LIMIT, SFTP_PREFETCH_TOTAL_MEMORY_LIMIT // safe_workers)
    allowed = max(1, budget // max(1, chunk_size))
    return max(depth for depth in SFTP_PREFETCH_DEPTHS if depth <= min(requested_depth, allowed)) if allowed >= 4 else 0


def ssh_compression_recommended(filename: str, *, latency_seconds: float | None = None) -> bool:
    """Recommend compression only for likely-compressible payloads on slower links."""
    compressed = {
        ".7z",
        ".bz2",
        ".dcd",
        ".gz",
        ".jpeg",
        ".jpg",
        ".mp4",
        ".nc",
        ".png",
        ".tar",
        ".tgz",
        ".xtc",
        ".xz",
        ".zip",
    }
    suffix = Path(filename).suffix.casefold()
    return suffix not in compressed and (latency_seconds is None or latency_seconds >= 0.02)


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
        maximum_sftp_transfers = int(raw.get("maximum_sftp_transfers", 3))
        sftp_chunk_size = int(raw.get("sftp_chunk_size", DEFAULT_SETTINGS["sftp_chunk_size"]))
    except (TypeError, ValueError) as exc:
        raise ProfileError("Scrollback and timeout must be whole numbers.") from exc
    if not 100 <= scrollback <= 100000 or not 1 <= timeout <= 120 or not 1 <= maximum_sftp_transfers <= 8:
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
            "maximum_sftp_transfers": maximum_sftp_transfers,
            # Older installations may have a valid custom value.  Keep it,
            # while the UI presents the bounded supported choices for new edits.
            "sftp_chunk_size": max(SFTP_TRANSFER_CHUNK_SIZES[0], min(sftp_chunk_size, SFTP_TRANSFER_CHUNK_SIZES[-1])),
            "show_transfer_manager_on_start": bool(raw.get("show_transfer_manager_on_start", True)),
            "transfer_manager_window": TransferManagerWindowState.from_settings(
                raw.get("transfer_manager_window")
            ).to_settings(),
            "theme": AppearanceState.normalize_theme(raw.get("theme", "system")),
            "application_font_size": AppearanceState.clamp_application_font(raw.get("application_font_size", 10)),
            "terminal_font_size": AppearanceState.clamp_terminal_font(raw.get("terminal_font_size", 10)),
        }
    )
    return result


@dataclass
class TransferManagerWindowState:
    """Display-free persistent state for the modeless transfer window."""

    width: int = 1180
    height: int = 430
    x: int | None = None
    y: int | None = None
    maximized: bool = False
    column_widths: dict[str, int] = field(default_factory=dict)
    column_order: list[str] = field(default_factory=list)
    sort_column: str = "queue"
    sort_descending: bool = False

    @classmethod
    def from_settings(cls, raw: object) -> "TransferManagerWindowState":
        data = raw if isinstance(raw, dict) else {}

        def integer(name: str, default: int) -> int:
            try:
                return int(data.get(name, default))
            except (TypeError, ValueError):
                return default

        widths = data.get("column_widths", {})
        return cls(
            width=max(760, min(integer("width", 1180), 4000)),
            height=max(240, min(integer("height", 430), 3000)),
            x=integer("x", 0) if data.get("x") is not None else None,
            y=integer("y", 0) if data.get("y") is not None else None,
            maximized=bool(data.get("maximized", False)),
            column_widths={
                str(k): max(40, min(int(v), 2000)) for k, v in widths.items() if str(v).lstrip("-").isdigit()
            },
            column_order=[str(value) for value in data.get("column_order", []) if isinstance(value, str)],
            sort_column=str(data.get("sort_column", "queue")),
            sort_descending=bool(data.get("sort_descending", False)),
        )

    def to_settings(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "x": self.x,
            "y": self.y,
            "maximized": self.maximized,
            "column_widths": self.column_widths,
            "column_order": self.column_order,
            "sort_column": self.sort_column,
            "sort_descending": self.sort_descending,
        }

    def geometry_for_screen(self, screen_width: int, screen_height: int) -> tuple[int, int, int, int]:
        width, height = min(self.width, screen_width), min(self.height, screen_height)
        x = (
            (screen_width - width) // 2
            if self.x is None or self.x < 0 or self.x + 80 > screen_width or self.x + width < 80
            else self.x
        )
        y = (
            (screen_height - height) // 2
            if self.y is None or self.y < 0 or self.y + 80 > screen_height or self.y + height < 80
            else self.y
        )
        return width, height, x, y

    def sorted_ids(self, items: list["TransferItem"], key: Callable[["TransferItem"], Any] | None = None) -> list[str]:
        rows = (
            list(items)
            if self.sort_column == "queue" or key is None
            else sorted(items, key=key, reverse=self.sort_descending)
        )
        return [item.item_id for item in rows]


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


@dataclass(frozen=True)
class LoginOptions:
    proxy_jump: str = ""
    timeout: int = 15
    keepalive_interval: int = 0
    compression: bool = False


@dataclass(frozen=True)
class TerminalOptions:
    terminal_type: str = "xterm-256color"
    scrollback: int = 5000
    starting_directory: str = ""
    startup_command: str = ""
    environment: tuple[tuple[str, str], ...] = ()
    auto_open: bool = True
    font_override: bool = False
    font_size: int = 10


@dataclass(frozen=True)
class SFTPOptions:
    initial_local_directory: str = ""
    initial_remote_directory: str = ""
    collision_behavior: str = "ask"
    preserve_timestamps: bool = False
    verify_transfers: bool = False
    auto_open: bool = False


@dataclass(frozen=True)
class TunnelRule:
    rule_id: str = field(default_factory=lambda: str(uuid4()))
    enabled: bool = True
    type: str = "Local"
    bind_address: str = "127.0.0.1"
    bind_port: int = 0
    destination_host: str = ""
    destination_port: int = 0
    description: str = ""


@dataclass(frozen=True)
class TunnelOptions:
    rules: tuple[TunnelRule, ...] = ()


@dataclass(frozen=True)
class ConnectionOptions:
    automatic_reconnect: bool = False
    reconnect_delay: int = 5
    maximum_reconnect_delay: int = 60
    maximum_attempts: int = 3
    exponential_backoff: bool = True
    reopen_terminal: bool = True
    reopen_sftp: bool = False
    restart_tunnels: bool = False
    logging_level: str = "normal"


def reconnect_delay(initial: int, maximum: int, attempt: int, exponential: bool = True) -> int:
    """Return the bounded delay before a 1-based reconnect attempt."""
    initial = max(1, int(initial))
    maximum = max(initial, int(maximum))
    attempt = max(1, int(attempt))
    return min(initial * (2 ** (attempt - 1)) if exponential else initial, maximum)


class ReconnectController:
    """UI-free reconnect state machine with injectable scheduling and connector."""

    STATES = {
        "connected",
        "connection lost",
        "waiting",
        "reconnecting",
        "reconnected",
        "attempts exhausted",
        "manually disconnected",
    }

    def __init__(
        self, options: dict[str, Any] | ConnectionOptions | None = None, schedule: Any = None, connector: Any = None
    ) -> None:
        raw = options if isinstance(options, dict) else (options.__dict__ if options else {})
        self.enabled = bool(raw.get("automatic_reconnect", False))
        self.initial_delay = max(1, int(raw.get("reconnect_delay", 5)))
        self.maximum_delay = max(self.initial_delay, int(raw.get("maximum_reconnect_delay", 60)))
        self.maximum_attempts = max(0, int(raw.get("maximum_attempts", 3)))
        self.exponential = bool(raw.get("exponential_backoff", True))
        self.schedule = schedule or (lambda delay, callback: callback())
        self.connector = connector
        self.state = "connected"
        self.attempt = 0
        self.generation = 0
        self.pending = False
        self._cancelled = False

    def unexpected_loss(self, generation: int) -> bool:
        if not self.enabled or self.pending or self._cancelled or generation != self.generation:
            return False
        self.state, self.attempt, self.pending = "connection lost", 0, True
        self._schedule_next()
        return True

    def _schedule_next(self) -> None:
        if not self.pending or self.attempt >= self.maximum_attempts:
            self.pending = False
            self.state = "attempts exhausted"
            return
        self.attempt += 1
        delay = reconnect_delay(self.initial_delay, self.maximum_delay, self.attempt, self.exponential)
        self.state = "waiting"
        self.schedule(delay, self._attempt)

    def _attempt(self) -> None:
        if not self.pending or self._cancelled:
            return
        self.state = "reconnecting"
        try:
            if self.connector is None or self.connector():
                self.pending = False
                self.state = "reconnected"
                return
        except Exception:
            pass
        self._schedule_next()

    def reconnect_now(self) -> None:
        if self._cancelled:
            return
        self.pending = True
        self._attempt()

    def cancel(self, manual: bool = True) -> None:
        self.pending = False
        self._cancelled = True
        self.state = "manually disconnected" if manual else "attempts exhausted"

    def new_session(self) -> int:
        self.generation += 1
        self._cancelled = False
        self.pending = False
        self.attempt = 0
        self.state = "connected"
        return self.generation


@dataclass
class StartupActionResult:
    name: str
    status: str = "pending"
    error: str = ""


class StartupActionCoordinator:
    """Deterministic, generation-aware post-login action coordinator."""

    ORDER = ("tunnels", "terminal", "sftp", "command")

    def __init__(self, handlers: dict[str, Any] | None = None) -> None:
        self.handlers = handlers or {}
        self.generation = 0
        self.running = False
        self.results: list[StartupActionResult] = []
        self.cancelled = False
        self._completed_generation: int | None = None

    def run(self, preferences: dict[str, Any], generation: int, *, manual: bool = False) -> list[StartupActionResult]:
        if (self.running or self._completed_generation == generation) and not manual:
            return list(self.results)
        if generation != self.generation:
            self.generation = generation
        self.cancelled = False
        self.running = True
        self.results = []
        enabled = {
            "tunnels": bool(preferences.get("start_enabled_tunnels") or preferences.get("restart_tunnels")),
            "terminal": bool(preferences.get("open_terminal", True)),
            "sftp": bool(preferences.get("open_sftp", False)),
            "command": bool(str(preferences.get("startup_command", "")).strip()),
        }
        for name in self.ORDER:
            if self.cancelled or generation != self.generation:
                self.results.append(StartupActionResult(name, "cancelled"))
                continue
            if not enabled[name]:
                self.results.append(StartupActionResult(name, "skipped"))
                continue
            result = StartupActionResult(name, "running")
            self.results.append(result)
            try:
                handler = self.handlers.get(name)
                if handler is None:
                    raise RuntimeError("Startup action unavailable.")
                handler(preferences) if name == "command" else handler()
                result.status = "completed"
            except Exception as exc:
                result.status = "failed"
                result.error = str(redact_secrets(str(exc)))
        self.running = False
        self._completed_generation = generation
        return list(self.results)

    def cancel(self) -> None:
        self.cancelled = True
        self.running = False

    def invalidate(self, generation: int) -> None:
        self.generation = generation
        self._completed_generation = None
        self.cancel()


@dataclass(frozen=True)
class DiagnosticRecord:
    field: str
    value: str


@dataclass
class ConnectionDiagnostics:
    records: list[DiagnosticRecord] = field(default_factory=list)
    generation: int = 0

    def as_text(self) -> str:
        return "SSHVault diagnostics (host and network metadata may be present)\n" + "\n".join(
            f"{r.field}: {r.value}" for r in self.records
        )


class DiagnosticsCollector:
    FIELDS = (
        "SSHVault version",
        "Python version",
        "Paramiko version",
        "Operating system",
        "Profile name",
        "Host",
        "Port",
        "Username",
        "Authentication method",
        "ProxyJump route",
        "DNS result",
        "TCP connection timing",
        "Connection state",
        "Session generation",
        "Host-key algorithm",
        "Host-key SHA-256 fingerprint",
        "Key-exchange algorithm",
        "Cipher",
        "MAC algorithm",
        "Compression",
        "Keepalive interval",
        "Terminal state",
        "SFTP state",
        "Running tunnel count",
        "Reconnect state",
        "Startup-action state",
        "Last redacted connection error",
    )

    @classmethod
    def collect(
        cls, profile: dict[str, Any] | None = None, session: dict[str, Any] | None = None
    ) -> ConnectionDiagnostics:
        profile = profile or {}
        session = session or {}
        values = {
            "SSHVault version": str(session.get("version", "0.3.4")),
            "Python version": platform.python_version(),
            "Paramiko version": str(session.get("paramiko_version", "Unavailable")),
            "Operating system": platform.platform(),
            "Profile name": str(profile.get("name", "Unavailable")),
            "Host": str(profile.get("host", "Unavailable")),
            "Port": str(profile.get("port", "Unavailable")),
            "Username": str(profile.get("user", "Unavailable")),
            "Authentication method": str(profile.get("auth_method", "Unavailable")),
            "ProxyJump route": str(profile.get("proxy_jump") or "Direct"),
            "DNS result": str(session.get("dns", "Unavailable")),
            "TCP connection timing": str(session.get("tcp_timing", "Unavailable")),
            "Connection state": str(session.get("state", "disconnected")),
            "Session generation": str(session.get("generation", 0)),
            "Host-key algorithm": str(session.get("host_key_algorithm", "Unavailable")),
            "Host-key SHA-256 fingerprint": str(session.get("host_key_fingerprint", "Unavailable")),
            "Key-exchange algorithm": str(session.get("kex", "Unavailable")),
            "Cipher": str(session.get("cipher", "Unavailable")),
            "MAC algorithm": str(session.get("mac", "Unavailable")),
            "Compression": str(session.get("compression", "Unavailable")),
            "Keepalive interval": str(session.get("keepalive", "Unavailable")),
            "Terminal state": str(session.get("terminal", "Unavailable")),
            "SFTP state": str(session.get("sftp", "Unavailable")),
            "Running tunnel count": str(session.get("tunnels", 0)),
            "Reconnect state": str(session.get("reconnect", "Unavailable")),
            "Startup-action state": str(session.get("startup", "Unavailable")),
            "Last redacted connection error": str(redact_secrets(session.get("error", "Unavailable"))),
        }
        return ConnectionDiagnostics(
            [DiagnosticRecord(name, values.get(name, "Unavailable")) for name in cls.FIELDS],
            int(session.get("generation", 0)),
        )

    @staticmethod
    def network_check(
        host: str,
        port: int,
        timeout: float = 3.0,
        resolver: Any = socket.getaddrinfo,
        connector: Any = socket.create_connection,
    ) -> dict[str, str]:
        started = time.monotonic()
        try:
            addresses = resolver(host, port, type=socket.SOCK_STREAM)
            connector((host, port), timeout=timeout).close()
            return {
                "dns": ", ".join(sorted({str(item[4][0]) for item in addresses})),
                "tcp": f"{time.monotonic() - started:.3f}s",
            }
        except Exception as exc:
            return {"dns": "Unavailable", "tcp": str(redact_secrets(str(exc)))}


@dataclass(frozen=True)
class ProfileLaunchPreferences:
    open_terminal: bool = True
    open_sftp: bool = False
    startup_command: str = ""


def default_profile_sections(raw: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return migrated, secret-free section dictionaries for an old profile."""
    raw = raw if isinstance(raw, dict) else {}
    return {
        "login_options": {
            "proxy_jump": str(raw.get("proxy_jump", "")),
            "timeout": int(raw.get("timeout", 15)),
            "keepalive_interval": 0,
            "compression": bool(raw.get("compression", False)),
        },
        "terminal_options": {
            "terminal_type": "xterm-256color",
            "scrollback": 5000,
            "starting_directory": str(raw.get("startup_directory", "")),
            "startup_command": str(raw.get("startup_command", "")),
            "environment": {},
            "auto_open": True,
            "font_override": False,
            "font_size": 10,
        },
        "sftp_options": {
            "initial_local_directory": "",
            "initial_remote_directory": "",
            "collision_behavior": "ask",
            "preserve_timestamps": False,
            "verify_transfers": False,
            "auto_open": False,
        },
        "tunnel_options": {"rules": []},
        "connection_options": {
            "automatic_reconnect": False,
            "reconnect_delay": 5,
            "maximum_reconnect_delay": 60,
            "maximum_attempts": 3,
            "exponential_backoff": True,
            "reopen_terminal": True,
            "reopen_sftp": False,
            "restart_tunnels": False,
            "logging_level": "normal",
        },
        "launch_preferences": {"open_terminal": True, "open_sftp": False, "startup_command": ""},
    }


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


@dataclass(frozen=True)
class ProfileValidationIssue:
    tab: str
    field: str
    message: str
    related_id: str | None = None


@dataclass
class ProfileDraft:
    """Staged, secret-free profile editing model."""

    values: dict[str, Any] = field(default_factory=dict)
    password: str = ""
    passphrase: str = ""
    remove_password: bool = False

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "ProfileDraft":
        safe = {key: value for key, value in profile.items() if key not in {"password", "passphrase"}}
        return cls(values=json.loads(json.dumps(safe, ensure_ascii=False)))

    def set_value(self, key: str, value: Any) -> None:
        self.values[key] = value

    def issues(
        self, profiles: list[dict[str, Any]] | None = None, editing_id: str | None = None
    ) -> list[ProfileValidationIssue]:
        issues: list[ProfileValidationIssue] = []
        try:
            validate_profile(self.values, check_key_exists=False)
        except ProfileError as exc:
            text = str(exc)
            field = "host" if "host" in text.casefold() else "profile"
            issues.append(ProfileValidationIssue("Login", field, text))
        method = str(self.values.get("auth_method", "agent"))
        if method == "key" and not str(self.values.get("key_path", "")).strip():
            issues.append(ProfileValidationIssue("Login", "key_path", "Choose a private-key path."))
        if profiles is not None:
            name = str(self.values.get("name", "")).strip().casefold()
            for profile in profiles:
                if profile.get("id") != editing_id and str(profile.get("name", "")).casefold() == name:
                    issues.append(ProfileValidationIssue("Login", "name", "Profile name already exists."))
        try:
            validate_environment(self.values.get("terminal_options", {}).get("environment", {}))
        except ProfileError as exc:
            issues.append(ProfileValidationIssue("Terminal", "environment", str(exc)))
        try:
            validate_tunnel_rules(self.values.get("tunnel_options", {}).get("rules", []))
        except ProfileError as exc:
            issues.append(ProfileValidationIssue("Tunnels", "rules", str(exc)))
        return issues

    def clean_profile(
        self, profiles: list[dict[str, Any]] | None = None, editing_id: str | None = None
    ) -> dict[str, Any]:
        issues = self.issues(profiles, editing_id)
        if issues:
            raise ProfileError(issues[0].message)
        return validate_profile(self.values, check_key_exists=False)

    def duplicate(self) -> "ProfileDraft":
        copy = ProfileDraft.from_profile(self.values)
        copy.values["id"] = str(uuid4())
        copy.values["name"] = f"{self.values.get('name', 'Profile')} Copy"
        copy.password = copy.passphrase = ""
        copy.remove_password = True
        rules = copy.values.get("tunnel_options", {}).get("rules", [])
        for rule in rules:
            rule["rule_id"] = str(uuid4())
        return copy


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
class RunningTunnel:
    """UI-free runtime record for one saved tunnel rule."""

    rule: dict[str, Any]
    runtime: TunnelRuntime
    status: str = "stopped"
    error: str = ""


class TunnelManager:
    """Validate and own saved tunnel runtimes for one SSH session.

    The Tk panel supplies the actual forwarding worker; this class owns the
    lifecycle decisions and prevents stale or conflicting starts.
    """

    def __init__(self, transport: Any = None, generation: int = 0) -> None:
        self.transport = transport
        self.generation = generation
        self.connected = transport is not None
        self.running: dict[str, RunningTunnel] = {}

    @staticmethod
    def _bind(rule: dict[str, Any]) -> tuple[str, int]:
        return (str(rule.get("bind_address", "127.0.0.1")).strip(), int(rule.get("bind_port", 0)))

    def validate_start(self, rule: dict[str, Any]) -> str | None:
        if not self.connected:
            return "Not connected."
        try:
            validate_tunnel_rules([rule])
        except ProfileError as exc:
            return str(exc)
        key = self._bind(rule)
        if any(
            self._bind(item.rule) == key for item in self.running.values() if item.status in {"starting", "running"}
        ):
            return "A tunnel already uses this bind endpoint."
        return None

    def start(self, rule: dict[str, Any], starter: Any = None) -> RunningTunnel:
        issue = self.validate_start(rule)
        if issue:
            raise ProfileError(issue)
        rule_id = str(rule.get("rule_id") or rule.get("id") or uuid4().hex)
        runtime = RunningTunnel(dict(rule, id=rule_id), TunnelRuntime(generation=self.generation), "starting")
        self.running[rule_id] = runtime
        try:
            if starter is not None:
                starter(runtime)
            runtime.status = "running"
        except Exception as exc:
            runtime.status = "failed"
            runtime.error = str(redact_secrets(str(exc)))
            runtime.runtime.stop()
            raise
        return runtime

    def stop(self, rule_id: str) -> bool:
        item = self.running.get(rule_id)
        if item is None or item.status in {"stopped", "stopping"}:
            return False
        item.status = "stopping"
        item.runtime.stop()
        item.status = "stopped"
        return True

    def stop_all(self) -> None:
        for rule_id in list(self.running):
            self.stop(rule_id)

    def invalidate(self, generation: int) -> None:
        if generation != self.generation:
            return
        self.stop_all()
        self.connected = False


def parse_socks5_connect(data: bytes) -> tuple[str, int] | None:
    """Parse a SOCKS5 CONNECT request, rejecting unsupported commands."""
    if len(data) < 7 or data[0] != 5 or data[1] != 1:
        return None
    atyp = data[3]
    pos = 4
    try:
        if atyp == 1 and len(data) >= pos + 4:
            host = str(ipaddress.ip_address(data[pos : pos + 4]))
            pos += 4
        elif atyp == 3 and len(data) > pos:
            length = data[pos]
            pos += 1
            if len(data) < pos + length:
                return None
            host = data[pos : pos + length].decode("idna")
            pos += length
        elif atyp == 4 and len(data) >= pos + 16:
            host = str(ipaddress.ip_address(data[pos : pos + 16]))
            pos += 16
        else:
            return None
        if len(data) < pos + 2:
            return None
        return host, int.from_bytes(data[pos : pos + 2], "big")
    except (UnicodeError, ValueError):
        return None


@dataclass
class TransferTimingMetrics:
    """Non-sensitive transfer timing counters, kept per transfer item."""

    remote_read_seconds: float = 0.0
    remote_write_seconds: float = 0.0
    local_read_seconds: float = 0.0
    local_write_seconds: float = 0.0
    sidecar_write_seconds: float = 0.0
    channel_creation_seconds: float = 0.0
    remote_read_calls: int = 0
    remote_write_calls: int = 0
    local_read_calls: int = 0
    local_write_calls: int = 0
    sidecar_write_calls: int = 0
    ui_progress_callbacks: int = 0
    bytes_read_remote: int = 0
    bytes_written_remote: int = 0
    bytes_read_local: int = 0
    bytes_written_local: int = 0

    def record(self, operation: str, elapsed: float, byte_count: int = 0) -> None:
        """Record only operation timing and byte counts, never path or data."""
        if operation == "remote_read":
            self.remote_read_seconds += elapsed
            self.remote_read_calls += 1
            self.bytes_read_remote += byte_count
        elif operation == "remote_write":
            self.remote_write_seconds += elapsed
            self.remote_write_calls += 1
            self.bytes_written_remote += byte_count
        elif operation == "local_read":
            self.local_read_seconds += elapsed
            self.local_read_calls += 1
            self.bytes_read_local += byte_count
        elif operation == "local_write":
            self.local_write_seconds += elapsed
            self.local_write_calls += 1
            self.bytes_written_local += byte_count
        elif operation == "sidecar_write":
            self.sidecar_write_seconds += elapsed
            self.sidecar_write_calls += 1

    def average_bytes_per_call(self, operation: str) -> float:
        calls, byte_count = {
            "remote_read": (self.remote_read_calls, self.bytes_read_remote),
            "remote_write": (self.remote_write_calls, self.bytes_written_remote),
            "local_read": (self.local_read_calls, self.bytes_read_local),
            "local_write": (self.local_write_calls, self.bytes_written_local),
        }.get(operation, (0, 0))
        return byte_count / calls if calls else 0.0


@dataclass
class DurableProgressPolicy:
    """Bound atomic sidecar rewrites while preserving a flushed offset."""

    completed_bytes: int
    updated_at: float
    byte_interval: int = SFTP_SIDECAR_PROGRESS_BYTES
    time_interval: float = SFTP_SIDECAR_PROGRESS_SECONDS

    def due(self, completed_bytes: int, now: float) -> bool:
        return (
            completed_bytes - self.completed_bytes >= self.byte_interval or now - self.updated_at >= self.time_interval
        )

    def persisted(self, completed_bytes: int, now: float) -> None:
        self.completed_bytes, self.updated_at = completed_bytes, now


@dataclass
class AdaptiveTransferTuner:
    """Small, session-only controller for a stable large-file download."""

    total: int | None
    chunk_size: int = 1048576
    prefetch_depth: int = 8
    active: bool = False
    stopped: bool = False
    last_bytes: int = 0
    last_time: float | None = None
    last_rate: float = 0.0
    non_improvements: int = 0

    def observe(self, completed_bytes: int, now: float, *, stable: bool = True) -> tuple[int, int]:
        """Evaluate one change at a time; never rewinds active transfer data."""
        if self.total is None or self.total < 32 * 1024 * 1024 or not stable or self.stopped:
            return self.chunk_size, self.prefetch_depth
        if not self.active:
            if completed_bytes < 8 * 1024 * 1024:
                return self.chunk_size, self.prefetch_depth
            self.active, self.last_bytes, self.last_time = True, completed_bytes, now
            return self.chunk_size, self.prefetch_depth
        if self.last_time is None or completed_bytes - self.last_bytes < 4 * 1024 * 1024 or now - self.last_time < 2.0:
            return self.chunk_size, self.prefetch_depth
        rate = (completed_bytes - self.last_bytes) / max(0.001, now - self.last_time)
        self.last_bytes, self.last_time = completed_bytes, now
        if self.last_rate == 0.0:
            self.last_rate = rate
            return self.chunk_size, self.prefetch_depth
        if rate > self.last_rate * 1.05:
            self.last_rate, self.non_improvements = rate, 0
            if self.chunk_size < 2 * 1024 * 1024:
                self.chunk_size = min(2 * 1024 * 1024, self.chunk_size * 2)
            elif self.prefetch_depth < 32:
                self.prefetch_depth *= 2
            return self.chunk_size, self.prefetch_depth
        if rate < self.last_rate * 0.9:
            self.non_improvements += 1
            self.chunk_size = max(256 * 1024, self.chunk_size // 2)
        else:
            self.non_improvements += 1
        if self.non_improvements >= 2:
            self.stopped = True
        return self.chunk_size, self.prefetch_depth


@dataclass
class TransferItem:
    """A serializable transfer request and its UI-independent progress."""

    source: str
    target: str
    direction: str
    total: int | None = None
    status: str = "Pending"
    transferred: int = 0
    error: str = ""
    generation: int = 0
    item_id: str = field(default_factory=lambda: uuid4().hex)
    started_at: float | None = None
    updated_at: float | None = None
    last_progress_at: float | None = None
    speed: float = 0.0
    average_speed: float = 0.0
    resume_offset: int = 0
    restart_required: bool = False
    delete_partial_on_cancel: bool = False
    parent_id: str | None = None
    metrics: TransferTimingMetrics = field(default_factory=TransferTimingMetrics)

    def progress(self) -> float | None:
        return None if not self.total or self.total < 0 else min(100.0, self.transferred * 100.0 / self.total)

    def remaining_seconds(self) -> float | None:
        if self.total is None or self.speed <= 0:
            return None
        return max(0.0, (self.total - self.transferred) / self.speed)


@dataclass
class TransferBatch:
    """A visible folder-transfer parent with independently visible children."""

    name: str
    direction: str
    source: str
    target: str
    children: list[str] = field(default_factory=list)
    batch_id: str = field(default_factory=lambda: uuid4().hex)


@dataclass(frozen=True)
class TransferProgress:
    item_id: str
    transferred: int
    total: int | None
    speed: float
    average_speed: float
    elapsed: float
    remaining: float | None


class TransferState:
    CHECKING = "Checking"
    ALREADY_COMPLETE = "Already complete"
    RESUME_AVAILABLE = "Resume available"
    RESUMING = "Resuming"
    DOWNLOADING = "Downloading"
    CONFLICT = "Conflict"
    PENDING = "Pending"
    PREPARING = "Preparing"
    TRANSFERRING = "Transferring"
    PAUSED = "Paused"
    VERIFYING = "Verifying"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"
    TERMINAL = {ALREADY_COMPLETE, COMPLETED, CONFLICT, FAILED, CANCELLED}


class DownloadResumeDecision:
    """The safe action for one local SFTP download destination."""

    DOWNLOAD = "download"
    ALREADY_COMPLETE = "already_complete"
    RESUME = "resume"
    ADOPT_LEGACY = "adopt_legacy"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class DownloadResumePlan:
    """Display-free resume decision made before normal collision handling."""

    decision: str
    status: str
    destination: Path
    partial_path: Path
    metadata_path: Path
    remote_path: str
    remote_size: int
    remote_mtime: int | None
    remote_identity: str
    offset: int = 0
    message: str = ""

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.remote_size - self.offset)


def partial_download_path(destination: str | Path) -> Path:
    """Return the public, predictable staging name for a download."""
    path = Path(destination)
    return path.with_name(path.name + ".sshvault-part")


def partial_download_metadata_path(destination: str | Path) -> Path:
    path = Path(destination)
    return path.with_name(path.name + ".sshvault-part.json")


def _absolute_destination(path: Path) -> str:
    return str(path.expanduser().resolve(strict=False))


def _normal_remote_path(path: str) -> str:
    normal = posixpath.normpath(path)
    return normal if normal.startswith("/") else "/" + normal


def read_partial_download_metadata(path: str | Path) -> dict[str, Any] | None:
    """Read untrusted sidecar data without allowing it to affect a resume."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def write_partial_download_metadata(
    destination: str | Path,
    *,
    remote_identity: str,
    remote_path: str,
    remote_size: int,
    remote_mtime: int | None,
    completed_bytes: int,
    now: float | None = None,
    created_at: float | None = None,
) -> Path:
    """Atomically persist non-secret identity and progress for a partial file."""
    timestamp = time.time() if now is None else now
    destination_path = Path(destination)
    metadata_path = partial_download_metadata_path(destination_path)
    existing = read_partial_download_metadata(metadata_path) or {}
    atomic_json_write(
        metadata_path,
        {
            "format_version": 1,
            "remote_identity": remote_identity,
            "remote_path": _normal_remote_path(remote_path),
            "expected_remote_size": int(remote_size),
            "remote_modification_time": remote_mtime,
            "local_destination_path": _absolute_destination(destination_path),
            "completed_byte_count": int(completed_bytes),
            "creation_time": existing.get("creation_time", timestamp) if created_at is None else created_at,
            "last_update_time": timestamp,
        },
    )
    return metadata_path


def _metadata_matches_download(
    metadata: dict[str, Any] | None,
    *,
    destination: Path,
    remote_identity: str,
    remote_path: str,
    remote_size: int,
    remote_mtime: int | None,
    partial_size: int,
) -> bool:
    if not metadata or metadata.get("format_version") != 1:
        return False
    expected = {
        "remote_identity": remote_identity,
        "remote_path": _normal_remote_path(remote_path),
        "expected_remote_size": int(remote_size),
        "local_destination_path": _absolute_destination(destination),
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        return False
    # A modification time is identity data when the server supplies it.  A
    # missing value cannot prove that a partial belongs to this remote object.
    if remote_mtime is not None and metadata.get("remote_modification_time") != remote_mtime:
        return False
    return (
        isinstance(metadata.get("completed_byte_count"), int)
        and metadata["completed_byte_count"] == partial_size
        and 0 <= partial_size <= remote_size
    )


def inspect_download_resume(
    destination: str | Path,
    *,
    remote_identity: str,
    remote_path: str,
    remote_size: int,
    remote_mtime: int | None = None,
) -> DownloadResumePlan:
    """Decide whether a download can be safely resumed without opening it.

    This deliberately treats a sidecar as an identity assertion, not merely a
    progress cache: host/profile identity, absolute paths, size and available
    modification time must all still match.
    """
    local = Path(destination)
    partial = partial_download_path(local)
    sidecar = partial_download_metadata_path(local)
    normalized_remote = _normal_remote_path(remote_path)

    def make(decision: str, status: str, offset: int = 0, message: str = "") -> DownloadResumePlan:
        return DownloadResumePlan(
            decision,
            status,
            local,
            partial,
            sidecar,
            normalized_remote,
            int(remote_size),
            remote_mtime,
            remote_identity,
            offset,
            message,
        )

    if remote_size < 0:
        return make(DownloadResumeDecision.CONFLICT, TransferState.CONFLICT, message="Invalid remote file size.")
    if local.exists() and local.is_dir():
        return make(
            DownloadResumeDecision.CONFLICT,
            TransferState.CONFLICT,
            message="Type conflict: remote file cannot replace a local directory.",
        )
    if partial.exists() and partial.is_dir():
        return make(
            DownloadResumeDecision.CONFLICT,
            TransferState.CONFLICT,
            message="Type conflict: partial download path is a directory.",
        )
    if local.is_file():
        local_size = local.stat().st_size
        if local_size == remote_size:
            return make(DownloadResumeDecision.ALREADY_COMPLETE, TransferState.ALREADY_COMPLETE, local_size)
        if local_size > remote_size:
            return make(
                DownloadResumeDecision.CONFLICT,
                TransferState.CONFLICT,
                local_size,
                "The local file is larger than the remote file and cannot be resumed safely.",
            )
        # An old SSHVault release wrote incomplete data to the final name.
        return make(
            DownloadResumeDecision.ADOPT_LEGACY,
            TransferState.RESUME_AVAILABLE,
            local_size,
            "Existing local file can be adopted as a resumable SSHVault partial download.",
        )
    if partial.is_file():
        partial_size = partial.stat().st_size
        metadata = read_partial_download_metadata(sidecar)
        if _metadata_matches_download(
            metadata,
            destination=local,
            remote_identity=remote_identity,
            remote_path=remote_path,
            remote_size=remote_size,
            remote_mtime=remote_mtime,
            partial_size=partial_size,
        ):
            return make(DownloadResumeDecision.RESUME, TransferState.RESUME_AVAILABLE, partial_size)
        return make(
            DownloadResumeDecision.CONFLICT,
            TransferState.CONFLICT,
            partial_size,
            "Partial-download metadata does not match this remote file; it cannot be resumed safely.",
        )
    return make(DownloadResumeDecision.DOWNLOAD, TransferState.DOWNLOADING)


def adopt_legacy_download(plan: DownloadResumePlan, *, now: float | None = None) -> DownloadResumePlan:
    """Safely migrate a user-confirmed old final-name partial to staging."""
    if plan.decision != DownloadResumeDecision.ADOPT_LEGACY:
        raise ProfileError("Only an eligible legacy partial can be adopted.")
    if plan.partial_path.exists():
        raise ProfileError("A partial download already exists; legacy file was not changed.")
    os.replace(plan.destination, plan.partial_path)
    write_partial_download_metadata(
        plan.destination,
        remote_identity=plan.remote_identity,
        remote_path=plan.remote_path,
        remote_size=plan.remote_size,
        remote_mtime=plan.remote_mtime,
        completed_bytes=plan.offset,
        now=now,
    )
    return DownloadResumePlan(
        DownloadResumeDecision.RESUME,
        TransferState.RESUME_AVAILABLE,
        **{
            key: getattr(plan, key)
            for key in (
                "destination",
                "partial_path",
                "metadata_path",
                "remote_path",
                "remote_size",
                "remote_mtime",
                "remote_identity",
            )
        },
        offset=plan.offset,
    )


TransferOperation = Callable[[TransferItem, Any, "TransferWorker"], None]


class TransferWorker:
    """One worker and exactly one SFTP client at a time.

    The operation calls :meth:`checkpoint` between chunks.  It deliberately
    releases its scheduler slot while paused, permitting pending work to run.
    """

    def __init__(self, scheduler: "TransferScheduler", item_id: str, attempt: int, client: Any) -> None:
        self.scheduler, self.item_id, self.attempt, self.client = scheduler, item_id, attempt, client
        self.worker_id = uuid4().hex

    def checkpoint(self, transferred: int | None = None, total: int | None = None) -> None:
        self.scheduler._checkpoint(self.item_id, self.attempt, transferred, total, self.worker_id)

    def mark_resuming(self) -> None:
        """Expose resume state only after both handles are positioned."""
        self.scheduler._mark_resuming(self.item_id, self.attempt, self.worker_id)

    def durable_update_required(self) -> bool:
        """Return whether pause/cancel/shutdown needs a durable local offset."""
        return self.scheduler._durable_update_required(self.item_id, self.attempt)

    @property
    def cancelled(self) -> bool:
        return self.scheduler._cancelled(self.item_id, self.attempt)


class TransferScheduler:
    """Thread-safe FIFO scheduler with bounded SFTP-client ownership.

    ``client_factory`` is called once for each active worker; a Paramiko SFTP
    client is never shared across threads.  Callbacks are intentionally plain
    functions so Tk can marshal them with ``after`` itself.
    """

    def __init__(
        self,
        client_factory: Callable[[], Any] | None = None,
        concurrency: int = 3,
        clock: Callable[[], float] = time.monotonic,
        on_change: Callable[[], None] | None = None,
        *,
        stall_timeout: float = 60.0,
        monitor_interval: float = 1.0,
        debug_transfers: bool = False,
    ) -> None:
        self.client_factory = client_factory
        self.concurrency = max(1, min(8, int(concurrency)))
        self.clock, self.on_change = clock, on_change
        self.items: list[TransferItem] = []
        self.batches: list[TransferBatch] = []
        self.generation = 0
        self.closed = False
        self._operations: dict[str, TransferOperation] = {}
        self._active: set[str] = set()
        self._threads: dict[str, threading.Thread] = {}
        self._clients: dict[str, Any] = {}
        self._attempts: dict[str, int] = {}
        self._paused: set[str] = set()
        self._cancelled_ids: set[str] = set()
        self._stalled_ids: set[str] = set()
        self._last_progress_notifications: dict[str, float] = {}
        self._condition = threading.Condition(threading.RLock())
        self.stall_timeout = max(1.0, float(stall_timeout))
        self.monitor_interval = max(0.05, float(monitor_interval))
        self.debug_transfers = debug_transfers
        self.diagnostic_events: list[dict[str, Any]] = []
        self._monitor_stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        if client_factory is not None:
            self._monitor_thread = threading.Thread(
                target=self._monitor_stalls, daemon=True, name="sshvault-sftp-transfer-monitor"
            )
            self._monitor_thread.start()

    @property
    def active(self) -> TransferItem | None:
        with self._condition:
            return next((x for x in self.items if x.item_id in self._active), None)

    @property
    def active_count(self) -> int:
        with self._condition:
            return len(self._active)

    def set_concurrency(self, value: int) -> None:
        with self._condition:
            self.concurrency = max(1, min(8, int(value)))
            threads = self._schedule_locked()
        self._start_threads(threads)
        self._changed()

    def enqueue(self, item: TransferItem, operation: TransferOperation | None = None) -> TransferItem:
        with self._condition:
            if self.closed:
                raise ProfileError("Transfer queue is closed.")
            item.generation = self.generation
            item.status = TransferState.PENDING
            self.items.append(item)
            if operation:
                self._operations[item.item_id] = operation
            threads = self._schedule_locked()
        self._start_threads(threads)
        self._changed()
        return item

    def record(self, item: TransferItem) -> TransferItem:
        """Add an already-resolved transfer row without scheduling I/O."""
        with self._condition:
            if self.closed:
                raise ProfileError("Transfer queue is closed.")
            item.generation = self.generation
            self.items.append(item)
        self._changed()
        return item

    def add_batch(
        self, batch: TransferBatch, children: list[tuple[TransferItem, TransferOperation | None]]
    ) -> TransferBatch:
        with self._condition:
            self.batches.append(batch)
        for item, operation in children:
            item.parent_id = batch.batch_id
            batch.children.append((self.enqueue(item, operation) if operation else self.record(item)).item_id)
        return batch

    def batch_progress(self, batch_id: str) -> TransferProgress | None:
        batch = next((x for x in self.batches if x.batch_id == batch_id), None)
        if batch is None:
            return None
        children = [self.get(item_id) for item_id in batch.children]
        rows = [x for x in children if x is not None]
        if not rows:
            return TransferProgress(batch_id, 0, 0, 0.0, 0.0, 0.0, 0.0)
        known = [x.total for x in rows if x.total is not None]
        total = sum(known) if len(known) == len(rows) else None
        transferred = sum(x.transferred for x in rows)
        speed = sum(x.speed for x in rows)
        return TransferProgress(
            batch_id,
            transferred,
            total,
            speed,
            speed,
            0.0,
            ((total - transferred) / speed if total is not None and speed else None),
        )

    def cancel_batch(self, batch_id: str) -> bool:
        batch = next((x for x in self.batches if x.batch_id == batch_id), None)
        if batch is None:
            return False
        for item_id in batch.children:
            self.cancel(item_id)
        return True

    def retry_batch(self, batch_id: str) -> bool:
        batch = next((x for x in self.batches if x.batch_id == batch_id), None)
        if batch is None:
            return False
        for item_id in batch.children:
            item = self.get(item_id)
            if item and item.status in {TransferState.FAILED, TransferState.CANCELLED}:
                self.retry(item_id)
        return True

    def _schedule_locked(self) -> list[threading.Thread]:
        """Reserve slots and create workers while locked; start them after unlock."""
        threads: list[threading.Thread] = []
        # The compatibility queue deliberately has no client factory.  Keep its
        # historical manual lifecycle without spawning a worker.
        if self.client_factory is None:
            if not self._active:
                item = next(
                    (x for x in self.items if x.status == TransferState.PENDING and x.item_id not in self._paused), None
                )
                if item:
                    item.status = TransferState.PREPARING
                    self._active.add(item.item_id)
            return threads
        while not self.closed and len(self._active) < self.concurrency:
            item = next(
                (x for x in self.items if x.status == TransferState.PENDING and x.item_id not in self._paused), None
            )
            if item is None:
                return threads
            item.status = TransferState.PREPARING
            item.started_at = self.clock()
            item.updated_at = item.started_at
            item.last_progress_at = item.started_at
            self._active.add(item.item_id)
            attempt = self._attempts.get(item.item_id, 0) + 1
            self._attempts[item.item_id] = attempt
            thread = threading.Thread(
                target=self._run,
                args=(item.item_id, self.generation, attempt),
                daemon=True,
                name="sshvault-sftp-transfer",
            )
            self._threads[item.item_id] = thread
            threads.append(thread)
        return threads

    @staticmethod
    def _start_threads(threads: list[threading.Thread]) -> None:
        for thread in threads:
            thread.start()

    def _diagnostic_locked(self, item: TransferItem, worker_id: str, state: str, *, reason: str = "") -> None:
        if not self.debug_transfers:
            return
        self.diagnostic_events.append(
            {
                "transfer_id": item.item_id,
                "worker_id": worker_id,
                "state": state,
                "resume_offset": item.resume_offset,
                "completed_bytes": item.transferred,
                "last_progress_timestamp": item.last_progress_at,
                "reason": reason,
            }
        )

    def _run(self, item_id: str, generation: int, attempt: int) -> None:
        client = None
        worker: TransferWorker | None = None
        try:
            if self.client_factory is None:
                raise RuntimeError("No SFTP client factory is available.")
            channel_started = time.perf_counter()
            client = self.client_factory()
            worker = TransferWorker(self, item_id, attempt, client)
            with self._condition:
                item = self.get(item_id)
                if (
                    item is None
                    or generation != self.generation
                    or attempt != self._attempts.get(item_id)
                    or item_id in self._cancelled_ids
                    or item_id in self._stalled_ids
                ):
                    return
                self._clients[item_id] = client
                item.metrics.channel_creation_seconds += time.perf_counter() - channel_started
                item.status, item.updated_at = (
                    (TransferState.DOWNLOADING if item.direction == "Download" else TransferState.TRANSFERRING),
                    self.clock(),
                )
                self._diagnostic_locked(item, worker.worker_id, "channel-created")
            self._changed()
            operation = self._operations.get(item_id)
            if operation is None:
                raise RuntimeError("No transfer operation is available.")
            operation(item, client, worker)
            with self._condition:
                item = self.get(item_id)
                if (
                    item
                    and generation == self.generation
                    and attempt == self._attempts.get(item_id)
                    and item_id not in self._cancelled_ids
                    and item_id not in self._stalled_ids
                ):
                    item.status = TransferState.COMPLETED
                    self._diagnostic_locked(item, worker.worker_id, TransferState.COMPLETED)
        except InterruptedError:
            with self._condition:
                item = self.get(item_id)
                if (
                    item
                    and generation == self.generation
                    and attempt == self._attempts.get(item_id)
                    and item_id not in self._stalled_ids
                ):
                    item.status = TransferState.CANCELLED
                    self._diagnostic_locked(item, worker.worker_id if worker else "", TransferState.CANCELLED)
        except Exception as exc:
            with self._condition:
                item = self.get(item_id)
                if (
                    item
                    and generation == self.generation
                    and attempt == self._attempts.get(item_id)
                    and item_id not in self._cancelled_ids
                    and item_id not in self._stalled_ids
                ):
                    item.status, item.error = TransferState.FAILED, str(redact_secrets(str(exc)))
                    self._diagnostic_locked(
                        item, worker.worker_id if worker else "", TransferState.FAILED, reason="error"
                    )
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            with self._condition:
                if attempt == self._attempts.get(item_id):
                    self._active.discard(item_id)
                    self._threads.pop(item_id, None)
                    if self._clients.get(item_id) is client:
                        self._clients.pop(item_id, None)
                    threads = self._schedule_locked()
                else:
                    threads = []
                self._condition.notify_all()
                item = self.get(item_id)
                if item is not None:
                    self._diagnostic_locked(item, worker.worker_id if worker else "", "worker-exit")
            self._start_threads(threads)
            self._changed()

    def _checkpoint(
        self, item_id: str, attempt: int, transferred: int | None, total: int | None, worker_id: str
    ) -> None:
        threads: list[threading.Thread] = []
        paused = False
        state_changed = False
        with self._condition:
            item = self.get(item_id)
            if (
                item is None
                or item.generation != self.generation
                or attempt != self._attempts.get(item_id)
                or item_id in self._cancelled_ids
                or item_id in self._stalled_ids
                or self.closed
            ):
                raise InterruptedError("Transfer cancelled")
            now = self.clock()
            if transferred is not None:
                previous, previous_at = item.transferred, item.updated_at or now
                item.transferred = max(item.transferred, transferred)
                delta = max(0, item.transferred - previous)
                elapsed = max(0.001, now - previous_at)
                item.speed = delta / elapsed
                if item.started_at is not None:
                    item.average_speed = item.transferred / max(0.001, now - item.started_at)
                if delta:
                    item.last_progress_at = now
                    self._diagnostic_locked(item, worker_id, "read-write-complete")
            if total is not None:
                item.total = total
            item.updated_at = now
            if item_id in self._paused:
                item.status = TransferState.PAUSED
                self._active.discard(item_id)
                threads = self._schedule_locked()
                paused = True
                state_changed = True
            elif transferred is not None and item.transferred > item.resume_offset:
                # The first completed read/write chunk ends the resume phase.
                next_state = TransferState.DOWNLOADING if item.direction == "Download" else TransferState.TRANSFERRING
                if item.status != next_state:
                    item.status = next_state
                    self._diagnostic_locked(item, worker_id, item.status)
                    state_changed = True
            self._condition.notify_all()
        self._start_threads(threads)
        self._changed(item_id=item_id, progress=True, force=state_changed)
        if paused:
            with self._condition:
                item = self.get(item_id)
                while (
                    item is not None
                    and item_id in self._paused
                    and attempt == self._attempts.get(item_id)
                    and item_id not in self._cancelled_ids
                    and not self.closed
                ):
                    self._condition.wait()
                if (
                    item is None
                    or attempt != self._attempts.get(item_id)
                    or item_id in self._cancelled_ids
                    or item_id in self._stalled_ids
                    or self.closed
                ):
                    raise InterruptedError("Transfer cancelled")
                while len(self._active) >= self.concurrency and not self.closed:
                    self._condition.wait()
                if self.closed:
                    raise InterruptedError("Transfer cancelled")
                self._active.add(item_id)

    def _mark_resuming(self, item_id: str, attempt: int, worker_id: str) -> None:
        with self._condition:
            item = self.get(item_id)
            if (
                item is None
                or attempt != self._attempts.get(item_id)
                or item_id in self._cancelled_ids
                or item_id in self._stalled_ids
                or self.closed
            ):
                raise InterruptedError("Transfer cancelled")
            item.status = TransferState.RESUMING
            item.updated_at = self.clock()
            self._diagnostic_locked(item, worker_id, TransferState.RESUMING)
        self._changed()

    def _cancelled(self, item_id: str, attempt: int) -> bool:
        with self._condition:
            return self.closed or attempt != self._attempts.get(item_id) or item_id in self._cancelled_ids

    def _durable_update_required(self, item_id: str, attempt: int) -> bool:
        with self._condition:
            return (
                self.closed
                or attempt != self._attempts.get(item_id)
                or item_id in self._paused
                or item_id in self._cancelled_ids
                or item_id in self._stalled_ids
            )

    def pause(self, item_id: str) -> bool:
        with self._condition:
            item = self.get(item_id)
            if item is None or item.status not in {
                TransferState.PENDING,
                TransferState.PREPARING,
                TransferState.TRANSFERRING,
                TransferState.RESUMING,
                TransferState.DOWNLOADING,
            }:
                return False
            self._paused.add(item_id)
            if item.status == TransferState.PENDING or self.client_factory is None:
                item.status = TransferState.PAUSED
            self._condition.notify_all()
        self._changed()
        return True

    def resume(self, item_id: str) -> bool:
        with self._condition:
            item = self.get(item_id)
            if item is None or item.status != TransferState.PAUSED:
                return False
            self._paused.discard(item_id)
            # An active worker is sleeping in checkpoint and owns the client;
            # do not launch a second worker for the same item.
            if item_id in self._threads:
                item.status = TransferState.PREPARING
                threads: list[threading.Thread] = []
            else:
                item.status = TransferState.PENDING
                threads = self._schedule_locked()
            self._condition.notify_all()
        self._start_threads(threads)
        self._changed()
        return True

    def cancel(self, item_id: str) -> bool:
        with self._condition:
            item = self.get(item_id)
            if item is None or item.status in TransferState.TERMINAL:
                return False
            self._cancelled_ids.add(item_id)
            self._paused.discard(item_id)
            if item.status in {TransferState.PENDING, TransferState.PAUSED}:
                item.status = TransferState.CANCELLED
            client = self._clients.get(item_id)
            self._condition.notify_all()
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        self._changed()
        return True

    def retry(self, item_id: str) -> bool:
        with self._condition:
            item = self.get(item_id)
            if item is None or item.status not in {TransferState.FAILED, TransferState.CANCELLED}:
                return False
            # A stalled SFTP channel is closed before the row is marked failed.
            # Do not let an uninterruptible legacy channel write beside a retry.
            if item_id in self._threads:
                return False
            # Download operations revalidate their sidecar and resume from the
            # durable partial offset.  Upload retains its historical restart.
            transferred = item.transferred if item.direction == "Download" else 0
            item.status, item.error, item.transferred, item.speed, item.average_speed = (
                TransferState.PENDING,
                "",
                transferred,
                0.0,
                0.0,
            )
            item.restart_required = False
            self._cancelled_ids.discard(item_id)
            self._stalled_ids.discard(item_id)
            item.last_progress_at = None
            threads = self._schedule_locked()
        self._start_threads(threads)
        self._changed()
        return True

    def retry_failed(self) -> None:
        for item in list(self.items):
            if item.status == TransferState.FAILED:
                self.retry(item.item_id)

    def remove(self, item_id: str) -> bool:
        with self._condition:
            item = self.get(item_id)
            if item is None or item.status not in {
                TransferState.PENDING,
                TransferState.PAUSED,
                *TransferState.TERMINAL,
            }:
                return False
            self.items.remove(item)
            self._operations.pop(item_id, None)
        self._changed()
        return True

    def clear_completed(self) -> None:
        for item in list(self.items):
            if item.status == TransferState.COMPLETED:
                self.remove(item.item_id)

    def pause_all(self) -> None:
        for item in list(self.items):
            self.pause(item.item_id)

    def resume_all(self) -> None:
        for item in list(self.items):
            self.resume(item.item_id)

    def cancel_all(self) -> None:
        for item in list(self.items):
            self.cancel(item.item_id)

    def move(self, item_id: str, delta: int) -> bool:
        with self._condition:
            index = next((i for i, x in enumerate(self.items) if x.item_id == item_id), -1)
            if index < 0 or self.items[index].status != TransferState.PENDING:
                return False
            target = index + delta
            if target < 0 or target >= len(self.items) or self.items[target].status != TransferState.PENDING:
                return False
            self.items[index], self.items[target] = self.items[target], self.items[index]
        self._changed()
        return True

    def get(self, item_id: str) -> TransferItem | None:
        return next((x for x in self.items if x.item_id == item_id), None)

    def summary(self) -> dict[str, float | int]:
        with self._condition:
            active = [
                x
                for x in self.items
                if x.status
                in {
                    TransferState.PREPARING,
                    TransferState.TRANSFERRING,
                    TransferState.DOWNLOADING,
                    TransferState.RESUMING,
                    TransferState.VERIFYING,
                }
            ]
            return {
                "active": len(active),
                "pending": sum(x.status == TransferState.PENDING for x in self.items),
                "completed": sum(x.status == TransferState.COMPLETED for x in self.items),
                "failed": sum(x.status == TransferState.FAILED for x in self.items),
                "speed": sum(x.speed for x in active),
                "transferred": sum(x.transferred for x in self.items),
            }

    def invalidate_session(self, fail_active: bool = False) -> None:
        with self._condition:
            self.generation += 1
            for item in self.items:
                if item.status not in TransferState.TERMINAL:
                    item.status = TransferState.FAILED if fail_active else TransferState.PAUSED
                    if fail_active:
                        item.error = "SFTP session disconnected"
            self._cancelled_ids.update(self._active)
            clients = list(self._clients.values())
            self._condition.notify_all()
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        self._changed()

    def shutdown(self, timeout: float = 1.0) -> None:
        with self._condition:
            self.closed = True
            for item in self.items:
                if item.status not in TransferState.TERMINAL:
                    item.status = TransferState.CANCELLED
            self._cancelled_ids.update(self._active)
            threads = list(self._threads.values())
            clients = list(self._clients.values())
            self._condition.notify_all()
        self._monitor_stop.set()
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=timeout)
        if self._monitor_thread is not None and self._monitor_thread is not threading.current_thread():
            self._monitor_thread.join(timeout=timeout)
        self._changed()

    def _monitor_stalls(self) -> None:
        while not self._monitor_stop.wait(self.monitor_interval):
            self.check_stalls()

    def check_stalls(self) -> list[str]:
        """Fail stalled workers without holding the scheduler lock for cleanup.

        Closing a worker-owned SFTP client closes only its channel.  Paramiko
        uses the already verified shared transport underneath, which remains
        available to browsing and the other worker channels.
        """
        threads: list[threading.Thread] = []
        clients: list[Any] = []
        stalled: list[str] = []
        with self._condition:
            now = self.clock()
            for item_id in list(self._active):
                item = self.get(item_id)
                if item is None or item.last_progress_at is None:
                    continue
                if now - item.last_progress_at < self.stall_timeout:
                    continue
                item.status = TransferState.FAILED
                item.error = "Transfer stalled: no completed read/write progress."
                self._stalled_ids.add(item_id)
                self._active.discard(item_id)
                stalled.append(item_id)
                client = self._clients.get(item_id)
                if client is not None:
                    clients.append(client)
                self._diagnostic_locked(item, "", TransferState.FAILED, reason="stall")
            if stalled:
                threads = self._schedule_locked()
                self._condition.notify_all()
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        self._start_threads(threads)
        if stalled:
            self._changed()
        return stalled

    def _changed(self, *, item_id: str | None = None, progress: bool = False, force: bool = True) -> None:
        if progress and item_id is not None and not force:
            now = self.clock()
            with self._condition:
                if now - self._last_progress_notifications.get(item_id, float("-inf")) < SFTP_PROGRESS_INTERVAL:
                    return
                self._last_progress_notifications[item_id] = now
                item = self.get(item_id)
                if item is not None:
                    item.metrics.ui_progress_callbacks += 1
        elif progress and item_id is not None:
            with self._condition:
                item = self.get(item_id)
                if item is not None:
                    item.metrics.ui_progress_callbacks += 1
        if self.on_change:
            self.on_change()


def safe_transfer_plan(root: str | Path, relative_paths: list[str]) -> list[tuple[Path, str]]:
    """Build a root-confined plan, rejecting traversal and symlink loops."""
    base = Path(root).resolve()
    plan: list[tuple[Path, str]] = []
    for raw in relative_paths:
        candidate = (base / raw).resolve()
        if candidate != base and base not in candidate.parents:
            raise ProfileError("Transfer path escapes the selected root.")
        if candidate.is_symlink():
            raise ProfileError("Symlinks are not followed during recursive transfer.")
        if candidate.is_dir():
            for child in candidate.rglob("*"):
                if child.is_symlink():
                    continue
                if child.is_file():
                    plan.append((child, str(child.relative_to(base))))
        elif candidate.is_file():
            plan.append((candidate, str(candidate.relative_to(base))))
    return plan


class TransferQueueManager(TransferScheduler):
    """Compatibility facade for the former queue API.

    New code should use :class:`TransferScheduler`; this facade preserves the
    small display-free API used by existing callers.
    """

    def __init__(self, generation: int = 0, concurrency: int = 3) -> None:
        super().__init__(None, 1)
        self.generation = generation

    def mark_transferring(self) -> bool:
        item = self.active
        if item is None:
            return False
        item.status = TransferState.TRANSFERRING
        return True

    def complete(self, item_id: str, *, error: str = "") -> bool:
        item = self.get(item_id)
        if item is None or item.generation != self.generation:
            return False
        item.status, item.error = (TransferState.FAILED if error else TransferState.COMPLETED), error
        with self._condition:
            self._active.discard(item_id)
            threads = self._schedule_locked()
        self._start_threads(threads)
        return True


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
    unseen_output: bool = False

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

    def note_output(self) -> None:
        if not self.follow_output:
            self.unseen_output = True

    def jump_to_bottom(self) -> None:
        self.follow_output = True
        self.unseen_output = False

    @staticmethod
    def requires_paste_confirmation(text: str) -> bool:
        return "\n" in text or "\r" in text

    @staticmethod
    def terminal_size(width: int, height: int, char_width: int, char_height: int) -> tuple[int, int]:
        return max(1, (max(0, width) - 8) // max(1, char_width)), max(1, (max(0, height) - 4) // max(1, char_height))


def terminal_key_sequence(keysym: str, char: str = "", state: int = 0, *, application_cursor: bool = False) -> str:
    """Translate a Tk key event to bytes understood by an xterm-compatible PTY.

    This deliberately has no Tk dependency so recorded key events can be
    regression-tested without a display.
    """
    shift, control, alt = bool(state & 0x0001), bool(state & 0x0004), bool(state & 0x0008)
    cursor = {"Up": "A", "Down": "B", "Right": "C", "Left": "D", "Home": "H", "End": "F"}
    if keysym in cursor:
        if control or alt or shift:
            modifier = 1 + shift + 4 * control + 2 * alt
            return f"\x1b[1;{modifier}{cursor[keysym]}"
        return f"\x1bO{cursor[keysym]}" if application_cursor else f"\x1b[{cursor[keysym]}"
    fixed = {
        "Delete": "\x1b[3~",
        "Insert": "\x1b[2~",
        "Prior": "\x1b[5~",
        "Next": "\x1b[6~",
        "Return": "\r",
        "KP_Enter": "\r",
        "Tab": "\t",
        "ISO_Left_Tab": "\x1b[Z",
        "Escape": "\x1b",
        "BackSpace": "\x7f",
    }
    if keysym in fixed:
        return fixed[keysym]
    if keysym.startswith("F") and keysym[1:].isdigit():
        return {
            1: "\x1bOP",
            2: "\x1bOQ",
            3: "\x1bOR",
            4: "\x1bOS",
            5: "\x1b[15~",
            6: "\x1b[17~",
            7: "\x1b[18~",
            8: "\x1b[19~",
            9: "\x1b[20~",
            10: "\x1b[21~",
            11: "\x1b[23~",
            12: "\x1b[24~",
        }.get(int(keysym[1:]), "")
    if control and len(char) == 1 and char.isalpha():
        return chr(ord(char.upper()) - ord("@"))
    if alt and char:
        return "\x1b" + char
    return char


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
    result = {
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
    defaults = default_profile_sections(raw)
    for section in (
        "login_options",
        "terminal_options",
        "sftp_options",
        "tunnel_options",
        "connection_options",
        "launch_preferences",
    ):
        value = raw.get(section)
        result[section] = value if isinstance(value, dict) else defaults[section]
    return result


def profile_identity(profile: dict[str, Any]) -> tuple[str, int, str]:
    return (str(profile["host"]).lower(), int(profile["port"]), str(profile["user"]).lower())


def validate_proxy_chain(profile: dict[str, Any], profiles: list[dict[str, Any]]) -> None:
    """Reject missing, self-referential, and circular ProxyJump chains."""
    by_name = {str(item.get("name", "")).casefold(): item for item in profiles}
    current = profile
    seen: set[str] = set()
    while True:
        name = str(current.get("name", "")).casefold()
        if name in seen:
            raise ProfileError("ProxyJump cycle detected: " + " → ".join(sorted(seen)))
        seen.add(name)
        target = str(current.get("proxy_jump", "")).strip()
        if not target:
            return
        if target.casefold() == name:
            raise ProfileError("A profile cannot use itself as ProxyJump.")
        next_profile = by_name.get(target.casefold())
        if next_profile is None:
            raise ProfileError(f"ProxyJump profile not found: {target}.")
        current = next_profile


def validate_environment(environment: dict[str, Any]) -> dict[str, str]:
    if not isinstance(environment, dict):
        raise ProfileError("Environment variables must be an object.")
    result: dict[str, str] = {}
    for key, value in environment.items():
        name = str(key)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ProfileError(f"Invalid environment variable name: {name}.")
        if name in result:
            raise ProfileError(f"Duplicate environment variable: {name}.")
        result[name] = str(value)
    return result


def validate_tunnel_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        raise ProfileError("Tunnel rules must be a list.")
    result: list[dict[str, Any]] = []
    endpoints: set[tuple[str, int]] = set()
    for raw in rules:
        rule = dict(raw)
        kind = str(rule.get("type", "Local"))
        if kind not in {"Local", "Remote", "SOCKS"}:
            raise ProfileError("Tunnel type must be Local, Remote, or SOCKS.")
        bind_port = validate_port(rule.get("bind_port", 0)) if rule.get("bind_port", 0) else 0
        destination_port = validate_port(rule.get("destination_port", 0)) if rule.get("destination_port", 0) else 0
        if kind != "SOCKS" and (not str(rule.get("destination_host", "")).strip() or not destination_port):
            raise ProfileError("Local and Remote tunnels require a destination host and port.")
        if kind == "SOCKS":
            destination_port, rule["destination_host"] = 0, ""
        endpoint = (str(rule.get("bind_address", "127.0.0.1")), bind_port)
        if bool(rule.get("enabled", True)) and endpoint in endpoints:
            raise ProfileError("Enabled tunnel bind endpoints must be unique.")
        endpoints.add(endpoint)
        rule.update(
            {
                "rule_id": str(rule.get("rule_id") or uuid4()),
                "enabled": bool(rule.get("enabled", True)),
                "type": kind,
                "bind_port": bind_port,
                "destination_port": destination_port,
                "description": str(rule.get("description", ""))[:200],
            }
        )
        result.append(rule)
    return result


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
