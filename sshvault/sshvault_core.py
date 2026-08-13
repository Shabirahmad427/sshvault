"""Storage, validation, secret handling, and safe connection helpers for SSHVault.

This module deliberately has no Tk dependencies so its behavior can be tested
without a display or a live SSH server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import errno
import ipaddress
import hashlib
import json
import os
import platform
import posixpath
import select
import socket
import socketserver
import subprocess
import secrets
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
    "restore_previous_sessions_on_start",
    "transfer_manager_window",
    "load_last_selected_profile",
    "login_automatically_on_start",
    "restore_window_position",
    "last_selected_profile_id",
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
    "restore_previous_sessions_on_start": False,
    "transfer_manager_window": {},
    # Startup stays passive unless the user explicitly opts in.
    "load_last_selected_profile": True,
    "login_automatically_on_start": False,
    "restore_window_position": True,
    "last_selected_profile_id": "",
}
SFTP_TRANSFER_CHUNK_SIZES = (65536, 131072, 262144, 524288, 1048576, 2097152)
SFTP_SIDECAR_PROGRESS_BYTES = 16 * 1024 * 1024
SFTP_SIDECAR_PROGRESS_SECONDS = 5.0
SFTP_PROGRESS_INTERVAL = 0.25
SFTP_PREFETCH_DEPTHS = (4, 8, 16, 32)
SFTP_PREFETCH_WORKER_MEMORY_LIMIT = 32 * 1024 * 1024
SFTP_PREFETCH_TOTAL_MEMORY_LIMIT = 96 * 1024 * 1024

OPTIONS_GROUPS = ("On successful login", "Application startup", "On logout")
POST_LOGIN_OPTION_LABELS = (
    "Open Terminal",
    "Open SFTP",
    "Start enabled services",
    "Run configured startup commands",
)
APPLICATION_STARTUP_OPTION_LABELS = (
    "Load last selected profile",
    "Log in automatically",
    "Restore previous sessions",
    "Restore window position",
)
LOGOUT_OPTION_LABELS = (
    "Close terminal windows",
    "Close SFTP windows",
    "Stop enabled services",
    "Ask before cancelling active transfers",
)
TERMINAL_GROUPS = ("Terminal Emulation", "Appearance", "Session Behavior", "Terminal Actions")
TERMINAL_BACKENDS = ("Automatic", "Native VTE", "Legacy")
TERMINAL_BELLS = ("System bell", "Visual bell", "Disabled")
TERMINAL_CURSOR_SHAPES = ("Block", "I-Beam", "Underline")
TERMINAL_COLOR_THEMES = ("System", "Light", "Dark")
SERVICES_SECTIONS = ("Port Forwarding", "SOCKS/HTTP Proxy", "X11 Forwarding")
X11_FORWARDING_OPTION_LABELS = (
    "Enable X11 forwarding",
    "Trusted forwarding",
    "X11 display",
)
PORT_FORWARDING_COLUMNS = (
    "Enabled",
    "Type",
    "Listen Host",
    "Listen Port",
    "Destination Host",
    "Destination Port",
)
PORT_FORWARDING_RUNTIME_COLUMNS = PORT_FORWARDING_COLUMNS + ("Status",)
PORT_FORWARDING_TYPES = ("Local", "Remote", "Dynamic", "HTTP")
CONTROLLER_REGION_ORDER = (
    "Profile heading",
    "Profile rail / Configuration notebook",
    "Connection log",
    "Login/status strip",
)
CONTROLLER_DEFAULT_GEOMETRY = (1050, 720)
CONTROLLER_MINIMUM_GEOMETRY = (900, 620)
SECTION_PADDING = 6
SFTP_GROUPS = ("Directory Defaults", "Transfer Defaults", "SFTP Actions")
SFTP_OVERWRITE_BEHAVIORS = ("Ask", "Overwrite", "Skip", "Rename")
SSH_SETTING_LABELS = (
    "Enable compression",
    "TCP keepalive",
    "Keepalive interval",
    "Maximum missed keepalives",
    "Agent forwarding",
    "Preferred key-exchange algorithm",
    "Preferred host-key algorithm",
    "Preferred cipher",
    "Preferred MAC",
)
SSH_KEY_EXCHANGE_CHOICES = (
    "Automatic",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
)
SSH_HOST_KEY_CHOICES = (
    "Automatic",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
)
SSH_CIPHER_CHOICES = (
    "Automatic",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
)
SSH_MAC_CHOICES = (
    "Automatic",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
)


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
            # Deliberately opt-in: older installations must never begin
            # connecting merely because they have a session file.
            "restore_previous_sessions_on_start": bool(raw.get("restore_previous_sessions_on_start", False)),
            "load_last_selected_profile": bool(raw.get("load_last_selected_profile", True)),
            "login_automatically_on_start": bool(raw.get("login_automatically_on_start", False)),
            "restore_window_position": bool(raw.get("restore_window_position", True)),
            "last_selected_profile_id": str(raw.get("last_selected_profile_id", "")).strip(),
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
    verify_transfers: bool = True
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

    # Keep the user-visible post-login order deterministic.  The historical
    # ``tunnels`` handler is the existing services implementation.
    ORDER = ("tunnels", "command", "terminal", "sftp")

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
            "tunnels": bool(
                preferences.get("start_enabled_services")
                or preferences.get("start_enabled_tunnels")
                or preferences.get("restart_tunnels")
            ),
            "terminal": bool(preferences.get("open_terminal", False)),
            "sftp": bool(preferences.get("open_sftp", False)),
            "command": bool(preferences.get("run_startup_commands", False))
            and bool(str(preferences.get("startup_command", "")).strip()),
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
    open_terminal: bool = False
    open_sftp: bool = False
    start_enabled_services: bool = False
    run_startup_commands: bool = False
    startup_command: str = ""


def default_ssh_preferences() -> dict[str, Any]:
    """Return passive defaults for the not-yet-runtime-bound SSH controls."""
    return {
        "compression": False,
        "tcp_keepalive": False,
        "keepalive_interval": 0,
        "maximum_missed_keepalives": 3,
        "agent_forwarding": False,
        "preferred_key_exchange": "Automatic",
        "preferred_host_key": "Automatic",
        "preferred_cipher": "Automatic",
        "preferred_mac": "Automatic",
    }


def validate_ssh_preferences(raw: object) -> dict[str, Any]:
    """Normalize safe SSH-tab values without applying them to a connection."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ProfileError("SSH preferences must be an object.")
    result = default_ssh_preferences()
    result.update(raw)
    for key, label in (
        ("compression", "Compression"),
        ("tcp_keepalive", "TCP keepalive"),
        ("agent_forwarding", "Agent forwarding"),
    ):
        if not isinstance(result[key], bool):
            raise ProfileError(f"{label} must be enabled or disabled.")
    for key, label, minimum, maximum in (
        ("keepalive_interval", "Keepalive interval", 0, 3600),
        ("maximum_missed_keepalives", "Maximum missed keepalives", 1, 20),
    ):
        value = result[key]
        if isinstance(value, (bool, float)):
            raise ProfileError(f"{label} must be a whole number from {minimum} to {maximum}.")
        try:
            value = int(str(value))
        except (TypeError, ValueError) as exc:
            raise ProfileError(f"{label} must be a whole number from {minimum} to {maximum}.") from exc
        if not minimum <= value <= maximum:
            raise ProfileError(f"{label} must be between {minimum} and {maximum}.")
        result[key] = value
    for key, label, choices in (
        ("preferred_key_exchange", "key-exchange algorithm", SSH_KEY_EXCHANGE_CHOICES),
        ("preferred_host_key", "host-key algorithm", SSH_HOST_KEY_CHOICES),
        ("preferred_cipher", "cipher", SSH_CIPHER_CHOICES),
        ("preferred_mac", "MAC", SSH_MAC_CHOICES),
    ):
        value = str(result[key]).strip()
        if value not in choices:
            raise ProfileError(f"Unsupported preferred {label}.")
        result[key] = value
    return result


def ssh_preferences_from_profile(profile: object) -> dict[str, Any]:
    """Read a profile's SSH preferences with backward-compatible defaults."""
    if not isinstance(profile, dict):
        return default_ssh_preferences()
    connection_options = profile.get("connection_options", {})
    if not isinstance(connection_options, dict):
        return default_ssh_preferences()
    stored = connection_options.get("ssh_preferences")
    if stored is None:
        legacy = default_ssh_preferences()
        legacy["compression"] = bool(profile.get("compression", False))
        terminal_options = profile.get("terminal_options", {})
        if isinstance(terminal_options, dict):
            legacy["agent_forwarding"] = bool(terminal_options.get("agent_forwarding", False))
        return validate_ssh_preferences(legacy)
    return validate_ssh_preferences(stored)


def set_working_ssh_preference(profile: dict[str, Any], key: str, value: Any) -> None:
    """Update only the supplied working profile; persistence remains explicit."""
    if key not in default_ssh_preferences():
        raise ProfileError("Unsupported SSH preference.")
    connection_options = dict(profile.get("connection_options", {}))
    preferences = dict(connection_options.get("ssh_preferences", {}))
    preferences[key] = value
    connection_options["ssh_preferences"] = preferences
    profile["connection_options"] = connection_options


@dataclass(frozen=True)
class SSHRuntimePreferences:
    """Validated per-host settings captured from one session snapshot."""

    compression: bool
    tcp_keepalive: bool
    keepalive_interval: int
    maximum_missed_keepalives: int
    agent_forwarding: bool
    preferred_key_exchange: str | None
    preferred_host_key: str | None
    preferred_cipher: str | None
    preferred_mac: str | None

    @property
    def algorithm_preferences(self) -> dict[str, str]:
        return {
            key: value
            for key, value in (
                ("kex", self.preferred_key_exchange),
                ("host_key", self.preferred_host_key),
                ("cipher", self.preferred_cipher),
                ("mac", self.preferred_mac),
            )
            if value is not None
        }


def ssh_runtime_preferences(profile: object) -> SSHRuntimePreferences:
    """Build one immutable runtime policy; Automatic values are omitted."""
    values = ssh_preferences_from_profile(profile)

    def selected(key: str) -> str | None:
        value = str(values[key])
        return None if value == "Automatic" else value

    return SSHRuntimePreferences(
        compression=bool(values["compression"]),
        tcp_keepalive=bool(values["tcp_keepalive"]),
        keepalive_interval=int(values["keepalive_interval"]),
        maximum_missed_keepalives=int(values["maximum_missed_keepalives"]),
        agent_forwarding=bool(values["agent_forwarding"]),
        preferred_key_exchange=selected("preferred_key_exchange"),
        preferred_host_key=selected("preferred_host_key"),
        preferred_cipher=selected("preferred_cipher"),
        preferred_mac=selected("preferred_mac"),
    )


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
            "scrollback": 10000,
            "starting_directory": str(raw.get("startup_directory", "")),
            "startup_command": str(raw.get("startup_command", "")),
            "environment": {},
            "auto_open": True,
            "font_override": False,
            "font_size": 10,
            "backend": "Automatic",
            "font": "Monospace",
            "cursor_shape": "Block",
            "cursor_blink": True,
            "bell": "System bell",
            "color_theme": "System",
            "agent_forwarding": False,
            "x11_forwarding": False,
            "x11_trusted": False,
            "x11_display": "",
            "close_on_logout": False,
            "scroll_on_output": False,
            "scroll_on_keystroke": True,
        },
        "sftp_options": {
            "initial_local_directory": "",
            "initial_remote_directory": "",
            "collision_behavior": "ask",
            "preserve_timestamps": False,
            "verify_transfers": True,
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
            "ssh_preferences": default_ssh_preferences(),
        },
        "launch_preferences": {
            "open_terminal": False,
            "open_sftp": False,
            "start_enabled_services": False,
            "run_startup_commands": False,
            "startup_command": "",
        },
    }


X11_FORWARDING_STATUSES = ("Stopped", "Active", "Failed")


def normalized_x11_forwarding_options(options: object) -> dict[str, Any]:
    """Return the secret-free X11 options used by one connection snapshot."""
    values = options if isinstance(options, dict) else {}
    return {
        "enabled": bool(values.get("x11_forwarding", False)),
        "trusted": bool(values.get("x11_trusted", False)),
        "display": str(values.get("x11_display", "")).strip(),
    }


def x11_display_screen(display: str) -> int:
    """Extract the X11 screen number without exposing or validating host data."""
    match = re.search(r":\d+(?:\.(\d+))?$", display.strip())
    if match is None or match.group(1) is None:
        return 0
    return int(match.group(1))


class X11ForwardingSession:
    """Session-scoped X11 request policy for newly opened SSH channels."""

    def __init__(
        self,
        session_id: str,
        terminal_options: object,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.options = normalized_x11_forwarding_options(terminal_options)
        self._environment = dict(os.environ if environment is None else environment)
        self.status = "Stopped"
        self.error = ""
        self.closed = False
        self.request_count = 0
        self.last_request: dict[str, Any] | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.options["enabled"])

    @property
    def trusted(self) -> bool:
        return bool(self.options["trusted"])

    @property
    def display(self) -> str:
        explicit = str(self.options["display"])
        return explicit or str(self._environment.get("DISPLAY", "")).strip()

    def request_for_channel(self, channel: Any) -> bool:
        """Request X11 on one channel; failure never escapes to the SSH session."""
        if self.closed or not self.enabled:
            return False
        display = self.display
        if not display:
            self.status = "Failed"
            self.error = "X11 display is unavailable."
            return False
        request = {
            "display": display,
            "trusted": self.trusted,
            "screen_number": x11_display_screen(display),
        }
        self.last_request = request
        try:
            # SSH's channel request carries screen/cookie data. Trusted versus
            # untrusted is a client policy; OpenSSH receives -Y/-X separately.
            channel.request_x11(
                screen_number=request["screen_number"],
                single_connection=False,
            )
        except Exception:
            self.status = "Failed"
            self.error = "X11 forwarding request failed."
            return False
        self.request_count += 1
        self.status = "Active"
        self.error = ""
        return True

    def close(self) -> None:
        """Forget this session's X11 policy without affecting other sessions."""
        if self.closed:
            return
        self.closed = True
        self.status = "Stopped"


def normalized_launch_preferences(raw: object) -> dict[str, Any]:
    """Return safe, profile-scoped post-login preferences.

    These are intentionally separate from the application startup settings.
    Old profiles load with passive defaults and are only changed on an explicit
    profile save.
    """
    source = raw if isinstance(raw, dict) else {}
    return {
        "open_terminal": bool(source.get("open_terminal", False)),
        "open_sftp": bool(source.get("open_sftp", False)),
        "start_enabled_services": bool(source.get("start_enabled_services", False)),
        "run_startup_commands": bool(source.get("run_startup_commands", False)),
        "startup_command": str(source.get("startup_command", "")).strip(),
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
        if self.kind not in {"Local", "Remote", "Dynamic/SOCKS", "HTTP"}:
            return "Choose a tunnel type."
        try:
            validate_host(self.bind_host)
            validate_port(self.bind_port)
        except ProfileError as exc:
            return str(exc)
        if self.kind not in {"Dynamic/SOCKS", "HTTP"}:
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
        return {"bind": True, "destination": self.kind not in {"Dynamic/SOCKS", "HTTP"}}


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


LOCAL_FORWARDING_STATUSES = ("Stopped", "Starting", "Active", "Failed")


@dataclass
class LocalForwardingRuleRuntime:
    """Session-owned status for one immutable forwarding-rule snapshot."""

    rule: dict[str, Any]
    status: str = "Stopped"
    error: str = ""


class LocalForwardingSession:
    """Own enabled Local listeners for exactly one authenticated session."""

    def __init__(
        self,
        session_id: str,
        transport: Any,
        rules: list[dict[str, Any]],
        starter: Callable[[RunningTunnel], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.manager = TunnelManager(transport, id(transport))
        self.starter = starter
        self.rules = json.loads(json.dumps(rules))
        self.records: dict[str, LocalForwardingRuleRuntime] = {}
        for rule in self.rules:
            rule_id = str(rule.get("rule_id") or uuid4())
            rule["rule_id"] = rule_id
            self.records[rule_id] = LocalForwardingRuleRuntime(rule)
        self.closed = False

    def start_enabled(self) -> dict[str, LocalForwardingRuleRuntime]:
        if self.closed:
            return self.records
        for record in self.records.values():
            if record.rule.get("type") != "Local" or not bool(record.rule.get("enabled", True)):
                continue
            if record.status in {"Starting", "Active"}:
                continue
            record.status = "Starting"
            record.error = ""
            try:
                self.manager.start(record.rule, self.starter)
            except Exception as exc:
                record.status = "Failed"
                record.error = str(redact_secrets(str(exc)))
                continue
            record.status = "Active"
        return self.records

    def stop_all(self) -> None:
        if self.closed:
            return
        self.manager.stop_all()
        for record in self.records.values():
            if record.status in {"Starting", "Active"}:
                record.status = "Stopped"
        self.closed = True

    def status(self, rule_id: str) -> str:
        record = self.records.get(rule_id)
        return record.status if record is not None else "Stopped"

    def active_rule_ids(self) -> list[str]:
        return [rule_id for rule_id, record in self.records.items() if record.status == "Active"]


def start_local_forwarding_listener(running: RunningTunnel, transport: Any) -> None:
    """Bind one local listener and bridge accepted sockets through *transport*."""
    rule = running.rule
    listen_host = str(rule["bind_address"])
    listen_port = int(rule["bind_port"])
    destination = (str(rule["destination_host"]), int(rule["destination_port"]))

    class ForwardingHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            channel = None
            try:
                channel = transport.open_channel(
                    "direct-tcpip",
                    destination,
                    self.request.getpeername(),
                )
                if channel is None:
                    return
                while not running.runtime.stop_event.is_set():
                    readable, _, _ = select.select([self.request, channel], [], [], 0.2)
                    if self.request in readable:
                        data = self.request.recv(65536)
                        if not data:
                            break
                        channel.sendall(data)
                    if channel in readable:
                        data = channel.recv(65536)
                        if not data:
                            break
                        self.request.sendall(data)
            except (OSError, EOFError):
                return
            finally:
                if channel is not None:
                    try:
                        channel.close()
                    except Exception:
                        pass

    address_family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET

    class ForwardingServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = False
        daemon_threads = True

        def close(self) -> None:
            self.server_close()

    ForwardingServer.address_family = address_family
    server = ForwardingServer((listen_host, listen_port), ForwardingHandler)
    server.timeout = 0.2
    running.runtime.listener = server

    def serve() -> None:
        try:
            while not running.runtime.stop_event.is_set():
                try:
                    server.handle_request()
                except OSError:
                    break
        finally:
            server.server_close()

    thread = threading.Thread(
        target=serve,
        daemon=True,
        name=f"sshvault-local-forward-{listen_port}",
    )
    running.runtime.thread = thread
    thread.start()


REMOTE_FORWARDING_STATUSES = LOCAL_FORWARDING_STATUSES


@dataclass
class RemoteForwardingRuleRuntime:
    """Session-owned status for one immutable Remote forwarding rule."""

    rule: dict[str, Any]
    status: str = "Stopped"
    error: str = ""


class RemoteForwardingSession:
    """Own enabled Remote listeners for exactly one authenticated session."""

    def __init__(
        self,
        session_id: str,
        transport: Any,
        rules: list[dict[str, Any]],
        starter: Callable[[RunningTunnel], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.manager = TunnelManager(transport, id(transport))
        self.starter = starter
        self.rules = json.loads(json.dumps(rules))
        self.records: dict[str, RemoteForwardingRuleRuntime] = {}
        for rule in self.rules:
            rule_id = str(rule.get("rule_id") or uuid4())
            rule["rule_id"] = rule_id
            self.records[rule_id] = RemoteForwardingRuleRuntime(rule)
        self.closed = False

    def start_enabled(self) -> dict[str, RemoteForwardingRuleRuntime]:
        if self.closed:
            return self.records
        for record in self.records.values():
            if record.rule.get("type") != "Remote" or not bool(record.rule.get("enabled", True)):
                continue
            if record.status in {"Starting", "Active"}:
                continue
            record.status = "Starting"
            record.error = ""
            try:
                self.manager.start(record.rule, self.starter)
            except Exception as exc:
                record.status = "Failed"
                record.error = str(redact_secrets(str(exc)))
                continue
            record.status = "Active"
        return self.records

    def stop_all(self) -> None:
        if self.closed:
            return
        self.manager.stop_all()
        for record in self.records.values():
            if record.status in {"Starting", "Active"}:
                record.status = "Stopped"
        self.closed = True

    def status(self, rule_id: str) -> str:
        record = self.records.get(rule_id)
        return record.status if record is not None else "Stopped"

    def active_rule_ids(self) -> list[str]:
        return [rule_id for rule_id, record in self.records.items() if record.status == "Active"]


def start_remote_forwarding_listener(running: RunningTunnel, transport: Any) -> None:
    """Request one server-side listener and bridge its channels locally."""
    rule = running.rule
    listen_host = str(rule["bind_address"])
    listen_port = int(rule["bind_port"])
    destination = (str(rule["destination_host"]), int(rule["destination_port"]))

    def bridge(channel: Any) -> None:
        local_socket = None
        try:
            local_socket = socket.create_connection(destination)
            while not running.runtime.stop_event.is_set():
                readable, _, _ = select.select([local_socket, channel], [], [], 0.2)
                if local_socket in readable:
                    data = local_socket.recv(65536)
                    if not data:
                        break
                    channel.sendall(data)
                if channel in readable:
                    data = channel.recv(65536)
                    if not data:
                        break
                    local_socket.sendall(data)
        except (OSError, EOFError):
            return
        finally:
            if local_socket is not None:
                local_socket.close()
            try:
                channel.close()
            except Exception:
                pass

    def handler(channel: Any, _origin: Any, _server: Any) -> None:
        threading.Thread(
            target=bridge,
            args=(channel,),
            daemon=True,
            name=f"sshvault-remote-forward-{listen_port}",
        ).start()

    transport.request_port_forward(listen_host, listen_port, handler=handler)

    class RemoteForwardHandle:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            transport.cancel_port_forward(listen_host, listen_port)

    running.runtime.listener = RemoteForwardHandle()


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


def open_socks5_connect_channel(data: bytes, transport: Any, origin: tuple[str, int]) -> Any:
    """Open one SSH channel for a validated SOCKS5 CONNECT request."""
    target = parse_socks5_connect(data)
    if target is None:
        raise ProfileError("Only SOCKS5 CONNECT requests are supported.")
    channel = transport.open_channel("direct-tcpip", target, origin)
    if channel is None:
        raise ProfileError("SOCKS5 destination connection failed.")
    return channel


DYNAMIC_FORWARDING_STATUSES = LOCAL_FORWARDING_STATUSES


@dataclass
class DynamicForwardingRuleRuntime:
    """Session-owned status for one immutable Dynamic forwarding rule."""

    rule: dict[str, Any]
    status: str = "Stopped"
    error: str = ""


class DynamicForwardingSession:
    """Own enabled SOCKS5 listeners for exactly one authenticated session."""

    def __init__(
        self,
        session_id: str,
        transport: Any,
        rules: list[dict[str, Any]],
        starter: Callable[[RunningTunnel], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.manager = TunnelManager(transport, id(transport))
        self.starter = starter
        self.rules = json.loads(json.dumps(rules))
        self.records: dict[str, DynamicForwardingRuleRuntime] = {}
        for rule in self.rules:
            rule_id = str(rule.get("rule_id") or uuid4())
            rule["rule_id"] = rule_id
            self.records[rule_id] = DynamicForwardingRuleRuntime(rule)
        self.closed = False

    def start_enabled(self) -> dict[str, DynamicForwardingRuleRuntime]:
        if self.closed:
            return self.records
        for record in self.records.values():
            if record.rule.get("type") not in {"SOCKS", "Dynamic", "Dynamic/SOCKS"} or not bool(
                record.rule.get("enabled", True)
            ):
                continue
            if record.status in {"Starting", "Active"}:
                continue
            record.status = "Starting"
            record.error = ""
            try:
                self.manager.start(record.rule, self.starter)
            except Exception as exc:
                record.status = "Failed"
                record.error = str(redact_secrets(str(exc)))
                continue
            record.status = "Active"
        return self.records

    def stop_all(self) -> None:
        if self.closed:
            return
        self.manager.stop_all()
        for record in self.records.values():
            if record.status in {"Starting", "Active"}:
                record.status = "Stopped"
        self.closed = True

    def status(self, rule_id: str) -> str:
        record = self.records.get(rule_id)
        return record.status if record is not None else "Stopped"

    def active_rule_ids(self) -> list[str]:
        return [rule_id for rule_id, record in self.records.items() if record.status == "Active"]


def start_dynamic_forwarding_listener(running: RunningTunnel, transport: Any) -> None:
    """Bind one TCP SOCKS5 CONNECT listener backed by SSH direct channels."""
    listen_host = str(running.rule["bind_address"])
    listen_port = int(running.rule["bind_port"])

    def receive_exact(client: Any, count: int) -> bytes:
        result = bytearray()
        while len(result) < count:
            chunk = client.recv(count - len(result))
            if not chunk:
                raise EOFError
            result.extend(chunk)
        return bytes(result)

    def receive_request(client: Any) -> bytes:
        header = receive_exact(client, 4)
        atyp = header[3]
        if atyp == 1:
            address = receive_exact(client, 4)
        elif atyp == 3:
            length = receive_exact(client, 1)
            address = length + receive_exact(client, length[0])
        elif atyp == 4:
            address = receive_exact(client, 16)
        else:
            address = b""
        return header + address + receive_exact(client, 2)

    class Socks5Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            client = self.request
            channel = None
            try:
                version, method_count = receive_exact(client, 2)
                methods = receive_exact(client, method_count)
                if version != 5 or 0 not in methods:
                    client.sendall(b"\x05\xff")
                    return
                client.sendall(b"\x05\x00")
                request = receive_request(client)
                if request[1] != 1:
                    client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                    return
                channel = open_socks5_connect_channel(
                    request,
                    transport,
                    client.getpeername(),
                )
                client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                while not running.runtime.stop_event.is_set():
                    readable, _, _ = select.select([client, channel], [], [], 0.2)
                    if client in readable:
                        data = client.recv(65536)
                        if not data:
                            break
                        channel.sendall(data)
                    if channel in readable:
                        data = channel.recv(65536)
                        if not data:
                            break
                        client.sendall(data)
            except (EOFError, OSError, ProfileError):
                if channel is None:
                    try:
                        client.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                    except OSError:
                        pass
            finally:
                if channel is not None:
                    try:
                        channel.close()
                    except Exception:
                        pass

    address_family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET

    class Socks5Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = False
        daemon_threads = True

        def close(self) -> None:
            self.server_close()

    Socks5Server.address_family = address_family
    server = Socks5Server((listen_host, listen_port), Socks5Handler)
    server.timeout = 0.2
    running.runtime.listener = server

    def serve() -> None:
        try:
            while not running.runtime.stop_event.is_set():
                try:
                    server.handle_request()
                except OSError:
                    break
        finally:
            server.server_close()

    thread = threading.Thread(
        target=serve,
        daemon=True,
        name=f"sshvault-socks5-{listen_port}",
    )
    running.runtime.thread = thread
    thread.start()


class HTTPConnectRequestError(ProfileError):
    """A sanitized HTTP proxy request error with an explicit response code."""

    def __init__(self, status_code: int, reason: str) -> None:
        super().__init__(reason)
        self.status_code = status_code
        self.reason = reason

    def response(self) -> bytes:
        allow = b"Allow: CONNECT\r\n" if self.status_code == 405 else b""
        status = f"HTTP/1.1 {self.status_code} {self.reason}\r\n".encode("ascii")
        return status + allow + b"Connection: close\r\nContent-Length: 0\r\n\r\n"


def parse_http_connect_request(data: bytes) -> tuple[str, int]:
    """Parse one bounded CONNECT header without retaining request metadata."""
    if len(data) > 16384 or b"\r\n\r\n" not in data:
        raise HTTPConnectRequestError(400, "Bad Request")
    try:
        first_line = data.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise HTTPConnectRequestError(400, "Bad Request") from exc
    parts = first_line.split()
    if not parts:
        raise HTTPConnectRequestError(400, "Bad Request")
    if parts[0] != "CONNECT":
        raise HTTPConnectRequestError(405, "Method Not Allowed")
    if len(parts) != 3 or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise HTTPConnectRequestError(400, "Bad Request")
    authority = parts[1]
    if authority.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", authority)
        if match is None:
            raise HTTPConnectRequestError(400, "Bad Request")
        host, raw_port = match.groups()
    else:
        if authority.count(":") != 1:
            raise HTTPConnectRequestError(400, "Bad Request")
        host, raw_port = authority.rsplit(":", 1)
    try:
        host = validate_host(host)
        port = validate_port(raw_port)
    except ProfileError as exc:
        raise HTTPConnectRequestError(400, "Bad Request") from exc
    return host, port


def open_http_connect_channel(data: bytes, transport: Any, origin: tuple[str, int]) -> Any:
    """Route one validated HTTP CONNECT request over the existing transport."""
    target = parse_http_connect_request(data)
    try:
        channel = transport.open_channel("direct-tcpip", target, origin)
    except Exception as exc:
        raise HTTPConnectRequestError(502, "Bad Gateway") from exc
    if channel is None:
        raise HTTPConnectRequestError(502, "Bad Gateway")
    return channel


HTTP_FORWARDING_STATUSES = LOCAL_FORWARDING_STATUSES


@dataclass
class HTTPForwardingRuleRuntime:
    """Session-owned status for one immutable HTTP CONNECT proxy rule."""

    rule: dict[str, Any]
    status: str = "Stopped"
    error: str = ""


class HTTPForwardingSession:
    """Own enabled HTTP CONNECT listeners for one authenticated session."""

    def __init__(
        self,
        session_id: str,
        transport: Any,
        rules: list[dict[str, Any]],
        starter: Callable[[RunningTunnel], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.manager = TunnelManager(transport, id(transport))
        self.starter = starter
        self.rules = json.loads(json.dumps(rules))
        self.records: dict[str, HTTPForwardingRuleRuntime] = {}
        for rule in self.rules:
            rule_id = str(rule.get("rule_id") or uuid4())
            rule["rule_id"] = rule_id
            self.records[rule_id] = HTTPForwardingRuleRuntime(rule)
        self.closed = False

    def start_enabled(self) -> dict[str, HTTPForwardingRuleRuntime]:
        if self.closed:
            return self.records
        for record in self.records.values():
            if record.rule.get("type") != "HTTP" or not bool(record.rule.get("enabled", True)):
                continue
            if record.status in {"Starting", "Active"}:
                continue
            record.status = "Starting"
            record.error = ""
            try:
                self.manager.start(record.rule, self.starter)
            except Exception as exc:
                record.status = "Failed"
                record.error = str(redact_secrets(str(exc)))
                continue
            record.status = "Active"
        return self.records

    def stop_all(self) -> None:
        if self.closed:
            return
        self.manager.stop_all()
        for record in self.records.values():
            if record.status in {"Starting", "Active"}:
                record.status = "Stopped"
        self.closed = True

    def status(self, rule_id: str) -> str:
        record = self.records.get(rule_id)
        return record.status if record is not None else "Stopped"

    def active_rule_ids(self) -> list[str]:
        return [rule_id for rule_id, record in self.records.items() if record.status == "Active"]


def start_http_connect_listener(running: RunningTunnel, transport: Any) -> None:
    """Bind a CONNECT-only HTTP proxy backed by SSH direct channels."""
    listen_host = str(running.rule["bind_address"])
    listen_port = int(running.rule["bind_port"])

    def receive_headers(client: Any) -> bytes:
        result = bytearray()
        while b"\r\n\r\n" not in result:
            chunk = client.recv(4096)
            if not chunk:
                raise HTTPConnectRequestError(400, "Bad Request")
            result.extend(chunk)
            if len(result) > 16384:
                raise HTTPConnectRequestError(400, "Bad Request")
        marker = result.find(b"\r\n\r\n") + 4
        return bytes(result[:marker])

    class HTTPConnectHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            client = self.request
            channel = None
            try:
                request = receive_headers(client)
                channel = open_http_connect_channel(
                    request,
                    transport,
                    client.getpeername(),
                )
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                while not running.runtime.stop_event.is_set():
                    readable, _, _ = select.select([client, channel], [], [], 0.2)
                    if client in readable:
                        payload = client.recv(65536)
                        if not payload:
                            break
                        channel.sendall(payload)
                    if channel in readable:
                        payload = channel.recv(65536)
                        if not payload:
                            break
                        client.sendall(payload)
            except HTTPConnectRequestError as exc:
                try:
                    client.sendall(exc.response())
                except OSError:
                    pass
            except (EOFError, OSError):
                return
            finally:
                if channel is not None:
                    try:
                        channel.close()
                    except Exception:
                        pass

    address_family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET

    class HTTPConnectServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = False
        daemon_threads = True

        def close(self) -> None:
            self.server_close()

    HTTPConnectServer.address_family = address_family
    server = HTTPConnectServer((listen_host, listen_port), HTTPConnectHandler)
    server.timeout = 0.2
    running.runtime.listener = server

    def serve() -> None:
        try:
            while not running.runtime.stop_event.is_set():
                try:
                    server.handle_request()
                except OSError:
                    break
        finally:
            server.server_close()

    thread = threading.Thread(
        target=serve,
        daemon=True,
        name=f"sshvault-http-connect-{listen_port}",
    )
    running.runtime.thread = thread
    thread.start()


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
    session_id: str | None = None
    profile_id: str | None = None
    diagnostics: list[str] = field(default_factory=list)
    metrics: TransferTimingMetrics = field(default_factory=TransferTimingMetrics)

    def progress(self) -> float | None:
        return None if not self.total or self.total < 0 else min(100.0, self.transferred * 100.0 / self.total)

    def remaining_seconds(self) -> float | None:
        if self.total is None or self.speed <= 0:
            return None
        return max(0.0, (self.total - self.transferred) / self.speed)


@dataclass(frozen=True)
class SFTPTransferQueueRow:
    item_id: str
    file: str
    direction: str
    progress: str
    speed: str
    eta: str
    status: str


def sftp_transfer_queue_rows(items: list[TransferItem]) -> list[SFTPTransferQueueRow]:
    rows = []
    for item in items:
        progress = item.progress()
        eta = item.remaining_seconds()
        rows.append(
            SFTPTransferQueueRow(
                item.item_id,
                Path(item.source).name,
                item.direction,
                "0.0%" if progress is None else f"{progress:.1f}%",
                "0 B/s" if item.speed <= 0 else f"{item.speed:.0f} B/s",
                ("Complete" if item.status == TransferState.COMPLETED else "calculating…")
                if eta is None
                else f"{eta:.0f}s",
                item.status,
            )
        )
    return rows


def sftp_transfer_control_states(
    selected: TransferItem | None,
    items: list[TransferItem],
) -> dict[str, bool]:
    status = selected.status if selected is not None else None
    return {
        "pause": status
        in {
            TransferState.PENDING,
            TransferState.PREPARING,
            TransferState.TRANSFERRING,
            TransferState.RESUMING,
            TransferState.DOWNLOADING,
        },
        "resume": status == TransferState.PAUSED,
        "cancel": selected is not None and status not in TransferState.TERMINAL,
        "retry": status in {TransferState.FAILED, TransferState.CANCELLED},
        "remove_completed": any(item.status == TransferState.COMPLETED for item in items),
    }


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

    def reconnect_client(self) -> Any:
        """Replace this worker's failed channel without changing its queue item."""
        self.client = self.scheduler._reconnect_worker_client(
            self.item_id, self.attempt, self.worker_id, self.client
        )
        return self.client

    def set_operation_timeout(self, value: float) -> None:
        """Raise the per-operation channel timeout for a known large transfer."""
        self.scheduler._set_client_timeout(self.client, value)

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
        reuse_worker_channels: bool = False,
        session_id: str | None = None,
        profile_id: str | None = None,
        operation_timeout: float = 30.0,
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
        self.reuse_worker_channels = bool(reuse_worker_channels)
        self.session_id = session_id
        self.profile_id = profile_id
        self.operation_timeout = max(1.0, float(operation_timeout))
        self._idle_worker_clients: list[Any] = []
        self._producer_threads: set[threading.Thread] = set()
        self.diagnostic_events: list[dict[str, Any]] = []
        self._monitor_stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        if client_factory is not None:
            self._monitor_thread = threading.Thread(
                target=self._monitor_stalls, daemon=True, name="sshvault-sftp-transfer-monitor"
            )
            self._monitor_thread.start()

    @staticmethod
    def _set_client_timeout(client: Any, value: float) -> None:
        channel_getter = getattr(client, "get_channel", None)
        if not callable(channel_getter):
            return
        channel = channel_getter()
        timeout_setter = getattr(channel, "settimeout", None)
        if callable(timeout_setter):
            timeout_setter(value)

    def _reconnect_worker_client(
        self,
        item_id: str,
        attempt: int,
        worker_id: str,
        failed_client: Any,
    ) -> Any:
        """Reconnect one worker and atomically publish its replacement channel."""
        if self.client_factory is None:
            raise RuntimeError("No SFTP client factory is available.")
        try:
            failed_client.close()
        except Exception:
            pass
        replacement = self.client_factory()
        self._set_client_timeout(replacement, self.operation_timeout)
        with self._condition:
            item = self.get(item_id)
            if (
                item is None
                or self.closed
                or attempt != self._attempts.get(item_id)
                or item_id in self._cancelled_ids
                or item_id in self._stalled_ids
            ):
                try:
                    replacement.close()
                except Exception:
                    pass
                raise InterruptedError
            self._clients[item_id] = replacement
            self._diagnostic_locked(item, worker_id, "channel-reconnected", reason="resume")
        return replacement

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
            item.session_id = self.session_id
            item.profile_id = self.profile_id
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
            item.session_id = self.session_id
            item.profile_id = self.profile_id
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

    def create_batch(self, batch: TransferBatch) -> TransferBatch:
        with self._condition:
            if self.closed:
                raise ProfileError("Transfer queue is closed.")
            self.batches.append(batch)
        self._changed()
        return batch

    def add_batch_item(
        self,
        batch: TransferBatch,
        item: TransferItem,
        operation: TransferOperation | None,
    ) -> TransferItem:
        item.parent_id = batch.batch_id
        queued = self.enqueue(item, operation) if operation else self.record(item)
        with self._condition:
            batch.children.append(queued.item_id)
        return queued

    def start_producer(self, item: TransferItem, producer: Callable[[TransferItem], None]) -> TransferItem:
        """Show a planning row immediately and run incremental discovery off-thread."""
        item.status = TransferState.PREPARING
        self.record(item)

        def run() -> None:
            try:
                producer(item)
                with self._condition:
                    if not self.closed and item.status != TransferState.FAILED:
                        item.status = TransferState.COMPLETED
            except Exception as exc:
                with self._condition:
                    if not self.closed:
                        item.status = TransferState.FAILED
                        item.error = str(redact_secrets(str(exc)))
            finally:
                with self._condition:
                    self._producer_threads.discard(threading.current_thread())
                self._changed()

        thread = threading.Thread(target=run, daemon=True, name="sshvault-sftp-folder-scan")
        with self._condition:
            if self.closed:
                raise ProfileError("Transfer queue is closed.")
            self._producer_threads.add(thread)
        thread.start()
        return item

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
        reusable = False
        try:
            if self.client_factory is None:
                raise RuntimeError("No SFTP client factory is available.")
            channel_started = time.perf_counter()
            if self.reuse_worker_channels:
                with self._condition:
                    if self._idle_worker_clients:
                        client = self._idle_worker_clients.pop()
            if client is None:
                client = self.client_factory()
            self._set_client_timeout(client, self.operation_timeout)
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
            reusable = self.reuse_worker_channels
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
            if worker is not None:
                client = worker.client
            keep_client = reusable and self.reuse_worker_channels and not self.closed and generation == self.generation
            if client is not None and keep_client:
                with self._condition:
                    self._idle_worker_clients.append(client)
            elif client is not None:
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
            if item_id not in self._operations and self.client_factory is not None:
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
            clients.extend(self._idle_worker_clients)
            self._idle_worker_clients.clear()
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
            producer_threads = list(self._producer_threads)
            clients = list(self._clients.values())
            clients.extend(self._idle_worker_clients)
            self._idle_worker_clients.clear()
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
        for thread in producer_threads:
            if thread is not threading.current_thread():
                thread.join(timeout=min(timeout, 0.1))
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


class SFTPTransferRouter:
    """Route browser selections through an existing transfer scheduler."""

    def __init__(
        self,
        scheduler: TransferScheduler,
        *,
        verify_completed: bool = True,
        follow_symlinks: bool = False,
    ) -> None:
        self.scheduler = scheduler
        self.verify_completed = verify_completed
        self.follow_symlinks = follow_symlinks

    @staticmethod
    def _raise_remote_error(exc: BaseException, fallback: str = "Transfer failed") -> None:
        """Translate common SFTP failures into stable, user-facing reasons."""
        detail = str(exc).casefold()
        code = getattr(exc, "errno", None)
        if code in {errno.EACCES, errno.EPERM} or "permission denied" in detail:
            raise ProfileError("Remote permission denied") from exc
        if code == errno.ENOENT or "no such file" in detail or "not found" in detail:
            raise ProfileError("Remote directory not found") from exc
        if code in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)} or any(
            text in detail for text in ("no space left", "quota exceeded", "disk full", "filesystem full")
        ):
            raise ProfileError("Remote filesystem full") from exc
        raise ProfileError(fallback) from exc

    @staticmethod
    def _channel_failure(exc: BaseException) -> str | None:
        detail = str(exc).casefold()
        if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in detail or "timeout" in detail:
            return "SFTP channel timeout"
        if isinstance(exc, (EOFError, ConnectionError, BrokenPipeError)) or any(
            text in detail
            for text in ("connection reset", "connection aborted", "broken pipe", "server connection dropped", "eof")
        ):
            return "Connection interrupted"
        return None

    @staticmethod
    def _source_snapshot(path: Path) -> tuple[int, int]:
        info = path.stat()
        return int(info.st_size), int(info.st_mtime_ns)

    @staticmethod
    def _large_file_timeout(total: int, configured: float) -> float:
        """Scale a socket-operation timeout without imposing a whole-file deadline."""
        gib = max(0.0, total / float(1024**3))
        return max(configured, min(900.0, 60.0 + gib * 30.0))

    @staticmethod
    def _existing_remote_directory(client: Any, path: str) -> bool:
        try:
            info = client.stat(path)
        except Exception:
            return False
        mode = getattr(info, "st_mode", None)
        return mode is None or (int(mode) & 0o170000) == 0o040000

    @classmethod
    def _ensure_remote_directory(cls, client: Any, path: str) -> None:
        try:
            client.mkdir(path)
        except OSError as exc:
            if cls._existing_remote_directory(client, path):
                return
            cls._raise_remote_error(exc, "Remote directory could not be created")

    @classmethod
    def _mkdir_remote(cls, item: TransferItem, client: Any, _worker: TransferWorker) -> None:
        """Create one remote directory, treating an existing directory as success."""
        cls._ensure_remote_directory(client, item.target)

    @staticmethod
    def _mkdir_local(item: TransferItem, _client: Any, _worker: TransferWorker) -> None:
        Path(item.target).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def action_states(
        *,
        local_selected: bool,
        remote_selected: bool,
        connected: bool,
        client_available: bool,
    ) -> dict[str, bool]:
        available = connected and client_available
        return {
            "upload": available and local_selected,
            "download": available and remote_selected,
        }

    @staticmethod
    def disabled_reasons(
        *,
        local_selected: bool,
        remote_selected: bool,
        connected: bool,
        client_available: bool,
    ) -> dict[str, str]:
        common = (
            ""
            if connected and client_available
            else ("session is not connected" if not connected else "remote client is unavailable")
        )
        return {
            "upload": common or ("" if local_selected else "no local item selected"),
            "download": common or ("" if remote_selected else "no remote item selected"),
        }

    def _digest_local(self, path: Path, length: int | None = None) -> bytes:
        digest = hashlib.sha1()
        remaining = length
        with path.open("rb") as source:
            while True:
                size = 256 * 1024 if remaining is None else min(256 * 1024, remaining)
                chunk = source.read(size)
                if not chunk:
                    break
                digest.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
        return digest.digest()

    @staticmethod
    def _digest_remote(client: Any, path: str, length: int | None = None) -> bytes | None:
        try:
            with client.open(path, "rb") as source:
                checker = getattr(source, "check", None)
                if not callable(checker):
                    return None
                return cast(bytes, checker("sha1", length=length or 0))
        except (OSError, NotImplementedError, AttributeError, TypeError):
            return None

    def _verify_remote_file(self, client: Any, local: Path, remote: str, total: int) -> bool:
        try:
            if int(client.stat(remote).st_size) != total:
                return False
        except (OSError, AttributeError, TypeError, ValueError):
            return False
        if not self.verify_completed:
            return True
        remote_digest = self._digest_remote(client, remote)
        return remote_digest is None or remote_digest == self._digest_local(local)

    def _partial_matches_source(self, client: Any, local: Path, remote: str, offset: int) -> bool:
        if offset <= 0:
            return True
        if not self.verify_completed:
            return True
        remote_digest = self._digest_remote(client, remote, offset)
        return remote_digest is None or remote_digest == self._digest_local(local, offset)

    @staticmethod
    def _tune_stream(stream: Any, *, remaining: int | None = None) -> None:
        """Enable Paramiko's safe pipelining/prefetch when the channel supports it.

        Lightweight test doubles and non-Paramiko clients simply fall back to
        the existing streaming loop. No transfer semantics depend on tuning.
        """
        pipelined = getattr(stream, "set_pipelined", None)
        if callable(pipelined):
            try:
                pipelined(True)
            except Exception:
                pass
        if remaining is None or remaining <= 0:
            return
        prefetch = getattr(stream, "prefetch", None)
        if callable(prefetch):
            try:
                prefetch(file_size=remaining, max_concurrent_prefetch_requests=32)
            except Exception:
                try:
                    prefetch(file_size=remaining)
                except Exception:
                    pass

    def _upload(self, item: TransferItem, client: Any, worker: TransferWorker) -> None:
        local = Path(item.source)
        try:
            start_snapshot = self._source_snapshot(local)
            total = start_snapshot[0]
            if not local.is_file() or not os.access(local, os.R_OK):
                raise PermissionError(item.source)
        except OSError as exc:
            raise ProfileError("Local file unreadable") from exc
        item.total = total
        set_timeout = getattr(worker, "set_operation_timeout", None)
        if callable(set_timeout):
            set_timeout(self._large_file_timeout(total, self.scheduler.operation_timeout))
        parent = posixpath.dirname(item.target)
        if parent and parent != "/":
            current = "/" if parent.startswith("/") else ""
            for part in parent.strip("/").split("/"):
                current = posixpath.join(current, part)
                self._ensure_remote_directory(client, current)

        try:
            final = client.stat(item.target)
        except (OSError, FileNotFoundError):
            final = None
        source_mtime = local.stat().st_mtime
        if (
            final is not None
            and int(getattr(final, "st_size", -1)) == total
            and getattr(final, "st_mtime", None) is not None
            and int(final.st_mtime) == int(source_mtime)
            and self._verify_remote_file(client, local, item.target, total)
        ):
            if self._source_snapshot(local) != start_snapshot:
                item.diagnostics.append("Source still changing")
                raise ProfileError("Source file is still being modified")
            item.transferred = total
            item.resume_offset = total
            worker.checkpoint(total, total)
            return

        partial = f"{item.target}.sshvault-part"
        reconnects = 0
        while True:
            partial_present = False
            try:
                partial_stat = client.stat(partial)
                partial_present = True
                offset = int(getattr(partial_stat, "st_size", 0))
            except (OSError, FileNotFoundError, TypeError, ValueError):
                offset = 0
            invalid_partial = offset < 0 or offset > total
            if partial_present and not invalid_partial:
                invalid_partial = not self._partial_matches_source(client, local, partial, offset)
            if invalid_partial:
                item.restart_required = True
                item.diagnostics.append("Invalid partial file")
                offset = 0
            if partial_present and offset == total:
                break
            source = target = None
            try:
                source = local.open("rb")
                target = client.open(partial, "ab" if offset else "wb")
                if offset:
                    source.seek(offset)
                    target.seek(offset)
                item.resume_offset = offset
                item.transferred = offset
                self._tune_stream(target)
                worker.checkpoint(offset, total)
                while chunk := source.read(1024 * 1024):
                    if self._source_snapshot(local) != start_snapshot:
                        item.diagnostics.append("Source still changing")
                        raise ProfileError("Source file is still being modified")
                    target.write(chunk)
                    item.transferred += len(chunk)
                    worker.checkpoint(item.transferred, total)
                target.close()
                target = None
                break
            except ProfileError:
                raise
            except Exception as exc:
                failure = self._channel_failure(exc)
                if failure is None:
                    self._raise_remote_error(exc)
                    raise AssertionError("unreachable")
                item.diagnostics.append(failure)
                if reconnects >= 3 or not hasattr(worker, "reconnect_client"):
                    raise ProfileError(failure) from exc
                reconnects += 1
                try:
                    client = worker.reconnect_client()
                except Exception as reconnect_exc:
                    raise ProfileError("Connection interrupted") from reconnect_exc
            finally:
                if source is not None:
                    source.close()
                if target is not None:
                    try:
                        target.close()
                    except Exception:
                        pass
        if self._source_snapshot(local) != start_snapshot:
            item.diagnostics.append("Source still changing")
            raise ProfileError("Source file is still being modified")
        try:
            final_partial_size = int(client.stat(partial).st_size)
        except Exception as exc:
            failure = self._channel_failure(exc)
            raise ProfileError(failure or "Final size mismatch") from exc
        if final_partial_size != total:
            raise ProfileError("Final size mismatch")
        if self.verify_completed:
            remote_digest = self._digest_remote(client, partial)
            if remote_digest is not None and remote_digest != self._digest_local(local):
                raise ProfileError("Checksum mismatch")
        try:
            client.remove(item.target)
        except (OSError, FileNotFoundError):
            pass
        try:
            client.rename(partial, item.target)
        except OSError as exc:
            self._raise_remote_error(exc)
        try:
            if int(client.stat(item.target).st_size) != total:
                raise ProfileError("Final size mismatch")
        except ProfileError:
            raise
        except Exception as exc:
            self._raise_remote_error(exc, "Final size mismatch")
        utime = getattr(client, "utime", None)
        if callable(utime):
            try:
                utime(item.target, (source_mtime, source_mtime))
            except OSError:
                pass

    def _download(self, item: TransferItem, client: Any, worker: TransferWorker) -> None:
        target = Path(item.target)
        target.parent.mkdir(parents=True, exist_ok=True)
        remote_stat = client.stat(item.source)
        total = int(getattr(remote_stat, "st_size", 0))
        item.total = total
        remote_mtime = getattr(remote_stat, "st_mtime", None)
        start_snapshot = (total, remote_mtime)
        set_timeout = getattr(worker, "set_operation_timeout", None)
        if callable(set_timeout):
            set_timeout(self._large_file_timeout(total, self.scheduler.operation_timeout))
        if (
            target.is_file()
            and target.stat().st_size == total
            and remote_mtime is not None
            and int(target.stat().st_mtime) == int(remote_mtime)
        ):
            if not self.verify_completed or self._digest_remote(client, item.source) in {
                None,
                self._digest_local(target),
            }:
                item.transferred = total
                item.resume_offset = total
                worker.checkpoint(total, total)
                return

        partial = Path(f"{item.target}.sshvault-part")
        reconnects = 0
        while True:
            try:
                offset = partial.stat().st_size
                partial_present = True
            except OSError:
                offset = 0
                partial_present = False
            invalid_partial = offset < 0 or offset > total
            if partial_present and not invalid_partial and offset and self.verify_completed:
                remote_prefix = self._digest_remote(client, item.source, offset)
                invalid_partial = remote_prefix is not None and remote_prefix != self._digest_local(partial)
            if invalid_partial:
                item.restart_required = True
                item.diagnostics.append("Invalid partial file")
                partial.unlink(missing_ok=True)
                offset = 0
            if partial_present and offset == total:
                break
            source = destination = None
            try:
                source = client.open(item.source, "rb")
                destination = partial.open("r+b" if offset else "wb")
                if offset:
                    source.seek(offset)
                    destination.seek(offset)
                item.resume_offset = offset
                item.transferred = offset
                self._tune_stream(source, remaining=total - offset)
                worker.checkpoint(offset, total)
                checked_at = offset
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)
                    item.transferred += len(chunk)
                    worker.checkpoint(item.transferred, total)
                    if item.transferred - checked_at >= 16 * 1024 * 1024:
                        current = client.stat(item.source)
                        if (int(current.st_size), getattr(current, "st_mtime", None)) != start_snapshot:
                            item.diagnostics.append("Source still changing")
                            raise ProfileError("Source file is still being modified")
                        checked_at = item.transferred
                destination.flush()
                break
            except ProfileError:
                raise
            except Exception as exc:
                failure = self._channel_failure(exc)
                if failure is None:
                    self._raise_remote_error(exc)
                    raise AssertionError("unreachable")
                item.diagnostics.append(failure)
                if reconnects >= 3 or not hasattr(worker, "reconnect_client"):
                    raise ProfileError(failure) from exc
                reconnects += 1
                try:
                    client = worker.reconnect_client()
                except Exception as reconnect_exc:
                    raise ProfileError("Connection interrupted") from reconnect_exc
            finally:
                if source is not None:
                    try:
                        source.close()
                    except Exception:
                        pass
                if destination is not None:
                    destination.close()
        final_source = client.stat(item.source)
        if (int(final_source.st_size), getattr(final_source, "st_mtime", None)) != start_snapshot:
            item.diagnostics.append("Source still changing")
            raise ProfileError("Source file is still being modified")
        if partial.stat().st_size != total:
            raise ProfileError("Final size mismatch")
        if self.verify_completed:
            remote_digest = self._digest_remote(client, item.source)
            if remote_digest is not None and remote_digest != self._digest_local(partial):
                raise ProfileError("Checksum mismatch")
        partial.replace(target)
        if remote_mtime is not None:
            try:
                os.utime(target, (remote_mtime, remote_mtime))
            except OSError:
                pass

    def _queue_batch(
        self,
        name: str,
        direction: str,
        source: str,
        target: str,
        children: list[tuple[TransferItem, TransferOperation | None]],
    ) -> list[TransferItem]:
        batch = TransferBatch(name, direction, source, target)
        self.scheduler.add_batch(batch, children)
        return [item for item_id in batch.children if (item := self.scheduler.get(item_id)) is not None]

    def _record_local_failure(
        self,
        source: Path,
        target: str,
        *,
        error: str = "Local file unreadable",
    ) -> TransferItem:
        item = TransferItem(
            str(source),
            target,
            "Upload",
            status=TransferState.FAILED,
            error=error,
        )
        return self.scheduler.record(item)

    def _folder_upload_children(self, source: Path, remote_root: str) -> Any:
        """Yield folder jobs as they are discovered; callers consume off-thread."""
        visited: set[tuple[int, int]] = set()
        for directory, names, files in os.walk(source, followlinks=self.follow_symlinks):
            local_directory = Path(directory)
            try:
                identity = local_directory.stat()
            except OSError:
                names.clear()
                yield (
                    TransferItem(
                        str(local_directory),
                        remote_root,
                        "Upload",
                        status=TransferState.FAILED,
                        error="Local file unreadable",
                    ),
                    None,
                )
                continue
            key = (identity.st_dev, identity.st_ino)
            if key in visited:
                names.clear()
                continue
            visited.add(key)
            if not self.follow_symlinks:
                names[:] = [name for name in names if not (local_directory / name).is_symlink()]
            relative = local_directory.relative_to(source)
            remote_directory = (
                remote_root if str(relative) == "." else posixpath.join(remote_root, str(relative).replace(os.sep, "/"))
            )
            yield (
                TransferItem(str(local_directory), remote_directory, "Upload", total=0),
                self._mkdir_remote,
            )
            for name in sorted(files):
                file_path = local_directory / name
                if file_path.is_symlink() and not self.follow_symlinks:
                    continue
                file_relative = file_path.relative_to(source)
                remote_path = posixpath.join(remote_root, str(file_relative).replace(os.sep, "/"))
                try:
                    size = file_path.stat().st_size
                    readable = file_path.is_file() and os.access(file_path, os.R_OK)
                except OSError:
                    readable = False
                    size = None
                if not readable:
                    yield (
                        TransferItem(
                            str(file_path.resolve()),
                            remote_path,
                            "Upload",
                            total=size,
                            status=TransferState.FAILED,
                            error="Local file unreadable",
                        ),
                        None,
                    )
                    continue
                yield (
                    TransferItem(str(file_path.resolve()), remote_path, "Upload", total=size),
                    self._upload,
                )

    def queue_uploads(self, local_paths: list[str], remote_directory: str) -> list[TransferItem]:
        target_directory = normalize_remote_path(remote_directory or "/")
        queued: list[TransferItem] = []
        for raw_path in local_paths:
            selected_source = Path(raw_path).expanduser()
            selected_name = selected_source.name
            if selected_source.is_symlink() and not self.follow_symlinks:
                queued.append(
                    self._record_local_failure(
                        selected_source.absolute(),
                        posixpath.join(target_directory, selected_name),
                        error="Symbolic links are not followed",
                    )
                )
                continue
            source = selected_source.resolve()
            if source.is_dir():
                remote_root = posixpath.join(target_directory, selected_name)
                batch = self.scheduler.create_batch(TransferBatch(selected_name, "Upload", str(source), remote_root))
                planning = TransferItem(str(source), remote_root, "Upload")

                def produce(_planning: TransferItem, *, root=source, target=remote_root, parent=batch) -> None:
                    discovered = 0
                    for item, operation in self._folder_upload_children(root, target):
                        if self.scheduler.closed:
                            return
                        self.scheduler.add_batch_item(parent, item, operation)
                        discovered += 1
                        _planning.transferred = discovered

                self.scheduler.start_producer(planning, produce)
                batch.children.append(planning.item_id)
                queued.append(planning)
                continue
            target = posixpath.join(target_directory, selected_name)
            try:
                readable = source.is_file() and os.access(source, os.R_OK)
                size = source.stat().st_size if readable else None
            except OSError:
                readable = False
                size = None
            if not readable:
                queued.append(self._record_local_failure(source, target))
                continue
            item = TransferItem(
                str(source),
                target,
                "Upload",
                total=size,
            )
            queued.append(self.scheduler.enqueue(item, self._upload))
        return queued

    def queue_downloads(
        self,
        remote_entries: list["RemoteBrowserEntry"],
        local_directory: str,
        browser_client: SFTPBrowserClient | None = None,
    ) -> list[TransferItem]:
        target_directory = Path(local_directory)
        queued: list[TransferItem] = []
        for entry in remote_entries:
            if entry.is_directory:
                local_root = target_directory / entry.name
                batch = self.scheduler.create_batch(
                    TransferBatch(entry.name, "Download", entry.full_path, str(local_root))
                )
                scan_item = TransferItem(entry.full_path, str(local_root), "Download")

                def scan(
                    item: TransferItem,
                    client: Any,
                    worker: TransferWorker,
                    *,
                    remote_root=entry.full_path,
                    destination=local_root,
                    parent=batch,
                ) -> None:
                    destination.mkdir(parents=True, exist_ok=True)
                    listing_client = client if hasattr(client, "list_directory") else SFTPBrowserClient(client)
                    pending = [(remote_root, destination)]
                    discovered = 0
                    while pending:
                        remote_path, local_path = pending.pop()
                        for child in list_remote_browser_entries(listing_client, remote_path, show_hidden=True):
                            child_local = local_path / child.name
                            if child.is_directory:
                                self.scheduler.add_batch_item(
                                    parent,
                                    TransferItem(child.full_path, str(child_local), "Download", total=0),
                                    self._mkdir_local,
                                )
                                pending.append((child.full_path, child_local))
                            else:
                                self.scheduler.add_batch_item(
                                    parent,
                                    TransferItem(
                                        child.full_path,
                                        str(child_local),
                                        "Download",
                                        total=child.size,
                                    ),
                                    self._download,
                                )
                            discovered += 1
                            worker.checkpoint(discovered, None)

                self.scheduler.add_batch_item(batch, scan_item, scan)
                queued.append(scan_item)
                continue
            item = TransferItem(
                entry.full_path,
                str(target_directory / entry.name),
                "Download",
                total=entry.size,
            )
            queued.append(self.scheduler.enqueue(item, self._download))
        return queued


class SFTPDragDropRouter:
    """Route safe cross-pane drops through an existing transfer router.

    Native drag-and-drop support is optional at the widget layer.  Keeping the
    direction and connection checks here makes both native drops and their
    display-free tests use the same transfer-scheduler path as the explicit
    Upload and Download buttons.
    """

    def __init__(self, transfer_router: SFTPTransferRouter) -> None:
        self.transfer_router = transfer_router

    @property
    def scheduler(self) -> TransferScheduler:
        return self.transfer_router.scheduler

    def route_drop(
        self,
        *,
        source_pane: str,
        target_pane: str,
        connected: bool,
        client_available: bool,
        local_paths: list[str] | None = None,
        remote_entries: list["RemoteBrowserEntry"] | None = None,
        local_directory: str = "",
        remote_directory: str = "",
    ) -> list[TransferItem]:
        """Queue one cross-pane copy, or safely ignore an invalid drop."""
        if (
            source_pane == target_pane
            or {source_pane, target_pane} != {"local", "remote"}
            or not connected
            or not client_available
        ):
            return []
        if source_pane == "local":
            return self.transfer_router.queue_uploads(local_paths or [], remote_directory)
        return self.transfer_router.queue_downloads(remote_entries or [], local_directory)


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


class SessionLifecycleState(str, Enum):
    """Canonical, display-free lifecycle state for one managed SSH session."""

    DISCONNECTED = "disconnected"
    VALIDATING = "validating"
    RESOLVING = "resolving"
    CONNECTING_PROXY = "connecting_proxy"
    CONNECTING_HOST = "connecting_host"
    VERIFYING_HOST_KEY = "verifying_host_key"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    DISCONNECTING = "disconnecting"
    FAILED = "failed"
    CANCELLED = "cancelled"


_SESSION_TRANSITIONS: dict[SessionLifecycleState, set[SessionLifecycleState]] = {
    SessionLifecycleState.DISCONNECTED: {SessionLifecycleState.VALIDATING},
    SessionLifecycleState.VALIDATING: {
        SessionLifecycleState.RESOLVING,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.RESOLVING: {
        SessionLifecycleState.CONNECTING_PROXY,
        SessionLifecycleState.CONNECTING_HOST,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.CONNECTING_PROXY: {
        SessionLifecycleState.CONNECTING_HOST,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.CONNECTING_HOST: {
        SessionLifecycleState.VERIFYING_HOST_KEY,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.VERIFYING_HOST_KEY: {
        SessionLifecycleState.AUTHENTICATING,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.AUTHENTICATING: {
        SessionLifecycleState.CONNECTED,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.CANCELLED,
    },
    SessionLifecycleState.CONNECTED: {
        SessionLifecycleState.RECONNECTING,
        SessionLifecycleState.DISCONNECTING,
        SessionLifecycleState.FAILED,
    },
    SessionLifecycleState.RECONNECTING: {
        SessionLifecycleState.RESOLVING,
        SessionLifecycleState.CONNECTING_HOST,
        SessionLifecycleState.FAILED,
        SessionLifecycleState.DISCONNECTING,
    },
    SessionLifecycleState.DISCONNECTING: {SessionLifecycleState.DISCONNECTED, SessionLifecycleState.FAILED},
    SessionLifecycleState.FAILED: {
        SessionLifecycleState.RECONNECTING,
        SessionLifecycleState.DISCONNECTING,
        SessionLifecycleState.DISCONNECTED,
        SessionLifecycleState.VALIDATING,
    },
    SessionLifecycleState.CANCELLED: {SessionLifecycleState.DISCONNECTING, SessionLifecycleState.DISCONNECTED},
}


def _session_snapshot(profile: dict[str, Any]) -> dict[str, Any]:
    """Copy a profile for runtime use without retaining credentials."""
    forbidden = {"password", "passphrase", "secret", "token", "private_key"}
    safe = {key: value for key, value in dict(profile).items() if str(key).casefold() not in forbidden}
    return cast(dict[str, Any], json.loads(json.dumps(safe)))


@dataclass
class SessionRecord:
    """Stable runtime identity and safe ownership metadata for one session."""

    session_id: str
    profile_id: str
    profile_snapshot: dict[str, Any]
    created_at: str
    state: SessionLifecycleState = SessionLifecycleState.DISCONNECTED
    last_state_change: str = ""
    last_error: str = ""
    disconnect_reason: str = ""
    connection_attempt: int = 0
    is_user_initiated: bool = True
    restore_eligible: bool = True
    cleanly_closed: bool = False
    terminal_ids: set[str] = field(default_factory=set)
    sftp_view_ids: set[str] = field(default_factory=set)
    tunnel_ids: set[str] = field(default_factory=set)
    reconnect_status: str = "idle"
    events: list[ConnectionLogEvent] = field(default_factory=list)
    max_events: int = 200

    def add_event(self, message: str, level: str = "info") -> None:
        self.events.append(ConnectionLogEvent(message, level))
        del self.events[: -self.max_events]

    def restoration_record(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "profile_id": self.profile_id,
            "created_at": self.created_at,
            "restore_eligible": self.restore_eligible,
            "was_connected": self.state is SessionLifecycleState.CONNECTED,
            "cleanly_closed": self.cleanly_closed,
        }


class SFTPBrowserClient:
    """Minimal browsing-only adapter around one independent SFTP channel."""

    def __init__(self, channel: Any) -> None:
        self._channel = channel
        self._closed = False

    def list_directory(self, path: str) -> Any:
        return self._channel.listdir_attr(path)

    def stat(self, path: str) -> Any:
        return self._channel.stat(path)

    def mkdir(self, path: str) -> None:
        self._channel.mkdir(path)

    def rename(self, old_path: str, new_path: str) -> None:
        self._channel.rename(old_path, new_path)

    def remove(self, path: str) -> None:
        self._channel.remove(path)

    def rmdir(self, path: str) -> None:
        self._channel.rmdir(path)

    def normalize(self, path: str) -> str:
        return str(self._channel.normalize(path))

    def home_directory(self) -> str:
        return self.normalize(".")

    def is_alive(self) -> bool:
        if self._closed:
            return False
        get_channel = getattr(self._channel, "get_channel", None)
        if not callable(get_channel):
            return True
        try:
            channel = get_channel()
        except Exception:
            return False
        if bool(getattr(channel, "closed", False)):
            return False
        active = getattr(channel, "active", None)
        return True if active is None else bool(active)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._channel.close()
        except Exception:
            pass


class SFTPBrowserRegistry:
    """Tk-free ownership map for isolated per-view browsing channels."""

    def __init__(self) -> None:
        self._clients: dict[str, dict[str, SFTPBrowserClient]] = {}

    def register(self, session_id: str, view_id: str, client: SFTPBrowserClient) -> None:
        self._clients.setdefault(session_id, {})[view_id] = client

    def get(self, session_id: str, view_id: str) -> SFTPBrowserClient | None:
        return self._clients.get(session_id, {}).get(view_id)

    def close_view(self, session_id: str, view_id: str) -> bool:
        client = self._clients.get(session_id, {}).pop(view_id, None)
        if client is None:
            return False
        client.close()
        if not self._clients.get(session_id):
            self._clients.pop(session_id, None)
        return True

    def close_session(self, session_id: str) -> None:
        for view_id in list(self._clients.get(session_id, {})):
            self.close_view(session_id, view_id)


@dataclass(frozen=True)
class LocalBrowserEntry:
    name: str
    full_path: str
    is_directory: bool
    is_symlink: bool
    size: int | None
    modified_time: float | None
    type_label: str
    permissions: str


@dataclass(frozen=True)
class RemoteBrowserEntry:
    name: str
    full_path: str
    is_directory: bool
    is_symlink: bool
    size: int | None
    modified_time: float | None
    type_label: str
    permissions: str
    owner: str


@dataclass
class SFTPViewNavigationState:
    local_current_path: str = field(default_factory=lambda: str(Path.home()))
    local_back_history: list[str] = field(default_factory=list)
    local_forward_history: list[str] = field(default_factory=list)
    remote_current_path: str = ""
    remote_back_history: list[str] = field(default_factory=list)
    remote_forward_history: list[str] = field(default_factory=list)
    local_sort_column: str = "name"
    local_sort_descending: bool = False
    remote_sort_column: str = "name"
    remote_sort_descending: bool = False
    local_loading: bool = False
    remote_loading: bool = False
    local_generation: int = 0
    remote_generation: int = 0
    last_local_error: str | None = None
    last_remote_error: str | None = None
    remote_available: bool = True

    def next_generation(self, remote: bool) -> int:
        if remote:
            self.remote_generation += 1
            return self.remote_generation
        self.local_generation += 1
        return self.local_generation

    def generation_current(self, generation: int, remote: bool) -> bool:
        return generation == (self.remote_generation if remote else self.local_generation)

    def begin_remote_listing(self) -> int:
        """Start one remote read and return its callback generation."""
        generation = self.next_generation(True)
        self.remote_loading = True
        self.last_remote_error = None
        return generation

    def complete_remote_listing(
        self,
        generation: int,
        path: str,
        *,
        error: str | None = None,
        view_open: bool = True,
        update_path: bool = True,
    ) -> bool:
        """Accept only the current open view's result.

        A failed result records its sanitized domain error but deliberately
        leaves the last successful path (and therefore its rendered entries)
        unchanged.
        """
        if not view_open or not self.generation_current(generation, True):
            return False
        self.remote_loading = False
        if error is not None:
            self.last_remote_error = error
            return False
        if update_path:
            self.remote_current_path = path
        self.last_remote_error = None
        return True

    def mark_remote_disconnected(self) -> None:
        """Invalidate pending remote work without changing paths or history."""
        self.next_generation(True)
        self.remote_loading = False
        self.remote_available = False
        self.last_remote_error = "Disconnected"

    def mark_remote_reconnected(self, client_alive: bool) -> bool:
        """Re-enable explicit remote actions without starting a directory read."""
        if not client_alive:
            return False
        self.remote_available = True
        self.remote_loading = False
        self.last_remote_error = None
        return True

    def navigate_new(self, path: str, remote: bool) -> bool:
        current = self.remote_current_path if remote else self.local_current_path
        if not path or path == current:
            return False
        back = self.remote_back_history if remote else self.local_back_history
        forward = self.remote_forward_history if remote else self.local_forward_history
        if current and (not back or back[-1] != current):
            back.append(current)
        forward.clear()
        if remote:
            self.remote_current_path = path
        else:
            self.local_current_path = path
        return True

    def navigate_back(self, remote: bool) -> bool:
        back = self.remote_back_history if remote else self.local_back_history
        forward = self.remote_forward_history if remote else self.local_forward_history
        if not back:
            return False
        current = self.remote_current_path if remote else self.local_current_path
        previous = back.pop()
        if current and (not forward or forward[-1] != current):
            forward.append(current)
        if remote:
            self.remote_current_path = previous
        else:
            self.local_current_path = previous
        return True

    def navigate_forward(self, remote: bool) -> bool:
        back = self.remote_back_history if remote else self.local_back_history
        forward = self.remote_forward_history if remote else self.local_forward_history
        if not forward:
            return False
        current = self.remote_current_path if remote else self.local_current_path
        following = forward.pop()
        if current and (not back or back[-1] != current):
            back.append(current)
        if remote:
            self.remote_current_path = following
        else:
            self.local_current_path = following
        return True

    def navigate_up(self, remote: bool) -> bool:
        path = self.remote_current_path if remote else self.local_current_path
        parent = posixpath.dirname(path) or "/" if remote else str(Path(path).parent)
        return self.navigate_new(parent, remote)

    def navigate_home(self, home: str, remote: bool) -> bool:
        return self.navigate_new(home, remote)

    def refresh(self, remote: bool) -> str:
        return self.remote_current_path if remote else self.local_current_path


def normalize_local_path(path: str) -> str:
    return os.path.normpath(os.path.expanduser(path))


def validate_sftp_item_name(name: str) -> str:
    value = str(name).strip()
    if not value:
        raise ProfileError("Enter a name.")
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise ProfileError("Name must not contain path separators.")
    return value


def create_local_browser_folder(directory: str, name: str) -> str:
    target = Path(directory) / validate_sftp_item_name(name)
    target.mkdir()
    return str(target)


def rename_local_browser_entry(source: str, name: str) -> str:
    path = Path(source)
    target = path.with_name(validate_sftp_item_name(name))
    path.rename(target)
    return str(target)


def delete_local_browser_entries(entries: list[Any]) -> list[str]:
    for entry in entries:
        path = Path(entry.full_path)
        if entry.is_directory and not entry.is_symlink:
            try:
                next(path.iterdir())
            except StopIteration:
                continue
            raise ProfileError("Directory must be empty before deletion.")
    deleted = []
    for entry in entries:
        path = Path(entry.full_path)
        if entry.is_directory and not entry.is_symlink:
            path.rmdir()
        else:
            path.unlink()
        deleted.append(str(path))
    return deleted


def initial_local_browser_path(path: str, home: str | None = None) -> str:
    fallback = normalize_local_path(home or str(Path.home()))
    candidate = normalize_local_path(path or fallback)
    return candidate if Path(candidate).is_dir() else fallback


def normalize_remote_path(path: str, home: str = "/") -> str:
    value = path or home
    return posixpath.normpath(value) if value.startswith("/") else posixpath.normpath(posixpath.join(home, value))


def create_remote_browser_folder(client: SFTPBrowserClient, directory: str, name: str) -> str:
    target = posixpath.join(normalize_remote_path(directory or "/"), validate_sftp_item_name(name))
    client.mkdir(target)
    return target


def rename_remote_browser_entry(client: SFTPBrowserClient, source: str, name: str) -> str:
    target = posixpath.join(posixpath.dirname(source), validate_sftp_item_name(name))
    client.rename(source, target)
    return target


def delete_remote_browser_entries(client: SFTPBrowserClient, entries: list[Any]) -> list[str]:
    for entry in entries:
        if entry.is_directory and list(client.list_directory(entry.full_path)):
            raise ProfileError("Directory must be empty before deletion.")
    deleted = []
    for entry in entries:
        if entry.is_directory:
            client.rmdir(entry.full_path)
        else:
            client.remove(entry.full_path)
        deleted.append(str(entry.full_path))
    return deleted


def _permissions(mode: int | None) -> str:
    if mode is None:
        return "—"
    try:
        return oct(int(mode) & 0o777)
    except (TypeError, ValueError):
        return "—"


def list_local_browser_entries(path: str, show_hidden: bool = False) -> list[LocalBrowserEntry]:
    target = normalize_local_path(path)
    try:
        children = list(Path(target).iterdir())
    except FileNotFoundError as exc:
        raise ProfileError("Local directory not found") from exc
    except PermissionError as exc:
        raise ProfileError("Local permission denied") from exc
    entries = []
    for child in children:
        if not show_hidden and child.name.startswith("."):
            continue
        try:
            info = child.lstat()
            directory = child.is_dir()
            symlink = child.is_symlink()
            entries.append(
                LocalBrowserEntry(
                    child.name,
                    str(child),
                    directory,
                    symlink,
                    info.st_size,
                    info.st_mtime,
                    "Directory" if directory else "File",
                    _permissions(info.st_mode),
                )
            )
        except OSError:
            entries.append(LocalBrowserEntry(child.name, str(child), False, False, None, None, "—", "—"))
    return sort_browser_entries(entries, "name", False)


def list_remote_browser_entries(
    client: SFTPBrowserClient, path: str, show_hidden: bool = False
) -> list[RemoteBrowserEntry]:
    target = normalize_remote_path(path, client.home_directory())
    try:
        attrs = client.list_directory(target)
    except FileNotFoundError as exc:
        raise ProfileError("Remote directory not found") from exc
    except PermissionError as exc:
        raise ProfileError("Remote permission denied") from exc
    except Exception as exc:
        raise ProfileError("Directory listing failed") from exc
    entries = []
    for item in attrs:
        name = str(getattr(item, "filename", ""))
        if not name or (not show_hidden and name.startswith(".")):
            continue
        mode = getattr(item, "st_mode", None)
        directory = bool(mode is not None and (int(cast(int, mode)) & 0o170000) == 0o040000)
        entries.append(
            RemoteBrowserEntry(
                name,
                posixpath.join(target, name),
                directory,
                False,
                getattr(item, "st_size", None),
                getattr(item, "st_mtime", None),
                "Directory" if directory else "File",
                _permissions(mode),
                str(getattr(item, "st_uid", "—")),
            )
        )
    return sort_browser_entries(entries, "name", False)


def sort_browser_entries(entries: list[Any], column: str, descending: bool) -> list[Any]:
    key = {
        "name": lambda e: e.name.casefold(),
        "size": lambda e: e.size if e.size is not None else -1,
        "modified": lambda e: e.modified_time if e.modified_time is not None else -1,
        "type": lambda e: e.type_label,
        "permissions": lambda e: e.permissions,
        "owner": lambda e: getattr(e, "owner", ""),
    }.get(column, lambda e: e.name.casefold())
    directories = [entry for entry in entries if entry.is_directory]
    files = [entry for entry in entries if not entry.is_directory]
    return sorted(directories, key=key, reverse=descending) + sorted(files, key=key, reverse=descending)


def browser_keyboard_index(
    current: int,
    count: int,
    key: str,
    page_size: int = 10,
) -> int | None:
    """Return the next visible row for standard file-list navigation."""
    if count <= 0:
        return None
    current = max(0, min(current, count - 1))
    delta = {
        "Up": -1,
        "Down": 1,
        "Prior": -max(1, page_size),
        "Next": max(1, page_size),
        "Home": -current,
        "End": count - 1 - current,
    }.get(key)
    if delta is None:
        return current
    return max(0, min(count - 1, current + delta))


def batch_browser_entries(entries: list[Any], batch_size: int = 100) -> list[list[Any]]:
    """Split rows into bounded UI insertion batches."""
    size = max(1, int(batch_size))
    return [entries[index : index + size] for index in range(0, len(entries), size)]


class SFTPListingCache:
    """Small per-view cache for the most recently rendered directories."""

    def __init__(self) -> None:
        self._entries: dict[str, list[Any]] = {}

    def get(self, key: str) -> list[Any] | None:
        value = self._entries.get(key)
        return None if value is None else list(value)

    def put(self, key: str, entries: list[Any]) -> None:
        self._entries[key] = list(entries)

    def clear(self) -> None:
        self._entries.clear()


def path_entry_shortcut_action(key: str) -> str | None:
    """Normalize path-entry edit keys independently of Caps Lock state."""
    action = str(key).casefold()
    return action if action in {"a", "c", "v", "x"} else None


def selected_directory_target(entries: list[Any], selected_paths: list[str]) -> str | None:
    """Return one selected directory path; file or multi-selection is inert."""
    if len(selected_paths) != 1:
        return None
    selected = selected_paths[0]
    return next(
        (str(entry.full_path) for entry in entries if entry.full_path == selected and entry.is_directory),
        None,
    )


def selected_file_entries(entries: list[Any], selected_paths: list[str]) -> list[Any]:
    """Return selected files in listing order; directories remain navigation-only."""
    selected = set(selected_paths)
    return [entry for entry in entries if entry.full_path in selected and not entry.is_directory]


def selected_browser_entries(entries: list[Any], selected_paths: list[str]) -> list[Any]:
    selected = set(selected_paths)
    return [entry for entry in entries if entry.full_path in selected]


def selected_browser_path(entries: list[Any], selected_paths: list[str]) -> str | None:
    selected = selected_browser_entries(entries, selected_paths)
    return str(selected[0].full_path) if len(selected) == 1 else None


def browser_entry_properties(entry: Any) -> dict[str, str]:
    return {
        "Name": str(entry.name),
        "Full path": str(entry.full_path),
        "Type": str(entry.type_label),
        "Size": "—" if entry.size is None else str(entry.size),
        "Modified": "—" if entry.modified_time is None else str(entry.modified_time),
        "Permissions": str(entry.permissions or "—"),
        "Owner": str(getattr(entry, "owner", "—") or "—"),
    }


def confirmed_sftp_delete_entries(entries: list[Any], confirmed: bool) -> list[Any]:
    return list(entries) if confirmed else []


def sftp_file_action_states(
    *,
    local_selection_count: int,
    remote_selection_count: int,
    local_loading: bool,
    remote_loading: bool,
    remote_available: bool,
) -> dict[str, bool]:
    return {
        "local_delete": not local_loading and local_selection_count > 0,
        "local_properties": not local_loading and local_selection_count == 1,
        "local_copy_path": not local_loading and local_selection_count == 1,
        "remote_delete": remote_available and not remote_loading and remote_selection_count > 0,
        "remote_properties": remote_available and not remote_loading and remote_selection_count == 1,
        "remote_copy_path": remote_available and not remote_loading and remote_selection_count == 1,
    }


def sftp_mutation_action_states(
    *,
    local_selection_count: int,
    remote_selection_count: int,
    local_loading: bool,
    remote_loading: bool,
    remote_available: bool,
) -> dict[str, bool]:
    return {
        "local_new_folder": not local_loading,
        "local_rename": not local_loading and local_selection_count == 1,
        "remote_new_folder": remote_available and not remote_loading,
        "remote_rename": remote_available and not remote_loading and remote_selection_count == 1,
    }


def update_browser_sort(state: SFTPViewNavigationState, column: str, *, remote: bool = False) -> None:
    column_attribute = "remote_sort_column" if remote else "local_sort_column"
    direction_attribute = "remote_sort_descending" if remote else "local_sort_descending"
    if getattr(state, column_attribute) == column:
        setattr(state, direction_attribute, not getattr(state, direction_attribute))
    else:
        setattr(state, column_attribute, column)
        setattr(state, direction_attribute, False)


class SessionController:
    """Thread-safe, Tk-free owner of session identity and lifecycle state."""

    def __init__(self) -> None:
        self.sessions: dict[str, SessionRecord] = {}
        self._lock = threading.RLock()

    def create_session(self, profile: dict[str, Any], *, user_initiated: bool = True) -> SessionRecord:
        snapshot = _session_snapshot(profile)
        validated = validate_profile(snapshot, check_key_exists=False)
        session = SessionRecord(
            session_id=str(uuid4()),
            profile_id=validated["id"],
            profile_snapshot=validated,
            created_at=datetime.now().astimezone().isoformat(),
            last_state_change=datetime.now().astimezone().isoformat(),
            is_user_initiated=user_initiated,
        )
        session.add_event("Session created.")
        with self._lock:
            self.sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            return self.sessions.get(session_id)

    def for_profile(self, profile_id: str) -> list[SessionRecord]:
        with self._lock:
            return [record for record in self.sessions.values() if record.profile_id == profile_id]

    def transition(self, session_id: str, state: SessionLifecycleState, message: str = "") -> SessionRecord:
        with self._lock:
            record = self.sessions.get(session_id)
            if record is None:
                raise KeyError(f"Unknown session: {session_id}")
            if state is record.state:
                return record
            if state is not SessionLifecycleState.DISCONNECTING and state not in _SESSION_TRANSITIONS[record.state]:
                raise ValueError(f"Invalid session transition: {record.state.value} -> {state.value}")
            old_state = record.state
            record.state = state
            record.last_state_change = datetime.now().astimezone().isoformat()
            if state is SessionLifecycleState.FAILED:
                record.last_error = str(redact_secrets(message))
            if state is SessionLifecycleState.DISCONNECTED:
                record.cleanly_closed = old_state is SessionLifecycleState.DISCONNECTING
            record.add_event(
                message or f"{old_state.value} → {state.value}.",
                "error" if state is SessionLifecycleState.FAILED else "info",
            )
            return record

    def begin_connection(self, session_id: str) -> bool:
        record = self.get(session_id)
        if record is None or record.state not in {SessionLifecycleState.DISCONNECTED, SessionLifecycleState.FAILED}:
            return False
        self.transition(session_id, SessionLifecycleState.VALIDATING, "Validating session profile.")
        return True

    def disconnect(self, session_id: str, reason: str = "") -> bool:
        record = self.get(session_id)
        if record is None or record.state is SessionLifecycleState.DISCONNECTED:
            return False
        if record.state is not SessionLifecycleState.DISCONNECTING:
            self.transition(session_id, SessionLifecycleState.DISCONNECTING, "Disconnecting session.")
        record.disconnect_reason = str(redact_secrets(reason))
        self.transition(session_id, SessionLifecycleState.DISCONNECTED, "Session disconnected.")
        return True

    def cancel(self, session_id: str) -> bool:
        record = self.get(session_id)
        if record is None or record.state in {SessionLifecycleState.CONNECTED, SessionLifecycleState.DISCONNECTED}:
            return False
        self.transition(session_id, SessionLifecycleState.CANCELLED, "Connection cancelled.")
        return True

    def reconnect(self, session_id: str) -> bool:
        record = self.get(session_id)
        if record is None or record.state not in {SessionLifecycleState.CONNECTED, SessionLifecycleState.FAILED}:
            return False
        self.transition(session_id, SessionLifecycleState.RECONNECTING, "Reconnect requested.")
        record.connection_attempt += 1
        record.reconnect_status = "reconnecting"
        return True

    def _register(self, session_id: str, value: str, attribute: str) -> None:
        record = self.get(session_id)
        if record is None:
            raise KeyError(f"Unknown session: {session_id}")
        cast(set[str], getattr(record, attribute)).add(value)

    def _unregister(self, session_id: str, value: str, attribute: str) -> None:
        record = self.get(session_id)
        if record is not None:
            cast(set[str], getattr(record, attribute)).discard(value)

    def register_terminal(self, session_id: str, terminal_id: str) -> None:
        self._register(session_id, terminal_id, "terminal_ids")

    def unregister_terminal(self, session_id: str, terminal_id: str) -> None:
        self._unregister(session_id, terminal_id, "terminal_ids")

    def register_sftp_view(self, session_id: str, view_id: str) -> None:
        self._register(session_id, view_id, "sftp_view_ids")

    def unregister_sftp_view(self, session_id: str, view_id: str) -> None:
        self._unregister(session_id, view_id, "sftp_view_ids")

    def register_tunnel(self, session_id: str, tunnel_id: str) -> None:
        self._register(session_id, tunnel_id, "tunnel_ids")

    def unregister_tunnel(self, session_id: str, tunnel_id: str) -> None:
        self._unregister(session_id, tunnel_id, "tunnel_ids")

    def restorable_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [record.restoration_record() for record in self.sessions.values() if record.restore_eligible]

    def shutdown_all(self) -> None:
        for session_id in list(self.sessions):
            self.disconnect(session_id, "Application shutdown.")


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


def terminal_key_sequence(
    keysym: str,
    char: str = "",
    state: int = 0,
    *,
    application_cursor: bool = False,
    application_keypad: bool = False,
) -> str:
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
    keypad = {
        "KP_0": "p",
        "KP_1": "q",
        "KP_2": "r",
        "KP_3": "s",
        "KP_4": "t",
        "KP_5": "u",
        "KP_6": "v",
        "KP_7": "w",
        "KP_8": "x",
        "KP_9": "y",
        "KP_Add": "k",
        "KP_Subtract": "m",
        "KP_Multiply": "j",
        "KP_Divide": "o",
        "KP_Decimal": "n",
    }
    if keysym in keypad and application_keypad:
        return "\x1bO" + keypad[keysym]
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
    if control:
        controls = {"@": "\x00", "[": "\x1b", "\\": "\x1c", "]": "\x1d", "^": "\x1e", "_": "\x1f", "?": "\x7f"}
        if char in controls:
            return controls[char]
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
        result[section] = (
            normalized_launch_preferences(value)
            if section == "launch_preferences"
            else value
            if isinstance(value, dict)
            else defaults[section]
        )
    raw_connection_options = result["connection_options"]
    connection_options = dict(raw_connection_options) if isinstance(raw_connection_options, dict) else {}
    if "ssh_preferences" in connection_options:
        connection_options["ssh_preferences"] = validate_ssh_preferences(connection_options["ssh_preferences"])
    else:
        legacy_profile = dict(result)
        legacy_profile["connection_options"] = connection_options
        connection_options["ssh_preferences"] = ssh_preferences_from_profile(legacy_profile)
    result["connection_options"] = connection_options
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
        kind = "SOCKS" if kind in {"Dynamic", "Dynamic/SOCKS", "SOCKS"} else kind
        if kind not in {"Local", "Remote", "SOCKS", "HTTP"}:
            raise ProfileError("Tunnel type must be Local, Remote, Dynamic, or HTTP.")
        bind_address = str(rule.get("bind_address", "127.0.0.1")).strip()
        if not bind_address:
            raise ProfileError("Listen host is required.")
        bind_port = validate_port(rule.get("bind_port", 0))
        destination_free = kind in {"SOCKS", "HTTP"}
        destination_port = validate_port(rule.get("destination_port", 0)) if not destination_free else 0
        if not destination_free and (not str(rule.get("destination_host", "")).strip() or not destination_port):
            raise ProfileError("Local and Remote tunnels require a destination host and port.")
        if destination_free:
            destination_port, rule["destination_host"] = 0, ""
        endpoint = (bind_address.casefold(), bind_port)
        enabled = bool(rule.get("enabled", True))
        if enabled:
            if endpoint in endpoints:
                raise ProfileError("Enabled tunnel listen endpoints must be unique.")
            endpoints.add(endpoint)
        rule.update(
            {
                "rule_id": str(rule.get("rule_id") or uuid4()),
                "enabled": enabled,
                "type": kind,
                "bind_address": bind_address,
                "bind_port": bind_port,
                "destination_port": destination_port,
                "description": str(rule.get("description", ""))[:200],
            }
        )
        result.append(rule)
    return result


def port_forwarding_display_row(rule: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    """Return the Services table representation of a canonical tunnel rule."""
    kind = "Dynamic" if rule.get("type") == "SOCKS" else str(rule.get("type", "Local"))
    return (
        "Yes" if bool(rule.get("enabled", True)) else "No",
        kind,
        str(rule.get("bind_address", "127.0.0.1")),
        str(rule.get("bind_port", "")),
        "" if kind in {"Dynamic", "HTTP"} else str(rule.get("destination_host", "")),
        "" if kind in {"Dynamic", "HTTP"} else str(rule.get("destination_port", "")),
    )


@dataclass
class PortForwardingEditor:
    """Display-free working-copy editor for saved forwarding rules."""

    rules: list[dict[str, Any]] = field(default_factory=list)
    loaded_rules: list[dict[str, Any]] = field(init=False)

    def __post_init__(self) -> None:
        self.rules = validate_tunnel_rules(json.loads(json.dumps(self.rules)))
        self.loaded_rules = json.loads(json.dumps(self.rules))

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "PortForwardingEditor":
        section = profile.get("tunnel_options", {})
        rules = section.get("rules", []) if isinstance(section, dict) else []
        return cls(rules)

    @property
    def dirty(self) -> bool:
        return self.rules != self.loaded_rules

    def add(self, rule: dict[str, Any]) -> dict[str, Any]:
        candidate = validate_tunnel_rules([*self.rules, rule])
        self.rules = candidate
        return self.rules[-1]

    def edit(self, rule_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        index = next(
            (position for position, rule in enumerate(self.rules) if rule.get("rule_id") == rule_id),
            None,
        )
        if index is None:
            raise ProfileError("Port-forwarding rule not found.")
        updated = dict(self.rules[index])
        updated.update(updates)
        updated["rule_id"] = rule_id
        candidate = list(self.rules)
        candidate[index] = updated
        self.rules = validate_tunnel_rules(candidate)
        return self.rules[index]

    def remove(self, rule_id: str) -> bool:
        remaining = [rule for rule in self.rules if rule.get("rule_id") != rule_id]
        if len(remaining) == len(self.rules):
            return False
        self.rules = remaining
        return True

    def duplicate(self, rule_id: str) -> dict[str, Any]:
        source = next((rule for rule in self.rules if rule.get("rule_id") == rule_id), None)
        if source is None:
            raise ProfileError("Port-forwarding rule not found.")
        duplicate = json.loads(json.dumps(source))
        duplicate["rule_id"] = str(uuid4())
        # An enabled exact copy would conflict with its source listener.
        duplicate["enabled"] = False
        return self.add(duplicate)

    def apply_to_working_profile(self, profile: dict[str, Any]) -> None:
        section = dict(profile.get("tunnel_options", {}))
        section["rules"] = json.loads(json.dumps(self.rules))
        profile["tunnel_options"] = section


def connection_kwargs(profile: dict[str, Any], password: str | None = None) -> dict[str, Any]:
    """Build Paramiko-safe connection keywords; no shell command is involved."""
    result: dict[str, Any] = {
        "hostname": profile["host"],
        "port": profile["port"],
        "username": profile["user"],
        "timeout": profile.get("timeout", 15),
        "compress": profile.get("compression", False),
        "allow_agent": profile.get("auth_method") == "agent",
        # An agent-only profile must not also parse unrelated ~/.ssh default
        # keys.  A malformed legacy DSA key otherwise aborts authentication
        # before the valid agent RSA/Ed25519 identities are attempted.
        "look_for_keys": profile.get("auth_method") != "agent",
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
    if isinstance(error, ProfileError) and (
        ("unsupported" in message and "ssh" in message)
        or "ssh algorithm" in message
        or "ssh keepalive" in message
        or "ssh runtime" in message
        or "preferred ssh" in message
    ):
        return "The selected SSH runtime preference is unsupported by this backend."
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


# ── Native VTE terminal backend ────────────────────────────────────────────
# This remains in the core module so the canonical single-file wheel can start
# the helper without adding a second, separately packaged executable.


@dataclass(frozen=True)
class VTEAvailability:
    available: bool
    interpreter: str | None = None
    reason: str = ""


def _gi_probe(interpreter: str) -> bool:
    try:
        result = subprocess.run(
            [
                interpreter,
                "-c",
                'import gi; gi.require_version("Gtk", "3.0"); gi.require_version("Vte", "2.91"); from gi.repository import Gtk, Vte',
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def detect_vte_backend() -> VTEAvailability:
    """Use the system interpreter for GTK/VTE, never an incompatible venv."""
    if platform.system() != "Linux":
        return VTEAvailability(False, reason="Native VTE is available only on Linux.")
    candidate = "/usr/bin/python3"
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and _gi_probe(candidate):
        return VTEAvailability(True, candidate)
    return VTEAvailability(False, reason="Install python3-gi and the VTE GTK introspection bindings.")


_VTE_ENV_NAMES = {
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "LANG",
    "LANGUAGE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
}


def vte_inherited_environment(parent: dict[str, str] | None = None) -> dict[str, str]:
    """Copy the GUI/session environment required by VTE and OpenSSH.

    Values are deliberately never sent through IPC or diagnostics.
    """
    source = os.environ if parent is None else parent
    names = _VTE_ENV_NAMES | {name for name in source if name.startswith("LC_")}
    return {name: source[name] for name in names if source.get(name)}


def vte_agent_diagnostics(environment: dict[str, str] | None = None) -> dict[str, bool]:
    """Return safe agent booleans only; never reveal a socket path or contents."""
    env = vte_inherited_environment(environment)
    path = env.get("SSH_AUTH_SOCK")
    return {"agent_socket_present": bool(path), "agent_socket_exists": bool(path and os.path.exists(path))}


def _safe_ssh_target(host: object, username: object) -> str:
    host_text, user_text = str(host).strip(), str(username).strip()
    try:
        validate_host(host_text)
    except ProfileError as exc:
        raise ProfileError("Native terminal host is invalid.") from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", user_text):
        raise ProfileError("Native terminal username is invalid.")
    return f"{user_text}@{host_text}"


def session_resource_title(resource: str, profile: dict[str, Any]) -> str:
    """Return a stable, human-readable owner label for a session resource."""
    user = str(profile.get("user", "")).strip()
    host = str(profile.get("host", "")).strip().split(".", 1)[0]
    owner = "@".join(part for part in (user, host) if part)
    return f"{resource} — {owner or str(profile.get('name', 'SSHVault'))}"


def build_native_ssh_argv(profile: dict[str, Any]) -> list[str]:
    """Build a restricted OpenSSH argv; no profile field is shell-expanded."""
    target = _safe_ssh_target(profile.get("host", ""), profile.get("user", ""))
    try:
        port = int(profile.get("port", DEFAULT_PORT))
    except (TypeError, ValueError) as exc:
        raise ProfileError("Native terminal port is invalid.") from exc
    if not 1 <= port <= 65535:
        raise ProfileError("Native terminal port is invalid.")
    argv = ["ssh", "-tt", "-p", str(port)]
    timeout = profile.get("timeout")
    if timeout not in (None, ""):
        try:
            value = int(cast(Any, timeout))
        except (TypeError, ValueError) as exc:
            raise ProfileError("Native terminal timeout is invalid.") from exc
        if not 1 <= value <= 3600:
            raise ProfileError("Native terminal timeout is invalid.")
        argv += ["-o", f"ConnectTimeout={value}"]
    options = profile.get("connection_options", {})
    if not isinstance(options, dict):
        options = {}
    for source, option, maximum in (
        ("keepalive_interval", "ServerAliveInterval", 3600),
        ("keepalive_count", "ServerAliveCountMax", 100),
    ):
        if options.get(source) not in (None, ""):
            value = int(options[source])
            if not 0 <= value <= maximum:
                raise ProfileError(f"Native terminal {source} is invalid.")
            argv += ["-o", f"{option}={value}"]
    if profile.get("compression") is True:
        argv.append("-C")
    proxy = profile.get("proxy_jump")
    if proxy:
        if not isinstance(proxy, str) or not re.fullmatch(r"[A-Za-z0-9@._,:\-\[\]]{1,512}", proxy):
            raise ProfileError("Native terminal ProxyJump is invalid.")
        argv += ["-J", proxy]
    if profile.get("auth_method") == "key":
        path = Path(str(profile.get("key_path", ""))).expanduser()
        if not path.is_file():
            raise ProfileError("Native terminal identity file is invalid.")
        argv += ["-i", str(path), "-o", "IdentitiesOnly=yes"]
    terminal_options = profile.get("terminal_options", {})
    terminal_options = terminal_options if isinstance(terminal_options, dict) else {}
    terminal_type = str(terminal_options.get("terminal_type", "xterm-256color")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", terminal_type):
        raise ProfileError("Native terminal type is invalid.")
    argv += ["-o", f"SetEnv=TERM={terminal_type}"]
    if terminal_options.get("agent_forwarding") is True:
        argv.append("-A")
    if terminal_options.get("x11_forwarding") is True:
        argv.append("-Y" if terminal_options.get("x11_trusted") is True else "-X")
    # Passwords are deliberately absent: OpenSSH prompts inside VTE.
    argv.append(target)
    command = str(profile.get("terminal_options", {}).get("startup_command", "")).strip()
    if command:
        argv.append(command)
    return argv


class TerminalBackend:
    label = "Legacy terminal"

    def open_terminal_tab(self, profile: dict[str, Any]) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class LegacyPyteTerminalBackend(TerminalBackend):
    """Marker backend: the Tk caller owns the existing TerminalWidget."""

    label = "Legacy terminal"

    def open_terminal_tab(self, profile: dict[str, Any]) -> bool:
        return False

    def close(self) -> None:
        return None


class VTETerminalBackend(TerminalBackend):
    """Control-plane client for the isolated GTK/VTE helper (never terminal bytes)."""

    label = "Native VTE"

    def __init__(self, availability: VTEAvailability | None = None):
        self.availability = availability or detect_vte_backend()
        self._directory: Path | None = None
        self._connection: socket.socket | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._token = secrets.token_urlsafe(32)
        self._environment = vte_inherited_environment()
        self.reason = self.availability.reason
        self._terminals: dict[str, dict[str, Any]] = {}
        self._last_window_id: str | None = None
        self.last_terminal_id: str | None = None
        self._request_lock = threading.Lock()
        self._last_terminal_poll = 0.0
        self._terminal_poll_interval = 0.5

    @property
    def status(self) -> str:
        if self._connection and self._process and self._process.poll() is None:
            return "Native VTE ready"
        if not self.availability.available:
            return "Legacy terminal — VTE unavailable"
        return f"Native VTE unavailable: {self.reason or 'helper exited'}"

    @staticmethod
    def _helper_path() -> Path:
        return Path(__file__).resolve().with_name("sshvault_vte_helper.py")

    def _startup_error(self, fallback: str) -> str:
        if not self._process or not self._process.stderr:
            return fallback
        try:
            detail = self._process.stderr.read(4096).decode("utf-8", "replace").strip()
        except (OSError, ValueError):
            return fallback
        if "GI/VTE import failed" in detail:
            return "GI import failed"
        if "display unavailable" in detail:
            return "display unavailable"
        if "Permission denied" in detail:
            return "permission error"
        return fallback

    def _fail(self, reason: str) -> bool:
        self.reason = reason
        self.close()
        return False

    def _receive(self, timeout: float) -> dict[str, Any] | None:
        if not self._connection:
            return None
        self._connection.settimeout(timeout)
        try:
            payload = self._connection.recv(4096)
            message = json.loads(payload.decode("utf-8").split("\n", 1)[0])
            return message if isinstance(message, dict) else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _request(self, command: str, **payload: Any) -> dict[str, Any] | None:
        """Send one authenticated control request and wait for its response."""
        if not self._connection:
            return None
        request_id = str(uuid4())
        message = {"type": command, "token": self._token, "request_id": request_id, **payload}
        with self._request_lock:
            try:
                connection = self._connection
                if connection is None:
                    return None
                connection.sendall((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
                response = self._receive(3)
            except OSError:
                return None
        if not response or response.get("type") != "response" or response.get("request_id") != request_id:
            return None
        return response

    def _start(self) -> bool:
        if self._connection and self._process and self._process.poll() is None:
            return True
        if self._process is not None and self._process.poll() is not None:
            if self._connection is not None:
                try:
                    self._connection.close()
                except OSError:
                    pass
                self._connection = None
            self._process = None
            if self._directory:
                shutil.rmtree(self._directory, ignore_errors=True)
                self._directory = None
        if not self.availability.available or not self.availability.interpreter:
            return self._fail(self.availability.reason or "VTE unavailable")
        helper = self._helper_path()
        if not helper.is_file():
            return self._fail("helper module missing")
        try:
            probe = subprocess.run(
                [self.availability.interpreter, "-I", str(helper), "--probe"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=self._environment,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return self._fail("helper module missing")
        if probe.returncode != 0:
            return self._fail("GI import failed")
        self._directory = Path(tempfile.mkdtemp(prefix="sshvault-vte-"))
        os.chmod(self._directory, 0o700)
        socket_path = self._directory / "control.sock"
        try:
            self._process = subprocess.Popen(
                [
                    self.availability.interpreter,
                    "-I",
                    str(helper),
                    "--socket",
                    str(socket_path),
                    "--token",
                    self._token,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=self._environment,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    return self._fail(self._startup_error("helper exited early"))
                if socket_path.exists():
                    mode = socket_path.stat().st_mode & 0o777
                    directory_mode = self._directory.stat().st_mode & 0o777
                    if mode != 0o600 or directory_mode != 0o700:
                        return self._fail("IPC socket permission error")
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        connection.connect(str(socket_path))
                    except OSError:
                        connection.close()
                        time.sleep(0.05)
                        continue
                    self._connection = connection
                    ready = self._receive(2)
                    if ready != {"type": "ready", "token": self._token}:
                        return self._fail("readiness handshake failed")
                    pong = self._request("ping")
                    if not pong or not pong.get("ok"):
                        return self._fail("readiness handshake failed")
                    self.reason = ""
                    return True
                time.sleep(0.05)
            return self._fail("readiness timeout")
        except (OSError, ValueError, subprocess.SubprocessError):
            return self._fail("IPC socket could not be created")

    def ensure_ready(self) -> bool:
        """Start and authenticate the helper before exposing Native VTE."""
        return self._start()

    def open_terminal_tab(self, profile: dict[str, Any]) -> bool:
        """Open another VTE tab in the last native window (or a first window)."""
        return self._open(profile, "open_tab")

    def open_terminal_window(self, profile: dict[str, Any]) -> bool:
        """Open an independent native VTE window."""
        return self._open(profile, "open_window")

    def _open(self, profile: dict[str, Any], command: str) -> bool:
        if not self._start():
            return False
        try:
            request: dict[str, Any] = {
                "argv": build_native_ssh_argv(profile),
                "title": session_resource_title("Terminal", profile),
                "session_id": str(profile.get("_session_id", "")),
                "terminal_options": dict(profile.get("terminal_options", {})),
            }
            if command == "open_tab" and self._last_window_id:
                request["window_id"] = self._last_window_id
            response = self._request(command, **request)
            if not response or not response.get("ok"):
                return self._fail("helper rejected terminal request")
            terminal_id, window_id = response.get("terminal_id"), response.get("window_id")
            if not isinstance(terminal_id, str) or not isinstance(window_id, str):
                return self._fail("invalid helper response")
            self._terminals[terminal_id] = {
                "terminal_id": terminal_id,
                "window_id": window_id,
                "title": request["title"],
                "session_id": request["session_id"],
            }
            self.last_terminal_id = terminal_id
            self._last_window_id = window_id
        except (OSError, TypeError, ProfileError):
            return self._fail("helper exited early")
        return True

    def list_terminals(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        if now - self._last_terminal_poll < self._terminal_poll_interval:
            return list(self._terminals.values())
        self._last_terminal_poll = now
        if not self._connection or not self._process or self._process.poll() is not None:
            if self._terminals:
                self.reason = "helper exited"
                self._terminals.clear()
                self.last_terminal_id = None
                self._last_window_id = None
            return []
        response = self._request("list_terminals")
        terminals = response.get("terminals", []) if response and response.get("ok") else []
        if isinstance(terminals, list):
            self._terminals = {
                str(item["terminal_id"]): item for item in terminals if isinstance(item, dict) and "terminal_id" in item
            }
            return list(self._terminals.values())
        return []

    def close_terminal(self, terminal_id: str) -> bool:
        """Close one native terminal asynchronously without affecting siblings."""
        if terminal_id not in self._terminals:
            return False
        self._terminals.pop(terminal_id, None)
        if self.last_terminal_id == terminal_id:
            self.last_terminal_id = next(reversed(self._terminals), None)
        if self._connection and self._process and self._process.poll() is None:

            def close_remote() -> None:
                self._request("close_tab", terminal_id=terminal_id)
                process = self._process
                if not self._terminals and process is not None:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        return

            threading.Thread(
                target=close_remote,
                daemon=True,
                name="sshvault-vte-close",
            ).start()
        return True

    def agent_diagnostics(self, *, selected_authentication: str = "") -> dict[str, bool]:
        """Opt-in safe diagnostics; values and credentials are never exposed."""
        status = vte_agent_diagnostics(self._environment)
        status["helper_inherited_agent"] = status["agent_socket_present"]
        status["openssh_child_inherited_agent"] = status["agent_socket_present"]
        status["agent_authentication_selected"] = selected_authentication == "agent"
        return status

    def development_diagnostics(self) -> dict[str, int | bool | str | None]:
        """Safe development-only state; command arguments are never exposed."""
        return {
            "helper_pid": self._process.pid if self._process else None,
            "helper_alive": bool(self._process and self._process.poll() is None),
            "vte_tabs": len(self._terminals),
            "openssh_child_pid": next((item.get("pid") for item in self._terminals.values()), None),
            "backend_state": self.status,
        }

    def close(self) -> None:
        if self._connection:
            try:
                self._connection.sendall(
                    (json.dumps({"type": "shutdown", "token": self._token, "request_id": str(uuid4())}) + "\n").encode()
                )
            except OSError:
                pass
            self._connection.close()
            self._connection = None
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._process.kill()
                try:
                    self._process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        self._process = None
        self._terminals.clear()
        self._last_window_id = None
        self.last_terminal_id = None
        if self._directory:
            shutil.rmtree(self._directory, ignore_errors=True)
            self._directory = None
