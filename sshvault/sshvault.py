#!/usr/bin/env python3
"""SSHVault — Bitvise-inspired SSH/SFTP workspace."""

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import os
import re
import hashlib
import codecs
import stat
import time
import queue
import socket
import select
import socketserver
import struct
import posixpath
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from uuid import uuid4
from sshvault_security import (
    AgentAuthenticationDiagnostic,
    agent_environment_diagnostics,
    prepare_agent_environment,
    ChangedHostKeyRejected,
    KnownHostsStore,
    SSHConnectionManager,
    TrustDecision,
    UnknownHostCancelled,
    ProxyConnectionContext,
    HostKeyRepository,
    request_agent_forwarding,
)
from sshvault_security import SecurityRequestQueue
from sshvault_core import (
    ProfileError,
    ProfileSidebarState,
    ProfileStore,
    SecretStore,
    WorkspaceChromeState,
    application_shortcut_allowed,
    validate_profile,
    DirectoryLoadState,
    SFTPPanelState,
    TerminalPanelState,
    terminal_key_sequence,
    VTETerminalBackend,
    detect_vte_backend,
    session_resource_title,
    TunnelFormState,
    TunnelRuntime,
    TunnelManager,
    ReconnectController,
    StartupActionCoordinator,
    DiagnosticsCollector,
    TransferItem,
    TransferBatch,
    TransferScheduler,
    TransferState,
    TransferManagerWindowState,
    DownloadResumeDecision,
    DurableProgressPolicy,
    AdaptiveTransferTuner,
    SFTP_TRANSFER_CHUNK_SIZES,
    adopt_legacy_download,
    inspect_download_resume,
    partial_download_metadata_path,
    partial_download_path,
    write_partial_download_metadata,
    CommandExecutionState,
    atomic_json_write,
    validate_settings,
    AppearanceState,
    confirm_multiline_paste_enabled,
    confirm_delete_enabled,
    confirm_overwrite_enabled,
    SessionDashboardState,
    SessionController,
    SessionLifecycleState,
    ImportPreviewRow,
    ImportDecisionModel,
    build_import_preview,
    default_profile_sections,
    friendly_connection_error,
    redact_secrets,
    OPTIONS_GROUPS,
    POST_LOGIN_OPTION_LABELS,
    APPLICATION_STARTUP_OPTION_LABELS,
    LOGOUT_OPTION_LABELS,
    TERMINAL_GROUPS,
    TERMINAL_BACKENDS,
    TERMINAL_BELLS,
    TERMINAL_CURSOR_SHAPES,
    TERMINAL_COLOR_THEMES,
    SERVICES_SECTIONS,
    X11_FORWARDING_OPTION_LABELS,
    PORT_FORWARDING_RUNTIME_COLUMNS,
    PORT_FORWARDING_TYPES,
    DynamicForwardingSession,
    HTTPForwardingSession,
    LocalForwardingSession,
    RemoteForwardingSession,
    X11ForwardingSession,
    PortForwardingEditor,
    port_forwarding_display_row,
    start_dynamic_forwarding_listener,
    start_http_connect_listener,
    start_local_forwarding_listener,
    start_remote_forwarding_listener,
    CONTROLLER_DEFAULT_GEOMETRY,
    CONTROLLER_MINIMUM_GEOMETRY,
    SECTION_PADDING,
    SFTP_GROUPS,
    SFTP_OVERWRITE_BEHAVIORS,
    SSH_SETTING_LABELS,
    SSH_KEY_EXCHANGE_CHOICES,
    SSH_HOST_KEY_CHOICES,
    SSH_CIPHER_CHOICES,
    SSH_MAC_CHOICES,
    default_ssh_preferences,
    set_working_ssh_preference,
    ssh_preferences_from_profile,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPDragDropRouter,
    SFTPTransferRouter,
    SFTPListingCache,
    SFTPViewNavigationState,
    browser_entry_properties,
    batch_browser_entries,
    browser_keyboard_index,
    path_entry_shortcut_action,
    confirmed_sftp_delete_entries,
    create_local_browser_folder,
    create_remote_browser_folder,
    delete_local_browser_entries,
    delete_remote_browser_entries,
    initial_local_browser_path,
    list_local_browser_entries,
    list_remote_browser_entries,
    normalize_local_path,
    normalize_remote_path,
    rename_local_browser_entry,
    rename_remote_browser_entry,
    selected_browser_entries,
    selected_browser_path,
    selected_directory_target,
    selected_file_entries,
    sftp_file_action_states,
    sftp_mutation_action_states,
    sftp_transfer_control_states,
    sftp_transfer_queue_rows,
    sort_browser_entries,
    update_browser_sort,
    validate_sftp_item_name,
    ssh_runtime_preferences,
)

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import pyte
except ImportError:
    pyte = None

CONFIG_DIR = Path.home() / ".config" / "sshvault"
VAULT_FILE = CONFIG_DIR / "vault.json"
LOG_FILE = CONFIG_DIR / "sshvault.log"
SESSION_FILE = CONFIG_DIR / "session.json"
RECORDINGS_DIR = CONFIG_DIR / "recordings"
KNOWN_HOSTS_FILE = CONFIG_DIR / "known_hosts"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
BACKUPS_DIR = CONFIG_DIR / "backups"
SFTP_SERVER_CONFIG_FILE = CONFIG_DIR / "sftp-server.json"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
RECORDINGS_DIR.mkdir(exist_ok=True)

# ── palette ──────────────────────────────────────────────────────────────────
BG = "#1e1e2e"
PANEL = "#2a2a3e"
ACCENT = "#7aa2f7"
GREEN = "#9ece6a"
RED = "#f7768e"
YELLOW = "#e0af68"
PURPLE = "#bb9af7"
CYAN = "#7dcfff"
TEXT = "#cdd6f4"
MUTED = "#6c7086"
MONO = ("MesloLGS Nerd Font Mono", 10)
FONT = ("Sans", 10)
FONT_B = ("Sans", 10, "bold")
CONTROLLER_PROFILE_ACTIONS = ("Load profile", "Save profile as", "New profile", "Reset profile")
CONTROLLER_CONFIG_TABS = ("Login", "Options", "Terminal", "SFTP", "Services", "SSH")
CONTROLLER_BOTTOM_ACTIONS = ("Log in / Log out", "Exit")
OPENING_BG = "#ececec"
OPENING_PANEL = "#f7f7f7"
PROFILE_RAIL_WIDTH = 152


class _ProfileSelectionModel:
    """Display-free compatibility model for UUID-based profile selection."""

    def __init__(self) -> None:
        self._items: list[str] = []
        self._selection: str | None = None
        self._focus: str | None = None

    def get_children(self) -> tuple[str, ...]:
        return tuple(self._items)

    def delete(self, *items: str) -> None:
        removed = set(items)
        self._items = [item for item in self._items if item not in removed]
        if self._selection in removed:
            self._selection = None
        if self._focus in removed:
            self._focus = None

    def insert(self, _parent: str, _position: str, *, iid: str, **_kwargs: object) -> None:
        if iid not in self._items:
            self._items.append(iid)

    def exists(self, item: str) -> bool:
        return item in self._items

    def selection(self) -> tuple[str, ...]:
        return (self._selection,) if self._selection is not None else ()

    def selection_set(self, item: str) -> None:
        self._selection = item if self.exists(item) else None

    def focus(self, item: str | None = None) -> str:
        if item is not None:
            self._focus = item if self.exists(item) else None
        return self._focus or ""


class _ConnectionViewRegistry:
    """Notebook-compatible registry without a visible controller tab strip."""

    def __init__(self) -> None:
        self._widgets: dict[str, tk.Misc] = {}
        self._labels: dict[str, str] = {}
        self._order: list[str] = []
        self._selected: str = ""

    def add(self, widget: tk.Misc, *, text: str) -> None:
        widget_id = str(widget)
        self._widgets[widget_id] = widget
        self._labels[widget_id] = text
        if widget_id not in self._order:
            self._order.append(widget_id)
        self._selected = widget_id

    def select(self, widget: tk.Misc | str | None = None) -> str:
        if widget is not None:
            widget_id = str(widget)
            if widget_id in self._widgets:
                self._selected = widget_id
        return self._selected

    def nametowidget(self, widget_id: str) -> tk.Misc:
        if widget_id not in self._widgets:
            raise KeyError(widget_id)
        return self._widgets[widget_id]

    def tabs(self) -> tuple[str, ...]:
        return tuple(self._order)

    def tab(self, widget: tk.Misc | str, option: str) -> str:
        if option != "text":
            raise KeyError(option)
        return self._labels.get(str(widget), "")

    def forget(self, widget: tk.Misc | str) -> None:
        widget_id = str(widget)
        self._widgets.pop(widget_id, None)
        self._labels.pop(widget_id, None)
        self._order = [item for item in self._order if item != widget_id]
        if self._selected == widget_id:
            self._selected = self._order[-1] if self._order else ""


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {redact_secrets(msg)}\n")


# ── Profile store compatibility facade ───────────────────────────────────────
class Vault:
    def __init__(self):
        self._store = ProfileStore(VAULT_FILE, SecretStore())
        self.entries = self._store.entries

    def save(self):
        self._store.save()

    def add(self, entry: dict, password: str = ""):
        self._store.add(entry, password)
        self.entries = self._store.entries

    def update(self, idx: int, entry: dict, password: str | None = None, remove_password: bool = False):
        self._store.update(idx, entry, password, remove_password=remove_password)
        self.entries = self._store.entries

    def delete(self, idx: int):
        self._store.delete(idx)
        self.entries = self._store.entries

    def secret_for(self, entry: dict) -> str | None:
        """Return a credential only for an in-memory connection attempt."""
        return self._store.secret_store.get(str(entry.get("id", "")))


# ── VT100/xterm colour palette (mapped onto the app's dark theme) ──────────
_TERM_BG = "#0d0d1a"
_NAME_COLORS = {
    "black": "#45475a",
    "red": RED,
    "green": GREEN,
    "yellow": YELLOW,
    "blue": ACCENT,
    "magenta": PURPLE,
    "cyan": CYAN,
    "white": TEXT,
    "brightblack": MUTED,
    "brightred": "#ff8fa3",
    "brightgreen": "#b8e994",
    "brightyellow": "#f4d58d",
    "brightblue": "#a3c2f7",
    "brightmagenta": "#d6b8f7",
    "brightcyan": "#a8e6ff",
    "brightwhite": "#ffffff",
}

_TAG_COLOR_CODES = {"err": "31", "info": "36", "ok": "32", "warn": "33", "hdr": "35"}
_URL_RE = re.compile(r"https?://[^\s<>()\"']+")
_URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%")


def _xterm_256_color(index: int) -> str:
    """Return an xterm palette colour without depending on a Tk colour name."""
    if index < 16:
        names = tuple(_NAME_COLORS)
        return _NAME_COLORS[names[index]]
    if index < 232:
        index -= 16
        levels = (0, 95, 135, 175, 215, 255)
        return "#%02x%02x%02x" % (levels[index // 36], levels[(index // 6) % 6], levels[index % 6])
    gray = 8 + (index - 232) * 10
    return f"#{gray:02x}{gray:02x}{gray:02x}"


def _terminal_color(value, default: str) -> str:
    """Map pyte named, indexed, and RGB colours onto Tk colour strings."""
    if value in (None, "default"):
        return default
    value = str(value)
    if value in _NAME_COLORS:
        return _NAME_COLORS[value]
    if re.fullmatch(r"[0-9a-fA-F]{6}", value):
        return "#" + value
    match = re.fullmatch(r"color(\d{1,3})", value)
    if match:
        return _xterm_256_color(min(255, int(match.group(1))))
    return default


# xterm-style key -> escape sequence translation for raw (non-echoing) input
_KEY_SEQS = {
    "Up": "\x1b[A",
    "Down": "\x1b[B",
    "Right": "\x1b[C",
    "Left": "\x1b[D",
    "Home": "\x1b[H",
    "End": "\x1b[F",
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
_KEY_SEQS.update(
    {
        f"F{n}": seq
        for n, seq in {
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
        }.items()
    }
)


if pyte:

    class _ScrollbackScreen(pyte.Screen):
        """pyte.Screen that hands off lines pushed out the top to a callback,
        giving the widget real terminal scrollback instead of just a fixed grid."""

        def __init__(self, columns, lines, on_scroll):
            super().__init__(columns, lines)
            self._on_scroll = on_scroll

        def index(self):
            top, bottom = self.margins or (0, self.lines - 1)
            if self.cursor.y == bottom and top == 0:
                self._on_scroll(dict(self.buffer.get(top, {})))
            super().index()


# ── Terminal widget (VT100/xterm emulation via pyte) ────────────────────────
class TerminalWidget(tk.Frame):
    def __init__(self, parent, cols=120, rows=32, scrollback_limit=5000, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._cols, self._rows = cols, rows
        self._terminal_state = TerminalPanelState(max_scrollback_lines=scrollback_limit)
        self._text = tk.Text(
            self,
            bg=_TERM_BG,
            fg=TEXT,
            insertbackground=TEXT,
            font=MONO,
            wrap="none",
            relief="flat",
            borderwidth=0,
            padx=4,
            pady=2,
            state="disabled",
        )
        # Keep the scrollbar as a real part of every terminal tab.  In
        # particular, route its command through us so clicking its trough or
        # dragging its thumb updates follow/unseen state as well as yview.
        self._scrollbar = tk.Scrollbar(
            self,
            command=self._on_scrollbar,
            bg=PANEL,
            activebackground=ACCENT,
            troughcolor=_TERM_BG,
            highlightthickness=0,
            relief="flat",
        )
        self._text.configure(yscrollcommand=self._on_yview)
        self._text.grid(row=0, column=0, sticky="nsew")
        self._scrollbar.grid(row=0, column=1, sticky="ns")
        self._unseen_button = tk.Button(
            self,
            text="New output ↓",
            command=self.jump_to_bottom,
            bg=PANEL,
            fg=ACCENT,
            activebackground=PANEL,
            activeforeground=ACCENT,
            relief="flat",
            takefocus=False,
        )
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self._channel = None
        self._recording = False
        self._rec_file = None
        self._lock = threading.RLock()
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._tag_cache: dict = {}
        self._scrollback_queue: list = []
        self._fallback_queue: queue.Queue[str] = queue.Queue()
        self._redraw_pending = False
        self._cursor_range = None
        self._resize_after_id = None
        self._io_stop = threading.Event()
        self._outbound: queue.Queue[str | None] = queue.Queue()
        self._reader_thread = None
        self._writer_thread = None
        self._bracketed_paste = False
        self._application_cursor_mode = False
        self._application_keypad_mode = False
        self._mouse_tracking = 0
        self._mouse_sgr = False
        self._cursor_shape = "block"
        self._cursor_blink = True
        self._input_mode_tail = ""
        self._find_matches: list[str] = []
        self._find_index = -1
        self.on_resize = None
        self.on_connection_lost = None

        if pyte:
            self._screen = _ScrollbackScreen(cols, rows, self._queue_scrollback)
            self._stream = pyte.Stream(self._screen)
            self._normal_screen = self._screen
            self._alternate_screen = None
            self._alternate_active = False
            self._alternate_control_tail = ""
        else:
            self._screen = None
            self._stream = None
            self._alternate_screen = None
            self._alternate_active = False
            self._alternate_control_tail = ""

        for _ in range(rows):
            self._text.configure(state="normal")
            self._text.insert("end", "\n")
            self._text.configure(state="disabled")
        self._text.mark_set("live_start", "1.0")

        self._text.bind("<Key>", self._on_key)
        # Bind these explicitly so Tk does not use Tab for focus traversal;
        # the remote shell receives it for command and path completion.
        self._text.bind("<Tab>", self._on_key)
        self._text.bind("<Shift-Tab>", self._on_key)
        self._text.bind("<Control-v>", self._on_paste)
        self._text.bind("<Control-V>", self._on_paste)
        self._text.bind("<Control-Shift-V>", self._on_paste)
        self._text.bind("<Control-Shift-C>", self._on_copy_shortcut)
        self._text.bind("<Control-Insert>", self._on_copy_shortcut)
        self._text.bind("<Control-Shift-F>", self._open_search)
        self._text.bind("<Shift-Insert>", self._on_paste)
        self._text.bind("<Button-2>", self._on_paste)
        self._text.bind("<Button-3>", self._show_context_menu)
        self._text.bind("<Configure>", self._on_configure)
        self._text.bind("<Button-1>", self._on_click)
        self._text.bind("<ButtonPress-1>", self._on_mouse_press, add="+")
        self._text.bind("<ButtonRelease-1>", self._on_mouse_release, add="+")
        self._text.bind("<Motion>", self._on_motion)
        self._text.bind("<MouseWheel>", self._on_scroll)
        self._text.bind("<Button-4>", self._on_scroll)
        self._text.bind("<Button-5>", self._on_scroll)
        self._text.tag_configure("url", foreground=CYAN, underline=True)
        self._context_menu = tk.Menu(self, tearoff=0)
        # Tk is single-threaded. The SSH worker updates only the terminal
        # model; this timer is the sole path that touches Tk widgets.
        self.after(16, self._render_loop)

    # ── output pipeline ─────────────────────────────────────────────────
    def write(self, text: str, tag: str = ""):
        """Feed plain app/status text (e.g. '[connected]') through the same
        VT100 pipeline so it lands in-line with real terminal output."""
        if tag in _TAG_COLOR_CODES:
            text = f"\x1b[{_TAG_COLOR_CODES[tag]}m{text}\x1b[0m"
        self._feed(text.replace("\n", "\r\n"))

    def _feed(self, data: str):
        if not data:
            return
        if self._recording and self._rec_file:
            try:
                self._rec_file.write(data)
            except Exception:
                pass
        if not self._stream:
            # Keep even the degraded renderer on the Tk thread.
            self._fallback_queue.put(data)
            with self._lock:
                self._redraw_pending = True
            return
        with self._lock:
            self._track_input_modes(data)
            # pyte intentionally leaves DEC alternate-screen handling to
            # applications.  Switch its listener at the DEC boundary so a
            # full-screen application cannot overwrite normal scrollback.
            data = self._alternate_control_tail + data
            self._alternate_control_tail = ""
            controls = ("\x1b[?47h", "\x1b[?47l", "\x1b[?1047h", "\x1b[?1047l", "\x1b[?1049h", "\x1b[?1049l")
            # Keep a possibly split alternate-screen control out of pyte until
            # it is complete; otherwise its parser binds the partial CSI to
            # the normal screen before this widget can swap buffers.
            marker = data.rfind("\x1b[?")
            if (
                marker >= 0
                and data[marker:] not in controls
                and any(control.startswith(data[marker:]) for control in controls)
            ):
                self._alternate_control_tail = data[marker:]
                data = data[:marker]
            parts = re.split(r"(\x1b\[\?(?:47|1047|1049)[hl])", data)
            for part in parts:
                if part in {"\x1b[?47h", "\x1b[?1047h", "\x1b[?1049h"}:
                    self._enter_alternate()
                elif part in {"\x1b[?47l", "\x1b[?1047l", "\x1b[?1049l"}:
                    self._leave_alternate()
                elif part:
                    self._stream.feed(part)
            self._redraw_pending = True

    def _enter_alternate(self):
        if self._alternate_active:
            return
        self._alternate_screen = _ScrollbackScreen(self._cols, self._rows, lambda _line: None)
        self._screen = self._alternate_screen
        self._stream.attach(self._screen)
        self._alternate_active = True

    def _leave_alternate(self):
        if not self._alternate_active:
            return
        self._screen = self._normal_screen
        self._stream.attach(self._screen)
        self._alternate_active = False

    def _fallback_append(self, data):
        self._text.configure(state="normal")
        self._text.insert("end", re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07", "", data))
        self._refresh_links()
        self._text.see("end")
        self._text.configure(state="disabled")

    def attach_channel(self, channel):
        self.detach()
        generation = self._terminal_state.begin(reconnecting=self._terminal_state.generation > 0)
        self._channel = channel
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._io_stop = threading.Event()
        self._outbound = queue.Queue()
        self._reader_thread = threading.Thread(
            target=self._reader, args=(channel, self._io_stop, self._decoder, generation), daemon=True
        )
        self._writer_thread = threading.Thread(
            target=self._writer, args=(channel, self._io_stop, self._outbound), daemon=True
        )
        self._reader_thread.start()
        self._writer_thread.start()
        self._terminal_state.connected(generation)

    def _reader(self, channel, stop, decoder, generation):
        while not stop.is_set() and not channel.closed:
            try:
                got = False
                if channel.recv_ready():
                    raw = channel.recv(32768)
                    if not raw:
                        break
                    data = decoder.decode(raw)
                    if data and self._terminal_state.accepts_output(generation):
                        self._feed(data)
                    got = True
                if channel.recv_stderr_ready():
                    raw = channel.recv_stderr(32768)
                    data = decoder.decode(raw)
                    if data and self._terminal_state.accepts_output(generation):
                        self._feed(data)
                    got = True
                if not got:
                    time.sleep(0.02)
            except Exception:
                break
        if not stop.is_set():
            self.after(
                0,
                lambda g=generation: (
                    self._terminal_state.ended(g, lost=True),
                    self.on_connection_lost and self.on_connection_lost(g),
                ),
            )

    @staticmethod
    def _writer(channel, stop, outbound):
        """Serialize writes: Channel.send() is allowed to be partial."""
        while not stop.is_set() and not channel.closed:
            try:
                data = outbound.get(timeout=0.1)
                if data is None:
                    break
                channel.sendall(data.encode("utf-8"))
            except queue.Empty:
                continue
            except Exception as exc:
                # Do not silently lose editor keystrokes.  The reader will
                # normally report the closed channel too, while this log
                # leaves a diagnostic trail for send failures.
                log(f"Terminal channel write failed: {exc}")
                break

    def _send(self, data: str):
        if data and self._channel and not self._channel.closed:
            self._outbound.put(data)

    def _track_input_modes(self, data: str):
        """Remember DECSET 2004 even when its escape sequence is split."""
        scan = self._input_mode_tail + data
        for enabled in re.findall(r"\x1b\[\?2004([hl])", scan):
            self._bracketed_paste = enabled == "h"
        for enabled in re.findall(r"\x1b\[\?1([hl])", scan):
            self._application_cursor_mode = enabled == "h"
        for enabled in re.findall(r"\x1b\[\?66([hl])", scan):
            self._application_keypad_mode = enabled == "h"
        for mode, enabled in re.findall(r"\x1b\[\?(1000|1002|1003|1006)([hl])", scan):
            if mode == "1006":
                self._mouse_sgr = enabled == "h"
            elif enabled == "h":
                self._mouse_tracking = int(mode)
            elif self._mouse_tracking == int(mode):
                self._mouse_tracking = 0
        for shape in re.findall(r"\x1b\[([0-6]) q", scan):
            self._cursor_shape = {"3": "underline", "4": "underline", "5": "bar", "6": "bar"}.get(shape, "block")
            self._cursor_blink = shape not in {"2", "4", "6"}
        self._input_mode_tail = scan[-32:]

    # ── redraw ───────────────────────────────────────────────────────────
    def _queue_scrollback(self, line: dict):
        with self._lock:
            self._scrollback_queue.append(line)

    def _render_loop(self):
        """Run on the Tk thread; never call Tk from Paramiko worker threads."""
        try:
            with self._lock:
                pending = self._redraw_pending
            if pending:
                self._redraw()
            self.after(16, self._render_loop)
        except tk.TclError:
            # The notebook can destroy a terminal while an SSH worker exits.
            pass

    def _style_tag(self, ch):
        fg = _terminal_color(ch.fg, TEXT)
        bg = _terminal_color(ch.bg, _TERM_BG)
        if ch.reverse:
            fg, bg = bg, fg
        if getattr(ch, "blink", False):
            fg = MUTED
        if getattr(ch, "conceal", False):
            fg = bg
        key = (fg, bg, ch.bold, getattr(ch, "italics", False), ch.underscore, getattr(ch, "strikethrough", False))
        tagname = self._tag_cache.get(key)
        if tagname is None:
            tagname = f"style{len(self._tag_cache)}"
            opts = {"foreground": fg, "background": bg}
            if ch.bold or getattr(ch, "italics", False):
                style = (
                    "bold italic" if ch.bold and getattr(ch, "italics", False) else ("bold" if ch.bold else "italic")
                )
                opts["font"] = (MONO[0], MONO[1], style)
            if ch.underscore:
                opts["underline"] = True
            if getattr(ch, "strikethrough", False):
                opts["overstrike"] = True
            self._text.tag_configure(tagname, **opts)
            self._tag_cache[key] = tagname
        return tagname

    def _build_runs(self, line: dict):
        runs = []
        cur_tag = None
        cur_chars = []
        default = self._screen.default_char
        for col in range(self._cols):
            ch = line.get(col, default)
            tag = self._style_tag(ch)
            d = ch.data or " "
            if tag == cur_tag:
                cur_chars.append(d)
            else:
                if cur_tag is not None:
                    runs.append(("".join(cur_chars), cur_tag))
                cur_tag = tag
                cur_chars = [d]
        if cur_tag is not None:
            runs.append(("".join(cur_chars), cur_tag))
        return runs

    def _redraw(self):
        if not self._screen:
            while True:
                try:
                    self._fallback_append(self._fallback_queue.get_nowait())
                except queue.Empty:
                    break
            with self._lock:
                self._redraw_pending = False
            return
        with self._lock:
            scrollback = self._scrollback_queue
            self._scrollback_queue = []
            dirty = sorted(self._screen.dirty)
            self._screen.dirty.clear()
            self._redraw_pending = False
            buffer = {row: dict(self._screen.buffer.get(row, {})) for row in dirty}
            cur = self._screen.cursor
            cursor_y, cursor_x, cursor_hidden = cur.y, cur.x, cur.hidden

        at_bottom = self._at_bottom()
        # A scrollbar trough click/drag can change yview just before its
        # idle callback updates the state.  Read yview here too so output in
        # that small window never snaps a user back to the bottom.
        if not at_bottom:
            self._terminal_state.follow_output = False
        self._text.configure(state="normal")
        touched_lines = set()

        for line in scrollback:
            line_no = int(self._text.index("live_start").split(".")[0])
            touched_lines.add(line_no)
            for text_run, tag in self._build_runs(line):
                self._text.insert("live_start", text_run, tag)
            self._text.insert("live_start", "\n")
        if scrollback:
            self._trim_scrollback()

        for row in dirty:
            row_start = self._text.index(f"live_start +{row}l linestart")
            row_end = self._text.index(f"live_start +{row}l lineend")
            touched_lines.add(int(row_start.split(".")[0]))
            self._text.delete(row_start, row_end)
            pos = row_start
            for text_run, tag in self._build_runs(buffer.get(row, {})):
                self._text.insert(pos, text_run, tag)
                pos = self._text.index(f"{pos}+{len(text_run)}c")

        if self._cursor_range:
            self._text.tag_remove("cursor", *self._cursor_range)
            self._cursor_range = None
        if not cursor_hidden:
            cpos = self._text.index(f"live_start +{cursor_y}l linestart +{cursor_x}c")
            cend = self._text.index(f"{cpos}+1c")
            self._text.tag_add("cursor", cpos, cend)
            cursor_opts = {"background": ACCENT, "foreground": BG}
            if self._cursor_shape == "underline":
                cursor_opts = {"underline": True, "foreground": ACCENT}
            elif self._cursor_shape == "bar":
                cursor_opts = {"underline": True, "foreground": ACCENT}
            self._text.tag_configure("cursor", **cursor_opts)
            self._cursor_range = (cpos, cend)

        if touched_lines:
            self._refresh_links(touched_lines)
        output_arrived = bool(scrollback or dirty)
        if output_arrived and at_bottom:
            self._terminal_state.follow_output = True
        if output_arrived and self._terminal_state.follow_output:
            self._text.see("end")
        elif output_arrived:
            self._terminal_state.note_output()
        self._update_unseen_indicator()
        self._text.configure(state="disabled")

    def _trim_scrollback(self):
        limit = self._terminal_state.max_scrollback_lines
        n_lines = int(self._text.index("live_start").split(".")[0]) - 1
        if n_lines > limit:
            self._text.delete("1.0", f"{n_lines - limit + 1}.0")

    # ── input: raw forwarding, no local echo (server drives the display) ──
    def _on_key(self, event):
        if not self._channel:
            return "break"
        ks = event.keysym
        if ks in ("Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Super_L", "Super_R", "Caps_Lock"):
            return "break"
        # Shift+PageUp/PageDown is the conventional local scrollback escape
        # hatch even while a full-screen remote program owns navigation keys.
        if ks in {"Prior", "Next"} and event.state & 0x0001:
            self._text.yview_scroll(-1 if ks == "Prior" else 1, "pages")
            self._sync_viewport_state()
            return "break"
        seq = terminal_key_sequence(
            ks,
            event.char,
            event.state,
            application_cursor=self._application_cursor_mode,
            application_keypad=self._application_keypad_mode,
        )
        if ks == "space" and event.state & 0x0004:
            seq = "\x00"
        if seq:
            self._send(seq)
        return "break"

    def _on_copy_shortcut(self, _event):
        """Copy only an existing Tk selection; Ctrl-C remains remote SIGINT."""
        self._copy_selection()
        return "break"

    def _open_search(self, _event=None):
        query = simpledialog_ask("Find in terminal", "Search text:")
        if query:
            self.find(query)
        self._text.focus_set()
        return "break"

    def _on_paste(self, _e):
        if self._channel:
            try:
                data = self.clipboard_get()
                settings = getattr(self.winfo_toplevel(), "_runtime_settings", None)
                if self._terminal_state.requires_paste_confirmation(data) and confirm_multiline_paste_enabled(settings):
                    if not messagebox.askyesno("Paste into terminal", "Paste multiple lines into the remote terminal?"):
                        return "break"
                if self._bracketed_paste:
                    data = "\x1b[200~" + data + "\x1b[201~"
                self._send(data)
            except Exception:
                pass
        return "break"

    def _on_scroll(self, event):
        if self._mouse_tracking and self._channel and not (getattr(event, "state", 0) & 0x0001):
            direction = 64 if getattr(event, "delta", 0) > 0 or getattr(event, "num", 0) == 4 else 65
            self._send_mouse(direction, event, release=False)
            return "break"
        self._text.yview_scroll(-1 if getattr(event, "delta", 0) > 0 or getattr(event, "num", 0) == 4 else 1, "units")
        self._sync_viewport_state()
        return "break"

    def _send_mouse(self, button: int, event, *, release: bool):
        """Encode xterm mouse input only after the remote enabled it."""
        if not self._channel or not self._mouse_tracking:
            return
        font = tkfont.Font(font=MONO)
        x = max(1, event.x // max(1, font.measure("M")) + 1)
        y = max(1, event.y // max(1, font.metrics("linespace")) + 1)
        if self._mouse_sgr:
            self._send(f"\x1b[<{button};{x};{y}{'m' if release else 'M'}")
        elif x < 224 and y < 224:
            self._send("\x1b[M" + chr(32 + button) + chr(32 + x) + chr(32 + y))

    def _on_mouse_press(self, event):
        if self._mouse_tracking and not (event.state & 0x0001):
            self._send_mouse(0, event, release=False)
            return "break"
        return None

    def _on_mouse_release(self, event):
        if self._mouse_tracking and not (event.state & 0x0001):
            self._send_mouse(3, event, release=True)
            return "break"
        return None

    def _on_scrollbar(self, *args):
        """Support thumb drag and page clicks through the native scrollbar."""
        self._text.yview(*args)
        self.after_idle(self._sync_viewport_state)

    def _on_yview(self, first, last):
        self._scrollbar.set(first, last)
        self.after_idle(self._sync_viewport_state)

    def _at_bottom(self):
        return self._text.yview()[1] >= 0.999

    def _sync_viewport_state(self):
        if self._at_bottom():
            self._terminal_state.jump_to_bottom()
        else:
            self._terminal_state.follow_output = False
        self._update_unseen_indicator()

    def _update_unseen_indicator(self):
        if self._terminal_state.unseen_output and not self._at_bottom():
            self._unseen_button.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-6)
        else:
            self._unseen_button.place_forget()

    def jump_to_bottom(self):
        self._terminal_state.jump_to_bottom()
        self._text.see("end")
        self._update_unseen_indicator()

    def find(self, query: str, *, previous: bool = False) -> tuple[int, int]:
        """Highlight case-insensitive matches without changing terminal data."""
        self._text.tag_remove("find", "1.0", "end")
        self._find_matches = []
        if not query:
            return (0, 0)
        needle = query.casefold()
        start = "1.0"
        while True:
            index = self._text.search(needle, start, stopindex="end", nocase=True)
            if not index:
                break
            end = self._text.index(f"{index}+{len(query)}c")
            self._text.tag_add("find", index, end)
            self._find_matches.append(index)
            start = end
        self._text.tag_configure("find", background=YELLOW, foreground=BG)
        if self._find_matches:
            self._find_index = (self._find_index - 1 if previous else self._find_index + 1) % len(self._find_matches)
            self._text.see(self._find_matches[self._find_index])
        return (self._find_index + 1 if self._find_matches else 0, len(self._find_matches))

    def _show_context_menu(self, event):
        """Provide familiar clipboard actions without intercepting Ctrl-C."""
        has_selection = bool(self._text.tag_ranges("sel"))
        self._context_menu.delete(0, "end")
        self._context_menu.add_command(
            label="Copy",
            command=self._copy_selection,
            state="normal" if has_selection else "disabled",
        )
        self._context_menu.add_command(label="Paste", command=lambda: self._on_paste(None))
        self._context_menu.add_command(label="Select All", command=self._select_all)
        self._context_menu.add_command(label="Clear Selection", command=self._clear_selection)
        self._context_menu.add_command(label="Search", command=self._open_search)
        self._text.focus_set()
        try:
            self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._context_menu.grab_release()
        return "break"

    def _copy_selection(self):
        try:
            selected = self._text.get("sel.first", "sel.last")
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(selected)

    def _clear_selection(self):
        self._text.tag_remove("sel", "1.0", "end")

    def _select_all(self):
        self._text.tag_add("sel", "1.0", "end-1c")

    def _on_click(self, event):
        url = self._url_at_index(f"@{event.x},{event.y}")
        if url:
            try:
                subprocess.Popen(["xdg-open", url])
            except Exception:
                pass
            return "break"
        self._text.focus_set()
        return "break"

    def _on_motion(self, event):
        cursor = "hand2" if self._url_at_index(f"@{event.x},{event.y}") else "xterm"
        self._text.configure(cursor=cursor)

    def _url_at_index(self, index: str) -> str | None:
        line, col = map(int, self._text.index(index).split("."))
        text = self._text.get(f"{line}.0", f"{line}.end")
        if not text:
            return None

        start = col
        while start > 0 and text[start - 1] in _URL_CHARS:
            start -= 1
        end = col
        while end < len(text) and text[end] in _URL_CHARS:
            end += 1

        fragment = text[start:end]
        if not fragment:
            return None

        full = fragment

        scan_line = line - 1
        while scan_line >= 1:
            prev = self._text.get(f"{scan_line}.0", f"{scan_line}.end")
            if not prev or len(prev) < self._cols:
                break
            i = len(prev)
            while i > 0 and prev[i - 1] in _URL_CHARS:
                i -= 1
            suffix = prev[i:]
            if not suffix:
                break
            full = suffix + full
            if "http://" in suffix or "https://" in suffix:
                break
            scan_line -= 1

        scan_line = line + 1
        while scan_line <= int(self._text.index("end-1c").split(".")[0]):
            nxt = self._text.get(f"{scan_line}.0", f"{scan_line}.end")
            if not nxt:
                break
            j = 0
            while j < len(nxt) and nxt[j] in _URL_CHARS:
                j += 1
            prefix = nxt[:j]
            if not prefix:
                break
            full += prefix
            if len(nxt) < self._cols:
                break
            scan_line += 1

        match = _URL_RE.search(full)
        return match.group(0) if match else None

    def _refresh_links(self, touched_lines=None):
        """Re-tag URLs.

        Rescanning the whole scrollback buffer on every redraw is O(n) per
        tick; with pyte feeding line-by-line during high-output commands
        (ls, find, git status on big trees) that becomes O(n^2) and stalls
        the UI. When touched_lines is given, only those lines are re-tagged.
        """
        if touched_lines is None:
            self._text.tag_remove("url", "1.0", "end")
            for _url, spans in self._collect_url_segments():
                for line, start, end in spans:
                    self._text.tag_add("url", f"{line}.{start}", f"{line}.{end}")
            return
        for line_no in touched_lines:
            self._text.tag_remove("url", f"{line_no}.0", f"{line_no}.end")
            text = self._text.get(f"{line_no}.0", f"{line_no}.end")
            if not text:
                continue
            for match in _URL_RE.finditer(text):
                self._text.tag_add("url", f"{line_no}.{match.start()}", f"{line_no}.{match.end()}")

    def _collect_url_segments(self):
        total_lines = int(self._text.index("end-1c").split(".")[0])
        lines = [self._text.get(f"{line}.0", f"{line}.end") for line in range(1, total_lines + 1)]
        segments = []
        seen = set()
        for line_no, text in enumerate(lines, start=1):
            for match in _URL_RE.finditer(text):
                key = (line_no, match.start())
                if key in seen:
                    continue
                url = match.group(0)
                spans = [(line_no, match.start(), match.end())]
                seen.add(key)
                next_line = line_no + 1
                while next_line <= total_lines:
                    continuation = lines[next_line - 1].lstrip()
                    if not continuation:
                        break
                    prefix_len = len(lines[next_line - 1]) - len(continuation)
                    cont_len = 0
                    for ch in continuation:
                        if ch in _URL_CHARS:
                            cont_len += 1
                        else:
                            break
                    if cont_len == 0:
                        break
                    url += continuation[:cont_len]
                    spans.append((next_line, prefix_len, prefix_len + cont_len))
                    next_line += 1
                segments.append((url, spans))
        return segments

    def _on_configure(self, event):
        if self._resize_after_id:
            self.after_cancel(self._resize_after_id)
        self._resize_after_id = self.after(150, lambda: self._apply_resize(event.width, event.height))

    def _apply_resize(self, width, height):
        self._resize_after_id = None
        if not self._screen:
            return
        f = tkfont.Font(font=MONO)
        char_w = max(1, f.measure("M"))
        char_h = max(1, f.metrics("linespace"))
        cols, rows = TerminalPanelState.terminal_size(width, height, char_w, char_h)
        if cols == self._cols and rows == self._rows:
            return
        self._cols, self._rows = cols, rows
        if self.on_resize:
            self.on_resize(cols, rows)
        with self._lock:
            self._screen.resize(rows, cols)
            if self._alternate_screen is not None and self._screen is not self._alternate_screen:
                self._alternate_screen.resize(rows, cols)
            if self._normal_screen is not self._screen:
                self._normal_screen.resize(rows, cols)
        # Rebuild only the live grid.  Incremental newline arithmetic here
        # used to delete an extra row on shrink, and inserting after a mark
        # with right gravity could move live_start below the terminal grid.
        grid_start = self._text.index("live_start")
        self._text.configure(state="normal")
        self._text.delete(grid_start, "end")
        self._text.insert("end", "\n" * rows)
        self._text.mark_set("live_start", grid_start)
        self._text.configure(state="disabled")
        if self._channel:
            try:
                self._channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass
        with self._lock:
            self._screen.dirty.update(range(rows))
        with self._lock:
            self._redraw_pending = True

    def start_recording(self, path: str):
        self._rec_file = open(path, "w", encoding="utf-8")
        self._rec_file.write(f"# SSHVault session recording — {datetime.now()}\n")
        self._recording = True

    def stop_recording(self):
        self._recording = False
        if self._rec_file:
            self._rec_file.close()
            self._rec_file = None

    def clear(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._cursor_range = None
        for _ in range(self._rows):
            self._text.insert("end", "\n")
        # Set the mark *after* creating the grid. Its right gravity is
        # intentional for scrollback, but would otherwise move it to the end.
        self._text.mark_set("live_start", "1.0")
        self._text.configure(state="disabled")
        if self._screen:
            with self._lock:
                self._screen.reset()
                self._scrollback_queue = []
                self._redraw_pending = True

    def detach(self):
        self.stop_recording()
        self._io_stop.set()
        try:
            self._outbound.put_nowait(None)
        except Exception:
            pass
        if self._channel:
            try:
                self._channel.close()
            except Exception:
                pass
        current = threading.current_thread()
        for worker in (self._reader_thread, self._writer_thread):
            if worker is not None and worker is not current and worker.is_alive():
                worker.join(0.25)
        self._reader_thread = None
        self._writer_thread = None
        self._channel = None
        self._terminal_state.generation += 1
        self._terminal_state.status = "disconnected"


# ── SFTP panel ───────────────────────────────────────────────────────────────
class SFTPTransferManagerWindow(tk.Toplevel):
    """Modeless transfer view. Closing it hides it; work continues."""

    COLUMNS = (
        "name",
        "direction",
        "source",
        "destination",
        "size",
        "transferred",
        "resume_offset",
        "remaining_bytes",
        "progress",
        "speed",
        "remaining",
        "status",
        "error",
    )

    def __init__(self, panel):
        super().__init__(panel.winfo_toplevel())
        self.panel = panel
        self._destroyed = False
        self._refresh_after = None
        self._fullscreen = False
        settings = getattr(panel.winfo_toplevel(), "_runtime_settings", {})
        self.state_model = TransferManagerWindowState.from_settings(
            settings.get("transfer_manager_window") if isinstance(settings, dict) else None
        )
        self.title(session_resource_title("SFTP Transfer Manager", panel._owner_profile))
        width, height, x, y = self.state_model.geometry_for_screen(self.winfo_screenwidth(), self.winfo_screenheight())
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(760, 240)
        self.protocol("WM_DELETE_WINDOW", self.hide)
        self.bind("<F11>", self._toggle_fullscreen)
        self.bind("<Escape>", self._exit_fullscreen)
        self.bind("<Configure>", self._configured)
        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x", padx=6, pady=4)
        self.summary = tk.StringVar()
        tk.Label(top, textvariable=self.summary, bg=PANEL, fg=TEXT, font=FONT).pack(side="left")
        actions = (
            ("Pause Selected", panel._pause_selected_transfer),
            ("Resume Selected", panel._resume_selected_transfer),
            ("Cancel Selected", panel._cancel_selected_transfer),
            ("Retry Selected", panel._retry_selected_transfer),
            ("Remove Selected", panel._remove_selected_transfer),
            ("Clear Completed", panel._clear_completed_transfers),
            ("Pause All", panel._pause_all_transfers),
            ("Resume All", panel._resume_all_transfers),
            ("Cancel All", panel._cancel_all_transfers),
        )
        bar = tk.Frame(self, bg=PANEL)
        bar.pack(fill="x", padx=6, pady=(0, 4))
        for label, command in actions:
            tk.Button(bar, text=label, command=command, bg=ACCENT, fg=BG, font=FONT, relief="flat").pack(
                side="left", padx=2
            )
        frame = tk.Frame(self, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=6, pady=4)
        self.tree = ttk.Treeview(frame, columns=self.COLUMNS, show="headings", selectmode="extended")
        if set(self.state_model.column_order) == set(self.COLUMNS):
            self.tree.configure(displaycolumns=self.state_model.column_order)
        for col in self.COLUMNS:
            self.tree.heading(col, text=col.replace("_", " ").title(), command=lambda c=col: self._sort(c))
            self.tree.column(
                col,
                width=self.state_model.column_widths.get(
                    col, 110 if col not in {"source", "destination", "error"} else 180
                ),
                anchor="w",
            )
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=xscroll.set)
        self.tree.pack(fill="both", expand=True)
        xscroll.pack(fill="x")
        self.tree.bind("<Double-Button-1>", self._details)
        self.menu = tk.Menu(self, tearoff=0)
        for label, command in actions[:5]:
            self.menu.add_command(label=label, command=command)
        self.tree.bind("<Button-3>", self._popup)
        self.tree.bind("<Delete>", lambda _event: panel._remove_selected_transfer())
        self.tree.bind("<space>", self._space_action)
        if self.state_model.maximized:
            self.after_idle(self._restore_maximized)

    def _restore_maximized(self):
        try:
            self.state("zoomed")
        except tk.TclError:
            pass

    def _popup(self, event):
        self.tree.selection_set(self.tree.identify_row(event.y))
        self.menu.tk_popup(event.x_root, event.y_root)

    def _sort(self, column):
        if self.state_model.sort_column == column:
            self.state_model.sort_descending = not self.state_model.sort_descending
        else:
            self.state_model.sort_column, self.state_model.sort_descending = column, False
        self.refresh()

    def _space_action(self, _event):
        for item_id in self.tree.selection():
            item = self.panel._transfer_manager.get(item_id)
            if item and item.status == TransferState.PAUSED:
                self.panel._transfer_manager.resume(item_id)
            elif item:
                self.panel._transfer_manager.pause(item_id)
        return "break"

    def _toggle_fullscreen(self, _event=None):
        self._fullscreen = not self._fullscreen
        self.attributes("-fullscreen", self._fullscreen)
        return "break"

    def _exit_fullscreen(self, _event=None):
        if self._fullscreen:
            self._fullscreen = False
            self.attributes("-fullscreen", False)
        return "break"

    def _configured(self, _event=None):
        if self._destroyed or self._fullscreen:
            return
        self.state_model.width, self.state_model.height = self.winfo_width(), self.winfo_height()
        self.state_model.x, self.state_model.y = self.winfo_x(), self.winfo_y()
        self.state_model.maximized = self.state() == "zoomed"

    def hide(self):
        self._persist()
        self.withdraw()

    def destroy_manager(self):
        if self._refresh_after is not None:
            self.after_cancel(self._refresh_after)
            self._refresh_after = None
        self._persist()
        self._destroyed = True
        self.destroy()

    def _persist(self):
        if self._destroyed:
            return
        self.state_model.column_widths = {column: self.tree.column(column, "width") for column in self.COLUMNS}
        displayed = self.tree.cget("displaycolumns")
        self.state_model.column_order = list(displayed) if isinstance(displayed, tuple) else list(self.COLUMNS)
        app = self.panel.winfo_toplevel()
        settings = getattr(app, "_runtime_settings", None)
        if isinstance(settings, dict):
            settings["transfer_manager_window"] = self.state_model.to_settings()
            try:
                atomic_json_write(SETTINGS_FILE, validate_settings(settings))
            except OSError:
                pass

    def request_refresh(self):
        if self._destroyed or self._refresh_after is not None:
            return
        delay = 1000 if self.state() == "withdrawn" else 150
        self._refresh_after = self.after(delay, self._run_refresh)

    def _run_refresh(self):
        self._refresh_after = None
        if not self._destroyed:
            self.refresh()

    def _details(self, _event):
        selected = self.tree.selection()
        if selected:
            item = self.panel._transfer_manager.get(selected[0])
            if item and item.status == TransferState.FAILED:
                messagebox.showerror("Transfer failed", item.error or "Unknown transfer error", parent=self)

    def refresh(self):
        if self._destroyed:
            return
        selected = self.tree.selection()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        items = list(self.panel._transfer_manager.items)
        key_map = {
            "name": lambda item: Path(item.source).name.casefold(),
            "direction": lambda item: item.direction,
            "size": lambda item: item.total or -1,
            "progress": lambda item: item.progress() or -1,
            "speed": lambda item: item.speed,
            "status": lambda item: item.status,
        }
        ordered = (
            items
            if self.state_model.sort_column == "queue"
            else sorted(
                items,
                key=key_map.get(self.state_model.sort_column, lambda item: item.item_id),
                reverse=self.state_model.sort_descending,
            )
        )
        for item in ordered:
            pct = "—" if item.progress() is None else f"{item.progress():.1f}%"
            eta = "—" if item.remaining_seconds() is None else f"{item.remaining_seconds():.0f}s"
            size = "—" if item.total is None else self.panel._fmt_size(item.total)
            remaining = "—" if item.total is None else self.panel._fmt_size(max(0, item.total - item.transferred))
            self.tree.insert(
                "",
                "end",
                iid=item.item_id,
                values=(
                    Path(item.source).name,
                    item.direction,
                    item.source,
                    item.target,
                    size,
                    self.panel._fmt_size(item.transferred),
                    self.panel._fmt_size(item.resume_offset),
                    remaining,
                    pct,
                    self.panel._fmt_size(item.speed) + "/s",
                    eta,
                    item.status + (" (Restart required)" if item.restart_required else ""),
                    item.error,
                ),
            )
        self.tree.selection_set([item_id for item_id in selected if self.tree.exists(item_id)])
        data = self.panel._transfer_manager.summary()
        self.summary.set(
            "Active: {active}   Pending: {pending}   Paused: {paused}   Completed: {completed}   Failed: {failed}   "
            "Total speed: {speed} B/s   Remaining: {remaining} B".format(
                **{
                    **data,
                    "paused": sum(x.status == TransferState.PAUSED for x in items),
                    "remaining": sum(max(0, (x.total or 0) - x.transferred) for x in items),
                }
            )
        )


class SFTPPanel(tk.Frame):
    def __init__(
        self,
        parent,
        sftp,
        default_local_directory=None,
        *,
        verify_completed=True,
        session_id: str | None = None,
        owner_profile: dict | None = None,
        **kw,
    ):
        super().__init__(parent, bg=PANEL, **kw)
        self._sftp = sftp
        self.session_id = session_id
        self._owner_profile = dict(owner_profile or {})
        self._remote_cwd = "/"
        self._local_cwd = (
            str(Path(default_local_directory).expanduser()) if default_local_directory else str(Path.home())
        )
        self._remote_history = [self._remote_cwd]
        self._remote_hist_idx = 0
        self._local_history = [self._local_cwd]
        self._local_hist_idx = 0
        self._remote_open_cache = Path(tempfile.gettempdir()) / "sshvault-open"
        self._remote_open_cache.mkdir(parents=True, exist_ok=True)
        self._transfer_queue: queue.Queue = queue.Queue()
        self._transfer_refresh_events: queue.Queue[bool] = queue.Queue(maxsize=1)
        self._transfer_cancel = threading.Event()
        self._closed = False
        self._remote_generation = 0
        self._sftp_state = SFTPPanelState()
        self._verify_completed = bool(verify_completed)
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", {})
        self._transfer_transport = getattr(self._sftp.get_channel(), "transport", None)
        self._transfer_manager = TransferScheduler(
            self._new_transfer_client,
            concurrency=settings.get("maximum_sftp_transfers", 3) if isinstance(settings, dict) else 3,
            on_change=self._request_transfer_refresh,
            reuse_worker_channels=True,
            session_id=self.session_id,
            profile_id=str(self._owner_profile.get("id", "")) or None,
            operation_timeout=30,
        )
        self._transfer_window = None
        self._local_load_state = DirectoryLoadState()
        self._local_load_lock = threading.Lock()
        self._local_load_path = self._local_cwd
        self._remote_navigation_busy = False
        self._path_menu = tk.Menu(self, tearoff=0)
        self._completion_menu = tk.Menu(self, tearoff=0)
        self._build()
        self._transfer_thread = threading.Thread(target=self._transfer_worker, daemon=True)
        self._transfer_thread.start()
        self.after(150, self._poll_transfer_refresh)
        self._refresh_local()
        self._refresh_remote()

    def _dispatch(self, callback):
        """Return worker results only while this panel still owns its session."""

        def guarded():
            if not self._closed:
                callback()

        try:
            self.after(0, guarded)
        except (RuntimeError, tk.TclError):
            pass

    def _request_transfer_refresh(self):
        """Queue worker state changes; only the Tk poller touches widgets."""
        if not self._closed:
            try:
                self._transfer_refresh_events.put_nowait(True)
            except queue.Full:
                # The poller reads current scheduler state, so one pending token
                # always represents the latest progress for every transfer.
                pass

    def _poll_transfer_refresh(self):
        if self._closed:
            return
        changed = False
        while True:
            try:
                self._transfer_refresh_events.get_nowait()
                changed = True
            except queue.Empty:
                break
        if changed:
            self._refresh_transfer_tree()
        self.after(150, self._poll_transfer_refresh)

    def _build(self):
        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x", padx=4, pady=2)
        tk.Label(top, text="SFTP", bg=PANEL, fg=ACCENT, font=FONT_B).pack(side="left")
        self._btn(top, "Transfers", self._show_transfer_manager).pack(side="left", padx=8)
        self._progress_var = tk.DoubleVar()
        self._progress = ttk.Progressbar(top, variable=self._progress_var, maximum=100, length=200)
        self._progress.pack(side="right", padx=8)
        self._status_var = tk.StringVar(value="Disconnected")
        tk.Label(top, textvariable=self._status_var, bg=PANEL, fg=MUTED, font=FONT).pack(side="right", padx=4)
        compact = tk.Frame(self, bg=PANEL)
        compact.pack(fill="x", padx=6, pady=(0, 2))
        self._transfer_summary_var = tk.StringVar(value="Transfers: 0 active · 0 pending · 0 B/s")
        tk.Label(compact, textvariable=self._transfer_summary_var, bg=PANEL, fg=MUTED, font=FONT).pack(side="left")
        self._btn(compact, "Open Transfer Manager", self._show_transfer_manager).pack(side="right")

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=4, pady=4)

        # local
        lf = tk.LabelFrame(panes, text="Local", bg=PANEL, fg=TEXT, font=FONT)
        self._local_path_var = tk.StringVar(value=self._local_cwd)
        lp = tk.Entry(
            lf,
            textvariable=self._local_path_var,
            bg="#0d0d1a",
            fg=TEXT,
            font=MONO,
            insertbackground=TEXT,
            relief="flat",
        )
        lp.pack(fill="x", padx=4, pady=2)
        lp.bind("<Return>", lambda _: self._cd_local(self._local_path_var.get()))
        lp.bind("<Tab>", self._complete_local_path)
        lp.bind("<Button-3>", lambda event: self._show_path_menu(event, self._local_path_var))
        self._bind_path_shortcuts(lp, self._local_path_var)
        lnav = tk.Frame(lf, bg=PANEL)
        lnav.pack(fill="x", padx=4, pady=(0, 2))
        self._btn(lnav, "Back", self._local_back).pack(side="left", padx=2)
        self._btn(lnav, "Forward", self._local_forward).pack(side="left", padx=2)
        self._btn(lnav, "Up", self._local_up).pack(side="left", padx=2)
        self._btn(lnav, "Refresh", self._refresh_local).pack(side="left", padx=2)
        cols = ("name", "type", "size", "modified")
        self._local_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (190, 70, 80, 130)):
            self._local_tree.heading(
                c, text=c.title(), command=lambda column=c: self._sort_tree(self._local_tree, column)
            )
            self._local_tree.column(c, width=w, anchor="w")
        self._local_tree.pack(fill="both", expand=True, padx=4)
        self._local_tree.bind("<Double-Button-1>", self._local_dbl)
        self._local_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_transfer_actions())
        lbtn = tk.Frame(lf, bg=PANEL)
        lbtn.pack(fill="x", padx=4, pady=2)
        self._upload_btn = self._btn(lbtn, "Upload", self._upload)
        self._upload_btn.pack(side="left", padx=2)
        self._btn(lbtn, "Upload folder", self._upload_folder).pack(side="left", padx=2)
        self._btn(lbtn, "New folder", self._local_mkdir).pack(side="left", padx=2)
        self._btn(lbtn, "Rename", self._local_rename).pack(side="left", padx=2)
        self._btn(lbtn, "Delete", self._local_delete).pack(side="left", padx=2)
        panes.add(lf)

        # remote
        rf = tk.LabelFrame(panes, text="Remote", bg=PANEL, fg=TEXT, font=FONT)
        self._remote_path_var = tk.StringVar(value=self._remote_cwd)
        rp = tk.Entry(
            rf,
            textvariable=self._remote_path_var,
            bg="#0d0d1a",
            fg=TEXT,
            font=MONO,
            insertbackground=TEXT,
            relief="flat",
        )
        rp.pack(fill="x", padx=4, pady=2)
        rp.bind("<Return>", lambda _: self._cd_remote(self._remote_path_var.get()))
        rp.bind("<Tab>", self._complete_remote_path)
        rp.bind("<Button-3>", lambda event: self._show_path_menu(event, self._remote_path_var))
        self._bind_path_shortcuts(rp, self._remote_path_var)
        rnav = tk.Frame(rf, bg=PANEL)
        rnav.pack(fill="x", padx=4, pady=(0, 2))
        self._remote_back_button = self._btn(rnav, "Back", self._remote_back)
        self._remote_back_button.pack(side="left", padx=2)
        self._remote_forward_button = self._btn(rnav, "Forward", self._remote_forward)
        self._remote_forward_button.pack(side="left", padx=2)
        self._remote_up_button = self._btn(rnav, "Up", self._remote_up)
        self._remote_up_button.pack(side="left", padx=2)
        self._btn(rnav, "Refresh", self._refresh_remote).pack(side="left", padx=2)
        self._remote_tree = ttk.Treeview(
            rf, columns=("name", "type", "size", "modified"), show="headings", selectmode="extended"
        )
        for c, w in zip(("name", "type", "size", "modified"), (190, 70, 80, 130)):
            self._remote_tree.heading(
                c, text=c.title(), command=lambda column=c: self._sort_tree(self._remote_tree, column)
            )
            self._remote_tree.column(c, width=w, anchor="w")
        self._remote_tree.pack(fill="both", expand=True, padx=4)
        self._remote_tree.bind("<Double-Button-1>", self._remote_dbl)
        self._remote_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_transfer_actions())
        rbtn = tk.Frame(rf, bg=PANEL)
        rbtn.pack(fill="x", padx=4, pady=2)
        self._download_btn = self._btn(rbtn, "Download", self._download)
        self._download_btn.pack(side="left", padx=2)
        self._btn(rbtn, "Download folder", self._download_folder).pack(side="left", padx=2)
        self._btn(rbtn, "Delete", self._remote_delete).pack(side="left", padx=2)
        self._btn(rbtn, "Rename", self._remote_rename).pack(side="left", padx=2)
        self._btn(rbtn, "Permissions", self._remote_chmod).pack(side="left", padx=2)
        self._btn(rbtn, "New folder", self._remote_mkdir).pack(side="left", padx=2)
        self._cancel_transfer_btn = self._btn(rbtn, "Cancel transfer", self._cancel_transfer)
        self._cancel_transfer_btn.pack(side="right", padx=2)
        panes.add(rf)
        self._update_transfer_actions()

    def _refresh_transfer_tree(self):
        data = self._transfer_manager.summary()
        self._transfer_summary_var.set(
            f"Transfers: {data['active']} active · {data['pending']} pending · {self._fmt_size(data['speed'])}/s"
        )
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", {})
        if (
            self._transfer_window is None
            and isinstance(settings, dict)
            and settings.get("show_transfer_manager_on_start", True)
            and any(item.status not in TransferState.TERMINAL for item in self._transfer_manager.items)
        ):
            # Showing is intentionally not focus_force(): terminal typing must
            # remain uninterrupted when a background transfer starts.
            self._transfer_window = SFTPTransferManagerWindow(self)
        if self._transfer_window is not None and self._transfer_window.winfo_exists():
            self._transfer_window.request_refresh()

    def _show_transfer_manager(self):
        if self._transfer_window is None or not self._transfer_window.winfo_exists():
            self._transfer_window = SFTPTransferManagerWindow(self)
        self._transfer_window.deiconify()
        if self._transfer_window.state() == "iconic":
            self._transfer_window.state("normal")
        self._transfer_window.lift()
        self._transfer_window.refresh()

    def _new_transfer_client(self):
        """Open one Paramiko SFTP channel for exactly one scheduler worker."""
        if paramiko is None or self._transfer_transport is None or not self._transfer_transport.is_active():
            raise RuntimeError("The verified SFTP session is no longer available.")
        try:
            return paramiko.SFTPClient.from_transport(
                self._transfer_transport, window_size=4 * 1024 * 1024, max_packet_size=32768
            )
        except TypeError:
            # Older supported Paramiko releases expose the same safe default
            # channel behaviour without these public tuning arguments.
            return paramiko.SFTPClient.from_transport(self._transfer_transport)

    def _transfer_chunk_size(self) -> int:
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", {})
        configured = settings.get("sftp_chunk_size") if isinstance(settings, dict) else None
        try:
            value = int(configured)
        except (TypeError, ValueError):
            value = 1048576
        return max(SFTP_TRANSFER_CHUNK_SIZES[0], min(value, SFTP_TRANSFER_CHUNK_SIZES[-1]))

    @staticmethod
    def _enable_download_prefetch(source, file_size: int) -> None:
        prefetch = getattr(source, "prefetch", None)
        if not callable(prefetch) or file_size <= 0:
            return
        try:
            prefetch(file_size=file_size, max_concurrent_prefetch_requests=8)
        except (AttributeError, NotImplementedError, OSError, TypeError):
            # Normal ordered reads remain correct on servers without prefetch.
            return

    @staticmethod
    def _enable_upload_pipelining(target) -> None:
        set_pipelined = getattr(target, "set_pipelined", None)
        if callable(set_pipelined):
            try:
                set_pipelined(True)
            except (AttributeError, NotImplementedError, OSError, TypeError):
                pass

    @staticmethod
    def _persist_download_progress(target, plan, local, completed, policy, metrics) -> None:
        """Flush data before atomically recording an equal-or-smaller offset."""
        started = time.perf_counter()
        target.flush()
        metrics.record("local_write", time.perf_counter() - started)
        started = time.perf_counter()
        write_partial_download_metadata(
            local,
            remote_identity=plan.remote_identity,
            remote_path=plan.remote_path,
            remote_size=plan.remote_size,
            remote_mtime=plan.remote_mtime,
            completed_bytes=completed,
        )
        metrics.record("sidecar_write", time.perf_counter() - started)
        policy.persisted(completed, time.monotonic())

    @staticmethod
    def _persist_closed_download_progress(plan, local, partial, metrics) -> None:
        """Record a closed file's flushed size after interruption or failure."""
        completed = partial.stat().st_size
        if completed > plan.remote_size:
            return
        started = time.perf_counter()
        write_partial_download_metadata(
            local,
            remote_identity=plan.remote_identity,
            remote_path=plan.remote_path,
            remote_size=plan.remote_size,
            remote_mtime=plan.remote_mtime,
            completed_bytes=completed,
        )
        metrics.record("sidecar_write", time.perf_counter() - started)

    def _pause_selected_transfer(self):
        for iid in self._selected_transfer_ids():
            self._transfer_manager.pause(iid)
        self._refresh_transfer_tree()

    def _resume_selected_transfer(self):
        for iid in self._selected_transfer_ids():
            self._transfer_manager.resume(iid)
        self._refresh_transfer_tree()

    def _cancel_selected_transfer(self):
        for iid in self._selected_transfer_ids():
            item = self._transfer_manager.get(iid)
            if item and item.direction == "Download":
                choice = messagebox.askyesnocancel(
                    "Cancel download",
                    "Keep the partial file for later resume?\n\nYes: Keep partial\nNo: Delete partial\nCancel: Keep downloading",
                    parent=self,
                )
                if choice is None:
                    continue
                item.delete_partial_on_cancel = choice is False
            self._transfer_manager.cancel(iid)
        self._refresh_transfer_tree()

    def _retry_failed_transfers(self):
        self._transfer_manager.retry_failed()
        self._refresh_transfer_tree()

    def _retry_selected_transfer(self):
        for iid in self._selected_transfer_ids():
            self._transfer_manager.retry(iid)
        self._refresh_transfer_tree()

    def _remove_selected_transfer(self):
        for iid in self._selected_transfer_ids():
            self._transfer_manager.remove(iid)
        self._refresh_transfer_tree()

    def _pause_all_transfers(self):
        self._transfer_manager.pause_all()

    def _resume_all_transfers(self):
        self._transfer_manager.resume_all()

    def _cancel_all_transfers(self):
        self._transfer_manager.cancel_all()

    def _move_selected_transfer(self, delta):
        for iid in self._selected_transfer_ids():
            self._transfer_manager.move(iid, delta)
        self._refresh_transfer_tree()

    def _selected_transfer_ids(self):
        selected = []
        if self._transfer_window is not None and self._transfer_window.winfo_exists():
            selected.extend(self._transfer_window.tree.selection())
        return set(selected)

    def _clear_completed_transfers(self):
        self._transfer_manager.clear_completed()
        self._refresh_transfer_tree()

    def _btn(self, p, t, c):
        return tk.Button(
            p, text=t, command=c, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=6, pady=2, cursor="hand2"
        )

    def _bind_path_shortcuts(self, entry, path_var):
        entry.bind("<Control-c>", lambda event: self._copy_path_shortcut(event, path_var))
        entry.bind("<Control-C>", lambda event: self._copy_path_shortcut(event, path_var))
        entry.bind("<Control-v>", self._paste_path_shortcut)
        entry.bind("<Control-V>", self._paste_path_shortcut)
        entry.bind("<Control-a>", self._select_all_path)
        entry.bind("<Control-A>", self._select_all_path)

    def _copy_path_shortcut(self, event, path_var):
        entry = event.widget
        path = entry.selection_get() if entry.selection_present() else path_var.get()
        self._copy_path(path)
        return "break"

    def _paste_path_shortcut(self, event):
        entry = event.widget
        try:
            pasted = self.clipboard_get()
        except tk.TclError:
            return "break"
        if entry.selection_present():
            entry.delete("sel.first", "sel.last")
        entry.insert("insert", pasted)
        return "break"

    @staticmethod
    def _select_all_path(event):
        event.widget.selection_range(0, "end")
        event.widget.icursor("end")
        return "break"

    def _show_path_menu(self, event, path_var):
        """Show clipboard actions for an SFTP local or remote path field."""
        entry = event.widget
        has_selection = bool(entry.selection_present())
        self._path_menu.delete(0, "end")
        self._path_menu.add_command(
            label="Copy selected text",
            command=lambda: entry.event_generate("<<Copy>>"),
            state="normal" if has_selection else "disabled",
        )
        self._path_menu.add_command(
            label="Copy directory path",
            command=lambda: self._copy_path(path_var.get()),
        )
        self._path_menu.add_command(label="Paste", command=lambda: entry.event_generate("<<Paste>>"))
        self._path_menu.add_command(label="Select all", command=lambda: entry.selection_range(0, "end"))
        entry.focus_set()
        try:
            self._path_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._path_menu.grab_release()
        return "break"

    def _copy_path(self, path: str):
        self.clipboard_clear()
        self.clipboard_append(path)
        self._set_status("Directory path copied")

    def _fmt_size(self, n):
        return SFTPPanelState.format_size(n)

    def _sort_tree(self, tree, column):
        rows = [(tree.set(item, column), item) for item in tree.get_children() if item != ".."]
        rows.sort(key=lambda pair: pair[0].casefold())
        if tree.exists(".."):
            tree.move("..", "", 0)
        for index, (_value, item) in enumerate(rows, start=1):
            tree.move(item, "", index)

    def _update_transfer_actions(self):
        actions = self._sftp_state.action_enabled(
            local_selected=bool([item for item in self._local_tree.selection() if item != ".."]),
            remote_selected=bool([item for item in self._remote_tree.selection() if item != ".."]),
        )
        self._upload_btn.configure(state="normal" if actions["upload"] else "disabled")
        self._download_btn.configure(state="normal" if actions["download"] else "disabled")
        self._cancel_transfer_btn.configure(state="normal" if actions["cancel"] else "disabled")

    def _cancel_transfer(self):
        self._transfer_manager.cancel_all()
        self._sftp_state.cancel()
        self._set_status(self._sftp_state.message)
        self._update_transfer_actions()

    def _refresh_remote(self):
        """Refresh remotely without blocking Tk's event loop.

        Paramiko SFTP requests can wait for a transfer using the same channel.
        They must therefore run in the transfer worker, never in a button
        callback on the Tk thread.
        """
        self._request_remote_directory(self._remote_cwd, record=False)

    def _set_remote_navigation_busy(self, busy):
        self._remote_navigation_busy = busy
        state = "disabled" if busy else "normal"
        for button in (
            self._remote_back_button,
            self._remote_forward_button,
            self._remote_up_button,
        ):
            button.configure(state=state)

    def _request_remote_directory(self, path, record=True):
        if self._closed or self._remote_navigation_busy:
            return
        self._remote_generation += 1
        generation = self._remote_generation
        self._set_remote_navigation_busy(True)
        # Show where navigation is headed immediately.  The directory contents
        # may take time to arrive when a transfer is in progress, but the path
        # field should never misleadingly keep showing the previous folder.
        requested_path = (
            self._remote_normalize(path) if str(path).startswith("/") else self._remote_join(self._remote_cwd, path)
        )
        self._remote_path_var.set(requested_path)
        self._set_status("Loading remote directory…")
        self._sftp_state.remote_state = "loading"
        self._transfer_queue.put(lambda p=path, r=record, g=generation: self._load_remote_directory(p, r, g))

    def _load_remote_directory(self, path, record, generation):
        try:
            normalized, remote_stat = self._resolve_remote_path(path)
            if not stat.S_ISDIR(remote_stat.st_mode):
                raise NotADirectoryError(normalized)
            attrs = self._sftp.listdir_attr(normalized)
        except Exception as e:
            self._dispatch(
                lambda err=e, g=generation: self._remote_directory_failed(err) if g == self._remote_generation else None
            )
            return

        self._dispatch(
            lambda g=generation: (
                self._show_remote_directory(normalized, attrs, record) if g == self._remote_generation else None
            )
        )

    def _remote_directory_failed(self, error):
        self._set_remote_navigation_busy(False)
        self._remote_path_var.set(self._remote_cwd)
        self._sftp_state.remote_state = "error"
        self._set_status("Could not load the remote directory.")
        log(f"SFTP directory load failed: {error}")

    def _show_remote_directory(self, normalized, attrs, record):
        self._remote_cwd = normalized
        if record:
            self._push_remote_history(normalized)
        self._remote_tree.delete(*self._remote_tree.get_children())
        self._remote_tree.insert("", "end", iid="..", values=("..", "", "", ""))
        for a in sorted(attrs, key=lambda x: (not stat.S_ISDIR(x.st_mode), x.filename)):
            is_dir = stat.S_ISDIR(a.st_mode)
            name = ("[DIR] " if is_dir else "") + a.filename
            size = "" if is_dir else self._fmt_size(a.st_size)
            mtime = datetime.fromtimestamp(a.st_mtime).strftime("%Y-%m-%d %H:%M") if a.st_mtime else ""
            self._remote_tree.insert(
                "", "end", iid=a.filename, values=(name, "Folder" if is_dir else "File", size, mtime)
            )
        self._remote_path_var.set(self._remote_cwd)
        self._sftp_state.remote_state = "ready"
        self._set_remote_navigation_busy(False)

    def _refresh_local(self):
        """Coalesce local directory refreshes; enumeration never touches Tk."""
        with self._local_load_lock:
            was_pending = self._local_load_state.pending
            self._local_load_state.request()
            self._local_load_path = self._local_cwd
            # A queued worker always reads the newest path/generation, so
            # repeated refreshes only invalidate work instead of accumulating
            # queue entries.
            should_queue = not was_pending
        self._sftp_state.local_state = "loading"
        self._set_status("Loading local directory…")
        if should_queue:
            self._transfer_queue.put(self._load_latest_local_directory)

    def _load_latest_local_directory(self):
        with self._local_load_lock:
            generation, path = self._local_load_state.generation, self._local_load_path
        try:
            rows = []
            for item in Path(path).iterdir():
                try:
                    info = item.stat()
                    is_dir = item.is_dir()
                    rows.append(
                        (
                            item.name,
                            is_dir,
                            "" if is_dir else self._fmt_size(info.st_size),
                            datetime.fromtimestamp(info.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        )
                    )
                except OSError:
                    rows.append((item.name, item.is_dir(), "", ""))
            rows.sort(key=lambda row: (not row[1], row[0].casefold()))
        except OSError as error:
            self._dispatch(lambda err=error, gen=generation: self._show_local_directory_error(gen, err))
            return
        self._dispatch(
            lambda gen=generation, target=path, entries=rows: self._show_local_directory(gen, target, entries)
        )

    def _queue_latest_local_if_needed(self):
        with self._local_load_lock:
            if self._local_load_state.closed or self._local_load_state.pending:
                return
            self._local_load_state.pending = True
        self._transfer_queue.put(self._load_latest_local_directory)

    def _show_local_directory(self, generation, path, rows):
        with self._local_load_lock:
            accepted = self._local_load_state.finish(generation, success=True)
            newest = self._local_load_state.generation
        if not accepted:
            if not self._local_load_state.closed and generation != newest:
                self._queue_latest_local_if_needed()
            return
        selected = set(self._local_tree.selection())
        self._local_tree.delete(*self._local_tree.get_children())
        self._local_tree.insert("", "end", iid="..", values=("..", "", "", ""))
        for name, is_dir, size, modified in rows:
            label = ("[DIR] " if is_dir else "") + name
            self._local_tree.insert("", "end", iid=name, values=(label, "Folder" if is_dir else "File", size, modified))
        for item in selected:
            if self._local_tree.exists(item):
                self._local_tree.selection_add(item)
        self._local_path_var.set(path)
        self._sftp_state.local_state = "empty" if not rows else "ready"
        self._set_status("Local directory is empty." if not rows else "Ready")

    def _show_local_directory_error(self, generation, error):
        with self._local_load_lock:
            accepted = self._local_load_state.finish(generation, success=False)
        if not accepted:
            return
        self._sftp_state.local_state = "error"
        self._set_status("Could not load the local directory. Check that it still exists and is accessible.")
        log(f"Local directory load failed: {error}")

    @staticmethod
    def _common_directory_prefix(names: list[str]) -> str:
        """Return the shared filename prefix without crossing directory names."""
        return os.path.commonprefix(names) if names else ""

    def _complete_local_path(self, event):
        """Complete a local directory in the SFTP location field on Tab."""
        typed = self._local_path_var.get().strip()
        expanded = Path(typed or self._local_cwd).expanduser()
        if typed.endswith(os.sep):
            search_dir = expanded if expanded.is_absolute() else Path(self._local_cwd) / expanded
            prefix = ""
        else:
            search_dir = expanded.parent if expanded.is_absolute() else Path(self._local_cwd) / expanded.parent
            prefix = expanded.name
        try:
            matches = sorted(item for item in search_dir.iterdir() if item.is_dir() and item.name.startswith(prefix))
        except OSError:
            matches = []
        if not matches:
            self._set_status("No matching local directory")
        elif len(matches) == 1:
            self._local_path_var.set(f"{matches[0]}{os.sep}")
            self._place_path_cursor_at_end(event.widget)
            self._set_status("Local directory completed")
        else:
            common = self._common_directory_prefix([item.name for item in matches])
            self._local_path_var.set(str(search_dir / common))
            self._place_path_cursor_at_end(event.widget)
            self._set_status(f"{len(matches)} local directories match")
            self._show_directory_suggestions(
                event.widget,
                self._local_path_var,
                [(item.name, f"{item}{os.sep}") for item in matches],
            )
        return "break"

    def _complete_remote_path(self, event):
        """Complete a remote directory in the SFTP location field on Tab."""
        typed = self._remote_path_var.get().strip()
        candidate = typed if typed.startswith("/") else self._remote_join(self._remote_cwd, typed)
        search_dir, prefix = posixpath.split(candidate)
        search_dir = search_dir or "/"
        try:
            search_dir, search_attr = self._resolve_remote_path(search_dir)
            if not stat.S_ISDIR(search_attr.st_mode):
                raise NotADirectoryError(search_dir)
            matches = sorted(
                entry.filename
                for entry in self._sftp.listdir_attr(search_dir)
                if stat.S_ISDIR(entry.st_mode) and entry.filename.startswith(prefix)
            )
        except Exception as e:
            self._set_status(f"Remote completion failed: {e}")
            return "break"
        if not matches:
            self._set_status("No matching remote directory")
        elif len(matches) == 1:
            self._remote_path_var.set(f"{self._remote_join(search_dir, matches[0])}/")
            self._place_path_cursor_at_end(event.widget)
            self._set_status("Remote directory completed")
        else:
            common = self._common_directory_prefix(matches)
            self._remote_path_var.set(self._remote_join(search_dir, common))
            self._place_path_cursor_at_end(event.widget)
            self._set_status(f"{len(matches)} remote directories match")
            self._show_directory_suggestions(
                event.widget,
                self._remote_path_var,
                [(name, f"{self._remote_join(search_dir, name)}/") for name in matches],
            )
        return "break"

    @staticmethod
    def _place_path_cursor_at_end(entry):
        entry.selection_clear()
        entry.focus_set()
        entry.icursor("end")

    def _show_directory_suggestions(self, entry, path_var, suggestions):
        """Offer matching directories when Tab cannot complete unambiguously."""
        self._completion_menu.delete(0, "end")
        for name, path in suggestions[:50]:
            self._completion_menu.add_command(
                label=name,
                command=lambda selected=path: self._choose_directory_suggestion(entry, path_var, selected),
            )
        if len(suggestions) > 50:
            self._completion_menu.add_command(label="More matches; keep typing to narrow them", state="disabled")
        try:
            self._completion_menu.tk_popup(entry.winfo_rootx(), entry.winfo_rooty() + entry.winfo_height())
        finally:
            self._completion_menu.grab_release()

    def _choose_directory_suggestion(self, entry, path_var, path):
        path_var.set(path)
        self._place_path_cursor_at_end(entry)
        self._set_status("Directory selected")

    def _local_dbl(self, _e):
        sel = self._local_tree.selection()
        if not sel:
            return
        name = sel[0]
        if name == "..":
            self._local_up()
        else:
            p = Path(self._local_cwd) / name
            if p.is_dir():
                self._cd_local(str(p))
            elif p.is_file():
                self._open_local_file(p)

    def _remote_dbl(self, _e):
        sel = self._remote_tree.selection()
        if not sel:
            return
        name = sel[0]
        if name == "..":
            self._remote_up()
        else:
            candidate = self._remote_join(self._remote_cwd, name)
            # The directory listing already carries this information.  Avoid a
            # second synchronous SFTP stat here; it can block the Tk thread
            # while another operation is using the SFTP channel.
            is_dir = self._remote_tree.item(name, "values")[0].startswith("[DIR] ")
            if is_dir:
                self._cd_remote(candidate)
            else:
                self._open_remote_file(candidate, name)

    def _local_normalize(self, path: str) -> str:
        return str(Path(path).expanduser().resolve())

    def _remote_normalize(self, path: str) -> str:
        return posixpath.normpath(path or "/") or "/"

    def _remote_join(self, base: str, name: str) -> str:
        return self._remote_normalize(posixpath.join(base or "/", name))

    def _resolve_remote_path(self, path: str):
        """Resolve shell paths when SFTP exposes a chrooted filesystem root."""
        normalized = self._remote_normalize(path)
        parts = [part for part in normalized.split("/") if part]
        candidates = [normalized]
        if normalized.startswith("/"):
            candidates.extend("/" + "/".join(parts[index:]) for index in range(1, len(parts)))
        last_error = None
        for candidate in dict.fromkeys(candidates):
            try:
                return candidate, self._sftp.stat(candidate)
            except Exception as e:
                last_error = e
        raise last_error or FileNotFoundError(path)

    def _push_local_history(self, path: str):
        if self._local_history[self._local_hist_idx] == path:
            return
        self._local_history = self._local_history[: self._local_hist_idx + 1]
        self._local_history.append(path)
        self._local_hist_idx = len(self._local_history) - 1

    def _push_remote_history(self, path: str):
        if self._remote_history[self._remote_hist_idx] == path:
            return
        self._remote_history = self._remote_history[: self._remote_hist_idx + 1]
        self._remote_history.append(path)
        self._remote_hist_idx = len(self._remote_history) - 1

    def _cd_local(self, path, record=True):
        normalized = self._local_normalize(path)
        if Path(normalized).is_dir():
            self._local_cwd = normalized
            self._local_path_var.set(normalized)
            if record:
                self._push_local_history(normalized)
            self._refresh_local()

    def _cd_remote(self, path, record=True):
        self._request_remote_directory(path, record=record)

    def _local_back(self):
        if self._local_hist_idx > 0:
            self._local_hist_idx -= 1
            self._cd_local(self._local_history[self._local_hist_idx], record=False)

    def _local_forward(self):
        if self._local_hist_idx + 1 < len(self._local_history):
            self._local_hist_idx += 1
            self._cd_local(self._local_history[self._local_hist_idx], record=False)

    def _local_up(self):
        self._cd_local(str(Path(self._local_cwd).parent))

    def _remote_back(self):
        if self._remote_hist_idx > 0:
            self._remote_hist_idx -= 1
            self._cd_remote(self._remote_history[self._remote_hist_idx], record=False)

    def _remote_forward(self):
        if self._remote_hist_idx + 1 < len(self._remote_history):
            self._remote_hist_idx += 1
            self._cd_remote(self._remote_history[self._remote_hist_idx], record=False)

    def _remote_up(self):
        self._cd_remote(posixpath.dirname(self._remote_cwd.rstrip("/")) or "/")

    def _open_with_system(self, path: Path):
        try:
            subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("Open", str(e))

    def _open_local_file(self, path: Path):
        self._open_with_system(path)

    def _open_remote_file(self, remote_path: str, name: str):
        local_name = Path(name).name
        cached = self._remote_open_cache / local_name
        self._set_status(f"Opening {local_name}…")
        self._transfer_queue.put(lambda r=remote_path, local_path=cached: self._download_and_open(r, local_path))

    def _download_and_open(self, remote_path: str, local_path: Path):
        self._sftp.get(remote_path, str(local_path), callback=self._progress_cb)
        self.after(0, lambda p=local_path: self._open_with_system(p))

    def _set_status(self, msg):
        self._status_var.set(msg)

    def _transfer_worker(self):
        while True:
            fn = self._transfer_queue.get()
            if fn is None:
                self._transfer_queue.task_done()
                return
            try:
                if not self._closed:
                    fn()
            except InterruptedError:
                self._sftp_state.cancel()
                self._dispatch(lambda: self._set_status("Transfer cancelled. Partial data was kept safely."))
            except Exception as e:
                self._sftp_state.fail(e)
                self._dispatch(lambda: self._set_status("Transfer failed. See the activity log for details."))
                log(f"SFTP transfer failed: {e}")
            finally:
                self._transfer_queue.task_done()
                self._dispatch(lambda: self._progress_var.set(0))
                self._dispatch(self._finish_transfer_state)

    def _finish_transfer_state(self):
        if self._sftp_state.transfer_state == "active":
            self._sftp_state.complete()
        self._set_status(self._sftp_state.message or "Ready")
        self._update_transfer_actions()

    def _progress_cb(self, transferred, total):
        if self._transfer_cancel.is_set():
            raise InterruptedError("Transfer cancelled")
        self._sftp_state.progress(transferred, total, now=time.monotonic())
        if total:
            pct = transferred / total * 100
            self._dispatch(lambda p=pct: self._progress_var.set(p))
        self._dispatch(lambda: self._set_status(self._sftp_state.progress_text(now=time.monotonic())))

    def _queue_local_operation(self, operation, success_message):
        if self._sftp_state.transfer_state == "active":
            self._set_status("Wait for the active transfer to finish or cancel it first.")
            return
        self._transfer_queue.put(lambda: self._run_local_operation(operation, success_message))

    def _run_local_operation(self, operation, success_message):
        operation()
        self.after(0, lambda: (self._refresh_local(), self._set_status(success_message)))

    def _local_rename(self):
        selection = [name for name in self._local_tree.selection() if name != ".."]
        if len(selection) != 1:
            return
        old_name = selection[0]
        new_name = simpledialog_ask("Rename local item", f"New name for '{old_name}':", old_name)
        if not new_name or new_name == old_name or Path(new_name).name != new_name:
            return
        source, target = Path(self._local_cwd) / old_name, Path(self._local_cwd) / new_name
        if target.exists():
            messagebox.showerror("Rename", "An item with that name already exists.")
            return
        self._queue_local_operation(lambda: source.rename(target), f"Renamed {old_name}")

    def _local_delete(self):
        selection = [name for name in self._local_tree.selection() if name != ".."]
        if not selection:
            return
        paths = [Path(self._local_cwd) / name for name in selection]
        has_nonempty_directory = any(path.is_dir() and any(path.iterdir()) for path in paths if path.exists())
        prompt = f"Delete {len(paths)} selected item(s)?"
        if has_nonempty_directory:
            prompt += " This includes a non-empty folder and cannot be undone."
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", None)
        if confirm_delete_enabled(settings) and not messagebox.askyesno("Delete local items", prompt):
            return

        def delete_paths():
            for path in paths:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

        self._queue_local_operation(delete_paths, "Local items deleted")

    def _partial_remote_path(self, remote: str) -> str:
        """Return the hidden, resumable staging path for a remote file."""
        directory, name = posixpath.split(remote)
        return self._remote_join(directory or "/", f".{name}.sshvault-partial")

    @staticmethod
    def _partial_local_path(local: Path) -> Path:
        """Return the dedicated, metadata-backed local download staging path."""
        return partial_download_path(local)

    @staticmethod
    def _partial_local_metadata_path(local: Path) -> Path:
        return partial_download_metadata_path(local)

    def _remote_identity(self, sftp=None) -> str:
        """Stable non-secret identity used only to bind download sidecars."""
        client = sftp or self._sftp
        try:
            peer = client.get_channel().getpeername()
            return f"sftp://{peer[0]}:{peer[1]}"
        except Exception:
            # The path still cannot be adopted across an unknown identity.
            return "sftp://unknown"

    def _remote_size(self, remote: str):
        try:
            return self._sftp.stat(remote).st_size
        except (FileNotFoundError, OSError):
            return None

    @staticmethod
    def _local_sha1(path: Path, length: int = 0) -> bytes:
        """Hash all of a file, or its first *length* bytes, without loading it."""
        digest = hashlib.sha1()
        remaining = length
        with path.open("rb") as source:
            while True:
                chunk = source.read(min(256 * 1024, remaining) if remaining else 256 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                if remaining:
                    remaining -= len(chunk)
                    if not remaining:
                        break
        return digest.digest()

    def _remote_sha1(self, remote: str, length: int = 0):
        """Use SFTP check-file when supported; otherwise return None.

        Bitvise SSH Server supports this SFTP extension, allowing an integrity
        check without downloading the remote file.  Most other SFTP servers do
        not, so callers retain the size-and-staging fallback in that case.
        """
        try:
            with self._sftp.open(remote, "rb") as source:
                return source.check("sha1", length=length)
        except (OSError, NotImplementedError):
            return None

    def _same_file(self, local: Path, remote: str, total: int) -> bool:
        if self._remote_size(remote) != total:
            return False
        remote_hash = self._remote_sha1(remote)
        return remote_hash is None or remote_hash == self._local_sha1(local)

    def _matching_prefix(self, local: Path, remote: str, offset: int) -> bool:
        """Check an already-transferred prefix when the server supports it."""
        if not offset:
            return True
        remote_hash = self._remote_sha1(remote, offset)
        return remote_hash is None or remote_hash == self._local_sha1(local, offset)

    def _upload_file(self, local: Path, remote: str, *, replace: bool = False) -> bool:
        """Upload *local* safely, resuming a prior interrupted upload if present.

        Files are transferred to a hidden staging name and renamed only after the
        remote size has been verified.  Therefore a normal destination file is
        considered complete, while an interrupted file is always retried.
        """
        total = local.stat().st_size
        if self._remote_size(remote) is not None and not replace:
            raise FileExistsError("A remote file with this name already exists.")
        if self._same_file(local, remote, total):
            log(f"Skipped completed upload: {local} -> {remote}")
            return False

        partial = self._partial_remote_path(remote)
        offset = self._remote_size(partial) or 0
        if offset > total or not self._matching_prefix(local, partial, offset):
            offset = 0

        self.after(0, lambda: self._set_status(f"Uploading {local.name} ({self._fmt_size(offset)} resumed)…"))
        # A staging file larger than its source cannot be resumed safely.
        remote_mode = "ab" if offset else "wb"
        with local.open("rb") as source, self._sftp.open(partial, remote_mode) as target:
            source.seek(offset)
            transferred = offset
            while chunk := source.read(self._transfer_chunk_size()):
                target.write(chunk)
                transferred += len(chunk)
                self._progress_cb(transferred, total)

        if not self._same_file(local, partial, total):
            raise OSError(f"Upload verification failed for {local.name}")

        # paramiko's standard rename is not guaranteed to overwrite an existing
        # target, so replace the known incomplete target before finalizing.
        try:
            self._sftp.remove(remote)
        except (FileNotFoundError, OSError):
            pass
        self._sftp.rename(partial, remote)
        log(f"Uploaded {local} -> {remote}")
        return True

    def _upload_with_cleanup(self, local: Path, remote: str, replace: bool) -> bool:
        try:
            return self._upload_file(local, remote, replace=replace)
        except Exception:
            try:
                self._sftp.remove(self._partial_remote_path(remote))
            except Exception:
                pass
            raise

    def _download_file(self, remote: str, local: Path, *, replace: bool = False) -> bool:
        """Download *remote* safely, resuming a prior interrupted download."""
        total = self._sftp.stat(remote).st_size
        if local.exists() and not replace:
            raise FileExistsError("A local file with this name already exists.")
        try:
            if local.is_file() and self._same_file(local, remote, total):
                log(f"Skipped completed download: {remote} -> {local}")
                return False
        except OSError:
            pass

        local.parent.mkdir(parents=True, exist_ok=True)
        partial = self._partial_local_path(local)
        try:
            offset = partial.stat().st_size
        except OSError:
            offset = 0
        if offset > total or not self._matching_prefix(partial, remote, offset):
            offset = 0

        self.after(0, lambda: self._set_status(f"Downloading {local.name} ({self._fmt_size(offset)} resumed)…"))
        local_mode = "ab" if offset else "wb"
        with self._sftp.open(remote, "rb") as source, partial.open(local_mode) as target:
            source.seek(offset)
            transferred = offset
            while chunk := source.read(self._transfer_chunk_size()):
                target.write(chunk)
                transferred += len(chunk)
                self._progress_cb(transferred, total)

        if not self._same_file(partial, remote, total):
            raise OSError(f"Download verification failed for {local.name}")
        os.replace(partial, local)
        log(f"Downloaded {remote} -> {local}")
        return True

    def _download_with_cleanup(self, remote: str, local: Path, replace: bool) -> bool:
        try:
            return self._download_file(remote, local, replace=replace)
        except Exception:
            try:
                self._partial_local_path(local).unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _upload(self):
        sel = self._local_tree.selection()
        if not sel:
            return
        for name in sel:
            if name == "..":
                continue
            local = str(Path(self._local_cwd) / name)
            remote = self._remote_join(self._remote_cwd, name)
            if Path(local).is_file():
                decision, remote = self._upload_collision_decision(name, remote)
                if decision == "skip":
                    continue
                self._transfer_cancel.clear()
                self._sftp_state.start_transfer(name, now=time.monotonic())
                self._update_transfer_actions()
                self._set_status(f"Uploading {name}…")
                self._transfer_manager.enqueue(
                    TransferItem(
                        local, remote, "Upload", total=Path(local).stat().st_size, generation=self._remote_generation
                    ),
                    lambda item, client, worker, local_path=Path(local), r=remote, replace=decision == "replace": (
                        self._scheduled_upload(item, client, worker, local_path, r, replace)
                    ),
                )
                self._refresh_transfer_tree()

    def _upload_folder(self):
        sel = self._local_tree.selection()
        if not sel:
            return
        for name in sel:
            if name == "..":
                continue
            local = Path(self._local_cwd) / name
            if local.is_dir():
                remote_root = self._remote_join(self._remote_cwd, name)
                children = []
                created_directories: set[str] = set()
                directory_cache_lock = threading.Lock()
                for file_path in sorted(path for path in local.rglob("*") if path.is_file() and not path.is_symlink()):
                    relative = file_path.relative_to(local)
                    remote = posixpath.join(remote_root, str(relative).replace(os.sep, "/"))
                    item = TransferItem(str(file_path), remote, "Upload", total=file_path.stat().st_size)
                    children.append(
                        (
                            item,
                            lambda current, client, worker, p=file_path, r=remote, cache=created_directories, lock=directory_cache_lock: (
                                self._scheduled_upload_with_dirs(current, client, worker, p, r, cache, lock)
                            ),
                        )
                    )
                batch = TransferBatch(name, "Upload", str(local), remote_root)
                self._transfer_manager.add_batch(batch, children)
                self._set_status(f"Queued folder {name} ({len(children)} files).")
                self._refresh_transfer_tree()

    def _scheduled_upload_with_dirs(self, item, sftp, worker, local, remote, directory_cache=None, cache_lock=None):
        directory = posixpath.dirname(remote)
        parts = directory.strip("/").split("/")
        current = "/" if directory.startswith("/") else ""
        for part in parts:
            if not part:
                continue
            current = posixpath.join(current, part)
            if directory_cache is not None and cache_lock is not None:
                with cache_lock:
                    if current in directory_cache:
                        continue
            try:
                sftp.mkdir(current)
                if directory_cache is not None and cache_lock is not None:
                    with cache_lock:
                        directory_cache.add(current)
            except OSError:
                # Do not cache errors: a failed or changed session must retry
                # directory creation on the next worker-owned channel.
                if directory_cache is not None and cache_lock is not None:
                    with cache_lock:
                        directory_cache.discard(current)
        self._scheduled_upload(item, sftp, worker, local, remote, False)

    def _upload_dir(self, local: Path, remote: str):
        try:
            self._sftp.mkdir(remote)
        except Exception:
            pass
        for item in local.iterdir():
            r = self._remote_join(remote, item.name)
            if item.is_dir():
                self._upload_dir(item, r)
            else:
                self._upload_file(item, r)

    def _download(self):
        sel = self._remote_tree.selection()
        if not sel:
            return
        for name in sel:
            if name == "..":
                continue
            remote = self._remote_join(self._remote_cwd, name)
            local = Path(self._local_cwd) / name
            try:
                attributes = self._sftp.stat(remote)
                plan = inspect_download_resume(
                    local,
                    remote_identity=self._remote_identity(),
                    remote_path=remote,
                    remote_size=attributes.st_size,
                    remote_mtime=getattr(attributes, "st_mtime", None),
                )
            except OSError as exc:
                messagebox.showerror("Download", str(redact_secrets(str(exc))), parent=self)
                continue
            if plan.decision == DownloadResumeDecision.ALREADY_COMPLETE:
                self._transfer_manager.record(
                    TransferItem(
                        remote,
                        str(local),
                        "Download",
                        total=plan.remote_size,
                        transferred=plan.remote_size,
                        status=TransferState.ALREADY_COMPLETE,
                        resume_offset=plan.remote_size,
                    )
                )
                self._set_status(f"Already complete: {name}")
                self._refresh_transfer_tree()
                continue
            if plan.decision == DownloadResumeDecision.ADOPT_LEGACY:
                if messagebox.askyesno(
                    "Resume existing download", plan.message + "\n\nAdopt and resume it?", parent=self
                ):
                    try:
                        plan = adopt_legacy_download(plan)
                        decision = "replace"
                    except (OSError, ProfileError) as exc:
                        messagebox.showerror("Download", str(exc), parent=self)
                        continue
                else:
                    decision, local = self._download_collision_decision(name, local)
                    if decision == "skip":
                        continue
                    plan = inspect_download_resume(
                        local,
                        remote_identity=self._remote_identity(),
                        remote_path=remote,
                        remote_size=attributes.st_size,
                        remote_mtime=getattr(attributes, "st_mtime", None),
                    )
            elif plan.decision == DownloadResumeDecision.CONFLICT:
                # Type and untrusted-sidecar conflicts are explicit; a size
                # collision still uses the user's normal collision preference.
                if local.is_file() and "larger" in plan.message:
                    messagebox.showwarning("Download", plan.message, parent=self)
                    decision, local = self._download_collision_decision(name, local)
                    if decision == "skip":
                        continue
                else:
                    self._transfer_manager.record(
                        TransferItem(
                            remote,
                            str(local),
                            "Download",
                            total=plan.remote_size,
                            status=TransferState.CONFLICT,
                            error=plan.message,
                        )
                    )
                    self._refresh_transfer_tree()
                    continue
            else:
                decision = "replace"
            self._transfer_cancel.clear()
            self._sftp_state.start_transfer(name, now=time.monotonic())
            self._update_transfer_actions()
            self._set_status(f"Downloading {name}…")
            self._transfer_manager.enqueue(
                TransferItem(
                    remote,
                    str(local),
                    "Download",
                    total=plan.remote_size,
                    transferred=plan.offset,
                    resume_offset=plan.offset,
                    generation=self._remote_generation,
                ),
                lambda item, client, worker, r=remote, local_path=local, replace=decision == "replace": (
                    self._scheduled_download(item, client, worker, r, local_path, replace)
                ),
            )
            self._refresh_transfer_tree()

    def _scheduled_upload(self, item, sftp, worker, local: Path, remote: str, replace: bool):
        """Worker-owned atomic upload with validated partial resume and reconnect."""
        if not replace:
            try:
                sftp.stat(remote)
            except (FileNotFoundError, OSError):
                pass
            else:
                raise FileExistsError("A remote file with this name already exists.")
        SFTPTransferRouter(
            self._transfer_manager, verify_completed=bool(getattr(self, "_verify_completed", False))
        )._upload(item, sftp, worker)

    def _scheduled_download(self, item, sftp, worker, remote: str, local: Path, replace: bool):
        """Worker-owned, sidecar-validated resumable and atomic download."""
        attributes = sftp.stat(remote)
        total = attributes.st_size
        source_snapshot = (int(total), getattr(attributes, "st_mtime", None))
        item.total = total
        timeout_setter = getattr(worker, "set_operation_timeout", None)
        transfer_manager = getattr(self, "_transfer_manager", None)
        if callable(timeout_setter) and transfer_manager is not None:
            timeout_setter(
                SFTPTransferRouter._large_file_timeout(total, transfer_manager.operation_timeout)
            )
        local.parent.mkdir(parents=True, exist_ok=True)
        plan = inspect_download_resume(
            local,
            remote_identity=self._remote_identity(sftp),
            remote_path=remote,
            remote_size=total,
            remote_mtime=getattr(attributes, "st_mtime", None),
        )
        if plan.decision == DownloadResumeDecision.ALREADY_COMPLETE:
            item.transferred = total
            item.status = TransferState.ALREADY_COMPLETE
            return
        if plan.decision == DownloadResumeDecision.ADOPT_LEGACY:
            # Adoption is only allowed after the UI obtained explicit consent.
            raise FileExistsError("Existing local file was not approved for resumable-download adoption.")
        if plan.decision == DownloadResumeDecision.CONFLICT:
            if not replace:
                raise FileExistsError(plan.message)
            # Overwrite is an explicit collision policy.  It also discards an
            # incompatible staging pair, never a matching resumable pair.
            local.unlink(missing_ok=True)
            plan.partial_path.unlink(missing_ok=True)
            plan.metadata_path.unlink(missing_ok=True)
            plan = inspect_download_resume(
                local,
                remote_identity=self._remote_identity(sftp),
                remote_path=remote,
                remote_size=total,
                remote_mtime=getattr(attributes, "st_mtime", None),
            )
        partial, offset = plan.partial_path, plan.offset
        policy = DurableProgressPolicy(offset, time.monotonic())
        if plan.decision == DownloadResumeDecision.DOWNLOAD:
            started = time.perf_counter()
            write_partial_download_metadata(
                local,
                remote_identity=plan.remote_identity,
                remote_path=remote,
                remote_size=total,
                remote_mtime=plan.remote_mtime,
                completed_bytes=0,
            )
            item.metrics.record("sidecar_write", time.perf_counter() - started)
        item.resume_offset, item.transferred = offset, offset
        try:
            local_mode = "r+b" if offset else "wb"
            with sftp.open(remote, "rb") as source, partial.open(local_mode) as target:
                source.seek(offset)
                target.seek(offset)
                if offset:
                    # Do not advertise a resume until both independently owned
                    # handles have reached the validated durable offset.
                    worker.mark_resuming()
                transferred = offset
                self._enable_download_prefetch(source, total)
                chunk_size = self._transfer_chunk_size()
                # A non-default chunk selection is an explicit manual choice.
                tuner = AdaptiveTransferTuner(
                    total if chunk_size == 1048576 else 0, chunk_size=chunk_size, prefetch_depth=8
                )
                source_checked_at = offset
                while True:
                    started = time.perf_counter()
                    chunk = source.read(chunk_size)
                    item.metrics.record("remote_read", time.perf_counter() - started, len(chunk))
                    if not chunk:
                        break
                    started = time.perf_counter()
                    target.write(chunk)
                    item.metrics.record("local_write", time.perf_counter() - started, len(chunk))
                    transferred += len(chunk)
                    if transferred - source_checked_at >= 16 * 1024 * 1024:
                        current = sftp.stat(remote)
                        if (int(current.st_size), getattr(current, "st_mtime", None)) != source_snapshot:
                            item.diagnostics.append("Source still changing")
                            raise ProfileError("Source file is still being modified")
                        source_checked_at = transferred
                    chunk_size, _prefetch_depth = tuner.observe(transferred, time.monotonic())
                    now = time.monotonic()
                    if policy.due(transferred, now) or worker.durable_update_required():
                        self._persist_download_progress(target, plan, local, transferred, policy, item.metrics)
                    worker.checkpoint(transferred, total)
                if policy.completed_bytes != transferred:
                    self._persist_download_progress(target, plan, local, transferred, policy, item.metrics)
            if partial.stat().st_size != total:
                raise ProfileError("Final size mismatch")
            final_source = sftp.stat(remote)
            if (int(final_source.st_size), getattr(final_source, "st_mtime", None)) != source_snapshot:
                item.diagnostics.append("Source still changing")
                raise ProfileError("Source file is still being modified")
            if bool(getattr(self, "_verify_completed", False)):
                verifier = SFTPTransferRouter(self._transfer_manager, verify_completed=True)
                remote_digest = verifier._digest_remote(sftp, remote)
                if remote_digest is not None and remote_digest != verifier._digest_local(partial):
                    raise ProfileError("Checksum mismatch")
            item.status = TransferState.VERIFYING
            os.replace(partial, local)
            self._partial_local_metadata_path(local).unlink(missing_ok=True)
        except InterruptedError:
            # Keep the flushed staging file and matching sidecar for pause,
            # cancel, disconnect and application shutdown.
            try:
                self._persist_closed_download_progress(plan, local, partial, item.metrics)
            except OSError:
                pass
            if item.delete_partial_on_cancel:
                partial.unlink(missing_ok=True)
                self._partial_local_metadata_path(local).unlink(missing_ok=True)
            raise
        except Exception as exc:
            # The file context has closed (and therefore flushed) before this
            # handler runs. Preserve that durable offset for a safe retry.
            try:
                self._persist_closed_download_progress(plan, local, partial, item.metrics)
            except OSError:
                pass
            failure = SFTPTransferRouter._channel_failure(exc)
            reconnects = sum(
                diagnostic in {"SFTP channel timeout", "Connection interrupted"}
                for diagnostic in item.diagnostics
            )
            if failure is not None:
                item.diagnostics.append(failure)
                if reconnects < 3:
                    replacement = worker.reconnect_client()
                    return self._scheduled_download(item, replacement, worker, remote, local, replace)
                raise ProfileError(failure) from exc
            raise

    def _collision_choice(self, direction: str, name: str) -> str:
        choice = messagebox.askyesnocancel(
            "File already exists",
            f"{name} already exists at the {direction} destination.\n\nYes: Replace\nNo: Rename\nCancel: Skip",
        )
        return "replace" if choice is True else "rename" if choice is False else "skip"

    def _unique_local_name(self, path: Path) -> Path:
        candidate, count = path, 2
        while candidate.exists():
            candidate = path.with_name(f"{path.stem} ({count}){path.suffix}")
            count += 1
        return candidate

    def _upload_collision_decision(self, name: str, remote: str) -> tuple[str, str]:
        if not self._remote_tree.exists(name):
            return "replace", remote
        choice = self._collision_choice("remote", name)
        if choice != "rename":
            return choice, remote
        stem, suffix = posixpath.splitext(remote)
        count = 2
        candidate = f"{stem} ({count}){suffix}"
        while self._remote_tree.exists(posixpath.basename(candidate)):
            count += 1
            candidate = f"{stem} ({count}){suffix}"
        return "replace", candidate

    def _download_collision_decision(self, name: str, local: Path) -> tuple[str, Path]:
        if not local.exists():
            return "replace", local
        choice = self._collision_choice("local", name)
        return (
            ("replace", local)
            if choice == "replace"
            else ("replace", self._unique_local_name(local))
            if choice == "rename"
            else ("skip", local)
        )

    def _download_folder(self):
        sel = self._remote_tree.selection()
        if not sel:
            return
        for name in sel:
            if name == "..":
                continue
            remote = self._remote_join(self._remote_cwd, name)
            local = Path(self._local_cwd) / name
            if local.exists() and not local.is_dir():
                self._transfer_manager.record(
                    TransferItem(
                        remote,
                        str(local),
                        "Download",
                        status=TransferState.CONFLICT,
                        error="Type conflict: remote directory cannot replace a local file.",
                    )
                )
                continue
            children = self._plan_folder_download(remote, local)
            batch = TransferBatch(name, "Download", remote, str(local))
            self._transfer_manager.add_batch(batch, children)
            self._set_status(f"Queued folder {name} ({len(children)} files).")
            self._refresh_transfer_tree()

    def _plan_folder_download(self, remote: str, local: Path):
        """Build independent resumable rows for every regular remote child."""
        local.mkdir(parents=True, exist_ok=True)
        children = []
        for attributes in self._sftp.listdir_attr(remote):
            remote_child = self._remote_join(remote, attributes.filename)
            local_child = local / attributes.filename
            if stat.S_ISDIR(attributes.st_mode):
                if local_child.exists() and not local_child.is_dir():
                    children.append(
                        (
                            TransferItem(
                                remote_child,
                                str(local_child),
                                "Download",
                                status=TransferState.CONFLICT,
                                error="Type conflict: remote directory cannot replace a local file.",
                            ),
                            None,
                        )
                    )
                else:
                    children.extend(self._plan_folder_download(remote_child, local_child))
                continue
            try:
                plan = inspect_download_resume(
                    local_child,
                    remote_identity=self._remote_identity(),
                    remote_path=remote_child,
                    remote_size=attributes.st_size,
                    remote_mtime=getattr(attributes, "st_mtime", None),
                )
            except OSError as exc:
                children.append(
                    (
                        TransferItem(
                            remote_child,
                            str(local_child),
                            "Download",
                            status=TransferState.FAILED,
                            error=str(redact_secrets(str(exc))),
                        ),
                        None,
                    )
                )
                continue
            if plan.decision == DownloadResumeDecision.ALREADY_COMPLETE:
                children.append(
                    (
                        TransferItem(
                            remote_child,
                            str(local_child),
                            "Download",
                            total=plan.remote_size,
                            transferred=plan.remote_size,
                            status=TransferState.ALREADY_COMPLETE,
                        ),
                        None,
                    )
                )
                continue
            if plan.decision == DownloadResumeDecision.ADOPT_LEGACY:
                if messagebox.askyesno(
                    "Resume existing download",
                    f"{local_child.name}: {plan.message}\n\nAdopt and resume it?",
                    parent=self,
                ):
                    try:
                        plan = adopt_legacy_download(plan)
                    except (OSError, ProfileError) as exc:
                        children.append(
                            (
                                TransferItem(
                                    remote_child,
                                    str(local_child),
                                    "Download",
                                    total=plan.remote_size,
                                    status=TransferState.CONFLICT,
                                    error=str(exc),
                                ),
                                None,
                            )
                        )
                        continue
                else:
                    decision, destination = self._download_collision_decision(local_child.name, local_child)
                    if decision == "skip":
                        children.append(
                            (
                                TransferItem(
                                    remote_child,
                                    str(local_child),
                                    "Download",
                                    total=plan.remote_size,
                                    status=TransferState.CANCELLED,
                                ),
                                None,
                            )
                        )
                        continue
                    local_child = destination
                    plan = inspect_download_resume(
                        local_child,
                        remote_identity=self._remote_identity(),
                        remote_path=remote_child,
                        remote_size=attributes.st_size,
                        remote_mtime=getattr(attributes, "st_mtime", None),
                    )
            elif plan.decision == DownloadResumeDecision.CONFLICT:
                if local_child.is_file() and "larger" in plan.message:
                    messagebox.showwarning("Download", plan.message, parent=self)
                    decision, destination = self._download_collision_decision(local_child.name, local_child)
                    if decision == "skip":
                        children.append(
                            (
                                TransferItem(
                                    remote_child,
                                    str(local_child),
                                    "Download",
                                    total=plan.remote_size,
                                    status=TransferState.CANCELLED,
                                ),
                                None,
                            )
                        )
                        continue
                    local_child = destination
                    plan = inspect_download_resume(
                        local_child,
                        remote_identity=self._remote_identity(),
                        remote_path=remote_child,
                        remote_size=attributes.st_size,
                        remote_mtime=getattr(attributes, "st_mtime", None),
                    )
                else:
                    children.append(
                        (
                            TransferItem(
                                remote_child,
                                str(local_child),
                                "Download",
                                total=plan.remote_size,
                                status=TransferState.CONFLICT,
                                error=plan.message,
                            ),
                            None,
                        )
                    )
                    continue
            item = TransferItem(
                remote_child,
                str(local_child),
                "Download",
                total=plan.remote_size,
                transferred=plan.offset,
                resume_offset=plan.offset,
            )
            children.append(
                (
                    item,
                    lambda current, client, worker, r=remote_child, p=local_child: self._scheduled_download(
                        current, client, worker, r, p, True
                    ),
                )
            )
        return children

    def _download_dir(self, remote: str, local: Path):
        local.mkdir(exist_ok=True)
        for a in self._sftp.listdir_attr(remote):
            r = self._remote_join(remote, a.filename)
            local_path = local / a.filename
            if stat.S_ISDIR(a.st_mode):
                self._download_dir(r, local_path)
            else:
                self._download_file(r, local_path)

    def _remote_delete(self):
        sel = self._remote_tree.selection()
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", None)
        if not sel or (
            confirm_delete_enabled(settings) and not messagebox.askyesno("Delete", f"Delete {len(sel)} item(s)?")
        ):
            return
        for name in sel:
            if name == "..":
                continue
            remote = self._remote_join(self._remote_cwd, name)
            self._transfer_queue.put(lambda path=remote: self._delete_remote_path(path))

    def _delete_remote_path(self, remote):
        try:
            self._sftp.remove(remote)
        except Exception:
            self._sftp.rmdir(remote)
        self.after(0, self._refresh_remote)

    def _remote_rename(self):
        sel = self._remote_tree.selection()
        if not sel:
            return
        old = sel[0]
        new = simpledialog_ask("Rename", f"New name for '{old}':", old)
        if new and new != old:
            old_path = self._remote_join(self._remote_cwd, old)
            new_path = self._remote_join(self._remote_cwd, new)
            self._transfer_queue.put(lambda source=old_path, target=new_path: self._rename_remote_path(source, target))

    def _rename_remote_path(self, old_path, new_path):
        self._sftp.rename(old_path, new_path)
        self.after(0, self._refresh_remote)

    def _remote_chmod(self):
        sel = self._remote_tree.selection()
        if not sel:
            return
        name = sel[0]
        remote = self._remote_join(self._remote_cwd, name)
        try:
            current = oct(stat.S_IMODE(self._sftp.stat(remote).st_mode))
        except Exception:
            current = "0755"
        mode_str = simpledialog_ask("Permissions", f"Octal mode for '{name}':", current)
        if mode_str:
            try:
                self._sftp.chmod(remote, int(mode_str, 8))
                self._refresh_remote()
            except Exception as e:
                messagebox.showerror("chmod", str(e))

    def _remote_mkdir(self):
        name = simpledialog_ask("New folder", "Folder name:")
        if name:
            try:
                self._sftp.mkdir(self._remote_join(self._remote_cwd, name))
                self._refresh_remote()
            except Exception as e:
                messagebox.showerror("mkdir", str(e))

    def _local_mkdir(self):
        name = simpledialog_ask("New folder", "Folder name:")
        if name:
            try:
                (Path(self._local_cwd) / name).mkdir()
                self._refresh_local()
            except Exception as e:
                messagebox.showerror("mkdir", str(e))

    def shutdown(self):
        """Cancel work and close this SFTP channel exactly once."""
        if self._closed:
            return
        self._closed = True
        self._remote_generation += 1
        with self._local_load_lock:
            self._local_load_state.close()
        self._transfer_cancel.set()
        self._transfer_manager.shutdown()
        if self._transfer_window is not None and self._transfer_window.winfo_exists():
            self._transfer_window.destroy_manager()
        try:
            self._sftp.close()
        except Exception as exc:
            log(f"SFTP cleanup failed: {exc}")
        self._transfer_queue.put(None)
        if self._transfer_thread is not threading.current_thread():
            self._transfer_thread.join(timeout=0.25)

    def destroy(self):
        """Suppress late worker callbacks when the SFTP panel is closed."""
        self.shutdown()
        super().destroy()


def simpledialog_ask(title, prompt, initial="", secret=False):
    d = tk.Toplevel()
    d.title(title)
    d.configure(bg=BG)
    d.resizable(False, False)
    result = [None]
    tk.Label(d, text=prompt, bg=BG, fg=TEXT, font=FONT).pack(padx=12, pady=(12, 4))
    var = tk.StringVar(value=initial)
    e = tk.Entry(
        d,
        textvariable=var,
        bg=PANEL,
        fg=TEXT,
        font=FONT,
        insertbackground=TEXT,
        relief="flat",
        width=32,
        show="●" if secret else "",
    )
    e.pack(padx=12, pady=4)
    e.select_range(0, "end")
    e.focus_set()

    def ok():
        result[0] = var.get()
        d.destroy()

    e.bind("<Return>", lambda _: ok())
    tk.Button(d, text="OK", command=ok, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=10).pack(pady=8)
    d.grab_set()
    d.wait_window()
    return result[0]


# ── Port forwarding ──────────────────────────────────────────────────────────
class PortForwardPanel(tk.Frame):
    def __init__(self, parent, client, saved_rules=None, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._client = client
        self._tunnels: list[dict] = []
        self._saved_rules = list(saved_rules or [])
        self._saved_status = {
            str(r.get("rule_id") or r.get("id") or i): "Stopped" for i, r in enumerate(self._saved_rules)
        }
        self._manager = TunnelManager(client.get_transport() if client else None, id(client))
        self._build()

    def _build(self):
        tk.Label(self, text="Port Forwarding", bg=PANEL, fg=ACCENT, font=FONT_B).pack(anchor="w", padx=8, pady=6)

        form = tk.Frame(self, bg=PANEL)
        form.pack(fill="x", padx=8, pady=4)
        self._tunnel_form = form

        self._type_var = tk.StringVar(value="Local")
        ttk.Combobox(
            form, textvariable=self._type_var, values=("Local", "Remote", "Dynamic/SOCKS"), state="readonly", width=20
        ).grid(row=0, column=1, sticky="w", padx=4, pady=2)
        tk.Label(form, text="Type", bg=PANEL, fg=MUTED, font=FONT).grid(row=0, column=0, sticky="e", padx=4)

        self._lhost = self._fld(form, "Bind address", 1, "127.0.0.1")
        self._lport = self._fld(form, "Local port", 2, "8022")
        self._rhost = self._fld(form, "Remote host", 3, "127.0.0.1")
        self._rport = self._fld(form, "Remote port", 4, "22")

        self._tunnel_error = tk.StringVar()
        tk.Label(form, textvariable=self._tunnel_error, bg=PANEL, fg=RED, font=FONT).grid(row=5, column=1, sticky="w")
        self._start_button = tk.Button(
            form, text="Start tunnel", command=self._add_tunnel, bg=GREEN, fg=BG, font=FONT, relief="flat", padx=8
        )
        self._start_button.grid(row=6, column=1, sticky="w", pady=6)
        for var in (self._type_var, self._lhost, self._lport, self._rhost, self._rport):
            var.trace_add("write", lambda *_: self._validate_tunnel())
        self._type_var.trace_add("write", lambda *_: self._sync_tunnel_fields())

        cols = ("type", "local", "remote", "status")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (100, 160, 160, 80)):
            self._tree.heading(c, text=c.title())
            self._tree.column(c, width=w, anchor="w")
        self._tree.pack(fill="both", expand=True, padx=8, pady=4)

        if self._saved_rules:
            tk.Label(self, text="Saved tunnel rules", bg=PANEL, fg=ACCENT, font=FONT_B).pack(
                anchor="w", padx=8, pady=(8, 2)
            )
            saved_cols = ("enabled", "type", "bind", "destination", "description", "status")
            self._saved_tree = ttk.Treeview(self, columns=saved_cols, show="headings", height=5, selectmode="browse")
            for col, width in zip(saved_cols, (65, 80, 140, 150, 180, 80)):
                self._saved_tree.heading(col, text=col.title())
                self._saved_tree.column(col, width=width, anchor="w")
            self._saved_tree.pack(fill="x", padx=8, pady=3)
            for index, rule in enumerate(self._saved_rules):
                rid = str(rule.get("rule_id") or rule.get("id") or index)
                kind = str(rule.get("type", "Local"))
                bind = f"{rule.get('bind_address', '127.0.0.1')}:{rule.get('bind_port', '')}"
                dest = (
                    "(dynamic)"
                    if kind == "SOCKS"
                    else f"{rule.get('destination_host', '')}:{rule.get('destination_port', '')}"
                )
                self._saved_tree.insert(
                    "",
                    "end",
                    iid=rid,
                    values=(
                        "Yes" if rule.get("enabled", True) else "No",
                        kind,
                        bind,
                        dest,
                        rule.get("description", ""),
                        self._saved_status[rid],
                    ),
                )
            saved_buttons = tk.Frame(self, bg=PANEL)
            saved_buttons.pack(anchor="w", padx=8, pady=3)
            tk.Button(
                saved_buttons, text="Start selected", command=self._start_saved_selected, bg=GREEN, fg=BG, relief="flat"
            ).pack(side="left", padx=(0, 4))
            tk.Button(
                saved_buttons, text="Start all enabled", command=self._start_all_saved, bg=GREEN, fg=BG, relief="flat"
            ).pack(side="left")
        else:
            self._saved_tree = None

        tk.Button(
            self, text="Stop selected", command=self._stop_tunnel, bg=RED, fg=BG, font=FONT, relief="flat", padx=8
        ).pack(anchor="w", padx=8, pady=4)
        tk.Button(
            self, text="Stop all", command=self._stop_all_tunnels, bg=PANEL, fg=TEXT, font=FONT, relief="flat", padx=8
        ).pack(anchor="w", padx=8, pady=(0, 4))
        self._validate_tunnel()

    def _start_saved_rule(self, rule):
        try:
            form_kind = "Dynamic/SOCKS" if rule.get("type") == "SOCKS" else str(rule.get("type", "Local"))
            self._type_var.set(form_kind)
            self._lhost.set(str(rule.get("bind_address", "127.0.0.1")))
            self._lport.set(str(rule.get("bind_port", "")))
            self._rhost.set(str(rule.get("destination_host", "")))
            self._rport.set(str(rule.get("destination_port", "")))
            self._add_tunnel()
            rid = str(rule.get("rule_id") or rule.get("id"))
            if self._saved_tree is not None and self._saved_tree.exists(rid):
                self._saved_status[rid] = "Running"
                self._saved_tree.set(rid, "status", "Running")
        except Exception as exc:
            self._tunnel_error.set("Could not start saved tunnel.")
            log(f"Saved tunnel start failed: {redact_secrets(str(exc))}")

    def _start_saved_selected(self):
        if self._saved_tree is None:
            return
        selected = self._saved_tree.selection()
        if not selected:
            return
        rid = selected[0]
        for rule in self._saved_rules:
            if str(rule.get("rule_id") or rule.get("id")) == rid:
                self._start_saved_rule(rule)
                return

    def _start_all_saved(self):
        for rule in self._saved_rules:
            if rule.get("enabled", True):
                self._start_saved_rule(rule)

    def _sync_tunnel_fields(self):
        visible = self._type_var.get() != "Dynamic/SOCKS"
        for row in (3, 4):
            for widget in self._tunnel_form.grid_slaves(row=row):
                widget.grid() if visible else widget.grid_remove()
        self._validate_tunnel()

    def _form_state(self):
        return TunnelFormState(
            self._type_var.get(), self._lhost.get(), self._lport.get(), self._rhost.get(), self._rport.get()
        )

    def _validate_tunnel(self):
        state = self._form_state()
        error = state.validate()
        warning = (
            " Public binding may expose this tunnel to the network." if state.public_bind_warning and not error else ""
        )
        self._tunnel_error.set((error or "") + warning)
        self._start_button.configure(state="normal" if not error else "disabled")

    def _fld(self, parent, label, row, default=""):
        tk.Label(parent, text=label, bg=PANEL, fg=MUTED, font=FONT).grid(row=row, column=0, sticky="e", padx=4, pady=2)
        var = tk.StringVar(value=default)
        tk.Entry(
            parent, textvariable=var, bg="#0d0d1a", fg=TEXT, font=FONT, insertbackground=TEXT, relief="flat", width=22
        ).grid(row=row, column=1, sticky="w", padx=4, pady=2)
        return var

    def _add_tunnel(self):
        if not self._client:
            self._tunnel_error.set("Not connected.")
            return
        form_state = self._form_state()
        error = form_state.validate()
        if error:
            self._tunnel_error.set(error)
            return
        if form_state.public_bind_warning and not messagebox.askyesno(
            "Public tunnel binding",
            "This tunnel binds outside loopback and may be reachable by other devices. Continue?",
        ):
            return
        kind = self._type_var.get()
        lhost = self._lhost.get().strip()
        lport = int(self._lport.get())
        rhost = self._rhost.get().strip()
        rport = int(self._rport.get())
        bind_key = (lhost, lport)
        if any(
            info.get("status") in {"active", "starting"} and info.get("bind_key") == bind_key for info in self._tunnels
        ):
            self._tunnel_error.set("A tunnel already uses this bind endpoint.")
            return

        runtime = TunnelRuntime(generation=id(self._client))
        if kind == "Local":
            t = threading.Thread(target=self._local_forward, args=(lhost, lport, rhost, rport, runtime), daemon=True)
            info = {
                "type": "Local",
                "local": f"{lhost}:{lport}",
                "remote": f"{rhost}:{rport}",
                "status": "active",
                "thread": t,
            }
            t.start()
        elif kind == "Remote":
            try:
                transport = self._client.get_transport()
                transport.request_port_forward("", rport)
                t = threading.Thread(
                    target=self._remote_forward, args=(transport, rport, lhost, lport, runtime), daemon=True
                )
                info = {
                    "type": "Remote",
                    "local": f"{lhost}:{lport}",
                    "remote": f"server:{rport}",
                    "status": "active",
                    "thread": t,
                }
                t.start()
            except Exception as e:
                messagebox.showerror("Port forward", str(e))
                return
        else:  # Dynamic SOCKS
            t = threading.Thread(target=self._socks_forward, args=(lhost, lport, runtime), daemon=True)
            info = {
                "type": "SOCKS5",
                "local": f"{lhost}:{lport}",
                "remote": "(dynamic)",
                "status": "active",
                "thread": t,
            }
            t.start()

        runtime.thread = t
        info["runtime"] = runtime
        info["bind_key"] = bind_key
        info["bytes"] = "Unavailable"
        self._tunnels.append(info)
        iid = str(len(self._tunnels) - 1)
        self._tree.insert("", "end", iid=iid, values=(info["type"], info["local"], info["remote"], info["status"]))
        log(f"Tunnel started: {info['type']} {info['local']} -> {info['remote']}")

    def _local_forward(self, lhost, lport, rhost, rport, runtime):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    chan = self.server._client.get_transport().open_channel(
                        "direct-tcpip", (rhost, rport), self.request.getpeername()
                    )
                    if chan is None:
                        return
                    while True:
                        r, _, _ = select.select([self.request, chan], [], [])
                        if self.request in r:
                            data = self.request.recv(1024)
                            if not data:
                                break
                            chan.send(data)
                        if chan in r:
                            data = chan.recv(1024)
                            if not data:
                                break
                            self.request.send(data)
                except Exception:
                    pass

        server = socketserver.ThreadingTCPServer((lhost, lport), Handler)
        server.timeout = 0.2
        server._client = self._client
        runtime.listener = server
        try:
            while not runtime.stop_event.is_set():
                server.handle_request()
        finally:
            server.server_close()

    def _remote_forward(self, transport, rport, lhost, lport, runtime):
        while not runtime.stop_event.is_set():
            chan = transport.accept(timeout=1)
            if chan is None:
                continue
            threading.Thread(target=self._bridge, args=(chan, lhost, lport), daemon=True).start()

    def _bridge(self, chan, lhost, lport):
        sock = socket.socket()
        try:
            sock.connect((lhost, lport))
            while True:
                r, _, _ = select.select([sock, chan], [], [])
                if sock in r:
                    data = sock.recv(1024)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sock.send(data)
        except Exception:
            pass
        finally:
            sock.close()
            chan.close()

    def _socks_forward(self, lhost, lport, runtime):
        class Socks5Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    s = self.request
                    s.recv(2)  # version + nmethods
                    s.sendall(b"\x05\x00")  # no auth
                    hdr = s.recv(4)
                    if len(hdr) < 4 or hdr[1] != 1:
                        return
                    atype = hdr[3]
                    if atype == 1:
                        addr = socket.inet_ntoa(s.recv(4))
                    elif atype == 3:
                        ln = ord(s.recv(1))
                        addr = s.recv(ln).decode()
                    else:
                        return
                    port = struct.unpack("!H", s.recv(2))[0]
                    s.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
                    chan = self.server._client.get_transport().open_channel(
                        "direct-tcpip", (addr, port), ("127.0.0.1", 0)
                    )
                    if not chan:
                        return
                    while True:
                        r, _, _ = select.select([s, chan], [], [])
                        if s in r:
                            data = s.recv(4096)
                            if not data:
                                break
                            chan.send(data)
                        if chan in r:
                            data = chan.recv(4096)
                            if not data:
                                break
                            s.send(data)
                except Exception:
                    pass

        srv = socketserver.ThreadingTCPServer((lhost, lport), Socks5Handler)
        srv.timeout = 0.2
        srv._client = self._client
        runtime.listener = srv
        try:
            while not runtime.stop_event.is_set():
                srv.handle_request()
        finally:
            srv.server_close()

    def _stop_tunnel(self):
        sel = self._tree.selection()
        if not sel:
            return
        for iid in sel:
            idx = int(iid)
            if idx < len(self._tunnels):
                self._tunnels[idx].get("runtime", TunnelRuntime()).stop()
                self._tunnels[idx]["status"] = "stopped"
                self._tree.set(iid, "status", "stopped")

    def _stop_all_tunnels(self):
        for index, info in enumerate(self._tunnels):
            if info.get("status") in {"active", "starting"}:
                info.get("runtime", TunnelRuntime()).stop()
                info["status"] = "stopped"
                if self._tree.exists(str(index)):
                    self._tree.set(str(index), "status", "stopped")

    def destroy(self):
        self._stop_all_tunnels()
        super().destroy()


# ── Remote exec panel ────────────────────────────────────────────────────────
class RemoteExecPanel(tk.Frame):
    def __init__(self, parent, client, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._client = client
        self._state = CommandExecutionState()
        self._active_channel = None
        self._output_parts = []
        self._output_sequence = 0
        self._save_generation = 0
        self._closed = False
        self._worker_thread = None
        self._build()

    def _build(self):
        tk.Label(self, text="Remote Execute", bg=BG, fg=ACCENT, font=FONT_B).pack(anchor="w", padx=8, pady=6)
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=8, pady=4)
        self._cmd_var = tk.StringVar()
        e = tk.Entry(
            top, textvariable=self._cmd_var, bg=PANEL, fg=TEXT, font=MONO, insertbackground=TEXT, relief="flat"
        )
        e.pack(side="left", fill="x", expand=True, padx=(0, 6))
        e.bind("<Return>", lambda _: self._run())
        self._run_btn = tk.Button(
            top, text="Run", command=self._run, bg=GREEN, fg=BG, font=FONT, relief="flat", padx=10
        )
        self._run_btn.pack(side="left")
        self._cancel_btn = tk.Button(
            top,
            text="Cancel",
            command=self._cancel,
            bg=YELLOW,
            fg=BG,
            font=FONT,
            relief="flat",
            padx=8,
            state="disabled",
        )
        self._cancel_btn.pack(side="left", padx=4)
        self._copy_btn = tk.Button(
            top,
            text="Copy Output",
            command=self._copy_output,
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            relief="flat",
            state="disabled",
        )
        self._copy_btn.pack(side="left", padx=4)
        self._save_btn = tk.Button(
            top,
            text="Save Output",
            command=self._save_output,
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            relief="flat",
            state="disabled",
        )
        self._save_btn.pack(side="left", padx=4)
        tk.Button(top, text="Clear", command=self._clear, bg=PANEL, fg=TEXT, font=FONT, relief="flat", padx=8).pack(
            side="left", padx=4
        )
        self._out = scrolledtext.ScrolledText(self, bg="#0d0d1a", fg=TEXT, font=MONO, relief="flat", state="disabled")
        self._out.pack(fill="both", expand=True, padx=8, pady=4)
        self._out.tag_configure("err", foreground=RED)
        self._out.tag_configure("hdr", foreground=ACCENT)

    def _run(self):
        cmd = self._cmd_var.get().strip()
        if not cmd:
            return
        if "\n" in cmd and not messagebox.askyesno(
            "Run multiline command", "Run this multiline command on the remote host?"
        ):
            return
        generation = self._state.start()
        if generation is None:
            return
        self._run_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._worker_thread = threading.Thread(target=self._exec, args=(cmd, generation), daemon=True)
        self._worker_thread.start()

    def _cancel(self):
        if self._state.cancel(self._state.generation) and self._active_channel:
            try:
                self._active_channel.close()
            except Exception:
                pass

    def shutdown(self):
        """Cancel command I/O and invalidate callbacks for this SSH session."""
        if self._closed:
            return
        self._closed = True
        self._save_generation += 1
        self._cancel()
        worker = self._worker_thread
        if worker is not None and worker is not threading.current_thread() and worker.is_alive():
            worker.join(0.25)
        self._worker_thread = None

    def _exec(self, cmd, generation):
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=60)
            channel = stdout.channel
            self._active_channel = channel
            while self._state.accepts(generation) and not channel.exit_status_ready():
                if channel.recv_ready():
                    self._queue_chunk(generation, channel.recv(32768).decode("utf-8", errors="replace"), "")
                if channel.recv_stderr_ready():
                    self._queue_chunk(generation, channel.recv_stderr(32768).decode("utf-8", errors="replace"), "err")
                time.sleep(0.02)
            while channel.recv_ready():
                self._queue_chunk(generation, channel.recv(32768).decode("utf-8", errors="replace"), "")
            while channel.recv_stderr_ready():
                self._queue_chunk(generation, channel.recv_stderr(32768).decode("utf-8", errors="replace"), "err")
            self.after(0, lambda: self._finish_exec(generation))
        except Exception as e:
            self.after(0, lambda error=e: self._finish_exec(generation, error))

    def _finish_exec(self, generation, error=None):
        if self._closed:
            return
        if not self._state.finish(generation, failed=error is not None):
            return
        if error:
            self._append("[error] Command failed. See the activity log for details.\n", "err")
            log(f"Command failed: {error}")
        self._active_channel = None
        self._run_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")

    def _queue_chunk(self, generation, text, tag):
        if self._closed or not text or not self._state.accepts(generation):
            return
        self._output_sequence += 1
        sequence = self._output_sequence
        self.after(0, lambda: self._append_chunk(generation, sequence, text, tag))

    def _append_chunk(self, generation, _sequence, text, tag):
        if not self._state.accepts(generation):
            return
        self._output_parts.append(text)
        self._append(text, tag)
        self._copy_btn.configure(state="normal")
        self._save_btn.configure(state="normal")

    def _copy_output(self):
        if self._output_parts:
            self.clipboard_clear()
            self.clipboard_append("".join(self._output_parts))

    def _save_output(self):
        if not self._output_parts:
            return
        path = filedialog.asksaveasfilename(
            title="Save command output", defaultextension=".txt", filetypes=(("Text files", "*.txt"),)
        )
        if not path:
            return
        target = Path(path)
        settings = getattr(self.winfo_toplevel(), "_runtime_settings", None)
        if (
            target.exists()
            and confirm_overwrite_enabled(settings)
            and not messagebox.askyesno("Overwrite output", "Replace the existing output file?")
        ):
            return
        snapshot = "".join(self._output_parts)
        self._save_generation += 1
        generation = self._save_generation
        self._save_btn.configure(state="disabled")
        threading.Thread(target=self._write_output, args=(target, snapshot, generation), daemon=True).start()

    def _write_output(self, target, snapshot, generation):
        temp_name = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(snapshot)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
            temp_name = None
            self.after(0, lambda: self._finish_save(generation))
        except OSError as error:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
            self.after(0, lambda err=error: self._finish_save(generation, err))

    def _finish_save(self, generation, error=None):
        if self._closed or generation != self._save_generation:
            return
        self._save_btn.configure(state="normal" if self._output_parts else "disabled")
        if error:
            messagebox.showerror("Save output", "Could not save output.")
            log(f"Save output failed: {error}")

    def _append(self, text, tag=""):
        self._out.configure(state="normal")
        self._out.insert("end", text, tag)
        self._out.see("end")
        self._out.configure(state="disabled")

    def _clear(self):
        self._out.configure(state="normal")
        self._out.delete("1.0", "end")
        self._out.configure(state="disabled")
        self._output_parts.clear()
        self._copy_btn.configure(state="disabled")
        self._save_btn.configure(state="disabled")

    def destroy(self):
        self.shutdown()
        super().destroy()


# ── FTP-to-SFTP bridge ───────────────────────────────────────────────────────
class FTPBridgePanel(tk.Frame):
    def __init__(self, parent, sftp_client, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._sftp = sftp_client
        self._server = None
        self._build()

    def _build(self):
        tk.Label(self, text="FTP-to-SFTP Bridge", bg=BG, fg=ACCENT, font=FONT_B).pack(anchor="w", padx=8, pady=6)
        tk.Label(
            self, text="Exposes remote SFTP as a local FTP server for legacy applications.", bg=BG, fg=MUTED, font=FONT
        ).pack(anchor="w", padx=8)
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=8, pady=8)
        tk.Label(row, text="Local FTP port:", bg=BG, fg=TEXT, font=FONT).pack(side="left")
        self._port_var = tk.StringVar(value="2121")
        tk.Entry(
            row,
            textvariable=self._port_var,
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            insertbackground=TEXT,
            relief="flat",
            width=8,
        ).pack(side="left", padx=6)
        self._toggle_btn = tk.Button(
            row, text="Start Bridge", command=self._toggle, bg=GREEN, fg=BG, font=FONT, relief="flat", padx=10
        )
        self._toggle_btn.pack(side="left")
        self._status = tk.Label(self, text="Stopped", bg=BG, fg=MUTED, font=FONT)
        self._status.pack(anchor="w", padx=8, pady=4)
        tk.Label(
            self, text="Connect legacy FTP clients to: ftp://anonymous@127.0.0.1:<port>", bg=BG, fg=MUTED, font=FONT
        ).pack(anchor="w", padx=8)

    def _toggle(self):
        if self._server:
            self._server.shutdown()
            self._server = None
            self._toggle_btn.configure(text="Start Bridge", bg=GREEN)
            self._status.configure(text="Stopped", fg=MUTED)
        else:
            port = int(self._port_var.get())
            sftp = self._sftp
            try:
                self._server = _SimpleFTPServer(sftp, port)
                threading.Thread(target=self._server.serve_forever, daemon=True).start()
                self._toggle_btn.configure(text="Stop Bridge", bg=RED)
                self._status.configure(text=f"Running on ftp://127.0.0.1:{port}", fg=GREEN)
                log(f"FTP bridge started on port {port}")
            except Exception as e:
                messagebox.showerror("FTP Bridge", str(e))

    def shutdown(self):
        if self._server is None:
            return
        server, self._server = self._server, None
        try:
            server.shutdown()
            server.server_close()
        except Exception as exc:
            log(f"FTP bridge cleanup failed: {exc}")

    def destroy(self):
        self.shutdown()
        super().destroy()


class _SimpleFTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, sftp, port):
        self._sftp = sftp
        self._cwd = "/"
        super().__init__(("127.0.0.1", port), _FTPHandler)

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, sftp=self._sftp)


class _FTPHandler(socketserver.StreamRequestHandler):
    def __init__(self, *a, sftp=None, **kw):
        self._sftp = sftp
        self._cwd = "/"
        self._data_sock = None
        super().__init__(*a, **kw)

    def handle(self):
        self._send("220 SSHVault FTP-to-SFTP bridge ready.")
        while True:
            try:
                line = self.rfile.readline().decode("utf-8", errors="replace").strip()
            except Exception:
                break
            if not line:
                break
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd == "USER":
                self._send("331 Password required.")
            elif cmd == "PASS":
                self._send("230 Logged in.")
            elif cmd == "SYST":
                self._send("215 UNIX Type: L8")
            elif cmd == "FEAT":
                self._send("211-Features:\r\n UTF8\r\n211 End")
            elif cmd == "PWD":
                self._send(f'257 "{self._cwd}" is current directory.')
            elif cmd == "CWD":
                self._cwd = arg if arg.startswith("/") else self._cwd.rstrip("/") + "/" + arg
                self._send("250 CWD command successful.")
            elif cmd == "PASV":
                self._data_sock = socket.socket()
                self._data_sock.bind(("127.0.0.1", 0))
                self._data_sock.listen(1)
                p = self._data_sock.getsockname()[1]
                h = "127,0,0,1"
                self._send(f"227 Entering Passive Mode ({h},{p // 256},{p % 256}).")
            elif cmd == "LIST":
                self._send("150 Opening data connection.")
                conn, _ = self._data_sock.accept()
                try:
                    for a in self._sftp.listdir_attr(self._cwd):
                        perms = "d" if stat.S_ISDIR(a.st_mode) else "-"
                        line = f"{perms}rwxr-xr-x 1 user group {a.st_size:>12} Jan  1 00:00 {a.filename}\r\n"
                        conn.sendall(line.encode())
                except Exception:
                    pass
                conn.close()
                self._send("226 Transfer complete.")
            elif cmd == "RETR":
                remote = self._cwd.rstrip("/") + "/" + arg
                self._send("150 Opening data connection.")
                conn, _ = self._data_sock.accept()
                try:
                    with self._sftp.open(remote, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            conn.sendall(chunk)
                except Exception as e:
                    conn.close()
                    self._send(f"550 {e}")
                    continue
                conn.close()
                self._send("226 Transfer complete.")
            elif cmd == "STOR":
                remote = self._cwd.rstrip("/") + "/" + arg
                self._send("150 Opening data connection.")
                conn, _ = self._data_sock.accept()
                try:
                    with self._sftp.open(remote, "wb") as f:
                        while True:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                except Exception as e:
                    conn.close()
                    self._send(f"550 {e}")
                    continue
                conn.close()
                self._send("226 Transfer complete.")
            elif cmd == "QUIT":
                self._send("221 Goodbye.")
                break
            else:
                self._send(f"502 {cmd} not implemented.")

    def _send(self, msg):
        self.wfile.write((msg + "\r\n").encode())
        self.wfile.flush()


# ── SSH Key generation ───────────────────────────────────────────────────────
class KeyGenDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Generate SSH Key Pair")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._build()
        self.grab_set()

    def _build(self):
        tk.Label(self, text="Generate SSH Key Pair", bg=BG, fg=ACCENT, font=FONT_B).pack(pady=(12, 4))
        f = tk.Frame(self, bg=BG)
        f.pack(padx=20, pady=4)

        tk.Label(f, text="Key type:", bg=BG, fg=MUTED, font=FONT).grid(row=0, column=0, sticky="e", pady=4)
        self._type_var = tk.StringVar(value="Ed25519")
        tk.OptionMenu(f, self._type_var, "Ed25519", "RSA-4096", "ECDSA-521").grid(row=0, column=1, sticky="w", padx=8)

        tk.Label(f, text="Save as:", bg=BG, fg=MUTED, font=FONT).grid(row=1, column=0, sticky="e", pady=4)
        self._path_var = tk.StringVar(value=str(Path.home() / ".ssh" / "id_ed25519"))
        tk.Entry(
            f, textvariable=self._path_var, bg=PANEL, fg=TEXT, font=FONT, insertbackground=TEXT, relief="flat", width=36
        ).grid(row=1, column=1, sticky="ew", padx=8)

        tk.Label(f, text="Passphrase:", bg=BG, fg=MUTED, font=FONT).grid(row=2, column=0, sticky="e", pady=4)
        self._pass_var = tk.StringVar()
        tk.Entry(
            f,
            textvariable=self._pass_var,
            show="●",
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            insertbackground=TEXT,
            relief="flat",
            width=36,
        ).grid(row=2, column=1, sticky="ew", padx=8)

        self._out = tk.Text(self, height=6, bg="#0d0d1a", fg=GREEN, font=MONO, relief="flat", state="disabled")
        self._out.pack(fill="x", padx=20, pady=8)

        tk.Button(
            self, text="Generate", command=self._generate, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=12, pady=4
        ).pack(pady=4)

    def _write(self, msg):
        self._out.configure(state="normal")
        self._out.insert("end", msg + "\n")
        self._out.configure(state="disabled")

    def _generate(self):
        ktype = self._type_var.get()
        path = Path(self._path_var.get())
        passphrase = self._pass_var.get() or None
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if ktype == "Ed25519":
                key = paramiko.Ed25519Key.generate()
            elif ktype.startswith("RSA"):
                key = paramiko.RSAKey.generate(bits=4096)
            else:
                key = paramiko.ECDSAKey.generate(bits=521)

            key.write_private_key_file(str(path), password=passphrase)
            path.with_suffix(".pub") if path.suffix != ".pub" else Path(str(path) + ".pub")
            pub_path = Path(str(path) + ".pub")
            pub_path.write_text(f"{key.get_name()} {key.get_base64()} SSHVault-generated\n")
            path.chmod(0o600)
            self._write(f"Private key: {path}")
            self._write(f"Public key:  {pub_path}")
            self._write(f"Fingerprint: {key.get_fingerprint().hex(':')}")
            self._write("Done! Configure the public key for this account on the SSH server.")
            self._write("For Bitvise: add it to the virtual account's public keys; never upload the private key.")
            log(f"Key generated: {path} ({ktype})")
        except Exception as e:
            self._write(f"Error: {e}")


class SFTPServerSettingsDialog(tk.Toplevel):
    """Persist safe local-server settings; starting a listener remains explicit."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.title("Built-in SFTP Server Settings")
        self.resizable(False, False)
        try:
            config = json.loads(SFTP_SERVER_CONFIG_FILE.read_text())
        except Exception:
            config = {}
        self._vars = {
            "listen_host": tk.StringVar(value=config.get("listen_host", "127.0.0.1")),
            "port": tk.StringVar(value=str(config.get("port", 2222))),
            "username": tk.StringVar(value=config.get("username", "sftpuser")),
            "root": tk.StringVar(value=config.get("root", str(Path.home() / "SFTP"))),
        }
        self._password = tk.StringVar()
        form = tk.Frame(self, bg=BG)
        form.pack(padx=16, pady=12)
        for row, (label, key) in enumerate(
            (
                ("Listen address", "listen_host"),
                ("Port", "port"),
                ("Virtual username", "username"),
                ("Root directory", "root"),
            )
        ):
            tk.Label(form, text=label + ":", bg=BG, fg=MUTED, font=FONT).grid(row=row, column=0, sticky="e", pady=4)
            tk.Entry(
                form,
                textvariable=self._vars[key],
                bg=PANEL,
                fg=TEXT,
                font=FONT,
                width=34,
                insertbackground=TEXT,
                relief="flat",
            ).grid(row=row, column=1, padx=8, pady=4)
        tk.Label(form, text="Password:", bg=BG, fg=MUTED, font=FONT).grid(row=4, column=0, sticky="e", pady=4)
        tk.Entry(
            form,
            textvariable=self._password,
            show="●",
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            width=34,
            insertbackground=TEXT,
            relief="flat",
        ).grid(row=4, column=1, padx=8, pady=4)
        tk.Label(
            self,
            text="SFTP only; no shell or port forwarding. Defaults bind only to localhost.",
            bg=BG,
            fg=YELLOW,
            font=FONT,
        ).pack(padx=16, pady=(0, 8))
        tk.Button(
            self, text="Save settings", command=self._save, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=12
        ).pack(pady=(0, 12))
        self.grab_set()

    def _save(self):
        try:
            port = int(self._vars["port"].get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("SFTP server", "Port must be between 1 and 65535.", parent=self)
            return
        root = Path(self._vars["root"].get()).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        config = {key: var.get().strip() for key, var in self._vars.items()}
        config["port"] = port
        # Password storage is intentionally deferred until an encrypted local
        # secret store is available; never write it into the JSON vault.
        SFTP_SERVER_CONFIG_FILE.write_text(json.dumps(config, indent=2))
        log(f"Saved built-in SFTP server settings for {config['listen_host']}:{port}")
        self.destroy()


# ── Connection info panel ────────────────────────────────────────────────────
class ConnectionInfoPanel(tk.Frame):
    def __init__(self, parent, client, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._client = client
        self._build()

    def _build(self):
        tk.Label(self, text="Connection Info", bg=BG, fg=ACCENT, font=FONT_B).pack(anchor="w", padx=8, pady=6)
        self._text = tk.Text(self, bg="#0d0d1a", fg=TEXT, font=MONO, relief="flat", state="disabled")
        self._text.pack(fill="both", expand=True, padx=8, pady=4)
        tk.Button(self, text="Refresh", command=self._refresh, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=8).pack(
            anchor="w", padx=8, pady=4
        )
        self._refresh()

    def _refresh(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        try:
            t = self._client.get_transport()
            if t:
                info = {
                    "Cipher": t.local_cipher,
                    "MAC": t.local_mac,
                    "Compression": t.local_compression,
                    "Server version": t.remote_version,
                    "Server host key": t.get_remote_server_key().get_name(),
                    "Host key fingerprint": t.get_remote_server_key().get_fingerprint().hex(":"),
                }
                for k, v in info.items():
                    self._text.insert("end", f"{k:<24}: {v}\n")
        except Exception as e:
            self._text.insert("end", f"Error: {e}\n")
        self._text.configure(state="disabled")


# ── Log viewer ───────────────────────────────────────────────────────────────
class LogViewerPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=8, pady=6)
        tk.Label(top, text="Activity Log", bg=BG, fg=ACCENT, font=FONT_B).pack(side="left")
        tk.Button(top, text="Refresh", command=self._load, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=8).pack(
            side="right"
        )
        tk.Button(top, text="Clear log", command=self._clear, bg=RED, fg=BG, font=FONT, relief="flat", padx=8).pack(
            side="right", padx=4
        )
        self._text = scrolledtext.ScrolledText(self, bg="#0d0d1a", fg=TEXT, font=MONO, relief="flat", state="disabled")
        self._text.pack(fill="both", expand=True, padx=8, pady=4)
        self._load()

    def _load(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        if LOG_FILE.exists():
            self._text.insert("end", LOG_FILE.read_text())
        self._text.see("end")
        self._text.configure(state="disabled")

    def _clear(self):
        if messagebox.askyesno("Clear log", "Clear the activity log?"):
            LOG_FILE.write_text("")
            self._load()


# ── Connection tab ────────────────────────────────────────────────────────────
class TrustDecisionBroker:
    """Pass host-key decisions from Paramiko workers to Tk's main thread."""

    def __init__(self, owner, unknown_factory=None, changed_factory=None):
        self.owner, self.state, self.closed, self.active = owner, SecurityRequestQueue(), False, None
        self.unknown_factory, self.changed_factory = unknown_factory, changed_factory
        owner.after(30, self._drain)

    def request(self, request):
        request = self.state.submit("unknown", request)
        if self.closed:
            return TrustDecision.CANCEL
        request.event.wait()
        return request.result or TrustDecision.CANCEL

    def warn_changed_key(self, request):
        request = self.state.submit("changed", request)
        if self.closed:
            return
        request.event.wait()

    def close(self):
        self.closed = True
        self.state.close()
        self.active = None

    def _drain(self):
        if self.closed:
            return
        try:
            item = self.state.next()
        except Exception:
            item = None
        if item is None:
            self.owner.after(30, self._drain)
            return
        request = item
        if request.kind == "changed":
            self.active = request
            self.changed_key(request.payload, request)
            return
        self.active = request
        payload = request.payload
        if self.unknown_factory:
            try:

                def resolve_factory(decision):
                    if self.state.resolve(request.identifier, decision):
                        self.active = None
                        self.owner.after(30, self._drain)

                self.unknown_factory(payload, request.identifier, resolve_factory)
            except Exception:
                self.state.resolve(request.identifier, TrustDecision.CANCEL)
                self.active = None
                self.owner.after(30, self._drain)
            return
        dialog = tk.Toplevel(self.owner)
        dialog.title("Verify server identity")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        text = (
            f"{payload.host_role}: {payload.profile_name}\n\nSSHVault has not seen this server identity before.\n\n"
            f"Host: {payload.hostname}:{payload.port}\nAlgorithm: {payload.key_type}\nFingerprint: {payload.fingerprint}"
        )
        tk.Label(dialog, text=text, justify="left", bg=BG, fg=TEXT, font=FONT).pack(padx=20, pady=16)

        def resolve(decision):
            self.state.resolve(request.identifier, decision)
            self.active = None
            dialog.destroy()
            self.owner.after(30, self._drain)

        buttons = tk.Frame(dialog, bg=BG)
        buttons.pack(pady=(0, 16))
        tk.Button(
            buttons, text="Trust Once", command=lambda: resolve(TrustDecision.TRUST_ONCE), bg=PANEL, fg=TEXT
        ).pack(side="left", padx=4)
        tk.Button(
            buttons, text="Trust and Save", command=lambda: resolve(TrustDecision.TRUST_AND_SAVE), bg=ACCENT, fg=BG
        ).pack(side="left", padx=4)
        tk.Button(buttons, text="Cancel", command=lambda: resolve(TrustDecision.CANCEL), bg=RED, fg=BG).pack(
            side="left", padx=4
        )
        dialog.protocol("WM_DELETE_WINDOW", lambda: resolve(TrustDecision.CANCEL))
        dialog.bind("<Escape>", lambda _e: resolve(TrustDecision.CANCEL))
        dialog.grab_set()
        self.owner.after(30, self._drain)

    def changed_key(self, request, state_request=None):
        if self.changed_factory:
            try:

                def acknowledge_factory():
                    if self.state.resolve(state_request.identifier):
                        self.active = None
                        self.owner.after(30, self._drain)

                self.changed_factory(request, state_request.identifier, acknowledge_factory)
            except Exception:
                self.state.resolve(state_request.identifier)
                self.active = None
                self.owner.after(30, self._drain)
            return
        dialog = tk.Toplevel(self.owner)
        dialog.title("Server identity changed")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        details = (
            f"{request.host_role}: {request.profile_name}\n\nThe stored server identity does not match the identity presented now. "
            "This can mean a reinstall, key rotation, changed DNS/routing, or interception.\n\n"
            f"Host: {request.hostname}:{request.port}\nAlgorithm: {request.key_type}\n"
            f"Saved: {request.saved_fingerprint}\nReceived: {request.received_fingerprint}"
        )
        tk.Label(dialog, text=details, justify="left", bg=BG, fg=TEXT, font=FONT).pack(padx=20, pady=16)

        def copy():
            dialog.clipboard_clear()
            dialog.clipboard_append(details)

        buttons = tk.Frame(dialog, bg=BG)
        buttons.pack(pady=(0, 16))
        tk.Button(buttons, text="Copy Details", command=copy, bg=PANEL, fg=TEXT).pack(side="left", padx=4)

        def close():
            if state_request:
                self.state.resolve(state_request.identifier)
            self.active = None
            dialog.destroy()
            self.owner.after(30, self._drain)

        tk.Button(buttons, text="Close", command=close, bg=RED, fg=BG).pack(side="left", padx=4)
        dialog.protocol("WM_DELETE_WINDOW", close)
        dialog.bind("<Escape>", lambda _e: close())
        dialog.grab_set()


class ConnectionTab(tk.Frame):
    def __init__(
        self,
        parent,
        entry: dict,
        vault_entries: list | None = None,
        *,
        session_controller=None,
        session_id: str | None = None,
        native_terminal_backend=None,
        **kw,
    ):
        super().__init__(parent, bg=BG, **kw)
        self._entry = entry
        self._session_controller = session_controller
        self.session_id = session_id
        self._owns_native_terminal_backend = native_terminal_backend is None
        self._native_terminal_backend = native_terminal_backend or VTETerminalBackend(detect_vte_backend())
        self._vte_availability = self._native_terminal_backend.availability
        self._native_terminal_ids: set[str] = set()
        # Capability detection is cheap and display-free.  The persistent GTK
        # helper starts only for the first explicit native terminal request.
        self._native_vte_ready = False
        self._vault_entries = vault_entries or []
        self._client: "paramiko.SSHClient | None" = None
        self._sftp = None
        self._recording = False
        self._terminals: list[TerminalWidget] = []
        self._sftp_panel = None
        self._ftp_bridge_panel = None
        self._tunnels_panel = None
        self._local_forwarding_service = None
        self._remote_forwarding_service = None
        self._dynamic_forwarding_service = None
        self._http_forwarding_service = None
        self._x11_forwarding_service = None
        self._agent_forwarding_handlers = []
        self._exec_panel = None
        self._info_panel = None
        self._key_passphrase = None  # Deliberately never saved in the vault.
        self._proxy_context: ProxyConnectionContext | None = None
        self._workspace_state = WorkspaceChromeState()
        self._dashboard_state = SessionDashboardState(
            profile_name=str(entry.get("name", "")),
            host=str(entry.get("host", "")),
            port=int(entry.get("port", 22)),
            username=str(entry.get("user", "")),
            auth_method=str(entry.get("auth_method", "")),
        )
        self._session_generation = 0
        reconnect_options = dict(entry.get("connection_options", {}))
        for key in (
            "automatic_reconnect",
            "reconnect_delay",
            "maximum_reconnect_delay",
            "maximum_attempts",
            "exponential_backoff",
        ):
            if key in entry:
                reconnect_options[key] = entry[key]
        self._reconnect_controller = ReconnectController(
            reconnect_options, self._schedule_reconnect, self._reconnect_attempt
        )
        self._startup_actions = StartupActionCoordinator()
        self._sftp_opening = False
        self._sftp_open_thread = None
        self._trust_broker = TrustDecisionBroker(self)
        self._build()

    def start_connection(self) -> None:
        """Explicit network entry point; construction is intentionally passive."""
        self._connect()

    def _session_transition(self, state, message: str = "") -> None:
        if self._session_controller is None or self.session_id is None:
            return
        try:
            self._session_controller.transition(self.session_id, state, message)
        except (KeyError, ValueError):
            log(f"Session lifecycle transition rejected: {message}")

    def _schedule_reconnect(self, delay, callback):
        generation = self._session_generation
        try:
            self.after(int(delay * 1000), lambda: callback() if generation == self._session_generation else None)
        except (RuntimeError, tk.TclError):
            pass

    def _reconnect_attempt(self):
        if self._workspace_state.status in {"connected", "connecting"}:
            return False
        self._disconnect(manual=False)
        self._connect(reconnecting=True)
        return True

    def _on_connection_lost(self, generation):
        if generation != self._session_generation or self._workspace_state.status != "connected":
            return
        self._set_workspace_status("failed", "Connection lost; reconnect scheduled.")
        self._reconnect_controller.unexpected_loss(generation)

    def _cancel_reconnect(self):
        self._reconnect_controller.cancel()

    def _reconnect_now(self):
        # An explicit user reconnect starts a fresh generation even after a
        # prior manual logout cancelled automatic reconnect scheduling.
        self._reconnect_controller.new_session()
        self._reconnect_controller.reconnect_now()

    def _select_or_create(self, attr, factory, text):
        panel = getattr(self, attr)
        if panel is not None and str(panel) in self._nb.tabs():
            self._nb.select(panel)
            return panel
        panel = factory()
        setattr(self, attr, panel)
        self._nb.add(panel, text=text)
        self._nb.select(panel)
        return panel

    def _build(self):
        toolbar = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground="#3b4261")
        toolbar.pack(fill="x", padx=4, pady=(4, 0))
        identity = tk.Frame(toolbar, bg=PANEL)
        identity.pack(side="left", fill="x", expand=True, padx=12, pady=8)
        tk.Label(
            identity,
            text=self._entry.get("name", self._entry.get("host", "Connection")),
            bg=PANEL,
            fg=TEXT,
            font=("TkDefaultFont", 11, "bold"),
        ).pack(anchor="w")
        host_label = f"{self._entry.get('user', '?')}@{self._entry.get('host', '')}"
        if self._entry.get("port", 22) != 22:
            host_label += f":{self._entry.get('port')}"
        tk.Label(identity, text=host_label, bg=PANEL, fg=MUTED, font=FONT).pack(anchor="w")
        initial_backend_status = (
            "Native VTE available — starts on first terminal"
            if self._vte_availability.available
            else self._native_terminal_backend.status
        )
        self._terminal_backend_status = tk.StringVar(value=initial_backend_status)
        self._terminal_backend_label = tk.Label(
            identity,
            textvariable=self._terminal_backend_status,
            bg=PANEL,
            fg=GREEN if self._vte_availability.available else YELLOW,
            font=FONT,
        )
        self._terminal_backend_label.pack(anchor="w")

        connection = tk.Frame(toolbar, bg=PANEL)
        connection.pack(side="right", padx=12, pady=8)
        self._status_dot = tk.Label(connection, text="●", bg=PANEL, fg=MUTED, font=("TkDefaultFont", 11))
        self._status_dot.pack(side="left", padx=(0, 4))
        self._workspace_status = tk.StringVar(value=self._workspace_state.message)
        tk.Label(connection, textvariable=self._workspace_status, bg=PANEL, fg=MUTED, font=FONT).pack(
            side="left", padx=(0, 8)
        )
        self._connect_progress = ttk.Progressbar(connection, mode="indeterminate", length=76)
        self._connect_button = ttk.Button(connection, command=self._toggle_connection)
        self._connect_button.pack(side="right")

        tools = tk.Frame(self, bg=BG)
        tools.pack(fill="x", padx=8, pady=(8, 2))
        self._tool_buttons = []
        for text, cmd in (
            ("New terminal", self._open_terminal),
            ("SFTP", self._open_sftp),
            ("Tunnels", self._open_tunnels),
            ("Run command", self._open_exec),
            ("Connection info", self._open_info),
            ("Connection log", self._show_connection_log),
            ("Close view", self._close_current_tab),
        ):
            button = ttk.Button(tools, text=text, command=cmd)
            button.pack(side="left", padx=(0, 6))
            self._tool_buttons.append(button)
            if text == "SFTP":
                self._sftp_open_button = button
        self._rec_btn = ttk.Button(tools, text="Record", command=self._toggle_record)
        self._rec_btn.pack(side="right")

        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=4, pady=4)
        self._terminal = self._create_terminal_tab(select=False)
        self._terminal.on_connection_lost = self._on_connection_lost
        self._terminal.on_resize = lambda cols, rows: (
            self._terminal_size_var.set(f"{cols} × {rows}") if hasattr(self, "_terminal_size_var") else None
        )
        self._last_workspace_tab = self._terminal
        self._nb.bind("<<NotebookTabChanged>>", self._remember_workspace_tab)
        self._nb.select(self._terminal)
        terminal_toolbar = tk.Frame(self, bg=PANEL)
        terminal_toolbar.pack(fill="x", padx=4, pady=(2, 0), before=self._nb)
        self._terminal_size_var = tk.StringVar(value=f"{self._terminal._cols} × {self._terminal._rows}")
        tk.Label(terminal_toolbar, text="Terminal", bg=PANEL, fg=TEXT, font=FONT_B).pack(side="left", padx=8, pady=4)
        tk.Label(terminal_toolbar, textvariable=self._terminal_size_var, bg=PANEL, fg=MUTED, font=FONT).pack(
            side="left", padx=4
        )
        for label, command in (
            ("Clear", self._clear_terminal),
            ("Copy", self._terminal._copy_selection),
            ("Paste", lambda: self._terminal._on_paste(None)),
            ("Find", self._find_terminal),
            ("Jump to Bottom", self._terminal.jump_to_bottom),
            ("Reconnect", self._connect),
            ("Disconnect", self._disconnect),
        ):
            ttk.Button(terminal_toolbar, text=label, command=command).pack(side="right", padx=3, pady=3)
        ttk.Button(terminal_toolbar, text="Reconnect now", command=self._reconnect_now).pack(
            side="right", padx=3, pady=3
        )
        ttk.Button(terminal_toolbar, text="Cancel reconnect", command=self._cancel_reconnect).pack(
            side="right", padx=3, pady=3
        )
        self._apply_workspace_state()

    def _show_connection_log(self):
        dialog = tk.Toplevel(self)
        dialog.title("Connection log")
        dialog.configure(bg=BG)
        dialog.transient(self)
        text = scrolledtext.ScrolledText(dialog, width=78, height=18, bg="#0d0d1a", fg=TEXT, font=MONO)
        text.pack(fill="both", expand=True, padx=10, pady=10)
        for event in self._dashboard_state.events:
            text.insert("end", f"[{event.level}] {event.message}\n")
        text.configure(state="disabled")
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 10))

    def _clear_terminal(self):
        if messagebox.askyesno("Clear terminal", "Clear visible terminal output and retained scrollback?"):
            self._terminal.clear()

    def _find_terminal(self):
        query = simpledialog_ask("Find in terminal", "Search text:")
        if query is not None:
            current, total = self._terminal.find(query)
            self._workspace_status.set(f"Find: {current} of {total} matches" if total else "Find: no matches")

    def _remember_workspace_tab(self, _event=None):
        try:
            selected = self._nb.nametowidget(self._nb.select())
        except tk.TclError:
            return
        if self._workspace_state.status == "connected" and str(selected) in self._nb.tabs():
            self._last_workspace_tab = selected

    def _toggle_connection(self):
        if self._workspace_state.status in {"connecting", "disconnecting"}:
            return
        if self._workspace_state.status == "connected":
            self._disconnect()
        else:
            self._connect()

    def _set_workspace_status(self, status: str, message: str = ""):
        self._workspace_state.transition(status, message)
        self._dashboard_state.transition(status, message or status)
        self._apply_workspace_state()

    def _apply_workspace_state(self):
        state = self._workspace_state
        colors = {
            "disconnected": MUTED,
            "connecting": YELLOW,
            "connected": GREEN,
            "disconnecting": YELLOW,
            "failed": RED,
        }
        self._status_dot.configure(fg=colors[state.status])
        self._workspace_status.set(str(state.message))
        label, enabled = state.connect_button
        self._connect_button.configure(text=label, state="normal" if enabled else "disabled")
        for button in self._tool_buttons:
            button.configure(state="normal" if state.connection_tools_enabled else "disabled")
        if self._sftp_opening:
            self._sftp_open_button.configure(state="disabled")
        self._rec_btn.configure(state="normal" if state.connection_tools_enabled else "disabled")
        for tab_id in self._nb.tabs():
            tab = self._nb.nametowidget(tab_id)
            tab_state = "normal" if state.connection_tools_enabled or tab is self._terminal else "disabled"
            self._nb.tab(tab, state=tab_state)
        if not state.connection_tools_enabled:
            try:
                current = self._nb.nametowidget(self._nb.select())
                if current is not self._terminal:
                    self._last_workspace_tab = current
                    self._nb.select(self._terminal)
            except tk.TclError:
                pass
        elif self._last_workspace_tab is not None and str(self._last_workspace_tab) in self._nb.tabs():
            self._nb.select(self._last_workspace_tab)
        if state.status == "connecting":
            self._connect_progress.pack(side="right", padx=(0, 8))
            self._connect_progress.start(10)
        else:
            self._connect_progress.stop()
            self._connect_progress.pack_forget()

    def _create_terminal_tab(self, select=True):
        terminal = TerminalWidget(self._nb)
        self._terminals.append(terminal)
        label = "Terminal" if len(self._terminals) == 1 else f"Terminal {len(self._terminals)}"
        self._nb.add(terminal, text=label)
        if select:
            self._nb.select(terminal)
        return terminal

    def _connect(self, reconnecting: bool = False):
        if self._workspace_state.status in {"connecting", "disconnecting", "connected"}:
            return
        if self._session_controller is not None and self.session_id is not None:
            if reconnecting:
                record = self._session_controller.get(self.session_id)
                if record is None:
                    return
                if record.state in {SessionLifecycleState.CONNECTED, SessionLifecycleState.FAILED}:
                    if not self._session_controller.reconnect(self.session_id):
                        return
                elif not self._session_controller.begin_connection(self.session_id):
                    return
            elif not self._session_controller.begin_connection(self.session_id):
                return
            self._session_transition(SessionLifecycleState.RESOLVING, "Resolving host.")
            self._session_transition(
                SessionLifecycleState.CONNECTING_PROXY
                if self._entry.get("proxy_jump")
                else SessionLifecycleState.CONNECTING_HOST,
                "Connecting to proxy." if self._entry.get("proxy_jump") else "Connecting to host.",
            )
            if self._entry.get("proxy_jump"):
                self._session_transition(SessionLifecycleState.CONNECTING_HOST, "Connecting to destination host.")
            self._session_transition(SessionLifecycleState.VERIFYING_HOST_KEY, "Verifying host key.")
            self._session_transition(SessionLifecycleState.AUTHENTICATING, "Authenticating session.")
        if not paramiko:
            self._set_workspace_status("failed", "SSH support is unavailable in this installation.")
            self._terminal.write("[error] paramiko not installed\n", "err")
            return
        self._session_generation += 1
        generation = self._session_generation
        self._is_reconnect_attempt = reconnecting
        self._reconnect_controller.new_session()
        self._set_workspace_status("connecting", "Reconnecting…" if reconnecting else "Connecting…")
        self._terminal.write(
            f"[connecting] {self._entry.get('user')}@{self._entry.get('host')}:{self._entry.get('port', 22)}\n", "info"
        )
        key_path = self._entry.get("key_path", "").strip()
        if key_path:
            self._key_passphrase = simpledialog_ask(
                "SSH key passphrase",
                f"Passphrase for {Path(key_path).name} (leave blank if unencrypted):",
                secret=True,
            )
            if self._key_passphrase is None:
                self._terminal.write("[cancelled] key authentication cancelled\n", "info")
                self._set_workspace_status("disconnected")
                return
        threading.Thread(target=self._do_connect, args=(generation,), daemon=True).start()

    def _do_connect(self, generation):
        def dispatch(callback):
            try:
                self.after(0, lambda: callback() if generation == self._session_generation else None)
            except (RuntimeError, tk.TclError):
                pass

        try:
            session_snapshot = self._session_profile_snapshot()
            secure_profile = dict(session_snapshot)
            secure_profile["auth_method"] = (
                "key" if session_snapshot.get("key_path") else "password" if self._entry.get("password") else "agent"
            )
            secure_profile.setdefault("timeout", 15)
            secure_profile.setdefault("compression", False)
            secure_profile["host_role"] = "Destination host"
            extra = {}
            # ProxyJump
            proxy_alias = session_snapshot.get("proxy_jump", "").strip()
            if proxy_alias:
                extra["sock"] = self._make_proxy_sock(
                    proxy_alias,
                    session_snapshot["host"],
                    int(session_snapshot.get("port", 22)),
                    generation,
                )
            manager = SSHConnectionManager(
                KnownHostsStore(KNOWN_HOSTS_FILE), secure_profile["host"], secure_profile["port"]
            )
            client = manager.connect(
                secure_profile,
                self._trust_broker.request,
                self._entry.get("password") or None,
                extra,
                self._report_agent_authentication,
            )
            if generation != self._session_generation:
                client.close()
                if self._proxy_context:
                    self._proxy_context.close()
                    self._proxy_context = None
                return
            if self._proxy_context:
                self._proxy_context.destination_client = client
            self._client = client
            dispatch(lambda: self._on_connected(generation))
            log(f"Connected: {self._entry.get('user')}@{self._entry.get('host')}")
        except UnknownHostCancelled:
            if self._proxy_context:
                self._proxy_context.close()
                self._proxy_context = None
            dispatch(
                lambda: (
                    self._terminal.write("[cancelled] server identity was not trusted\n", "info"),
                    self._set_workspace_status(
                        "disconnected", "Connection cancelled: server identity was not trusted."
                    ),
                )
            )
        except ChangedHostKeyRejected:
            if self._proxy_context:
                self._proxy_context.close()
                self._proxy_context = None
            dispatch(
                lambda: self._set_workspace_status("failed", "Connection blocked because the server identity changed.")
            )
        except paramiko.BadHostKeyException as e:
            if self._proxy_context:
                self._proxy_context.close()
                self._proxy_context = None
            request = manager.changed_request(secure_profile, e)
            self._trust_broker.warn_changed_key(request)
            dispatch(
                lambda: self._set_workspace_status("failed", "Connection blocked because the server identity changed.")
            )
        except Exception as e:
            if self._proxy_context:
                self._proxy_context.close()
                self._proxy_context = None
            dispatch(lambda err=e: self._on_error(err))

    def _report_agent_authentication(self, event: AgentAuthenticationDiagnostic) -> None:
        """Publish only the username and public fingerprint for an agent offer."""
        message = event.sanitized_message()
        log(message)
        try:
            self.after(0, lambda: self._terminal.write(f"[auth] {message}\n", "info"))
        except (RuntimeError, tk.TclError):
            pass

    def _make_proxy_sock(self, proxy_alias: str, target_host: str, target_port: int, generation=None):
        self.after(0, lambda: self._terminal.write(f"[proxy] connecting via jump host '{proxy_alias}'…\n", "info"))

        # 1. look up jump host in vault entries by name/host alias
        proxy_entry = None
        for ve in self._vault_entries:
            if ve.get("name", "").lower() == proxy_alias.lower() or ve.get("host", "").lower() == proxy_alias.lower():
                proxy_entry = ve
                break

        # 2. fall back to ~/.ssh/config
        ssh_cfg = paramiko.SSHConfig()
        cfg_path = Path.home() / ".ssh" / "config"
        if cfg_path.exists():
            with open(cfg_path) as f:
                ssh_cfg.parse(f)
        cfg_info = ssh_cfg.lookup(proxy_alias)

        if proxy_entry:
            proxy_host = proxy_entry.get("host", proxy_alias)
            proxy_port = int(proxy_entry.get("port", 22))
            proxy_user = proxy_entry.get("user", "root")
            proxy_key = proxy_entry.get("key_path", "") or None
            proxy_pass = proxy_entry.get("password", "") or None
        else:
            proxy_host = cfg_info.get("hostname", proxy_alias)
            proxy_port = int(cfg_info.get("port", 22))
            proxy_user = cfg_info.get("user", self._entry.get("user", "root"))
            # expand ~ and %d in key paths
            raw_keys: list[str] = list(cfg_info.get("identityfile", []))
            proxy_key = None
            for raw in raw_keys:
                expanded = Path(str(raw).replace("%d", str(Path.home()))).expanduser()
                if expanded.exists():
                    proxy_key = str(expanded)
                    break
            proxy_pass = None

        proxy_profile = {
            "name": proxy_alias,
            "host": proxy_host,
            "port": proxy_port,
            "user": proxy_user,
            "auth_method": "key" if proxy_key else "password" if proxy_pass else "agent",
            "key_path": proxy_key or "",
            "timeout": 15,
            "compression": bool(proxy_entry.get("compression", False)) if proxy_entry else False,
            "connection_options": dict(proxy_entry.get("connection_options", {})) if proxy_entry else {},
            "terminal_options": dict(proxy_entry.get("terminal_options", {})) if proxy_entry else {},
            "host_role": "Jump host",
        }
        manager = SSHConnectionManager(KnownHostsStore(KNOWN_HOSTS_FILE), proxy_host, proxy_port)
        try:
            proxy_client = manager.connect(
                proxy_profile,
                self._trust_broker.request,
                proxy_pass,
                diagnose_agent_key=self._report_agent_authentication,
            )
        except paramiko.BadHostKeyException as exc:
            self._trust_broker.warn_changed_key(manager.changed_request(proxy_profile, exc))
            raise ChangedHostKeyRejected("The jump-host server identity changed.") from exc
        if generation is not None and generation != self._session_generation:
            proxy_client.close()
            raise RuntimeError("Stale SSH session was closed.")
        self.after(
            0,
            lambda: self._terminal.write(
                f"[proxy] jump host connected ({proxy_user}@{proxy_host}), opening channel to {target_host}:{target_port}\n",
                "ok",
            ),
        )
        transport = proxy_client.get_transport()
        chan = transport.open_channel("direct-tcpip", (target_host, target_port), ("127.0.0.1", 0))
        if chan is None:
            proxy_client.close()
            raise RuntimeError(f"Jump host {proxy_host} refused channel to {target_host}:{target_port}")
        self._proxy_context = ProxyConnectionContext(jump_client=proxy_client, proxy_channel=chan)
        return chan

    def _on_connected(self, generation=None):
        if generation is not None and generation != self._session_generation:
            return
        self._set_workspace_status("connected", "Connected securely.")
        self._session_transition(SessionLifecycleState.CONNECTED, "Session established.")
        app = self.winfo_toplevel()
        if hasattr(app, "_refresh_sessions"):
            self.after(0, app._refresh_sessions)
        self._terminal.write("[connected]\n", "ok")
        self._start_enabled_local_forwarding()
        self._start_enabled_remote_forwarding()
        self._start_enabled_dynamic_forwarding()
        self._start_enabled_http_forwarding()
        self._start_x11_forwarding()
        # Post-login actions are sourced from this ConnectionTab's immutable
        # profile snapshot.  They never run merely from selecting or editing
        # a profile, and reconnects deliberately do not replay them.
        if self._is_reconnect_attempt:
            return
        prefs = dict(self._entry.get("launch_preferences", {}))
        prefs["start_enabled_tunnels"] = bool(prefs.get("start_enabled_services", False))
        prefs["startup_command"] = str(self._entry.get("startup_command", prefs.get("startup_command", "")))
        self._startup_actions.handlers = {
            "tunnels": self._start_saved_tunnels,
            "terminal": lambda: self._attach_shell(self._terminal),
            "sftp": self._open_phase_one_sftp_view,
            "command": lambda data: self._run_startup_command(
                str(data.get("startup_command", "")), self._session_generation
            ),
        }
        self._startup_actions.run(prefs, self._session_generation)

    def _open_phase_one_sftp_view(self) -> None:
        """Open one session-owned Phase 1 SFTP shell after CONNECTED only."""
        if self._session_controller is None or not self.session_id:
            return
        record = self._session_controller.get(self.session_id)
        app = self.winfo_toplevel()
        if record is not None and hasattr(app, "_open_sftp_placeholder"):
            app._open_sftp_placeholder(record)

    def _start_saved_tunnels(self):
        self._start_enabled_local_forwarding()
        self._start_enabled_remote_forwarding()
        self._start_enabled_dynamic_forwarding()
        self._start_enabled_http_forwarding()

    def _start_enabled_local_forwarding(self):
        if not self._client or self._session_controller is None or not self.session_id:
            return
        if self._local_forwarding_service is not None and not self._local_forwarding_service.closed:
            self._local_forwarding_service.start_enabled()
            return
        transport = self._client.get_transport()
        if transport is None:
            return
        rules = self._entry.get("tunnel_options", {}).get("rules", [])
        service = LocalForwardingSession(
            self.session_id,
            transport,
            rules,
            starter=lambda running: start_local_forwarding_listener(running, transport),
        )
        service.start_enabled()
        self._local_forwarding_service = service
        for rule_id in service.active_rule_ids():
            self._session_controller.register_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_local_forwarding_services"):
            app._local_forwarding_services[self.session_id] = service
        if hasattr(app, "_refresh_services_tab"):
            self.after(0, app._refresh_services_tab)
        for record in service.records.values():
            if record.status == "Failed":
                log(f"Local forwarding failed: {record.error}")

    def _stop_local_forwarding(self):
        service = self._local_forwarding_service
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        if self._session_controller is not None and self.session_id is not None:
            for rule_id in active_ids:
                self._session_controller.unregister_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_local_forwarding_services") and self.session_id:
            if app._local_forwarding_services.get(self.session_id) is service:
                app._local_forwarding_services.pop(self.session_id, None)
        if hasattr(app, "_refresh_services_tab"):
            try:
                self.after(0, app._refresh_services_tab)
            except (RuntimeError, tk.TclError):
                pass
        self._local_forwarding_service = None

    def _start_enabled_remote_forwarding(self):
        if not self._client or self._session_controller is None or not self.session_id:
            return
        if self._remote_forwarding_service is not None and not self._remote_forwarding_service.closed:
            self._remote_forwarding_service.start_enabled()
            return
        transport = self._client.get_transport()
        if transport is None:
            return
        rules = self._entry.get("tunnel_options", {}).get("rules", [])
        service = RemoteForwardingSession(
            self.session_id,
            transport,
            rules,
            starter=lambda running: start_remote_forwarding_listener(running, transport),
        )
        service.start_enabled()
        self._remote_forwarding_service = service
        for rule_id in service.active_rule_ids():
            self._session_controller.register_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_remote_forwarding_services"):
            app._remote_forwarding_services[self.session_id] = service
        if hasattr(app, "_refresh_services_tab"):
            self.after(0, app._refresh_services_tab)
        for record in service.records.values():
            if record.status == "Failed":
                log(f"Remote forwarding failed: {record.error}")

    def _stop_remote_forwarding(self):
        service = self._remote_forwarding_service
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        if self._session_controller is not None and self.session_id is not None:
            for rule_id in active_ids:
                self._session_controller.unregister_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_remote_forwarding_services") and self.session_id:
            if app._remote_forwarding_services.get(self.session_id) is service:
                app._remote_forwarding_services.pop(self.session_id, None)
        if hasattr(app, "_refresh_services_tab"):
            try:
                self.after(0, app._refresh_services_tab)
            except (RuntimeError, tk.TclError):
                pass
        self._remote_forwarding_service = None

    def _start_enabled_dynamic_forwarding(self):
        if not self._client or self._session_controller is None or not self.session_id:
            return
        if self._dynamic_forwarding_service is not None and not self._dynamic_forwarding_service.closed:
            self._dynamic_forwarding_service.start_enabled()
            return
        transport = self._client.get_transport()
        if transport is None:
            return
        rules = self._entry.get("tunnel_options", {}).get("rules", [])
        service = DynamicForwardingSession(
            self.session_id,
            transport,
            rules,
            starter=lambda running: start_dynamic_forwarding_listener(running, transport),
        )
        service.start_enabled()
        self._dynamic_forwarding_service = service
        for rule_id in service.active_rule_ids():
            self._session_controller.register_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_dynamic_forwarding_services"):
            app._dynamic_forwarding_services[self.session_id] = service
        if hasattr(app, "_refresh_services_tab"):
            self.after(0, app._refresh_services_tab)
        for record in service.records.values():
            if record.status == "Failed":
                log(f"Dynamic forwarding failed: {record.error}")

    def _stop_dynamic_forwarding(self):
        service = self._dynamic_forwarding_service
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        if self._session_controller is not None and self.session_id is not None:
            for rule_id in active_ids:
                self._session_controller.unregister_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_dynamic_forwarding_services") and self.session_id:
            if app._dynamic_forwarding_services.get(self.session_id) is service:
                app._dynamic_forwarding_services.pop(self.session_id, None)
        if hasattr(app, "_refresh_services_tab"):
            try:
                self.after(0, app._refresh_services_tab)
            except (RuntimeError, tk.TclError):
                pass
        self._dynamic_forwarding_service = None

    def _start_enabled_http_forwarding(self):
        if not self._client or self._session_controller is None or not self.session_id:
            return
        if self._http_forwarding_service is not None and not self._http_forwarding_service.closed:
            self._http_forwarding_service.start_enabled()
            return
        transport = self._client.get_transport()
        if transport is None:
            return
        rules = self._session_profile_snapshot().get("tunnel_options", {}).get("rules", [])
        service = HTTPForwardingSession(
            self.session_id,
            transport,
            rules,
            starter=lambda running: start_http_connect_listener(running, transport),
        )
        service.start_enabled()
        self._http_forwarding_service = service
        for rule_id in service.active_rule_ids():
            self._session_controller.register_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_http_forwarding_services"):
            app._http_forwarding_services[self.session_id] = service
        if hasattr(app, "_refresh_services_tab"):
            self.after(0, app._refresh_services_tab)
        for record in service.records.values():
            if record.status == "Failed":
                log(f"HTTP CONNECT proxy failed: {record.error}")

    def _stop_http_forwarding(self):
        service = self._http_forwarding_service
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        if self._session_controller is not None and self.session_id is not None:
            for rule_id in active_ids:
                self._session_controller.unregister_tunnel(self.session_id, rule_id)
        app = self.winfo_toplevel()
        if hasattr(app, "_http_forwarding_services") and self.session_id:
            if app._http_forwarding_services.get(self.session_id) is service:
                app._http_forwarding_services.pop(self.session_id, None)
        if hasattr(app, "_refresh_services_tab"):
            try:
                self.after(0, app._refresh_services_tab)
            except (RuntimeError, tk.TclError):
                pass
        self._http_forwarding_service = None

    def _session_profile_snapshot(self) -> dict:
        if self._session_controller is not None and self.session_id:
            record = self._session_controller.get(self.session_id)
            if record is not None:
                return record.profile_snapshot
        return self._entry

    def _owned_session_profile_snapshot(self) -> dict:
        snapshot = dict(self._session_profile_snapshot())
        snapshot["_session_id"] = self.session_id or ""
        return snapshot

    def _start_x11_forwarding(self) -> None:
        """Capture X11 policy once, after authentication, for this session."""
        if not self.session_id:
            return
        if self._x11_forwarding_service is not None and not self._x11_forwarding_service.closed:
            return
        snapshot = self._session_profile_snapshot()
        self._x11_forwarding_service = X11ForwardingSession(
            self.session_id,
            snapshot.get("terminal_options", {}),
        )
        app = self.winfo_toplevel()
        if hasattr(app, "_x11_forwarding_services"):
            app._x11_forwarding_services[self.session_id] = self._x11_forwarding_service
        if hasattr(app, "_refresh_services_tab"):
            self.after(0, app._refresh_services_tab)

    def _stop_x11_forwarding(self) -> None:
        service = self._x11_forwarding_service
        if service is None:
            return
        service.close()
        app = self.winfo_toplevel()
        if hasattr(app, "_x11_forwarding_services") and self.session_id:
            if app._x11_forwarding_services.get(self.session_id) is service:
                app._x11_forwarding_services.pop(self.session_id, None)
        if hasattr(app, "_refresh_services_tab"):
            try:
                self.after(0, app._refresh_services_tab)
            except (RuntimeError, tk.TclError):
                pass
        self._x11_forwarding_service = None

    def _run_startup_command(self, command, generation):
        if not command.strip() or generation != self._session_generation or not self._client:
            return
        client = self._client

        def worker():
            try:
                _, stdout, _ = client.exec_command(command)
                stdout.channel.recv_exit_status()
            except Exception as exc:
                log(f"Startup command failed: {redact_secrets(str(exc))}")

        threading.Thread(target=worker, daemon=True, name="sshvault-startup-command").start()

    def _attach_shell(self, terminal: TerminalWidget):
        snapshot = self._owned_session_profile_snapshot()
        if self._vte_availability.available and self._native_terminal_backend.open_terminal_tab(snapshot):
            if (
                self._session_controller is not None
                and self.session_id
                and self._native_terminal_backend.last_terminal_id
            ):
                self._session_controller.register_terminal(
                    self.session_id, self._native_terminal_backend.last_terminal_id
                )
            if self._native_terminal_backend.last_terminal_id:
                self._native_terminal_ids.add(self._native_terminal_backend.last_terminal_id)
            self._native_vte_ready = True
            self._terminal_backend_status.set(self._native_terminal_backend.status)
            terminal.write("[Native VTE terminal opened in its own window]\n", "info")
            return
        if not self._client:
            return
        x11 = self._x11_forwarding_service
        runtime = ssh_runtime_preferences(snapshot)
        if (x11 is None or not x11.enabled) and not runtime.agent_forwarding:
            channel = self._client.invoke_shell(
                term="xterm-256color",
                width=terminal._cols,
                height=terminal._rows,
            )
            terminal.attach_channel(channel)
            return
        transport = self._client.get_transport()
        if transport is None:
            terminal.write("[x11] X11 forwarding request failed.\n", "err")
            return
        channel = transport.open_session()
        if x11 is not None and x11.enabled and not x11.request_for_channel(channel):
            terminal.write(f"[x11] {x11.error}\n", "err")
            log(x11.error)
        if runtime.agent_forwarding:
            try:
                handler = request_agent_forwarding(channel, snapshot)
            except ProfileError as exc:
                terminal.write(f"[agent] {exc}\n", "err")
                log(str(exc))
            else:
                if handler is not None:
                    self._agent_forwarding_handlers.append(handler)
        terminal_options = snapshot.get("terminal_options", {})
        terminal_type = str(terminal_options.get("terminal_type", "xterm-256color"))
        channel.get_pty(term=terminal_type, width=terminal._cols, height=terminal._rows)
        channel.invoke_shell()
        terminal.attach_channel(channel)

    def _open_terminal(self):
        # Native sessions are separate GTK windows: terminal bytes never pass
        # through Tk, Paramiko, or the legacy pyte renderer.
        if self._vte_availability.available:
            if self._entry.get("auth_method") == "password":
                messagebox.showinfo(
                    "Native VTE terminal", "OpenSSH will request the password interactively in the terminal."
                )
            if self._native_terminal_backend.open_terminal_tab(self._owned_session_profile_snapshot()):
                if (
                    self._session_controller is not None
                    and self.session_id
                    and self._native_terminal_backend.last_terminal_id
                ):
                    self._session_controller.register_terminal(
                        self.session_id, self._native_terminal_backend.last_terminal_id
                    )
                if self._native_terminal_backend.last_terminal_id:
                    self._native_terminal_ids.add(self._native_terminal_backend.last_terminal_id)
                self._native_vte_ready = True
                self._terminal_backend_status.set(self._native_terminal_backend.status)
                return
            self._native_vte_ready = False
            self._terminal_backend_status.set(self._native_terminal_backend.status)
            self._terminal_backend_label.configure(fg=YELLOW)
            messagebox.showwarning("Native VTE terminal", self._native_terminal_backend.status)
        if not self._client:
            messagebox.showerror("Terminal", "Not connected.")
            return
        terminal = self._create_terminal_tab()
        self._attach_shell(terminal)

    def _close_current_tab(self):
        current = self._nb.nametowidget(self._nb.select())
        if current is self._terminal:
            if len(self._terminals) == 1:
                messagebox.showinfo("Terminal", "Keep at least one terminal tab open.")
                return
            replacement = next((term for term in self._terminals if term is not self._terminal), None)
            if replacement is not None:
                self._terminal = replacement
        if isinstance(current, TerminalWidget):
            current.detach()
            if current in self._terminals:
                self._terminals.remove(current)
        # SFTP and FTP Bridge are created as a pair in _open_sftp and share
        # the same SFTP channel. Closing only one left the other behind as an
        # orphaned, non-functional tab, since nothing ever forgot it.
        paired = None
        if current is self._sftp_panel:
            paired = self._ftp_bridge_panel
            self._sftp_panel = None
            self._ftp_bridge_panel = None
        elif current is self._ftp_bridge_panel:
            paired = self._sftp_panel
            self._sftp_panel = None
            self._ftp_bridge_panel = None
        elif current is self._tunnels_panel:
            self._tunnels_panel = None
        elif current is self._exec_panel:
            self._exec_panel = None
        elif current is self._info_panel:
            self._info_panel = None
        self._nb.forget(current)
        current.destroy()
        if paired is not None and str(paired) in self._nb.tabs():
            self._nb.forget(paired)
            paired.destroy()

    def _on_error(self, err):
        message = friendly_connection_error(err)
        self._session_transition(SessionLifecycleState.FAILED, message)
        self._set_workspace_status("failed", message)
        self._terminal.write(f"[error] {message}\n", "err")
        app = self.winfo_toplevel()
        if hasattr(app, "_refresh_sessions"):
            self.after(0, app._refresh_sessions)
        log(f"Error: {err}")

    def _disconnect(self, manual: bool = True):
        if self._workspace_state.status in {"disconnected", "disconnecting"}:
            return
        if manual:
            self._reconnect_controller.cancel()
        self._set_workspace_status("disconnecting")
        self._session_transition(SessionLifecycleState.DISCONNECTING, "Disconnecting session.")
        self._session_generation += 1
        self._stop_local_forwarding()
        self._stop_remote_forwarding()
        self._stop_dynamic_forwarding()
        self._stop_http_forwarding()
        self._stop_x11_forwarding()
        self._sftp_opening = False
        sftp_thread = self._sftp_open_thread
        if sftp_thread is not None and sftp_thread is not threading.current_thread() and sftp_thread.is_alive():
            sftp_thread.join(timeout=0.25)
        self._sftp_open_thread = None
        self._cleanup_connection_panels()
        for terminal in list(self._terminals):
            terminal.detach()
        for terminal_id in list(self._native_terminal_ids):
            self._native_terminal_backend.close_terminal(terminal_id)
            if self._session_controller is not None and self.session_id:
                self._session_controller.unregister_terminal(self.session_id, terminal_id)
        self._native_terminal_ids.clear()
        if self._owns_native_terminal_backend:
            self._native_terminal_backend.close()
        self._agent_forwarding_handlers.clear()
        # A proxied destination belongs to its context; that context closes
        # destination, channel, and jump client exactly once in order.
        if self._client and not self._proxy_context:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        if self._proxy_context:
            for error in self._proxy_context.close():
                log(f"Proxy cleanup failed: {error}")
            self._proxy_context = None
        self._set_workspace_status("disconnected")
        if self._session_controller is not None and self.session_id is not None:
            try:
                self._session_controller.disconnect(
                    self.session_id, "Manual disconnect" if manual else "Reconnect cleanup"
                )
            except ValueError:
                pass
        self._terminal.write("\n[disconnected]\n", "info")
        app = self.winfo_toplevel()
        if hasattr(app, "_refresh_sessions"):
            self.after(0, app._refresh_sessions)

    def _cleanup_connection_panels(self):
        """Release every session-bound panel; one cleanup error never stops others."""
        panels = (
            ("_sftp_panel", "shutdown"),
            ("_ftp_bridge_panel", "shutdown"),
            ("_exec_panel", "shutdown"),
            ("_tunnels_panel", "_stop_all_tunnels"),
        )
        for attribute, action in panels:
            panel = getattr(self, attribute, None)
            if panel is None:
                continue
            try:
                getattr(panel, action)()
            except Exception as exc:
                log(f"Session cleanup failed: {exc}")
            try:
                if str(panel) in self._nb.tabs():
                    self._nb.forget(panel)
                panel.destroy()
            except Exception as exc:
                log(f"Session panel release failed: {exc}")
            setattr(self, attribute, None)

    def _open_sftp(self):
        if not self._client:
            messagebox.showerror("SFTP", "Not connected.")
            return
        if self._sftp_panel is not None and str(self._sftp_panel) in self._nb.tabs():
            self._nb.select(self._sftp_panel)
            return
        if self._sftp_opening:
            return
        self._sftp_opening = True
        generation, client = self._session_generation, self._client
        self._sftp_open_button.configure(state="disabled")
        self._workspace_status.set("Opening SFTP…")

        def dispatch(callback):
            try:
                self.after(0, callback)
            except (RuntimeError, tk.TclError):
                pass

        def stale() -> bool:
            return (
                generation != self._session_generation
                or client is not self._client
                or self._workspace_state.status != "connected"
            )

        def opened(sftp):
            if stale():
                try:
                    sftp.close()
                except Exception:
                    pass
                if generation == self._session_generation and client is self._client:
                    self._sftp_opening = False
                    self._apply_workspace_state()
                return
            self._sftp_opening = False
            sftp_options = self._entry.get("sftp_options", {})
            verify_completed = bool(
                sftp_options.get(
                    "verify_completed_transfers",
                    sftp_options.get("verify_transfers", self._entry.get("verify_transfers", True)),
                )
            )
            self._sftp_panel = SFTPPanel(
                self._nb,
                sftp,
                self._entry.get("default_download_directory"),
                verify_completed=verify_completed,
                session_id=self.session_id,
                owner_profile=self._session_profile_snapshot(),
            )
            self._nb.add(self._sftp_panel, text="SFTP")
            self._nb.select(self._sftp_panel)
            self._ftp_bridge_panel = FTPBridgePanel(self._nb, sftp)
            self._nb.add(self._ftp_bridge_panel, text="FTP Bridge")
            self._workspace_status.set("Connected securely.")
            self._apply_workspace_state()

        def failed(error):
            if stale():
                if generation == self._session_generation and client is self._client:
                    self._sftp_opening = False
                    self._apply_workspace_state()
                return
            self._sftp_opening = False
            self._workspace_status.set("Could not open SFTP.")
            self._apply_workspace_state()
            log(f"SFTP startup failed: {redact_secrets(str(error))}")
            messagebox.showerror("SFTP", "Could not start SFTP for this connection.")

        def open_worker():
            try:
                sftp = client.open_sftp()
                dispatch(lambda: opened(sftp))
            except Exception as exc:
                dispatch(lambda error=exc: failed(error))

        worker = threading.Thread(target=open_worker, daemon=True, name="sshvault-sftp-open")
        self._sftp_open_thread = worker
        worker.start()

    def _open_tunnels(self):
        if not self._client:
            messagebox.showerror("Tunnels", "Not connected.")
            return
        rules = self._entry.get("tunnel_options", {}).get("rules", [])
        self._select_or_create("_tunnels_panel", lambda: PortForwardPanel(self._nb, self._client, rules), "Tunnels")

    def _open_exec(self):
        if not self._client:
            messagebox.showerror("Exec", "Not connected.")
            return
        self._select_or_create("_exec_panel", lambda: RemoteExecPanel(self._nb, self._client), "Exec")

    def _open_info(self):
        if not self._client:
            messagebox.showerror("Info", "Not connected.")
            return
        self._select_or_create("_info_panel", lambda: ConnectionInfoPanel(self._nb, self._client), "Info")

    def _toggle_record(self):
        if not self._recording:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = self._entry.get("host", "session")
            path = str(RECORDINGS_DIR / f"{host}_{ts}.log")
            self._terminal.start_recording(path)
            self._recording = True
            self._rec_btn.configure(text="Stop rec", bg=YELLOW)
            self._terminal.write(f"[recording -> {path}]\n", "info")
        else:
            self._terminal.stop_recording()
            self._recording = False
            self._rec_btn.configure(text="Record", bg=RED)
            self._terminal.write("[recording stopped]\n", "info")

    def destroy(self):
        self.shutdown()
        super().destroy()

    def shutdown(self):
        """Use the same idempotent cleanup path for manual and app shutdown."""
        self._trust_broker.close()
        self._disconnect()


# ── Entry dialog ──────────────────────────────────────────────────────────────
class EntryDialog(tk.Toplevel):
    """Editor for a saved connection; secrets never become profile fields."""

    _AUTH_LABELS = {"SSH agent": "agent", "Password": "password", "Private key": "key"}
    _AUTH_NAMES = {value: label for label, value in _AUTH_LABELS.items()}

    def __init__(self, parent, entry: dict | None = None):
        super().__init__(parent)
        self.title("Connection Details")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.result: dict | None = None
        self.secret: str | None = None
        self.remove_secret = False
        self._editing = bool(entry)
        self._secret_changed = False
        self._last_auth = "agent"
        self._build(entry or {})
        self.grab_set()
        self.wait_window()

    def _fld(self, label, row, value="", show=""):
        label_widget = tk.Label(self._f, text=label, bg=BG, fg=MUTED, font=FONT)
        label_widget.grid(row=row, column=0, sticky="e", padx=8, pady=3)
        var = tk.StringVar(value=value)
        widget = tk.Entry(
            self._f,
            textvariable=var,
            bg=PANEL,
            fg=TEXT,
            font=FONT,
            insertbackground=TEXT,
            relief="flat",
            show=show,
            width=30,
        )
        widget.grid(row=row, column=1, sticky="ew", padx=8, pady=3)
        error = tk.StringVar()
        error_widget = tk.Label(self._f, textvariable=error, bg=BG, fg=RED, font=("Sans", 8), anchor="w")
        error_widget.grid(row=row, column=2, sticky="w", padx=(0, 8))
        return var, label_widget, widget, error

    def _set_field_visible(self, parts, visible: bool):
        for widget in parts[:3]:
            if visible:
                widget.grid()
            else:
                widget.grid_remove()

    def _entry_auth_method(self, entry: dict) -> str:
        value = str(entry.get("auth_method", "")).lower()
        if value in self._AUTH_NAMES:
            return value
        return "key" if entry.get("key_path") else "agent"

    def _build(self, e):
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self._f = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(self._f, text="Login")
        terminal_tab = tk.Frame(self._notebook, bg=BG)
        sftp_tab = tk.Frame(self._notebook, bg=BG)
        tunnels_tab = tk.Frame(self._notebook, bg=BG)
        options_tab = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(terminal_tab, text="Terminal")
        self._notebook.add(sftp_tab, text="SFTP")
        self._notebook.add(tunnels_tab, text="Tunnels")
        self._notebook.add(options_tab, text="Options")
        self._f.columnconfigure(1, weight=1)
        self._name, *_name_parts = self._fld("Name", 0, e.get("name", ""))
        self._host, *_host_parts = self._fld("Host", 1, e.get("host", ""))
        self._port, *_port_parts = self._fld("Port", 2, str(e.get("port", "22")))
        self._user, *_user_parts = self._fld("User", 3, e.get("user", "root"))
        self._field_errors = {
            "name": _name_parts[-1],
            "host": _host_parts[-1],
            "port": _port_parts[-1],
            "user": _user_parts[-1],
            "auth": tk.StringVar(),
            "key_path": tk.StringVar(),
        }
        auth = self._entry_auth_method(e)
        self._auth = tk.StringVar(value=self._AUTH_NAMES[auth])
        self._last_auth = auth
        self._original_auth = auth
        tk.Label(self._f, text="Authentication", bg=BG, fg=MUTED, font=FONT).grid(
            row=4, column=0, sticky="e", padx=8, pady=3
        )
        self._auth_menu = ttk.Combobox(
            self._f, textvariable=self._auth, values=tuple(self._AUTH_LABELS), state="readonly", width=27
        )
        self._auth_menu.grid(row=4, column=1, sticky="ew", padx=8, pady=3)
        tk.Label(self._f, textvariable=self._field_errors["auth"], bg=BG, fg=RED, font=("Sans", 8)).grid(
            row=4, column=2, sticky="w"
        )
        self._password, *self._password_parts = self._fld("Password", 5, "", show="●")
        self._password_hint = tk.Label(
            self._f,
            text="Stored securely; leave blank to keep it unchanged.",
            bg=BG,
            fg=MUTED,
            font=("Sans", 8),
            anchor="w",
        )
        self._password_hint.grid(row=6, column=1, sticky="w", padx=8)
        self._remove_secret_var = tk.BooleanVar(value=False)
        self._remove_secret = tk.Checkbutton(
            self._f,
            text="Remove stored password",
            variable=self._remove_secret_var,
            bg=BG,
            fg=MUTED,
            activebackground=BG,
            activeforeground=TEXT,
            selectcolor=PANEL,
            font=("Sans", 8),
        )
        self._remove_secret.grid(row=7, column=1, sticky="w", padx=8)
        self._key_path, *self._key_parts = self._fld("Key file", 8, e.get("key_path", ""))
        self._browse_btn = tk.Button(
            self._f, text="Browse…", command=self._browse, bg=PANEL, fg=TEXT, font=FONT, relief="flat"
        )
        self._browse_btn.grid(row=8, column=2, padx=4)
        self._passphrase, *self._passphrase_parts = self._fld("Passphrase", 9, "", show="●")
        self._passphrase_hint = tk.Label(
            self._f, text="Optional; never stored in the profile file.", bg=BG, fg=MUTED, font=("Sans", 8), anchor="w"
        )
        self._passphrase_hint.grid(row=10, column=1, sticky="w", padx=8)
        self._proxy, *_ = self._fld("ProxyJump", 11, e.get("proxy_jump", ""))
        self._tags, *_ = self._fld("Tags", 12, ", ".join(e.get("tags", [])))
        self._notes, *_ = self._fld("Notes", 13, e.get("notes", ""))
        terminal = e.get("terminal_options", {})
        sftp = e.get("sftp_options", {})
        connection = e.get("connection_options", {})
        self._terminal_type = tk.StringVar(value=terminal.get("terminal_type", "xterm-256color"))
        self._terminal_scrollback = tk.StringVar(value=str(terminal.get("scrollback", 5000)))
        self._terminal_start = tk.StringVar(value=terminal.get("starting_directory", ""))
        self._terminal_command = tk.StringVar(value=terminal.get("startup_command", ""))
        self._terminal_auto = tk.BooleanVar(value=terminal.get("auto_open", True))
        self._sftp_local = tk.StringVar(value=sftp.get("initial_local_directory", ""))
        self._sftp_remote = tk.StringVar(value=sftp.get("initial_remote_directory", ""))
        self._sftp_collision = tk.StringVar(value=sftp.get("collision_behavior", "ask"))
        self._sftp_timestamps = tk.BooleanVar(value=sftp.get("preserve_timestamps", False))
        self._sftp_verify = tk.BooleanVar(value=sftp.get("verify_transfers", False))
        self._sftp_auto = tk.BooleanVar(value=sftp.get("auto_open", False))
        self._reconnect = tk.BooleanVar(value=connection.get("automatic_reconnect", False))
        self._reconnect_delay = tk.StringVar(value=str(connection.get("reconnect_delay", 5)))
        self._reconnect_max = tk.StringVar(value=str(connection.get("maximum_reconnect_delay", 60)))
        self._reconnect_attempts = tk.StringVar(value=str(connection.get("maximum_attempts", 3)))
        self._backoff = tk.BooleanVar(value=connection.get("exponential_backoff", True))
        self._reopen_terminal = tk.BooleanVar(value=connection.get("reopen_terminal", True))
        self._reopen_sftp = tk.BooleanVar(value=connection.get("reopen_sftp", False))
        self._restart_tunnels = tk.BooleanVar(value=connection.get("restart_tunnels", False))
        self._logging_level = tk.StringVar(value=connection.get("logging_level", "normal"))
        self._build_profile_sections(terminal_tab, sftp_tab, tunnels_tab, options_tab, e)
        self._error = tk.StringVar()
        tk.Label(self, textvariable=self._error, bg=BG, fg=RED, font=FONT, anchor="w").pack(fill="x", padx=16)

        bf = tk.Frame(self, bg=BG)
        bf.pack(pady=8)
        self._save_btn = tk.Button(
            bf, text="Save", command=self._save, bg=ACCENT, fg=BG, font=FONT, relief="flat", padx=12
        )
        self._save_btn.pack(side="left", padx=4)
        tk.Button(bf, text="Cancel", command=self.destroy, bg=PANEL, fg=TEXT, font=FONT, relief="flat", padx=12).pack(
            side="left", padx=4
        )
        self._auth.trace_add("write", self._on_auth_changed)
        for variable in (self._name, self._host, self._port, self._user, self._key_path, self._tags):
            variable.trace_add("write", lambda *_: self._validate())
        self._password.trace_add("write", self._on_secret_changed)
        self._remove_secret_var.trace_add("write", lambda *_: self._validate())
        self._sync_auth_fields()
        self._validate()

    def _build_profile_sections(self, terminal, sftp, tunnels, options, entry):
        self._env_rows = list(entry.get("terminal_options", {}).get("environment", {}).items())
        self._env_tree = ttk.Treeview(terminal, columns=("name", "value"), show="headings", height=5)
        self._env_tree.heading("name", text="Name")
        self._env_tree.heading("value", text="Value")
        self._env_tree.grid(row=5, column=0, columnspan=2, padx=8, pady=6)
        for name, value in self._env_rows:
            self._env_tree.insert("", "end", values=(name, value))
        env_actions = tk.Frame(terminal, bg=BG)
        env_actions.grid(row=6, column=0, columnspan=2, sticky="w", padx=8)
        for label, command in (
            ("Add", self._env_add),
            ("Edit", self._env_edit),
            ("Remove", self._env_remove),
            ("Move Up", lambda: self._env_move(-1)),
            ("Move Down", lambda: self._env_move(1)),
        ):
            ttk.Button(env_actions, text=label, command=command).pack(side="left", padx=2)
        for row, (label, var) in enumerate(
            (
                ("Terminal type", self._terminal_type),
                ("Scrollback", self._terminal_scrollback),
                ("Starting directory", self._terminal_start),
                ("Startup command", self._terminal_command),
            )
        ):
            tk.Label(terminal, text=label, bg=BG, fg=TEXT, font=FONT).grid(
                row=row, column=0, sticky="w", padx=8, pady=4
            )
            tk.Entry(terminal, textvariable=var, bg=PANEL, fg=TEXT, insertbackground=TEXT, font=FONT, width=34).grid(
                row=row, column=1, sticky="ew", padx=8, pady=4
            )
        tk.Checkbutton(
            terminal,
            text="Open terminal automatically",
            variable=self._terminal_auto,
            bg=BG,
            fg=TEXT,
            selectcolor=PANEL,
        ).grid(row=4, column=0, columnspan=2, sticky="w", padx=8)
        for row, (label, var) in enumerate(
            (("Initial local directory", self._sftp_local), ("Initial remote directory", self._sftp_remote))
        ):
            tk.Label(sftp, text=label, bg=BG, fg=TEXT, font=FONT).grid(row=row, column=0, sticky="w", padx=8, pady=4)
            tk.Entry(sftp, textvariable=var, bg=PANEL, fg=TEXT, insertbackground=TEXT, font=FONT, width=34).grid(
                row=row, column=1, sticky="ew", padx=8, pady=4
            )
        tk.Label(sftp, text="Collision behavior", bg=BG, fg=TEXT, font=FONT).grid(row=2, column=0, sticky="w", padx=8)
        ttk.Combobox(
            sftp, textvariable=self._sftp_collision, values=("ask", "skip", "overwrite", "rename"), state="readonly"
        ).grid(row=2, column=1, sticky="w", padx=8)
        for row, (label, var) in enumerate(
            (
                ("Preserve timestamps", self._sftp_timestamps),
                ("Verify transfers", self._sftp_verify),
                ("Open SFTP automatically", self._sftp_auto),
            ),
            start=3,
        ):
            tk.Checkbutton(sftp, text=label, variable=var, bg=BG, fg=TEXT, selectcolor=PANEL).grid(
                row=row, column=0, columnspan=2, sticky="w", padx=8
            )
        self._tunnel_rules = [dict(rule) for rule in entry.get("tunnel_options", {}).get("rules", [])]
        self._tunnel_tree = ttk.Treeview(
            tunnels, columns=("enabled", "type", "bind", "destination", "description"), show="headings", height=7
        )
        for col in ("enabled", "type", "bind", "destination", "description"):
            self._tunnel_tree.heading(col, text=col.title())
        self._tunnel_tree.pack(fill="both", expand=True, padx=8, pady=8)
        for rule in self._tunnel_rules:
            destination = (
                ""
                if rule.get("type") == "SOCKS"
                else f"{rule.get('destination_host', '')}:{rule.get('destination_port', '')}"
            )
            self._tunnel_tree.insert(
                "",
                "end",
                values=(
                    rule.get("enabled", True),
                    rule.get("type", "Local"),
                    f"{rule.get('bind_address', '127.0.0.1')}:{rule.get('bind_port', 0)}",
                    destination,
                    rule.get("description", ""),
                ),
            )
        tunnel_actions = tk.Frame(tunnels, bg=BG)
        tunnel_actions.pack(anchor="w", padx=8)
        for label, command in (
            ("Add", self._tunnel_add),
            ("Edit", self._tunnel_edit),
            ("Duplicate", self._tunnel_duplicate),
            ("Remove", self._tunnel_remove),
            ("Enable/Disable", self._tunnel_toggle),
            ("Move Up", lambda: self._tunnel_move(-1)),
            ("Move Down", lambda: self._tunnel_move(1)),
        ):
            ttk.Button(tunnel_actions, text=label, command=command).pack(side="left", padx=2)
        for row, (label, var) in enumerate(
            (
                ("Automatic reconnect", self._reconnect),
                ("Initial delay", self._reconnect_delay),
                ("Maximum delay", self._reconnect_max),
                ("Maximum attempts", self._reconnect_attempts),
            )
        ):
            tk.Label(options, text=label, bg=BG, fg=TEXT, font=FONT).grid(row=row, column=0, sticky="w", padx=8, pady=4)
            (tk.Checkbutton if isinstance(var, tk.BooleanVar) else tk.Entry)(
                options,
                textvariable=var,
                bg=BG if isinstance(var, tk.BooleanVar) else PANEL,
                fg=TEXT,
                selectcolor=PANEL if isinstance(var, tk.BooleanVar) else None,
            ).grid(row=row, column=1, sticky="w", padx=8, pady=4)
        tk.Checkbutton(
            options, text="Exponential backoff", variable=self._backoff, bg=BG, fg=TEXT, selectcolor=PANEL
        ).grid(row=4, column=0, columnspan=2, sticky="w", padx=8)
        ttk.Combobox(
            options, textvariable=self._logging_level, values=("errors", "normal", "detailed"), state="readonly"
        ).grid(row=5, column=1, sticky="w", padx=8)

    def _env_add(self):
        name = simpledialog_ask("Environment variable", "Name:")
        value = simpledialog_ask("Environment variable", "Value:") if name is not None else None
        if name is not None and value is not None:
            self._env_rows.append((name, value))
            self._env_tree.insert("", "end", values=(name, value))

    def _env_edit(self):
        selected = self._env_tree.selection()
        if selected:
            index = self._env_tree.index(selected[0])
            name = simpledialog_ask("Environment variable", "Name:", initialvalue=self._env_rows[index][0])
            value = (
                simpledialog_ask("Environment variable", "Value:", initialvalue=self._env_rows[index][1])
                if name is not None
                else None
            )
            if name is not None and value is not None:
                self._env_rows[index] = (name, value)
                self._env_tree.item(selected[0], values=(name, value))

    def _env_remove(self):
        selected = self._env_tree.selection()
        if selected:
            self._env_rows.pop(self._env_tree.index(selected[0]))
            self._env_tree.delete(selected[0])

    def _env_move(self, delta):
        selected = self._env_tree.selection()
        if not selected:
            return
        index = self._env_tree.index(selected[0])
        target = index + delta
        if 0 <= target < len(self._env_rows):
            self._env_rows[index], self._env_rows[target] = self._env_rows[target], self._env_rows[index]
            self._env_tree.move(selected[0], "", target)

    def _tunnel_add(self):
        self._tunnel_rules.append(
            {
                "rule_id": str(uuid4()),
                "enabled": True,
                "type": "Local",
                "bind_address": "127.0.0.1",
                "bind_port": 0,
                "destination_host": "",
                "destination_port": 0,
                "description": "",
            }
        )
        self._tunnel_refresh()

    def _tunnel_refresh(self):
        for item in self._tunnel_tree.get_children():
            self._tunnel_tree.delete(item)
        for rule in self._tunnel_rules:
            destination = (
                ""
                if rule.get("type") == "SOCKS"
                else f"{rule.get('destination_host', '')}:{rule.get('destination_port', '')}"
            )
            self._tunnel_tree.insert(
                "",
                "end",
                values=(
                    rule.get("enabled", True),
                    rule.get("type", "Local"),
                    f"{rule.get('bind_address', '127.0.0.1')}:{rule.get('bind_port', 0)}",
                    destination,
                    rule.get("description", ""),
                ),
            )

    def _tunnel_edit(self):
        selected = self._tunnel_tree.selection()
        if selected:
            rule = self._tunnel_rules[self._tunnel_tree.index(selected[0])]
            rule["type"] = "SOCKS" if rule.get("type") != "SOCKS" else "Local"
            if rule["type"] == "SOCKS":
                rule["destination_host"], rule["destination_port"] = "", 0
            self._tunnel_refresh()

    def _tunnel_duplicate(self):
        selected = self._tunnel_tree.selection()
        if selected:
            rule = dict(self._tunnel_rules[self._tunnel_tree.index(selected[0])])
            rule["rule_id"] = str(uuid4())
            self._tunnel_rules.append(rule)
            self._tunnel_refresh()

    def _tunnel_remove(self):
        selected = self._tunnel_tree.selection()
        if selected:
            self._tunnel_rules.pop(self._tunnel_tree.index(selected[0]))
            self._tunnel_refresh()

    def _tunnel_toggle(self):
        selected = self._tunnel_tree.selection()
        if selected:
            rule = self._tunnel_rules[self._tunnel_tree.index(selected[0])]
            rule["enabled"] = not rule.get("enabled", True)
            self._tunnel_refresh()

    def _tunnel_move(self, delta):
        selected = self._tunnel_tree.selection()
        if not selected:
            return
        index = self._tunnel_tree.index(selected[0])
        target = index + delta
        if 0 <= target < len(self._tunnel_rules):
            self._tunnel_rules[index], self._tunnel_rules[target] = (
                self._tunnel_rules[target],
                self._tunnel_rules[index],
            )
            self._tunnel_refresh()

    def _browse(self):
        p = filedialog.askopenfilename(title="Select SSH Key", initialdir=str(Path.home() / ".ssh"))
        if p:
            self._key_path.set(p)

    def _auth_method(self) -> str:
        return self._AUTH_LABELS.get(self._auth.get(), "")

    def _on_auth_changed(self, *_args):
        selected = self._auth_method()
        if self._editing and selected != self._last_auth and self._last_auth == "password":
            if not messagebox.askyesno(
                "Change authentication", "Changing authentication can remove the stored password. Continue?"
            ):
                self._auth.set(self._AUTH_NAMES[self._last_auth])
                return
            self._remove_secret_var.set(True)
        self._last_auth = selected
        self._sync_auth_fields()
        self._validate()

    def _on_secret_changed(self, *_args):
        self._secret_changed = bool(self._password.get())
        self._validate()

    def _sync_auth_fields(self):
        method = self._auth_method()
        password_visible = method == "password"
        key_visible = method == "key"
        self._set_field_visible(self._password_parts, password_visible)
        self._password_hint.grid() if password_visible else self._password_hint.grid_remove()
        self._remove_secret.grid() if password_visible and self._editing else self._remove_secret.grid_remove()
        self._set_field_visible(self._key_parts, key_visible)
        self._browse_btn.grid() if key_visible else self._browse_btn.grid_remove()
        self._set_field_visible(self._passphrase_parts, key_visible)
        self._passphrase_hint.grid() if key_visible else self._passphrase_hint.grid_remove()

    def _profile_data(self) -> dict:
        return {
            "name": self._name.get(),
            "host": self._host.get(),
            "port": self._port.get(),
            "user": self._user.get(),
            "auth_method": self._auth_method(),
            "key_path": self._key_path.get(),
            "proxy_jump": self._proxy.get(),
            "tags": self._tags.get(),
            "notes": self._notes.get(),
            "terminal_options": {
                "terminal_type": self._terminal_type.get(),
                "scrollback": self._terminal_scrollback.get(),
                "starting_directory": self._terminal_start.get(),
                "startup_command": self._terminal_command.get(),
                "auto_open": self._terminal_auto.get(),
                "environment": dict(self._env_rows),
            },
            "tunnel_options": {"rules": self._tunnel_rules},
            "sftp_options": {
                "initial_local_directory": self._sftp_local.get(),
                "initial_remote_directory": self._sftp_remote.get(),
                "collision_behavior": self._sftp_collision.get(),
                "preserve_timestamps": self._sftp_timestamps.get(),
                "verify_transfers": self._sftp_verify.get(),
                "auto_open": self._sftp_auto.get(),
            },
            "connection_options": {
                "automatic_reconnect": self._reconnect.get(),
                "reconnect_delay": self._reconnect_delay.get(),
                "maximum_reconnect_delay": self._reconnect_max.get(),
                "maximum_attempts": self._reconnect_attempts.get(),
                "exponential_backoff": self._backoff.get(),
                "reopen_terminal": self._reopen_terminal.get(),
                "reopen_sftp": self._reopen_sftp.get(),
                "restart_tunnels": self._restart_tunnels.get(),
                "logging_level": self._logging_level.get(),
            },
        }

    def _show_validation_error(self, message: str):
        for error in self._field_errors.values():
            error.set("")
        lowered = message.lower()
        field = "host"
        for marker, candidate in (
            ("port", "port"),
            ("username", "user"),
            ("key", "key_path"),
            ("authentication", "auth"),
            ("name", "name"),
            ("hostname", "host"),
        ):
            if marker in lowered:
                field = candidate
                break
        self._field_errors[field].set(message)
        self._error.set("")

    def _validate(self):
        try:
            validate_profile(self._profile_data(), check_key_exists=True)
        except ProfileError as exc:
            self._show_validation_error(str(exc))
            self._save_btn.configure(state="disabled")
            return False
        for error in self._field_errors.values():
            error.set("")
        self._error.set("")
        self._save_btn.configure(state="normal")
        return True

    def _save(self):
        try:
            self.result = validate_profile(self._profile_data())
        except ProfileError as exc:
            self._show_validation_error(str(exc))
            return
        self.secret = self._password.get() if self._auth_method() == "password" and self._secret_changed else None
        self.remove_secret = bool(self._remove_secret_var.get()) or (
            self._editing and self._original_auth == "password" and self._auth_method() != "password"
        )
        self.destroy()


class DiagnosticsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Connection Diagnostics")
        self.geometry("760x600")
        self.transient(parent)
        profile = getattr(parent, "_entry", {})
        session = {
            "state": getattr(getattr(parent, "_workspace_state", None), "status", "disconnected"),
            "generation": getattr(parent, "_session_generation", 0),
            "version": "0.3.4",
        }
        self._diagnostics = DiagnosticsCollector.collect(profile, session)
        self._tree = ttk.Treeview(self, columns=("field", "value"), show="headings")
        self._tree.heading("field", text="Field")
        self._tree.heading("value", text="Value")
        self._tree.column("field", width=250)
        self._tree.column("value", width=470)
        self._tree.pack(fill="both", expand=True, padx=8, pady=8)
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left", padx=3)
        ttk.Button(bar, text="Run Network Check", command=self.network_check).pack(side="left", padx=3)
        ttk.Button(bar, text="Agent Diagnostics", command=self.agent_diagnostics).pack(side="left", padx=3)
        ttk.Button(bar, text="Copy Diagnostics", command=self.copy).pack(side="left", padx=3)
        ttk.Button(bar, text="Save Diagnostics", command=self.save).pack(side="left", padx=3)
        self.refresh()

    def refresh(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for index, record in enumerate(self._diagnostics.records):
            self._tree.insert("", "end", iid=str(index), values=(record.field, record.value))

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self._diagnostics.as_text())

    def save(self):
        destination = filedialog.asksaveasfilename(parent=self, title="Save diagnostics", defaultextension=".txt")
        if destination:
            try:
                atomic_json_write(Path(destination), {"schema_version": 1, "diagnostics": self._diagnostics.as_text()})
            except Exception:
                messagebox.showerror("Diagnostics", "Could not save diagnostics.", parent=self)

    def network_check(self):
        host = str(getattr(self.master, "_entry", {}).get("host", ""))
        port = int(getattr(self.master, "_entry", {}).get("port", 22))

        def worker():
            result = DiagnosticsCollector.network_check(host, port)
            try:
                self.after(0, lambda: self._network_done(result))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True, name="sshvault-network-check").start()

    def agent_diagnostics(self):
        details = agent_environment_diagnostics()
        lines = [
            f"SSH_AUTH_SOCK: {details['ssh_auth_sock'] or 'Unavailable'}",
            f"Visible agent keys: {details['key_count']}",
        ]
        lines.extend(f"{item['type']} {item['fingerprint']}" for item in details["keys"])
        if details["warning"]:
            lines.append(f"Warning: {details['warning']}")
        messagebox.showinfo("SSH Agent Diagnostics", "\n".join(lines), parent=self)

    def _network_done(self, result):
        records = [r for r in self._diagnostics.records if r.field not in {"DNS result", "TCP connection timing"}]
        records.extend(
            [
                type(self._diagnostics.records[0])("DNS result", result["dns"]),
                type(self._diagnostics.records[0])("TCP connection timing", result["tcp"]),
            ]
        )
        self._diagnostics.records = records
        self.refresh()


class HostKeyManagerDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Host Keys")
        self.geometry("980x360")
        self.transient(parent)
        self._repo = HostKeyRepository(KNOWN_HOSTS_FILE, getattr(parent, "_entries", []))
        cols = ("host", "port", "algorithm", "fingerprint", "first", "last", "profiles")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for col, width in zip(cols, (150, 55, 100, 250, 170, 170, 180)):
            self._tree.heading(col, text=col.title(), command=lambda c=col: self._sort(c))
            self._tree.column(col, width=width, anchor="w")
        self._tree.pack(fill="both", expand=True, padx=8, pady=8)
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        for label, command in (
            ("Refresh", self.refresh),
            ("Copy fingerprint", self.copy_fingerprint),
            ("Copy selected row", self.copy_row),
            ("Export", self.export),
            ("Remove", self.remove),
        ):
            ttk.Button(bar, text=label, command=command).pack(side="left", padx=3)
        self.refresh()

    def refresh(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for index, record in enumerate(self._repo.list_records()):
            self._tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    record.hostname,
                    record.port,
                    record.algorithm,
                    record.fingerprint,
                    record.first_trusted,
                    record.last_used,
                    ", ".join(record.associated_profiles),
                ),
            )

    def _record(self):
        selected = self._tree.selection()
        if not selected:
            return None
        records = self._repo.list_records()
        index = int(selected[0])
        return records[index] if index < len(records) else None

    def _sort(self, column):
        rows = [(self._tree.set(iid, column), iid) for iid in self._tree.get_children()]
        for position, (_, iid) in enumerate(sorted(rows, key=lambda row: row[0].casefold())):
            self._tree.move(iid, "", position)

    def copy_fingerprint(self):
        record = self._record()
        if record:
            self.clipboard_clear()
            self.clipboard_append(record.fingerprint)

    def copy_row(self):
        record = self._record()
        if record:
            self.clipboard_clear()
            self.clipboard_append(f"{record.hostname}:{record.port} {record.algorithm} {record.fingerprint}")

    def export(self):
        destination = filedialog.asksaveasfilename(parent=self, title="Export host-key data", defaultextension=".json")
        if destination:
            try:
                self._repo.export(Path(destination))
                messagebox.showinfo("Host Keys", "Host-key data exported.", parent=self)
            except Exception:
                messagebox.showerror("Host Keys", "Could not export host-key data.", parent=self)

    def remove(self):
        record = self._record()
        if record is None:
            return
        count = len(record.associated_profiles)
        message = f"Remove {record.hostname}:{record.port} ({record.algorithm})\n{record.fingerprint}\nAssociated profiles: {count}"
        if messagebox.askyesno("Remove host key", message + "\n\nThis cannot be undone.", parent=self):
            try:
                self._repo.remove(record)
                self.refresh()
            except Exception:
                messagebox.showerror("Host Keys", "Could not remove the selected entry.", parent=self)


class SettingsDialog(tk.Toplevel):
    """Secret-free application preferences with background atomic persistence."""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self._closed = False
        self._generation = 0
        self.title("Settings")
        self.configure(bg=BG)
        self.resizable(False, False)
        values = {
            "scrollback_limit": 5000,
            "connection_timeout": 15,
            "download_directory": str(Path.home()),
            "confirm_multiline_paste": True,
            "confirm_delete": True,
            "confirm_overwrite": True,
            "theme": "system",
            "application_font_size": 10,
            "terminal_font_size": 10,
            "maximum_sftp_transfers": 3,
            "sftp_chunk_size": 1048576,
            "show_transfer_manager_on_start": True,
            "restore_previous_sessions_on_start": False,
        }
        try:
            if SETTINGS_FILE.exists():
                values.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
        self._vars = {
            key: tk.StringVar(value=str(values[key]))
            for key in (
                "scrollback_limit",
                "connection_timeout",
                "download_directory",
                "maximum_sftp_transfers",
                "sftp_chunk_size",
            )
        }
        self._bools = {
            key: tk.BooleanVar(value=bool(values[key]))
            for key in (
                "confirm_multiline_paste",
                "confirm_delete",
                "confirm_overwrite",
                "show_transfer_manager_on_start",
                "restore_previous_sessions_on_start",
            )
        }
        self._appearance = AppearanceState.from_settings(values)
        form = tk.Frame(self, bg=BG)
        form.pack(padx=16, pady=14, fill="both")
        for row, (key, label) in enumerate(
            (
                ("scrollback_limit", "Terminal scrollback lines"),
                ("connection_timeout", "Connection timeout (seconds)"),
                ("download_directory", "Default download directory"),
                ("maximum_sftp_transfers", "Maximum simultaneous SFTP transfers"),
                ("sftp_chunk_size", "SFTP transfer chunk size"),
            )
        ):
            tk.Label(form, text=label, bg=BG, fg=TEXT, font=FONT).grid(row=row, column=0, sticky="w", pady=3)
            if key == "sftp_chunk_size":
                ttk.Combobox(
                    form,
                    textvariable=self._vars[key],
                    values=("64 KiB", "128 KiB", "256 KiB", "512 KiB", "1 MiB", "2 MiB"),
                    state="readonly",
                ).grid(row=row, column=1, sticky="ew", padx=8)
                self._vars[key].set(self._chunk_size_label(values[key]))
            else:
                tk.Entry(form, textvariable=self._vars[key], bg=PANEL, fg=TEXT, insertbackground=TEXT).grid(
                    row=row, column=1, sticky="ew", padx=8
                )
        ttk.Button(form, text="Browse", command=self._browse).grid(row=2, column=2)
        appearance_row = 5
        tk.Label(form, text="Theme", bg=BG, fg=TEXT, font=FONT).grid(row=appearance_row, column=0, sticky="w", pady=3)
        self._theme_var = tk.StringVar(value=self._appearance.theme.title())
        ttk.Combobox(
            form, textvariable=self._theme_var, values=("System", "Light", "Dark"), state="readonly", width=12
        ).grid(row=appearance_row, column=1, sticky="w", padx=8)
        tk.Label(form, text="Application font size", bg=BG, fg=TEXT, font=FONT).grid(
            row=appearance_row + 1, column=0, sticky="w", pady=3
        )
        self._app_font_var = tk.StringVar(value=str(self._appearance.application_font_size))
        tk.Spinbox(form, from_=8, to=24, textvariable=self._app_font_var, width=6).grid(
            row=appearance_row + 1, column=1, sticky="w", padx=8
        )
        tk.Label(form, text="Terminal font size", bg=BG, fg=TEXT, font=FONT).grid(
            row=appearance_row + 2, column=0, sticky="w", pady=3
        )
        self._term_font_var = tk.StringVar(value=str(self._appearance.terminal_font_size))
        tk.Spinbox(form, from_=8, to=32, textvariable=self._term_font_var, width=6).grid(
            row=appearance_row + 2, column=1, sticky="w", padx=8
        )
        for row, (key, label) in enumerate(
            (
                ("confirm_multiline_paste", "Confirm multiline paste"),
                ("confirm_delete", "Confirm delete"),
                ("confirm_overwrite", "Confirm overwrite"),
                ("show_transfer_manager_on_start", "Show Transfer Manager when a transfer starts"),
                ("restore_previous_sessions_on_start", "Restore previous sessions on startup"),
            ),
            start=appearance_row + 3,
        ):
            tk.Checkbutton(form, text=label, variable=self._bools[key], bg=BG, fg=TEXT, selectcolor=PANEL).grid(
                row=row, column=0, columnspan=2, sticky="w"
            )
        info = f"Data: {CONFIG_DIR}\nSettings: {SETTINGS_FILE}\nVault: {VAULT_FILE}\nKnown hosts: {KNOWN_HOSTS_FILE}\nBackups: {BACKUPS_DIR}"
        tk.Label(form, text=info, bg=BG, fg=MUTED, font=("TkDefaultFont", 8), justify="left").grid(
            row=appearance_row + 6, column=0, columnspan=3, sticky="w", pady=(10, 4)
        )
        self._error = tk.StringVar()
        tk.Label(form, textvariable=self._error, bg=BG, fg=RED, font=FONT).grid(
            row=appearance_row + 7, column=0, columnspan=3, sticky="w"
        )
        self._save = ttk.Button(form, text="Save", command=self._save_settings)
        self._save.grid(row=appearance_row + 8, column=1, sticky="e", pady=8)
        ttk.Button(form, text="Reset Appearance", command=self._reset_appearance).grid(
            row=appearance_row + 8, column=0, pady=8
        )
        ttk.Button(form, text="Cancel", command=self.destroy).grid(row=appearance_row + 8, column=2, pady=8)
        form.columnconfigure(1, weight=1)
        for var in self._vars.values():
            var.trace_add("write", lambda *_: self._validate())
        self._theme_var.trace_add("write", lambda *_: self._validate())
        self._app_font_var.trace_add("write", lambda *_: self._validate())
        self._term_font_var.trace_add("write", lambda *_: self._validate())
        self._validate()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.grab_set()

    def _data(self):
        chunk_sizes = {
            "64 KiB": 65536,
            "128 KiB": 131072,
            "256 KiB": 262144,
            "512 KiB": 524288,
            "1 MiB": 1048576,
            "2 MiB": 2097152,
        }
        values = {k: v.get() for k, v in self._vars.items()}
        values["sftp_chunk_size"] = chunk_sizes.get(values["sftp_chunk_size"], values["sftp_chunk_size"])
        return {
            **values,
            **{k: v.get() for k, v in self._bools.items()},
            "theme": self._theme_var.get().casefold(),
            "application_font_size": self._app_font_var.get(),
            "terminal_font_size": self._term_font_var.get(),
        }

    @staticmethod
    def _chunk_size_label(value):
        labels = {
            65536: "64 KiB",
            131072: "128 KiB",
            262144: "256 KiB",
            524288: "512 KiB",
            1048576: "1 MiB",
            2097152: "2 MiB",
        }
        try:
            return labels.get(int(value), "1 MiB")
        except (TypeError, ValueError):
            return "1 MiB"

    def _reset_appearance(self):
        self._theme_var.set("System")
        self._app_font_var.set("10")
        self._term_font_var.set("10")

    def _validate(self):
        try:
            validate_settings(self._data())
            self._error.set("")
            self._save.configure(state="normal")
            return True
        except ProfileError as exc:
            self._error.set(str(exc))
            self._save.configure(state="disabled")
            return False

    def _browse(self):
        path = filedialog.askdirectory(initialdir=self._vars["download_directory"].get() or str(Path.home()))
        if path:
            self._vars["download_directory"].set(path)

    def _save_settings(self):
        if not self._validate():
            return
        data = validate_settings(self._data())
        self._generation += 1
        generation = self._generation
        self._save.configure(state="disabled")
        threading.Thread(target=self._write, args=(data, generation), daemon=True).start()

    def _write(self, data, generation):
        try:
            atomic_json_write(SETTINGS_FILE, data)
            self.after(0, lambda: self._saved(generation, data))
        except OSError as exc:
            self.after(0, lambda e=exc: self._failed(generation, e))

    def _saved(self, generation, data):
        if self._closed or generation != self._generation:
            return
        self.parent._runtime_settings = data
        if hasattr(self.parent, "_apply_appearance"):
            self.parent._apply_appearance(data)
        for tab in self.parent._conn_tabs.values():
            panel = getattr(tab, "_sftp_panel", None)
            if panel is not None:
                panel._transfer_manager.set_concurrency(data["maximum_sftp_transfers"])
            for terminal in tab._terminals:
                terminal._terminal_state.max_scrollback_lines = data["scrollback_limit"]
        self.destroy()

    def _failed(self, generation, error):
        if self._closed or generation != self._generation:
            return
        self._error.set("Could not save settings.")
        self._save.configure(state="normal")
        log(f"Settings save failed: {error}")

    def destroy(self):
        self._closed = True
        self._generation += 1
        super().destroy()


# ── Main app ─────────────────────────────────────────────────────────────────
class SSHVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSHVault")
        self.configure(bg=OPENING_BG)
        self.geometry(f"{CONTROLLER_DEFAULT_GEOMETRY[0]}x{CONTROLLER_DEFAULT_GEOMETRY[1]}")
        self.minsize(*CONTROLLER_MINIMUM_GEOMETRY)
        self._apply_style()
        self._runtime_settings = self._load_settings()
        self._apply_appearance(self._runtime_settings)
        self._vault = Vault()
        # Application scope is capability detection only. Connected sessions
        # each construct and own their own backend/helper below.
        self._native_terminal_backend = VTETerminalBackend(detect_vte_backend())
        self._session_controller = SessionController()
        self.selected_profile_id: str | None = None
        self.loaded_profile_snapshot: dict | None = None
        self.working_profile: dict | None = None
        self.profile_dirty = False
        self.profile_validation_errors: list[str] = []
        # Transitional UI lookup only.  SessionController owns identity/state.
        self._conn_tabs: dict[str, ConnectionTab] = {}
        self._session_serial = 0
        self._sftp_views: dict[str, tk.Toplevel] = {}
        self._sftp_browser_clients = SFTPBrowserRegistry()
        self._sftp_view_state_callbacks = {}
        self._sftp_transfer_schedulers = {}
        self._sftp_transfer_status_callbacks = {}
        self._sftp_transfer_queue_callbacks = {}
        self._sftp_change_queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._local_forwarding_services = {}
        self._remote_forwarding_services = {}
        self._dynamic_forwarding_services = {}
        self._http_forwarding_services = {}
        self._x11_forwarding_services = {}
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_menu()
        self._build_ui()
        self._build_statusbar()
        self._restore_session()
        self.after(100, self._poll_sftp_transfer_changes)
        self.after_idle(self._apply_configured_startup)

    def _load_settings(self):
        try:
            return (
                validate_settings(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
                if SETTINGS_FILE.exists()
                else validate_settings({})
            )
        except (OSError, json.JSONDecodeError, ProfileError):
            return validate_settings({})

    def _save_runtime_settings(self) -> None:
        """Persist application-only choices without ever touching profiles."""
        try:
            self._runtime_settings = validate_settings(self._runtime_settings)
            atomic_json_write(SETTINGS_FILE, self._runtime_settings)
        except (OSError, ProfileError):
            return

    def _apply_configured_startup(self) -> None:
        """Apply explicit startup choices after the passive shell is ready."""
        last_profile_id = str(self._runtime_settings.get("last_selected_profile_id", ""))
        if self._runtime_settings.get("load_last_selected_profile", True) and self._tree.exists(last_profile_id):
            self._tree.selection_set(last_profile_id)
            self._tree.focus(last_profile_id)
            self._on_profile_selection()
        if self._runtime_settings.get("restore_previous_sessions_on_start", False):
            self._restore_previous_sessions(startup=True)
            return
        if self._runtime_settings.get("login_automatically_on_start", False):
            self._connect()

    def _apply_appearance(self, settings):
        appearance = AppearanceState.from_settings(settings)
        self._appearance = appearance
        try:
            tkfont.nametofont("TkDefaultFont").configure(size=appearance.application_font_size)
            tkfont.nametofont("TkTextFont").configure(size=appearance.application_font_size)
            tkfont.nametofont("TkFixedFont").configure(size=appearance.terminal_font_size)
        except tk.TclError:
            pass

    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Profile", command=self._add_entry)
        file_menu.add_command(label="Edit Profile", command=self._edit_entry)
        file_menu.add_command(label="Delete Profile", command=self._delete_entry)
        file_menu.add_separator()
        file_menu.add_command(label="Import from ~/.ssh/config", command=self._import_ssh_config)
        file_menu.add_command(label="Create Profile Backup", command=self._create_profile_backup)
        file_menu.add_command(label="Restore Profile Backup", command=self._restore_profile_backup)
        file_menu.add_command(label="Restore Previous Sessions", command=self._restore_previous_sessions)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Generate Key Pair", command=self._keygen)
        tools_menu.add_command(label="Transfer Manager", command=self._open_transfer_manager)
        tools_menu.add_command(label="Built-in SFTP Server Settings", command=self._sftp_server_settings)
        tools_menu.add_command(label="Activity Log", command=self._open_log)
        tools_menu.add_command(label="Settings", command=self._open_settings)
        tools_menu.add_command(label="Host Keys", command=self._open_host_keys)
        tools_menu.add_command(label="Diagnostics", command=self._open_diagnostics)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)
        self.bind_all("<Control-Shift-T>", lambda _event: self._open_transfer_manager())

    def _open_transfer_manager(self):
        """Open the selected session's manager without disturbing workspace focus."""
        record = self._selected_session_record()
        tab = self._conn_tabs.get(record.session_id) if record else None
        panel = getattr(tab, "_sftp_panel", None)
        if panel is not None:
            panel._show_transfer_manager()
        return "break"

    def _show_about(self):
        messagebox.showinfo(
            "About SSHVault",
            "SSHVault — Bitvise-inspired SSH/SFTP workspace\nProfiles, terminal, SFTP, tunneling, key management.",
        )

    def _build_statusbar(self):
        # The controller strip is the sole visible status location.  Keep
        # these variables for existing non-visual status callbacks.
        self._application_statusbar = None
        self._status_var = tk.StringVar(value="Ready")
        self._profile_count_var = tk.StringVar()
        self._update_statusbar()

    def _update_statusbar(self):
        n_profiles = len(self._vault.entries)
        n_sessions = len(self._conn_tabs)
        self._profile_count_var.set(f"{n_profiles} profile(s)  |  {n_sessions} active session(s)")

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=TEXT, padding=[10, 4], font=FONT)
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", BG)])
        s.configure("Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL, font=FONT, rowheight=24)
        s.configure("Treeview.Heading", background=BG, foreground=MUTED, font=FONT)
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG)])
        # The profile list is intentionally quieter than file-transfer and
        # tunnel tables: it behaves like a compact list of saved destinations.
        s.configure(
            "Profile.Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            borderwidth=0,
            relief="flat",
            font=FONT,
            rowheight=44,
        )
        s.configure(
            "Profile.Treeview.Heading",
            background=PANEL,
            foreground=MUTED,
            borderwidth=0,
            relief="flat",
            font=("Sans", 9, "bold"),
        )
        s.map(
            "Profile.Treeview",
            background=[("selected", "#3b4261"), ("!selected", PANEL)],
            foreground=[("selected", "#ffffff"), ("!selected", TEXT)],
        )
        s.configure("TProgressbar", troughcolor=PANEL, background=ACCENT)
        s.configure("Controller.TFrame", background=BG)
        s.configure("Toolbar.TFrame", background=PANEL)
        s.configure("Compact.TButton", padding=(7, 2))
        s.configure("Primary.TButton", padding=(9, 2))
        s.configure("Rail.TButton", padding=(7, 5), anchor="w")
        s.configure("Opening.TNotebook", background=OPENING_BG, borderwidth=1)
        s.configure(
            "Opening.TNotebook.Tab",
            background="#dedede",
            foreground="#202020",
            padding=(10, 3),
            font=FONT,
        )
        s.map(
            "Opening.TNotebook.Tab",
            background=[("selected", OPENING_PANEL)],
            foreground=[("selected", "#101010")],
        )
        s.configure("Status.TLabel", background=PANEL, foreground=TEXT)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED)
        s.configure("Section.TLabelframe", padding=SECTION_PADDING)
        s.configure("Section.TLabelframe.Label", font=FONT_B)
        s.configure("ConnectionLog.TFrame", background=OPENING_PANEL)

    def _build_ui(self):
        self._tree = _ProfileSelectionModel()
        self._search_var = tk.StringVar()
        self._sort_var = tk.StringVar(value="Name")
        self._profile_selection_note = tk.StringVar()
        self._profile_choice_ids: dict[str, str] = {}
        self._profile_choice = tk.StringVar()
        self._profile_heading = tk.StringVar(value="Profile: New profile")
        self._conn_notebook = _ConnectionViewRegistry()
        self._connection_view_host: tk.Frame | None = None

        heading = tk.Frame(self, bg=OPENING_PANEL, height=34, bd=1, relief="groove")
        self._profile_heading_frame = heading
        heading.pack(fill="x", side="top", padx=5, pady=(5, 0))
        heading.pack_propagate(False)
        tk.Label(
            heading,
            textvariable=self._profile_heading,
            bg=OPENING_PANEL,
            fg="#202020",
            font=("Sans", 11, "bold"),
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=8)

        bottom = tk.Frame(self, bg=OPENING_PANEL, height=42, bd=1, relief="groove")
        self._controller_bottom_bar = bottom
        bottom.pack(side="bottom", fill="x", padx=5, pady=(3, 5))
        bottom.pack_propagate(False)
        self._controller_status = tk.StringVar(value="Disconnected")
        self._connection_action_button = ttk.Button(
            bottom, text="Log in", command=self._toggle_connection_action, style="Primary.TButton"
        )
        self._connection_action_button.pack(side="left", padx=(PROFILE_RAIL_WIDTH + 10, 4), pady=6)
        self._exit_button = ttk.Button(bottom, text="Exit", command=self._on_close, style="Compact.TButton")
        self._exit_button.pack(side="right", padx=8, pady=6)
        self._controller_status_label = tk.Label(
            bottom,
            textvariable=self._controller_status,
            bg=OPENING_PANEL,
            fg="#404040",
            font=FONT,
            anchor="e",
        )
        self._controller_status_label.pack(side="right", padx=8)

        body = tk.Frame(self, bg=OPENING_BG)
        self._opening_body = body
        body.pack(fill="both", expand=True, padx=5, pady=(3, 0))

        rail = tk.Frame(body, bg=OPENING_PANEL, width=PROFILE_RAIL_WIDTH, bd=1, relief="groove")
        self._profile_rail = rail
        rail.pack(side="left", fill="y", padx=(0, 5))
        rail.pack_propagate(False)
        tk.Label(
            rail,
            text="Profile",
            bg=OPENING_PANEL,
            fg="#303030",
            font=FONT_B,
            anchor="w",
        ).pack(fill="x", padx=8, pady=(9, 5))

        rail_commands = {
            "Load profile": ("↥", self._show_load_profile_menu),
            "Save profile as": ("▣", self._save_as_working_profile),
            "New profile": ("＋", self._new_profile_from_rail),
            "Reset profile": ("↶", self._reset_profile_from_rail),
        }
        self._toolbar_buttons = {}
        for label in CONTROLLER_PROFILE_ACTIONS:
            icon, command = rail_commands[label]
            button = ttk.Button(rail, text=f"{icon}  {label}", command=command, style="Rail.TButton")
            button.pack(fill="x", padx=7, pady=3)
            self._toolbar_buttons[label] = button

        right = tk.Frame(body, bg=OPENING_BG)
        self._controller_workspace = right
        right.pack(side="left", fill="both", expand=True)
        self._control_notebook = ttk.Notebook(right, style="Opening.TNotebook")
        self._control_pages = {}
        for name in CONTROLLER_CONFIG_TABS:
            page = tk.Frame(self._control_notebook, bg=OPENING_BG)
            self._control_notebook.add(page, text=name)
            self._control_pages[name] = page
        self._build_login_tab(self._control_pages["Login"])
        self._build_options_tab(self._control_pages["Options"])
        self._build_terminal_tab(self._control_pages["Terminal"])
        self._build_sftp_tab(self._control_pages["SFTP"])
        self._build_services_tab(self._control_pages["Services"])
        self._build_ssh_tab(self._control_pages["SSH"])

        controller_log = ttk.Frame(right, style="ConnectionLog.TFrame")
        self._controller_log_frame = controller_log
        tk.Label(controller_log, text="Connection log", bg=OPENING_PANEL, fg="#202020", font=FONT_B).pack(
            anchor="w", padx=8, pady=(4, 0)
        )
        log_body = tk.Frame(controller_log, bg=OPENING_PANEL)
        log_body.pack(fill="x", padx=8, pady=4)
        self._controller_log = tk.Text(
            log_body,
            height=9,
            bg="#ffffff",
            fg="#202020",
            insertbackground="#202020",
            font=MONO,
            state="disabled",
            relief="sunken",
            bd=1,
        )
        log_scroll = ttk.Scrollbar(log_body, orient="vertical", command=self._controller_log.yview)
        self._controller_log.configure(yscrollcommand=log_scroll.set)
        self._controller_log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        controller_log.pack(side="bottom", fill="x", padx=3, pady=(3, 0))
        self._control_notebook.pack(side="top", fill="both", expand=True, padx=3)

        self._bind_profile_shortcuts()
        self._refresh_list()
        self._refresh_sessions()

    def _refresh_profile_heading(self) -> None:
        profile = self.working_profile or {}
        name = str(profile.get("name") or profile.get("host") or "New profile")
        changed = " (changed)" if self.profile_dirty else ""
        if hasattr(self, "_profile_heading"):
            self._profile_heading.set(f"Profile: {name}{changed}")
        self.title(f"SSHVault — {name}")

    def _select_profile_from_rail(self, profile_id: str) -> bool:
        def select() -> bool:
            if not self._tree.exists(profile_id):
                return False
            self._tree.selection_set(profile_id)
            self._tree.focus(profile_id)
            self._on_profile_selection()
            return True

        return self.resolve_unsaved_profile_changes(select)

    def _show_load_profile_menu(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        items = self._profile_dropdown_items(self._vault.entries)
        if not items:
            menu.add_command(label="No saved profiles", state="disabled")
        for label, profile_id in items:
            menu.add_command(
                label=label,
                command=lambda selected_id=profile_id: self._select_profile_from_rail(selected_id),
            )
        button = self._toolbar_buttons["Load profile"]
        try:
            menu.tk_popup(button.winfo_rootx(), button.winfo_rooty() + button.winfo_height())
        finally:
            menu.grab_release()

    def _reset_profile_from_rail(self) -> bool:
        profile_id = self.selected_profile_id
        if not profile_id:
            self.clear_working_profile()
            self._refresh_profile_heading()
            return True

        def reset() -> bool:
            loaded = self.load_profile_working_copy(profile_id)
            self._refresh_login_tab()
            self._refresh_profile_heading()
            self._refresh_action_states()
            return loaded

        return self.resolve_unsaved_profile_changes(reset)

    def _new_profile_from_rail(self) -> bool:
        def create() -> bool:
            profile = {
                "name": "",
                "host": "",
                "port": 22,
                "user": "",
                "auth_method": "agent",
                "key_path": "",
                "proxy_jump": "",
                "tags": [],
                "notes": "",
            }
            profile.update(default_profile_sections(profile))
            self._tree.selection_set("")
            self.selected_profile_id = None
            self.loaded_profile_snapshot = None
            self.working_profile = profile
            self.profile_dirty = True
            self.profile_validation_errors = []
            self._refresh_login_tab()
            self._refresh_options_tab()
            self._refresh_terminal_tab()
            self._refresh_sftp_tab()
            self._refresh_services_tab()
            self._refresh_ssh_tab()
            self._refresh_profile_heading()
            self._refresh_action_states()
            return True

        return self.resolve_unsaved_profile_changes(create)

    def _toggle_connection_action(self) -> None:
        record = self._selected_session_record()
        if record and record.state not in {
            SessionLifecycleState.DISCONNECTED,
            SessionLifecycleState.FAILED,
            SessionLifecycleState.CANCELLED,
        }:
            self._logout_selected_session()
        else:
            self._connect()

    def _ensure_connection_view_host(self) -> tk.Frame:
        if self._connection_view_host is None or not self._connection_view_host.winfo_exists():
            self._connection_view_host = tk.Frame(self)
        return self._connection_view_host

    def _select_profile_from_dropdown(self, _event=None):
        profile_id = self._profile_choice_ids.get(self._profile_choice.get(), "")
        if self._tree.exists(profile_id):
            self._tree.selection_set(profile_id)
            self._tree.focus(profile_id)
            self._on_profile_selection()

    def _build_login_tab(self, page):
        for child in page.winfo_children():
            child.destroy()
        self._login_vars = {
            key: tk.StringVar()
            for key in (
                "host",
                "port",
                "user",
                "auth_method",
                "key_path",
                "proxy_type",
                "proxy_host",
                "proxy_port",
                "proxy_user",
            )
        }
        groups = []
        for title in ("Server", "Authentication", "Host Key", "Proxy"):
            group = ttk.LabelFrame(page, text=title, padding=6)
            groups.append(group)
        groups[0].grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        groups[3].grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        groups[2].grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        groups[1].grid(row=0, column=1, rowspan=3, sticky="nsew", padx=4, pady=4)
        page.columnconfigure((0, 1), weight=1)
        page.rowconfigure(2, weight=1)
        for row, (label, key) in enumerate((("Host", "host"), ("Port", "port"))):
            ttk.Label(groups[0], text=label).grid(row=row, column=0, sticky="w")
            entry = ttk.Entry(groups[0], textvariable=self._login_vars[key], width=36)
            entry.grid(row=row, column=1, sticky="ew")
            self._login_vars[key].trace_add("write", lambda *_args, name=key: self._login_field_changed(name))
        ttk.Label(groups[1], text="Username").grid(row=0, column=0, sticky="w")
        username = ttk.Entry(groups[1], textvariable=self._login_vars["user"], width=36)
        username.grid(row=0, column=1, sticky="ew")
        self._login_vars["user"].trace_add("write", lambda *_args: self._login_field_changed("user"))
        ttk.Label(groups[1], text="Initial method").grid(row=1, column=0, sticky="w")
        auth = ttk.Combobox(
            groups[1],
            textvariable=self._login_vars["auth_method"],
            state="readonly",
            values=("Automatic", "SSH Agent", "Private Key", "Password", "Keyboard Interactive", "OpenSSH Config"),
        )
        auth.grid(row=1, column=1, sticky="ew")
        self._auth_summary = ttk.Label(groups[1], text="Automatic authentication uses existing safe defaults.")
        self._auth_summary.grid(row=2, column=1, sticky="w")
        self._password_label = ttk.Label(groups[1], text="Passphrase / password")
        self._password_label.grid(row=2, column=0, sticky="w")
        self._password_entry = ttk.Entry(groups[1], show="•")
        self._password_entry.grid(row=2, column=1, sticky="ew")
        self._key_label = ttk.Label(groups[1], text="SSH key / Agent")
        self._key_label.grid(row=3, column=0, sticky="w")
        self._key_entry = ttk.Entry(groups[1], textvariable=self._login_vars["key_path"])
        self._key_entry.grid(row=3, column=1, sticky="ew")
        self._manage_keys_button = ttk.Button(groups[1], text="Manage Keys", command=self._keygen)
        self._manage_keys_button.grid(row=3, column=2)
        for row, label in enumerate(("Host-key policy", "Known-hosts source", "Fingerprint")):
            ttk.Label(groups[2], text=label).grid(row=row, column=0, sticky="w")
            ttk.Label(groups[2], text="Not checked" if label == "Fingerprint" else "System defaults").grid(
                row=row, column=1, sticky="w"
            )
        ttk.Button(groups[2], text="Manage Host Keys", command=self._open_host_keys).grid(row=3, column=1, sticky="w")
        for row, (label, key) in enumerate(
            (
                ("Proxy type", "proxy_type"),
                ("Proxy host", "proxy_host"),
                ("Proxy port", "proxy_port"),
                ("Proxy username", "proxy_user"),
            )
        ):
            ttk.Label(groups[3], text=label).grid(row=row, column=0, sticky="w")
            widget = (
                ttk.Combobox(
                    groups[3], textvariable=self._login_vars[key], values=("None", "SSH ProxyJump"), state="readonly"
                )
                if key == "proxy_type"
                else ttk.Entry(groups[3], textvariable=self._login_vars[key])
            )
            widget.grid(row=row, column=1, sticky="ew")
        self._login_vars["proxy_type"].trace_add("write", lambda *_: self._login_field_changed("proxy_jump"))
        self._login_vars["auth_method"].trace_add("write", lambda *_: self._sync_login_visibility())
        self._proxy_widgets = [groups[3].grid_slaves(row=row, column=1)[0] for row in (1, 2, 3)]
        self._sync_login_visibility()

    def _build_options_tab(self, page):
        """Build the compact, working-copy backed Options tab.

        The checkboxes deliberately only edit configuration state.  Runtime
        actions are consumed from the immutable session snapshot after an SSH
        connection reaches CONNECTED.
        """
        for child in page.winfo_children():
            child.destroy()
        self._profile_option_vars = {
            "open_terminal": tk.BooleanVar(value=False),
            "open_sftp": tk.BooleanVar(value=False),
            "start_enabled_services": tk.BooleanVar(value=False),
            "run_startup_commands": tk.BooleanVar(value=False),
            "close_terminal_windows": tk.BooleanVar(value=False),
            "close_sftp_windows": tk.BooleanVar(value=False),
            "stop_enabled_services": tk.BooleanVar(value=True),
            "ask_before_cancelling_active_transfers": tk.BooleanVar(value=True),
        }
        self._application_option_vars = {
            "load_last_selected_profile": tk.BooleanVar(
                value=bool(self._runtime_settings.get("load_last_selected_profile", True))
            ),
            "login_automatically_on_start": tk.BooleanVar(
                value=bool(self._runtime_settings.get("login_automatically_on_start", False))
            ),
            "restore_previous_sessions_on_start": tk.BooleanVar(
                value=bool(self._runtime_settings.get("restore_previous_sessions_on_start", False))
            ),
            "restore_window_position": tk.BooleanVar(
                value=bool(self._runtime_settings.get("restore_window_position", True))
            ),
        }
        groups = []
        for column, title in enumerate(OPTIONS_GROUPS):
            group = ttk.LabelFrame(page, text=title, padding=6)
            group.grid(row=0, column=column, sticky="nsew", padx=4, pady=4)
            groups.append(group)
            page.columnconfigure(column, weight=1)
        for row, (label, key) in enumerate(
            (
                (POST_LOGIN_OPTION_LABELS[0], "open_terminal"),
                (POST_LOGIN_OPTION_LABELS[1], "open_sftp"),
                (POST_LOGIN_OPTION_LABELS[2], "start_enabled_services"),
                (POST_LOGIN_OPTION_LABELS[3], "run_startup_commands"),
            )
        ):
            ttk.Checkbutton(groups[0], text=label, variable=self._profile_option_vars[key]).grid(
                row=row, column=0, sticky="w"
            )
            self._profile_option_vars[key].trace_add(
                "write", lambda *_args, name=key: self._profile_option_changed(name)
            )
        ttk.Label(page, text="Changes to connection options apply to the next login.", style="Muted.TLabel").grid(
            row=1, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 4)
        )
        for row, (label, key) in enumerate(
            (
                (APPLICATION_STARTUP_OPTION_LABELS[0], "load_last_selected_profile"),
                (APPLICATION_STARTUP_OPTION_LABELS[1], "login_automatically_on_start"),
                (APPLICATION_STARTUP_OPTION_LABELS[2], "restore_previous_sessions_on_start"),
                (APPLICATION_STARTUP_OPTION_LABELS[3], "restore_window_position"),
            )
        ):
            ttk.Checkbutton(groups[1], text=label, variable=self._application_option_vars[key]).grid(
                row=row, column=0, sticky="w"
            )
            self._application_option_vars[key].trace_add(
                "write", lambda *_args, name=key: self._application_option_changed(name)
            )
        for row, (label, key) in enumerate(
            (
                (LOGOUT_OPTION_LABELS[0], "close_terminal_windows"),
                (LOGOUT_OPTION_LABELS[1], "close_sftp_windows"),
                (LOGOUT_OPTION_LABELS[2], "stop_enabled_services"),
                (LOGOUT_OPTION_LABELS[3], "ask_before_cancelling_active_transfers"),
            )
        ):
            ttk.Checkbutton(groups[2], text=label, variable=self._profile_option_vars[key]).grid(
                row=row, column=0, sticky="w"
            )
            self._profile_option_vars[key].trace_add(
                "write", lambda *_args, name=key: self._profile_option_changed(name)
            )

    def _profile_option_changed(self, key: str) -> None:
        if getattr(self, "_options_refreshing", False) or self.working_profile is None:
            return
        if key in {"open_terminal", "open_sftp", "start_enabled_services", "run_startup_commands"}:
            section = dict(self.working_profile.get("launch_preferences", {}))
            section[key] = bool(self._profile_option_vars[key].get())
            self.working_profile["launch_preferences"] = section
        else:
            section = dict(self.working_profile.get("connection_options", {}))
            section[key] = bool(self._profile_option_vars[key].get())
            self.working_profile["connection_options"] = section
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_action_states()

    def _application_option_changed(self, key: str) -> None:
        if not hasattr(self, "_application_option_vars"):
            return
        self._runtime_settings[key] = bool(self._application_option_vars[key].get())
        self._save_runtime_settings()

    def _refresh_options_tab(self) -> None:
        if not hasattr(self, "_profile_option_vars"):
            return
        self._options_refreshing = True
        try:
            profile = self.working_profile or {}
            launch = profile.get("launch_preferences", {})
            logout = profile.get("connection_options", {})
            for key in ("open_terminal", "open_sftp", "start_enabled_services", "run_startup_commands"):
                self._profile_option_vars[key].set(bool(launch.get(key, False)))
            for key, default in (
                ("close_terminal_windows", False),
                ("close_sftp_windows", False),
                ("stop_enabled_services", True),
                ("ask_before_cancelling_active_transfers", True),
            ):
                self._profile_option_vars[key].set(bool(logout.get(key, default)))
        finally:
            self._options_refreshing = False

    def _build_terminal_tab(self, page):
        for child in page.winfo_children():
            child.destroy()
        self._terminal_option_vars = {
            "backend": tk.StringVar(value="Automatic"),
            "terminal_type": tk.StringVar(value="xterm-256color"),
            "scrollback": tk.StringVar(value="10000"),
            "bell": tk.StringVar(value="System bell"),
            "startup_command": tk.StringVar(),
            "font": tk.StringVar(value="Monospace"),
            "font_size": tk.StringVar(value="10"),
            "cursor_shape": tk.StringVar(value="Block"),
            "cursor_blink": tk.BooleanVar(value=True),
            "color_theme": tk.StringVar(value="System"),
            "agent_forwarding": tk.BooleanVar(value=False),
            "x11_forwarding": tk.BooleanVar(value=False),
            "close_on_logout": tk.BooleanVar(value=False),
            "scroll_on_output": tk.BooleanVar(value=False),
            "scroll_on_keystroke": tk.BooleanVar(value=True),
        }
        groups = []
        for position, title in enumerate(TERMINAL_GROUPS):
            group = ttk.LabelFrame(page, text=title, padding=6)
            if position < 2:
                group.grid(row=0, column=position, sticky="nsew", padx=4, pady=4)
            else:
                group.grid(row=position - 1, column=0, columnspan=2, sticky="nsew", padx=4, pady=4)
            groups.append(group)
        page.columnconfigure((0, 1), weight=1)
        page.rowconfigure(1, weight=1)
        emulation = (
            ("Backend", "backend", TERMINAL_BACKENDS),
            ("Terminal type", "terminal_type", None),
            ("Scrollback lines", "scrollback", None),
            ("Bell", "bell", TERMINAL_BELLS),
            ("Initial command", "startup_command", None),
        )
        for row, (label, key, values) in enumerate(emulation):
            ttk.Label(groups[0], text=label).grid(row=row, column=0, sticky="w")
            widget = (
                ttk.Combobox(groups[0], textvariable=self._terminal_option_vars[key], values=values, state="readonly")
                if values
                else ttk.Entry(groups[0], textvariable=self._terminal_option_vars[key], width=36)
            )
            widget.grid(row=row, column=1, sticky="ew")
        self._terminal_backend_status = tk.StringVar(value="Native VTE unavailable")
        ttk.Label(groups[0], textvariable=self._terminal_backend_status).grid(row=5, column=1, sticky="w", pady=(4, 0))
        appearance = (
            ("Font", "font", None),
            ("Font size", "font_size", None),
            ("Cursor shape", "cursor_shape", TERMINAL_CURSOR_SHAPES),
            ("Cursor blink", "cursor_blink", "check"),
            ("Color theme", "color_theme", TERMINAL_COLOR_THEMES),
        )
        for row, (label, key, values) in enumerate(appearance):
            ttk.Label(groups[1], text=label).grid(row=row, column=0, sticky="w")
            if values == "check":
                widget = ttk.Checkbutton(groups[1], variable=self._terminal_option_vars[key])
            elif values:
                widget = ttk.Combobox(
                    groups[1], textvariable=self._terminal_option_vars[key], values=values, state="readonly"
                )
            else:
                widget = ttk.Entry(groups[1], textvariable=self._terminal_option_vars[key], width=36)
            widget.grid(row=row, column=1, sticky="w" if values == "check" else "ew")
        behavior = (
            ("Agent forwarding", "agent_forwarding"),
            ("X11 forwarding", "x11_forwarding"),
            ("Close terminal windows on logout", "close_on_logout"),
            ("Scroll on output", "scroll_on_output"),
            ("Scroll on keystroke", "scroll_on_keystroke"),
        )
        for row, (label, key) in enumerate(behavior):
            ttk.Checkbutton(groups[2], text=label, variable=self._terminal_option_vars[key]).grid(
                row=row, column=0, sticky="w"
            )
        ttk.Label(groups[2], text="Changes apply to newly opened terminals.").grid(
            row=5, column=0, sticky="w", pady=(4, 0)
        )
        self._terminal_action_buttons = []
        for column, label in enumerate(("Open Terminal", "Open Another Terminal")):
            button = ttk.Button(groups[3], text=label, command=self._open_selected_session_terminal)
            button.grid(row=0, column=column, sticky="w", padx=(0, 6))
            self._terminal_action_buttons.append(button)
        for key, variable in self._terminal_option_vars.items():
            variable.trace_add("write", lambda *_args, name=key: self._terminal_option_changed(name))
        self._refresh_terminal_tab()
        self._refresh_sftp_tab()

    def _terminal_option_changed(self, key: str) -> None:
        if getattr(self, "_terminal_options_refreshing", False) or self.working_profile is None:
            return
        options = dict(self.working_profile.get("terminal_options", {}))
        value = self._terminal_option_vars[key].get()
        if key == "font_size":
            try:
                size = int(value)
            except (TypeError, ValueError):
                self.profile_validation_errors = ["Font size must be an integer between 6 and 72."]
                self._refresh_action_states()
                return
            if not 6 <= size <= 72:
                self.profile_validation_errors = ["Font size must be between 6 and 72."]
                self._refresh_action_states()
                return
            value = size
        elif key == "scrollback":
            try:
                value = max(0, int(value))
            except (TypeError, ValueError):
                self.profile_validation_errors = ["Scrollback lines must be a whole number."]
                self._refresh_action_states()
                return
        elif isinstance(value, bool):
            value = bool(value)
        options[key] = value
        self.working_profile["terminal_options"] = options
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_action_states()
        self._refresh_services_tab()

    def _refresh_terminal_tab(self) -> None:
        if not hasattr(self, "_terminal_option_vars"):
            return
        self._terminal_options_refreshing = True
        try:
            options = (self.working_profile or {}).get("terminal_options", {})
            defaults = {
                "backend": "Automatic",
                "terminal_type": "xterm-256color",
                "scrollback": 10000,
                "bell": "System bell",
                "startup_command": "",
                "font": "Monospace",
                "font_size": 10,
                "cursor_shape": "Block",
                "cursor_blink": True,
                "color_theme": "System",
                "agent_forwarding": False,
                "x11_forwarding": False,
                "close_on_logout": False,
                "scroll_on_output": False,
                "scroll_on_keystroke": True,
            }
            for key, default in defaults.items():
                self._terminal_option_vars[key].set(options.get(key, default))
            availability = self._native_terminal_backend.availability
            self._terminal_backend_status.set(
                "Native VTE available"
                if availability.available
                else f"Native VTE unavailable: {availability.reason or 'unavailable'}"
            )
        finally:
            self._terminal_options_refreshing = False
        self._refresh_terminal_action_states()

    def _refresh_terminal_action_states(self) -> None:
        if not hasattr(self, "_terminal_action_buttons"):
            return
        record = self._selected_session_record()
        enabled = bool(record and record.state is SessionLifecycleState.CONNECTED)
        for button in self._terminal_action_buttons:
            button.configure(state="normal" if enabled else "disabled")

    def _build_sftp_tab(self, page):
        for child in page.winfo_children():
            child.destroy()
        self._sftp_option_vars = {
            "initial_local_directory": tk.StringVar(value=str(Path.home())),
            "initial_remote_directory": tk.StringVar(),
            "show_hidden": tk.BooleanVar(value=False),
            "collision_behavior": tk.StringVar(value="Ask"),
            "resume_partial": tk.BooleanVar(value=True),
            "preserve_timestamps": tk.BooleanVar(value=True),
            "concurrent_transfers": tk.StringVar(value="3"),
            "verify_transfers": tk.BooleanVar(value=True),
            "follow_symlinks": tk.BooleanVar(value=False),
        }
        groups = []
        for pos, title in enumerate(SFTP_GROUPS):
            group = ttk.LabelFrame(page, text=title, padding=6)
            group.grid(
                row=0 if pos < 2 else 1,
                column=pos if pos < 2 else 0,
                columnspan=1 if pos < 2 else 2,
                sticky="nsew",
                padx=4,
                pady=4,
            )
            groups.append(group)
        page.columnconfigure((0, 1), weight=1)
        for row, (label, key) in enumerate(
            (
                ("Initial local directory", "initial_local_directory"),
                ("Initial remote directory", "initial_remote_directory"),
            )
        ):
            ttk.Label(groups[0], text=label).grid(row=row, column=0, sticky="w")
            ttk.Entry(groups[0], textvariable=self._sftp_option_vars[key]).grid(row=row, column=1, sticky="ew")
        ttk.Checkbutton(groups[0], text="Show hidden files", variable=self._sftp_option_vars["show_hidden"]).grid(
            row=2, column=0, columnspan=2, sticky="w"
        )
        for row, (label, key) in enumerate(
            (("Overwrite behavior", "collision_behavior"), ("Concurrent transfers", "concurrent_transfers"))
        ):
            ttk.Label(groups[1], text=label).grid(row=row, column=0, sticky="w")
            widget = (
                ttk.Combobox(
                    groups[1],
                    textvariable=self._sftp_option_vars[key],
                    values=SFTP_OVERWRITE_BEHAVIORS,
                    state="readonly",
                )
                if key == "collision_behavior"
                else ttk.Entry(groups[1], textvariable=self._sftp_option_vars[key], width=6)
            )
            widget.grid(row=row, column=1, sticky="ew")
        for row, (label, key) in enumerate(
            (
                ("Resume partial transfers", "resume_partial"),
                ("Preserve timestamps", "preserve_timestamps"),
                ("Verify completed transfers", "verify_transfers"),
                ("Follow symbolic links", "follow_symlinks"),
            ),
            start=2,
        ):
            ttk.Checkbutton(groups[1], text=label, variable=self._sftp_option_vars[key]).grid(
                row=row, column=0, columnspan=2, sticky="w"
            )
        self._sftp_action_buttons = []
        for col, (label, command) in enumerate(
            (
                ("Open SFTP", self._open_selected_session_sftp),
                ("Open Another SFTP", self._open_selected_session_sftp),
                ("Transfer Manager", self._open_transfer_manager),
            )
        ):
            button = ttk.Button(groups[2], text=label, command=command)
            button.grid(row=0, column=col, padx=3, sticky="w")
            self._sftp_action_buttons.append(button)
        self._refresh_sftp_action_states()
        for key, variable in self._sftp_option_vars.items():
            variable.trace_add("write", lambda *_args, name=key: self._sftp_option_changed(name))

    def _sftp_option_changed(self, key: str) -> None:
        if getattr(self, "_sftp_options_refreshing", False) or self.working_profile is None:
            return
        options = dict(self.working_profile.get("sftp_options", {}))
        value = self._sftp_option_vars[key].get()
        if key == "concurrent_transfers":
            try:
                value = int(value)
            except (TypeError, ValueError):
                self.profile_validation_errors = ["Concurrent transfers must be an integer between 1 and 16."]
                self._refresh_action_states()
                return
            if not 1 <= value <= 16:
                self.profile_validation_errors = ["Concurrent transfers must be between 1 and 16."]
                self._refresh_action_states()
                return
        elif key == "collision_behavior":
            value = str(value).lower()
        options[key] = value
        self.working_profile["sftp_options"] = options
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_action_states()

    def _refresh_sftp_tab(self) -> None:
        if not hasattr(self, "_sftp_option_vars"):
            return
        self._sftp_options_refreshing = True
        try:
            options = (self.working_profile or {}).get("sftp_options", {})
            defaults = {
                "initial_local_directory": str(Path.home()),
                "initial_remote_directory": "",
                "show_hidden": False,
                "collision_behavior": "Ask",
                "resume_partial": True,
                "preserve_timestamps": True,
                "concurrent_transfers": self._runtime_settings.get("maximum_sftp_transfers", 3),
                "verify_transfers": True,
                "follow_symlinks": False,
            }
            for key, default in defaults.items():
                value = options.get(key, default)
                if key == "collision_behavior":
                    value = str(value).title()
                self._sftp_option_vars[key].set(value)
        finally:
            self._sftp_options_refreshing = False
        self._refresh_sftp_action_states()

    def _refresh_sftp_action_states(self):
        if not hasattr(self, "_sftp_action_buttons"):
            return
        connected = bool(
            (record := self._selected_session_record()) and record.state is SessionLifecycleState.CONNECTED
        )
        for button in self._sftp_action_buttons[:2]:
            button.configure(state="normal" if connected else "disabled")

    def _build_services_tab(self, page):
        for child in page.winfo_children():
            child.destroy()
        groups = []
        for position, title in enumerate(SERVICES_SECTIONS):
            group = ttk.LabelFrame(page, text=title, padding=6)
            if position == 0:
                group.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=4, pady=4)
            else:
                group.grid(row=1, column=position - 1, sticky="nsew", padx=4, pady=4)
            groups.append(group)
        page.columnconfigure((0, 1), weight=1)
        page.rowconfigure(0, weight=1)

        columns = tuple(f"column_{index}" for index in range(len(PORT_FORWARDING_RUNTIME_COLUMNS)))
        self._services_rules_tree = ttk.Treeview(
            groups[0],
            columns=columns,
            show="headings",
            selectmode="browse",
            height=8,
        )
        for column, label in zip(columns, PORT_FORWARDING_RUNTIME_COLUMNS, strict=True):
            self._services_rules_tree.heading(column, text=label)
            self._services_rules_tree.column(
                column,
                width=105,
                stretch=label in {"Listen Host", "Destination Host"},
            )
        self._services_rules_tree.pack(fill="both", expand=True)
        actions = ttk.Frame(groups[0])
        actions.pack(fill="x", pady=(6, 0))
        for label, command in (
            ("Add", self._add_service_rule),
            ("Edit", self._edit_service_rule),
            ("Remove", self._remove_service_rule),
            ("Duplicate", self._duplicate_service_rule),
        ):
            ttk.Button(actions, text=label, command=command).pack(side="left", padx=(0, 4))
        self._services_rules_tree.bind("<Double-Button-1>", lambda _event: self._edit_service_rule())
        self._services_rules_tree.bind("<Return>", lambda _event: self._edit_service_rule())

        ttk.Label(
            groups[1],
            text="Dynamic rules provide a per-session SOCKS proxy. Runtime activation follows in a later phase.",
            wraplength=420,
            justify="left",
        ).pack(anchor="w")
        self._services_x11_refreshing = False
        self._services_x11_vars = {
            "x11_forwarding": tk.BooleanVar(value=False),
            "x11_trusted": tk.BooleanVar(value=False),
            "x11_display": tk.StringVar(),
        }
        ttk.Checkbutton(
            groups[2],
            text=X11_FORWARDING_OPTION_LABELS[0],
            variable=self._services_x11_vars["x11_forwarding"],
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(
            groups[2],
            text=X11_FORWARDING_OPTION_LABELS[1],
            variable=self._services_x11_vars["x11_trusted"],
        ).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Label(groups[2], text=X11_FORWARDING_OPTION_LABELS[2]).grid(row=2, column=0, sticky="w", padx=(0, 6))
        self._services_x11_display = ttk.Entry(
            groups[2],
            textvariable=self._services_x11_vars["x11_display"],
            width=24,
        )
        self._services_x11_display.grid(row=2, column=1, sticky="ew")
        groups[2].columnconfigure(1, weight=1)
        self._services_x11_summary = tk.StringVar(value="Stopped")
        ttk.Label(
            groups[2],
            textvariable=self._services_x11_summary,
            wraplength=420,
            justify="left",
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))
        for key, variable in self._services_x11_vars.items():
            variable.trace_add("write", lambda *_args, name=key: self._service_x11_changed(name))
        self._refresh_services_tab()

    def _service_x11_changed(self, key: str) -> None:
        if self._services_x11_refreshing or self.working_profile is None:
            return
        terminal_options = dict(self.working_profile.get("terminal_options", {}))
        value = self._services_x11_vars[key].get()
        terminal_options[key] = bool(value) if key != "x11_display" else str(value).strip()
        self.working_profile["terminal_options"] = terminal_options
        enabled = bool(self._services_x11_vars["x11_forwarding"].get())
        self._services_x11_display.configure(state="normal" if enabled else "disabled")
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_action_states()
        self._refresh_terminal_tab()

    def _selected_service_rule_id(self) -> str | None:
        if not hasattr(self, "_services_rules_tree"):
            return None
        selection = self._services_rules_tree.selection()
        return selection[0] if len(selection) == 1 else None

    def _service_rule_dialog(self, existing=None):
        dialog = tk.Toplevel(self)
        dialog.title("Edit Port Forwarding" if existing else "Add Port Forwarding")
        dialog.transient(self)
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill="both", expand=True)
        existing = existing or {}
        kind = "Dynamic" if existing.get("type") == "SOCKS" else str(existing.get("type", "Local"))
        values = {
            "enabled": tk.BooleanVar(value=bool(existing.get("enabled", True))),
            "type": tk.StringVar(value=kind),
            "bind_address": tk.StringVar(value=str(existing.get("bind_address", "127.0.0.1"))),
            "bind_port": tk.StringVar(value=str(existing.get("bind_port", ""))),
            "destination_host": tk.StringVar(value=str(existing.get("destination_host", ""))),
            "destination_port": tk.StringVar(
                value="" if kind == "Dynamic" else str(existing.get("destination_port", ""))
            ),
        }
        ttk.Checkbutton(frame, text="Enabled", variable=values["enabled"]).grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
        )
        labels = (
            ("Type", "type"),
            ("Listen Host", "bind_address"),
            ("Listen Port", "bind_port"),
            ("Destination Host", "destination_host"),
            ("Destination Port", "destination_port"),
        )
        widgets = {}
        for row, (label, key) in enumerate(labels, start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
            widget = (
                ttk.Combobox(
                    frame,
                    textvariable=values[key],
                    values=PORT_FORWARDING_TYPES,
                    state="readonly",
                    width=24,
                )
                if key == "type"
                else ttk.Entry(frame, textvariable=values[key], width=28)
            )
            widget.grid(row=row, column=1, sticky="ew", pady=2)
            widgets[key] = widget
        error_var = tk.StringVar()
        ttk.Label(frame, textvariable=error_var, foreground="#c33").grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(4, 0),
        )
        result = {}

        def sync_destination(*_args) -> None:
            state = "disabled" if values["type"].get() in {"Dynamic", "HTTP"} else "normal"
            widgets["destination_host"].configure(state=state)
            widgets["destination_port"].configure(state=state)

        def submit() -> None:
            rule = {
                "rule_id": str(existing.get("rule_id", "")),
                "enabled": bool(values["enabled"].get()),
                "type": values["type"].get(),
                "bind_address": values["bind_address"].get(),
                "bind_port": values["bind_port"].get(),
                "destination_host": values["destination_host"].get(),
                "destination_port": values["destination_port"].get(),
            }
            try:
                PortForwardingEditor([]).add(rule)
            except ProfileError as exc:
                error_var.set(str(exc))
                return
            result["rule"] = rule
            dialog.destroy()

        values["type"].trace_add("write", sync_destination)
        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right")
        ttk.Button(buttons, text="OK", command=submit).pack(side="right", padx=(0, 6))
        sync_destination()
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.wait_window(dialog)
        return result.get("rule")

    def _services_editor(self) -> PortForwardingEditor | None:
        if self.working_profile is None:
            return None
        try:
            return PortForwardingEditor.from_profile(self.working_profile)
        except ProfileError as exc:
            self.profile_validation_errors = [str(exc)]
            self._refresh_action_states()
            return None

    def _commit_service_editor(self, editor: PortForwardingEditor) -> None:
        if self.working_profile is None:
            return
        editor.apply_to_working_profile(self.working_profile)
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_services_tab()
        self._refresh_action_states()

    def _add_service_rule(self) -> None:
        editor = self._services_editor()
        rule = self._service_rule_dialog() if editor is not None else None
        if editor is None or rule is None:
            return
        try:
            editor.add(rule)
        except ProfileError as exc:
            messagebox.showerror("Port Forwarding", str(exc), parent=self)
            return
        self._commit_service_editor(editor)

    def _edit_service_rule(self) -> None:
        editor = self._services_editor()
        rule_id = self._selected_service_rule_id()
        if editor is None or rule_id is None:
            return
        existing = next((rule for rule in editor.rules if rule.get("rule_id") == rule_id), None)
        if existing is None:
            return
        updates = self._service_rule_dialog(existing)
        if updates is None:
            return
        try:
            editor.edit(rule_id, updates)
        except ProfileError as exc:
            messagebox.showerror("Port Forwarding", str(exc), parent=self)
            return
        self._commit_service_editor(editor)

    def _remove_service_rule(self) -> None:
        editor = self._services_editor()
        rule_id = self._selected_service_rule_id()
        if editor is None or rule_id is None:
            return
        if not messagebox.askyesno("Port Forwarding", "Remove the selected forwarding rule?", parent=self):
            return
        if editor.remove(rule_id):
            self._commit_service_editor(editor)

    def _duplicate_service_rule(self) -> None:
        editor = self._services_editor()
        rule_id = self._selected_service_rule_id()
        if editor is None or rule_id is None:
            return
        try:
            duplicate = editor.duplicate(rule_id)
        except ProfileError as exc:
            messagebox.showerror("Port Forwarding", str(exc), parent=self)
            return
        self._commit_service_editor(editor)
        if self._services_rules_tree.exists(str(duplicate["rule_id"])):
            self._services_rules_tree.selection_set(str(duplicate["rule_id"]))

    def _refresh_services_tab(self) -> None:
        if not hasattr(self, "_services_rules_tree"):
            return
        selected = self._selected_service_rule_id()
        self._services_rules_tree.delete(*self._services_rules_tree.get_children())
        editor = self._services_editor()
        if editor is not None:
            for rule in editor.rules:
                rule_id = str(rule["rule_id"])
                record = self._selected_session_record()
                local_service = self._local_forwarding_services.get(record.session_id) if record is not None else None
                remote_service = self._remote_forwarding_services.get(record.session_id) if record is not None else None
                dynamic_service = (
                    self._dynamic_forwarding_services.get(record.session_id) if record is not None else None
                )
                http_service = self._http_forwarding_services.get(record.session_id) if record is not None else None
                statuses = [
                    service.status(rule_id)
                    for service in (local_service, remote_service, dynamic_service, http_service)
                    if service is not None
                ]
                status = next((value for value in statuses if value != "Stopped"), "Stopped")
                self._services_rules_tree.insert(
                    "",
                    "end",
                    iid=rule_id,
                    values=port_forwarding_display_row(rule) + (status,),
                )
        if selected and self._services_rules_tree.exists(selected):
            self._services_rules_tree.selection_set(selected)
        terminal_options = (self.working_profile or {}).get("terminal_options", {})
        self._services_x11_refreshing = True
        try:
            self._services_x11_vars["x11_forwarding"].set(bool(terminal_options.get("x11_forwarding", False)))
            self._services_x11_vars["x11_trusted"].set(bool(terminal_options.get("x11_trusted", False)))
            self._services_x11_vars["x11_display"].set(str(terminal_options.get("x11_display", "")))
        finally:
            self._services_x11_refreshing = False
        enabled = bool(self._services_x11_vars["x11_forwarding"].get())
        self._services_x11_display.configure(state="normal" if enabled else "disabled")
        record = self._selected_session_record()
        service = self._x11_forwarding_services.get(record.session_id) if record is not None else None
        if service is not None and service.error:
            summary = service.error
        elif service is not None:
            summary = service.status
        else:
            summary = "Enabled for newly opened terminals." if enabled else "Disabled"
        self._services_x11_summary.set(summary)

    def _build_ssh_tab(self, page) -> None:
        for child in page.winfo_children():
            child.destroy()
        section = ttk.LabelFrame(page, text="SSH Preferences", padding=8)
        section.grid(row=0, column=0, sticky="new", padx=8, pady=8)
        page.columnconfigure(0, weight=1)
        section.columnconfigure(1, weight=1)
        defaults = default_ssh_preferences()
        self._ssh_option_vars = {
            "compression": tk.BooleanVar(value=defaults["compression"]),
            "tcp_keepalive": tk.BooleanVar(value=defaults["tcp_keepalive"]),
            "keepalive_interval": tk.StringVar(value=str(defaults["keepalive_interval"])),
            "maximum_missed_keepalives": tk.StringVar(value=str(defaults["maximum_missed_keepalives"])),
            "agent_forwarding": tk.BooleanVar(value=defaults["agent_forwarding"]),
            "preferred_key_exchange": tk.StringVar(value="Automatic"),
            "preferred_host_key": tk.StringVar(value="Automatic"),
            "preferred_cipher": tk.StringVar(value="Automatic"),
            "preferred_mac": tk.StringVar(value="Automatic"),
        }
        rows = (
            ("compression", SSH_SETTING_LABELS[0], "check", None),
            ("tcp_keepalive", SSH_SETTING_LABELS[1], "check", None),
            ("keepalive_interval", SSH_SETTING_LABELS[2], "entry", None),
            (
                "maximum_missed_keepalives",
                SSH_SETTING_LABELS[3],
                "entry",
                None,
            ),
            ("agent_forwarding", SSH_SETTING_LABELS[4], "check", None),
            (
                "preferred_key_exchange",
                SSH_SETTING_LABELS[5],
                "combo",
                SSH_KEY_EXCHANGE_CHOICES,
            ),
            (
                "preferred_host_key",
                SSH_SETTING_LABELS[6],
                "combo",
                SSH_HOST_KEY_CHOICES,
            ),
            (
                "preferred_cipher",
                SSH_SETTING_LABELS[7],
                "combo",
                SSH_CIPHER_CHOICES,
            ),
            ("preferred_mac", SSH_SETTING_LABELS[8], "combo", SSH_MAC_CHOICES),
        )
        for row, (key, label, kind, values) in enumerate(rows):
            if kind == "check":
                widget = ttk.Checkbutton(
                    section,
                    text=label,
                    variable=self._ssh_option_vars[key],
                )
                widget.grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
            else:
                ttk.Label(section, text=label).grid(
                    row=row,
                    column=0,
                    sticky="w",
                    padx=(0, 8),
                    pady=2,
                )
                if kind == "combo":
                    widget = ttk.Combobox(
                        section,
                        textvariable=self._ssh_option_vars[key],
                        values=values,
                        state="readonly",
                        width=42,
                    )
                else:
                    widget = ttk.Entry(
                        section,
                        textvariable=self._ssh_option_vars[key],
                        width=10,
                    )
                widget.grid(row=row, column=1, sticky="ew", pady=2)
        self._ssh_validation_message = tk.StringVar()
        ttk.Label(
            section,
            textvariable=self._ssh_validation_message,
            foreground="#c33",
        ).grid(row=len(rows), column=0, columnspan=2, sticky="w", pady=(6, 0))
        for key, variable in self._ssh_option_vars.items():
            variable.trace_add(
                "write",
                lambda *_args, name=key: self._ssh_option_changed(name),
            )
        self._refresh_ssh_tab()

    def _ssh_option_changed(self, key: str) -> None:
        if getattr(self, "_ssh_options_refreshing", False) or self.working_profile is None:
            return
        value = self._ssh_option_vars[key].get()
        set_working_ssh_preference(self.working_profile, key, value)
        self.recalculate_profile_dirty()
        valid = self._validate_working_profile()
        self._ssh_validation_message.set("" if valid else self.profile_validation_errors[0])
        self._refresh_action_states()

    def _refresh_ssh_tab(self) -> None:
        if not hasattr(self, "_ssh_option_vars"):
            return
        profile = self.working_profile or {}
        try:
            preferences = ssh_preferences_from_profile(profile)
            error = ""
        except ProfileError as exc:
            preferences = default_ssh_preferences()
            connection_options = profile.get("connection_options", {})
            if isinstance(connection_options, dict):
                raw = connection_options.get("ssh_preferences", {})
                if isinstance(raw, dict):
                    preferences.update(raw)
            error = str(exc)
        self._ssh_options_refreshing = True
        try:
            for key, variable in self._ssh_option_vars.items():
                variable.set(preferences[key])
        finally:
            self._ssh_options_refreshing = False
        self._ssh_validation_message.set(error)

    def _sync_login_visibility(self):
        method = self._login_vars["auth_method"].get()
        password = method in {"Password", "Keyboard Interactive"}
        key = method == "Private Key"
        (self._password_label.grid if password else self._password_label.grid_remove)()
        (self._password_entry.grid if password else self._password_entry.grid_remove)()
        (self._key_label.grid if key else self._key_label.grid_remove)()
        (self._key_entry.grid if key else self._key_entry.grid_remove)()
        (self._manage_keys_button.grid if key else self._manage_keys_button.grid_remove)()
        (self._auth_summary.grid if method == "Automatic" else self._auth_summary.grid_remove)()
        proxy_enabled = self._login_vars["proxy_type"].get() == "SSH ProxyJump"
        for widget in self._proxy_widgets:
            widget.configure(state="normal" if proxy_enabled else "disabled")

    def _login_field_changed(self, field):
        if (
            not hasattr(self, "_login_vars")
            or self.working_profile is None
            or getattr(self, "_login_refreshing", False)
        ):
            return
        mapping = {"user": "user", "host": "host", "port": "port", "key_path": "key_path"}
        if field in mapping:
            self.update_working_profile_field(mapping[field], self._login_vars[field].get())
        elif field == "proxy_jump":
            if self._login_vars["proxy_type"].get() == "SSH ProxyJump":
                self.update_working_profile_field("proxy_jump", self.working_profile.get("proxy_jump", ""))
            else:
                self.update_working_profile_field("proxy_jump", "")

    def _refresh_login_tab(self):
        if not hasattr(self, "_login_vars") or self.working_profile is None:
            return
        self._login_refreshing = True
        try:
            for key in ("host", "port", "user", "key_path"):
                self._login_vars[key].set(str(self.working_profile.get(key, "")))
            self._login_vars["auth_method"].set(
                {"agent": "SSH Agent", "key": "Private Key", "password": "Password"}.get(
                    self.working_profile.get("auth_method"), "Automatic"
                )
            )
            self._login_vars["proxy_type"].set("SSH ProxyJump" if self.working_profile.get("proxy_jump") else "None")
            proxy = str(self.working_profile.get("proxy_jump", ""))
            user, _, host = proxy.partition("@")
            self._login_vars["proxy_host"].set(host if host else proxy)
            self._login_vars["proxy_user"].set(user if host else "")
            self._login_vars["proxy_port"].set("22" if proxy else "")
            self._sync_login_visibility()
        finally:
            self._login_refreshing = False

    @staticmethod
    def _profile_dropdown_items(entries) -> list[tuple[str, str]]:
        """Return unique display labels mapped to stable profile UUIDs."""
        name_counts: dict[str, int] = {}
        for entry in entries:
            name = str(entry.get("name") or entry.get("host") or "Profile")
            name_counts[name] = name_counts.get(name, 0) + 1
        used: dict[str, int] = {}
        items: list[tuple[str, str]] = []
        for entry in entries:
            name = str(entry.get("name") or entry.get("host") or "Profile")
            label = name
            if name_counts[name] > 1:
                target = f"{entry.get('user', '')}@{entry.get('host', '')}".strip("@")
                label = f"{name} — {target}" if target else name
            used[label] = used.get(label, 0) + 1
            if used[label] > 1:
                label = f"{label} ({used[label]})"
            items.append((label, str(entry.get("id", ""))))
        return items

    def _refresh_list(self):
        selected = self._selected_idx()
        selected_id = self._vault.entries[selected].get("id") if selected is not None else None
        state = ProfileSidebarState(self._vault.entries, self._search_var.get(), self._sort_var.get(), selected_id)
        self._tree.delete(*self._tree.get_children())
        visible = state.visible_profiles()
        for entry in visible:
            host = entry.get("host", "")
            details = f"{entry.get('user', '')}@{host}" + (
                f":{entry.get('port')}" if entry.get("port", 22) != 22 else ""
            )
            auth = {"agent": "Agent", "password": "Password", "key": "Key"}.get(entry.get("auth_method"), "Agent")
            self._tree.insert(
                "",
                "end",
                iid=str(entry.get("id")),
                values=(entry.get("name", host), details, auth, ", ".join(entry.get("tags", []))),
            )
        if selected_id:
            for entry in self._vault.entries:
                profile_id = str(entry.get("id"))
                if entry.get("id") == selected_id and self._tree.exists(profile_id):
                    self._tree.selection_set(profile_id)
                    self._tree.focus(profile_id)
                    break
        items = self._profile_dropdown_items(self._vault.entries)
        self._profile_choice_ids = dict(items)
        if selected_id:
            self._profile_choice.set(next((label for label, profile_id in items if profile_id == str(selected_id)), ""))
        elif self._profile_choice.get() not in self._profile_choice_ids:
            self._profile_choice.set("")
        self._update_profile_actions()

    def _refresh_sessions(self):
        self._sync_sftp_view_session_states()
        selected = getattr(self, "_selected_session_id", None)
        if selected and self._session_controller.get(selected) is None:
            self._selected_session_id = None
        self._refresh_action_states()
        self._refresh_terminal_action_states()
        self._refresh_sftp_action_states()
        self._refresh_services_tab()

    def _sync_sftp_view_session_states(self) -> None:
        for view_id, (session_id, callback) in list(self._sftp_view_state_callbacks.items()):
            if view_id not in self._sftp_views:
                self._sftp_view_state_callbacks.pop(view_id, None)
                continue
            record = self._session_controller.get(session_id)
            state = record.state if record is not None else SessionLifecycleState.DISCONNECTED
            try:
                callback(state)
            except tk.TclError:
                self._sftp_view_state_callbacks.pop(view_id, None)

    def _on_session_selection(self, _event=None):
        selection = self._sessions_tree.selection()
        self._selected_session_id = selection[0] if selection else None
        self._refresh_action_states()
        self._refresh_controller_log()
        self._refresh_terminal_action_states()
        self._refresh_sftp_action_states()
        self._refresh_services_tab()

    def _refresh_controller_log(self):
        if not hasattr(self, "_controller_log"):
            return
        record = self._selected_session_record()
        lines = [] if record is None else [f"[{event.level}] {event.message}" for event in record.events]
        self._controller_log.configure(state="normal")
        self._controller_log.delete("1.0", "end")
        self._controller_log.insert("end", "\n".join(lines))
        self._controller_log.configure(state="disabled")
        if hasattr(self, "_controller_status"):
            self._controller_status.set(record.state.value.replace("_", " ").title() if record else "Disconnected")

    def _selected_idx(self) -> int | None:
        sel = self._tree.selection()
        if not sel:
            return None
        return next((index for index, entry in enumerate(self._vault.entries) if entry.get("id") == sel[0]), None)

    def _clear_search(self):
        self._search_var.set("")
        self._toolbar_buttons["Load profile"].focus_set()

    def _update_profile_actions(self):
        self._refresh_action_states()

    def _refresh_action_states(self):
        if not hasattr(self, "_toolbar_buttons"):
            return
        profile = self._selected_idx() is not None
        session = self._selected_session_record()
        state = session.state if session else None
        rail_enabled = {
            "Load profile": bool(self._vault.entries),
            "Save profile as": bool(self.working_profile and not self.profile_validation_errors),
            "New profile": True,
            "Reset profile": bool(self.working_profile),
        }
        for key, button in self._toolbar_buttons.items():
            button.configure(state="normal" if rail_enabled.get(key, False) else "disabled")
        if not hasattr(self, "_connection_action_button"):
            return
        disconnecting_states = {
            SessionLifecycleState.VALIDATING,
            SessionLifecycleState.RESOLVING,
            SessionLifecycleState.CONNECTING_PROXY,
            SessionLifecycleState.CONNECTING_HOST,
            SessionLifecycleState.VERIFYING_HOST_KEY,
            SessionLifecycleState.AUTHENTICATING,
            SessionLifecycleState.CONNECTED,
            SessionLifecycleState.RECONNECTING,
            SessionLifecycleState.DISCONNECTING,
        }
        if state in disconnecting_states:
            self._connection_action_button.configure(text="Log out", state="normal")
        else:
            valid_profile = profile and not self.profile_validation_errors
            self._connection_action_button.configure(text="Log in", state="normal" if valid_profile else "disabled")

    def _selected_session_record(self):
        session_id = getattr(self, "_selected_session_id", None)
        return self._session_controller.get(session_id) if session_id else None

    def _select_session_for_profile(self, profile_id: str) -> None:
        """Focus a profile's own session without disturbing other sessions."""
        records = self._session_controller.for_profile(profile_id)
        inactive_states = {
            SessionLifecycleState.DISCONNECTED,
            SessionLifecycleState.FAILED,
            SessionLifecycleState.CANCELLED,
        }
        active_records = [record for record in records if record.state not in inactive_states]
        selected = (active_records or records)[-1] if records else None
        self._selected_session_id = selected.session_id if selected is not None else None
        self._refresh_controller_log()
        self._refresh_sessions()

    def resolve_unsaved_profile_changes(self, pending_action) -> bool:
        if not self.profile_dirty:
            return bool(pending_action())
        choice = messagebox.askyesnocancel("Unsaved profile", "Save changes before continuing?", parent=self)
        if choice is None:
            return False
        if choice:
            self._save_working_profile()
            if self.profile_dirty:
                return False
        else:
            self.discard_working_profile_changes()
        return bool(pending_action())

    def _save_as_working_profile(self):
        if self.working_profile is None or not self._validate_working_profile():
            return
        name = simpledialog_ask(
            "Save Profile As", "New profile name:", initialvalue=self.working_profile.get("name", "")
        )
        if not name or not name.strip():
            return
        clone = {
            key: value for key, value in self.working_profile.items() if key not in {"id", "password", "passphrase"}
        }
        clone["name"] = name.strip()
        try:
            created = self._vault.add(clone)
        except ProfileError as exc:
            messagebox.showerror("Save Profile As", str(exc), parent=self)
            return
        self.load_profile_working_copy(str(created["id"]))
        self._refresh_list()
        self._tree.selection_set(str(created["id"]))
        self._update_statusbar()

    def _save_working_profile(self):
        """Milestone B placeholder: profile dialogs remain the existing safe editor."""
        self._edit_entry()

    def _logout_selected_session(self):
        record = self._selected_session_record()
        if record and record.profile_snapshot.get("connection_options", {}).get("close_sftp_windows", False):
            self._close_sftp_views_for_session(record.session_id)
        if record:
            stop_sftp_resources = getattr(self, "_stop_sftp_resources_for_session", None)
            if callable(stop_sftp_resources):
                stop_sftp_resources(record.session_id)
        tab = self._conn_tabs.get(record.session_id) if record else None
        if tab:
            # Logout leaves the controller workspace reusable.  Full shutdown
            # is reserved for destroying the tab/application.
            tab._disconnect()
        elif record:
            self._stop_local_forwarding_for_session(record.session_id)
            self._stop_remote_forwarding_for_session(record.session_id)
            self._stop_dynamic_forwarding_for_session(record.session_id)
            self._stop_http_forwarding_for_session(record.session_id)
            self._stop_x11_forwarding_for_session(record.session_id)
            self._session_controller.disconnect(record.session_id, "User requested log out.")
        self._refresh_action_states()

    def _stop_sftp_resources_for_session(self, session_id: str) -> None:
        """Stop only the browser channels and transfer workers owned by one session."""
        scheduler = self._sftp_transfer_schedulers.pop(session_id, None)
        if scheduler is not None:
            scheduler.invalidate_session(fail_active=True)
            scheduler.shutdown()
        self._sftp_browser_clients.close_session(session_id)

    def _stop_local_forwarding_for_session(self, session_id: str) -> None:
        service = self._local_forwarding_services.pop(session_id, None)
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        for rule_id in active_ids:
            self._session_controller.unregister_tunnel(session_id, rule_id)
        self._refresh_services_tab()

    def _stop_remote_forwarding_for_session(self, session_id: str) -> None:
        service = self._remote_forwarding_services.pop(session_id, None)
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        for rule_id in active_ids:
            self._session_controller.unregister_tunnel(session_id, rule_id)
        self._refresh_services_tab()

    def _stop_dynamic_forwarding_for_session(self, session_id: str) -> None:
        service = self._dynamic_forwarding_services.pop(session_id, None)
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        for rule_id in active_ids:
            self._session_controller.unregister_tunnel(session_id, rule_id)
        self._refresh_services_tab()

    def _stop_http_forwarding_for_session(self, session_id: str) -> None:
        service = self._http_forwarding_services.pop(session_id, None)
        if service is None:
            return
        active_ids = service.active_rule_ids()
        service.stop_all()
        for rule_id in active_ids:
            self._session_controller.unregister_tunnel(session_id, rule_id)
        self._refresh_services_tab()

    def _stop_x11_forwarding_for_session(self, session_id: str) -> None:
        service = self._x11_forwarding_services.pop(session_id, None)
        if service is None:
            return
        service.close()
        self._refresh_services_tab()

    def _close_sftp_views_for_session(self, session_id: str) -> None:
        for view_id, window in list(self._sftp_views.items()):
            record = self._session_controller.get(session_id)
            if record is None or view_id not in record.sftp_view_ids:
                continue
            self._session_controller.unregister_sftp_view(session_id, view_id)
            self._sftp_views.pop(view_id, None)
            self._sftp_view_state_callbacks.pop(view_id, None)
            self._sftp_transfer_status_callbacks.pop(view_id, None)
            self._sftp_transfer_queue_callbacks.pop(view_id, None)
            try:
                window.destroy()
            except tk.TclError:
                pass
            threading.Thread(
                target=self._sftp_browser_clients.close_view,
                args=(session_id, view_id),
                daemon=True,
                name="sshvault-sftp-view-close",
            ).start()
        self._refresh_sessions()

    def _reconnect_selected_session(self):
        record = self._selected_session_record()
        tab = self._conn_tabs.get(record.session_id) if record else None
        if tab:
            tab._reconnect_now()

    def _open_selected_session_terminal(self):
        record = self._selected_session_record()
        tab = self._conn_tabs.get(record.session_id) if record else None
        if tab:
            tab._open_terminal()

    def _open_selected_session_sftp(self):
        record = self._selected_session_record()
        if record is not None:
            self._open_sftp_placeholder(record)

    def _sftp_transfer_router(self, record) -> SFTPTransferRouter:
        options = record.profile_snapshot.get("sftp_options", {})
        verify_completed = bool(options.get("verify_completed_transfers", options.get("verify_transfers", True)))
        scheduler = self._sftp_transfer_schedulers.get(record.session_id)
        if scheduler is None:
            tab = self._conn_tabs.get(record.session_id)
            client = getattr(tab, "_client", None)
            if client is None or record.state is not SessionLifecycleState.CONNECTED:
                raise ProfileError("SFTP transfers are unavailable.")
            concurrency = int(options.get("concurrent_transfers", 3))
            scheduler = TransferScheduler(
                lambda connection=client: connection.open_sftp(),
                concurrency=concurrency,
                on_change=lambda session_id=record.session_id: self._sftp_transfer_changed(session_id),
                reuse_worker_channels=True,
                session_id=record.session_id,
                profile_id=str(record.profile_snapshot.get("id", "")) or None,
                operation_timeout=float(options.get("operation_timeout", 30.0)),
            )
            self._sftp_transfer_schedulers[record.session_id] = scheduler
        return SFTPTransferRouter(
            scheduler,
            verify_completed=verify_completed,
            follow_symlinks=bool(options.get("follow_symlinks", False)),
        )

    def _sftp_transfer_changed(self, session_id: str) -> None:
        changes = getattr(self, "_sftp_change_queue", None)
        if changes is not None:
            changes.put(session_id)

    def _poll_sftp_transfer_changes(self) -> None:
        changed: set[str] = set()
        while True:
            try:
                changed.add(self._sftp_change_queue.get_nowait())
            except queue.Empty:
                break
        for session_id in changed:
            scheduler = self._sftp_transfer_schedulers.get(session_id)
            if scheduler is None:
                continue
            summary = scheduler.summary()
            if summary["failed"]:
                message = "Transfer failed."
            elif summary["active"] or summary["pending"]:
                message = f"{summary['active']} active · {summary['pending']} pending"
            elif scheduler.items:
                message = "Transfers complete."
            else:
                message = ""
            for view_session_id, callback in list(self._sftp_transfer_status_callbacks.values()):
                if view_session_id == session_id:
                    callback(message)
            for view_session_id, callback in list(self._sftp_transfer_queue_callbacks.values()):
                if view_session_id == session_id:
                    callback()
        try:
            self.after(100, self._poll_sftp_transfer_changes)
        except (RuntimeError, tk.TclError):
            return

    def _open_sftp_placeholder(self, record) -> str | None:
        """Create the Phase 1 isolated SFTP browser shell without a client."""
        if record.state is not SessionLifecycleState.CONNECTED:
            return None
        snapshot = json.loads(json.dumps(record.profile_snapshot))
        view_id = str(uuid4())
        window = tk.Toplevel(self)
        window.title(session_resource_title("SFTP", snapshot))
        window.geometry("900x540")
        body = ttk.Frame(window, padding=8)
        body.pack(fill="both", expand=True)
        local = ttk.LabelFrame(body, text="Local", padding=8)
        local.grid(row=0, column=0, sticky="nsew", padx=4)
        remote = ttk.LabelFrame(body, text="Remote", padding=8)
        remote.grid(row=0, column=1, sticky="nsew", padx=4)
        body.columnconfigure((0, 1), weight=1)
        options = snapshot.get("sftp_options", {})
        initial = initial_local_browser_path(str(options.get("initial_local_directory", Path.home())))
        state = SFTPViewNavigationState(local_current_path=initial)
        local_entries = []
        local_cache = SFTPListingCache()
        path_var, status_var = tk.StringVar(value=state.local_current_path), tk.StringVar()
        columns = ("name", "size", "modified", "type", "permissions")
        tree = ttk.Treeview(local, columns=columns, show="headings", selectmode="extended")
        for column, label in zip(columns, ("Name", "Size", "Modified", "Type", "Permissions"), strict=True):
            tree.heading(column, text=label)
            tree.column(column, width=90, stretch=column == "name")

        def load(path=None, *, force: bool = False):
            target = normalize_local_path(path or state.local_current_path)
            if state.local_loading and not force:
                return
            generation = state.next_generation(False)
            state.local_loading = True
            update_mutation_actions()
            cache_key = f"{target}|{bool(options.get('show_hidden', False))}"

            def worker() -> None:
                try:
                    cached = None if force else local_cache.get(cache_key)
                    entries = (
                        cached
                        if cached is not None
                        else list_local_browser_entries(target, bool(options.get("show_hidden", False)))
                    )
                    error = None
                except ProfileError as exc:
                    entries = []
                    error = str(exc)
                except Exception:
                    entries = []
                    error = "Local directory not found"

                def apply_result() -> None:
                    if view_id not in self._sftp_views or not state.generation_current(generation, False):
                        return
                    state.local_loading = False
                    if error is not None:
                        state.last_local_error = error
                        status_var.set(error)
                        update_mutation_actions()
                        return
                    state.last_local_error = None
                    local_cache.put(cache_key, entries)
                    sorted_entries = sort_browser_entries(entries, state.local_sort_column, state.local_sort_descending)
                    local_entries[:] = sorted_entries
                    if target != state.local_current_path:
                        state.navigate_new(target, False)
                    path_var.set(state.local_current_path)
                    tree.delete(*tree.get_children())
                    for batch in batch_browser_entries(sorted_entries):
                        for entry in batch:
                            tree.insert(
                                "",
                                "end",
                                values=(
                                    entry.name,
                                    entry.size if entry.size is not None else "—",
                                    entry.modified_time or "—",
                                    entry.type_label,
                                    entry.permissions,
                                ),
                                tags=(entry.full_path, "dir" if entry.is_directory else "file"),
                            )
                    status_var.set(f"{len(sorted_entries)} items")
                    update_mutation_actions()

                try:
                    self.after(0, apply_result)
                except (RuntimeError, tk.TclError):
                    return

            threading.Thread(target=worker, daemon=True, name=f"sshvault-sftp-local-{view_id[:8]}").start()

        def sort(column):
            update_browser_sort(state, column)
            load(force=True)

        for column in columns:
            tree.heading(column, command=lambda name=column: sort(name))

        bar = ttk.Frame(local)
        bar.pack(fill="x")
        local_action_bar = ttk.Frame(local)
        local_action_bar.pack(fill="x")
        local_buttons = {}
        for label, command in (
            ("Back", lambda: state.navigate_back(False) and load()),
            ("Forward", lambda: state.navigate_forward(False) and load()),
            ("Up", lambda: state.navigate_up(False) and load()),
            ("Home", lambda: state.navigate_home(str(Path.home()), False) and load()),
            ("Refresh", lambda: load(force=True)),
            ("New Folder", None),
            ("Rename", None),
            ("Delete", None),
            ("Properties", None),
            ("Copy Path", None),
        ):
            parent = bar if label in {"Back", "Forward", "Up", "Home", "Refresh"} else local_action_bar
            button = ttk.Button(parent, text=label, command=command)
            button.pack(side="left", padx=2)
            local_buttons[label] = button
        entry = ttk.Entry(local, textvariable=path_var)
        entry.pack(fill="x", pady=3)

        def bind_path_shortcuts(widget, navigate):
            """Keep path editing predictable across keyboard layouts."""

            def shortcut(event):
                key = path_entry_shortcut_action(str(event.keysym))
                if key is None:
                    return
                try:
                    if key == "a":
                        widget.selection_range(0, "end")
                    elif key == "c":
                        if widget.selection_present():
                            widget.clipboard_clear()
                            widget.clipboard_append(widget.selection_get())
                    elif key == "x":
                        if widget.selection_present():
                            widget.clipboard_clear()
                            widget.clipboard_append(widget.selection_get())
                            widget.delete("sel.first", "sel.last")
                    elif key == "v":
                        value = widget.clipboard_get()
                        if widget.selection_present():
                            widget.delete("sel.first", "sel.last")
                        widget.insert("insert", value)
                    else:
                        return
                except tk.TclError:
                    return "break"
                return "break"

            # A generic Control binding keeps Ctrl+Shift shortcuts working
            # when Caps Lock changes the key symbol's case.
            widget.bind("<Control-KeyPress>", shortcut, add="+")
            widget.bind("<Return>", navigate, add="+")

        bind_path_shortcuts(entry, lambda _event: load(path_var.get()))

        def open_selected(_event=None):
            selection = tree.selection()
            if len(selection) != 1:
                return
            tags = tree.item(selection[0], "tags")
            if len(tags) >= 2 and tags[1] == "dir":
                load(str(tags[0]))

        tree.bind("<Double-Button-1>", open_selected)
        tree.bind("<Return>", open_selected)

        def bind_list_navigation(widget):
            def move(event):
                item_ids = list(widget.get_children())
                if not item_ids:
                    return "break"
                focused = widget.focus()
                current = item_ids.index(focused) if focused in item_ids else 0
                try:
                    page = max(1, int(widget.cget("height")))
                except (TypeError, ValueError, tk.TclError):
                    page = 10
                target = browser_keyboard_index(current, len(item_ids), str(event.keysym), page)
                if target is None:
                    return "break"
                target_id = item_ids[target]
                # Treeview's native mouse handling remains responsible for
                # Ctrl/Shift ranges; keyboard movement preserves those modes.
                if event.state & 0x0001:  # Shift
                    anchor = getattr(widget, "_sshvault_anchor", current)
                    lo, hi = sorted((anchor, target))
                    widget.selection_set(item_ids[lo : hi + 1])
                elif event.state & 0x0004:  # Control
                    if target_id in widget.selection():
                        widget.selection_remove(target_id)
                    else:
                        widget.selection_add(target_id)
                else:
                    widget.selection_set(target_id)
                widget._sshvault_anchor = target
                widget.focus(target_id)
                widget.see(target_id)
                return "break"

            for key in ("Up", "Down", "Prior", "Next", "Home", "End"):
                widget.bind(f"<{key}>", move, add="+")

        bind_list_navigation(tree)
        tree.pack(fill="both", expand=True)
        ttk.Label(local, textvariable=status_var).pack(anchor="w")
        remote_path_var = tk.StringVar(value=str(options.get("initial_remote_directory", "")))
        remote_status_var = tk.StringVar(value="Loading…")
        remote_bar = ttk.Frame(remote)
        remote_bar.pack(fill="x")
        remote_action_bar = ttk.Frame(remote)
        remote_action_bar.pack(fill="x")
        remote_buttons = {}
        for label in (
            "Back",
            "Forward",
            "Up",
            "Home",
            "Refresh",
            "New Folder",
            "Rename",
            "Delete",
            "Properties",
            "Copy Path",
        ):
            parent = remote_bar if label in {"Back", "Forward", "Up", "Home", "Refresh"} else remote_action_bar
            button = ttk.Button(parent, text=label)
            button.pack(side="left", padx=2)
            remote_buttons[label] = button
        remote_entry = ttk.Entry(remote, textvariable=remote_path_var)
        remote_entry.pack(fill="x", pady=3)
        remote_columns = ("name", "size", "modified", "type", "permissions", "owner")
        remote_table = ttk.Frame(remote)
        remote_table.pack(fill="both", expand=True)
        remote_tree = ttk.Treeview(
            remote_table,
            columns=remote_columns,
            show="headings",
            selectmode="extended",
        )
        remote_scrollbar = ttk.Scrollbar(remote_table, orient="vertical", command=remote_tree.yview)
        remote_tree.configure(yscrollcommand=remote_scrollbar.set)
        for column, label in zip(
            remote_columns,
            ("Name", "Size", "Modified", "Type", "Permissions", "Owner"),
            strict=True,
        ):
            remote_tree.heading(column, text=label)
            remote_tree.column(column, width=90, stretch=column == "name")
        remote_tree.pack(side="left", fill="both", expand=True)
        remote_scrollbar.pack(side="right", fill="y")
        ttk.Label(remote, textvariable=remote_status_var).pack(anchor="w")
        queue_frame = ttk.LabelFrame(body, text="Transfer queue", padding=4)
        queue_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=4, pady=(6, 0))
        queue_columns = ("file", "direction", "progress", "speed", "eta", "status")
        queue_tree = ttk.Treeview(
            queue_frame,
            columns=queue_columns,
            show="headings",
            selectmode="browse",
            height=5,
        )
        for column, label in zip(
            queue_columns,
            ("File", "Direction", "Progress", "Speed", "ETA", "Status"),
            strict=True,
        ):
            queue_tree.heading(column, text=label)
            queue_tree.column(column, width=105, stretch=column in {"file", "status"})
        queue_tree.pack(fill="both", expand=True)
        queue_actions = ttk.Frame(queue_frame)
        queue_actions.pack(fill="x", pady=(4, 0))
        queue_buttons = {}
        for label in ("Pause", "Resume", "Cancel", "Retry", "Remove Completed"):
            button = ttk.Button(queue_actions, text=label, state="disabled")
            button.pack(side="left", padx=(0, 4))
            queue_buttons[label] = button
        transfer_bar = ttk.Frame(body)
        transfer_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=4, pady=(6, 0))
        upload_button = ttk.Button(transfer_bar, text="Upload", state="disabled")
        upload_button.pack(side="left", padx=(0, 4))
        download_button = ttk.Button(transfer_bar, text="Download", state="disabled")
        download_button.pack(side="left")
        transfer_status_var = tk.StringVar()
        ttk.Label(transfer_bar, textvariable=transfer_status_var).pack(side="left", padx=8)
        body.rowconfigure(0, weight=1)
        tab = self._conn_tabs.get(record.session_id)
        client = getattr(tab, "_client", None)
        # Let the shell paint before the channel handshake begins; directory
        # reads themselves are dispatched asynchronously below.
        remote_status_var.set("Connecting…")
        try:
            window.update_idletasks()
        except tk.TclError:
            window.destroy()
            return None
        try:
            browser_client = SFTPBrowserClient(client.open_sftp()) if client is not None else None
        except Exception:
            browser_client = None
        if browser_client is None:
            window.destroy()
            messagebox.showerror("SFTP", "SFTP is unavailable for this connection.", parent=self)
            return None
        self._sftp_browser_clients.register(record.session_id, view_id, browser_client)
        self._session_controller.register_sftp_view(record.session_id, view_id)
        self._sftp_views[view_id] = window
        self._sftp_transfer_status_callbacks[view_id] = (record.session_id, transfer_status_var.set)
        remote_entries = []
        remote_mutating = {"active": False}

        def current_transfer_scheduler():
            return self._sftp_transfer_schedulers.get(record.session_id)

        def selected_transfer_item():
            scheduler = current_transfer_scheduler()
            selection = queue_tree.selection()
            return scheduler.get(selection[0]) if scheduler is not None and len(selection) == 1 else None

        def update_queue_actions(_event=None) -> None:
            scheduler = current_transfer_scheduler()
            items = list(scheduler.items) if scheduler is not None else []
            enabled = sftp_transfer_control_states(selected_transfer_item(), items)
            for label, key in (
                ("Pause", "pause"),
                ("Resume", "resume"),
                ("Cancel", "cancel"),
                ("Retry", "retry"),
                ("Remove Completed", "remove_completed"),
            ):
                queue_buttons[label].configure(state="normal" if enabled[key] else "disabled")

        def refresh_transfer_queue() -> None:
            scheduler = current_transfer_scheduler()
            selected = set(queue_tree.selection())
            queue_tree.delete(*queue_tree.get_children())
            rows = sftp_transfer_queue_rows(list(scheduler.items) if scheduler is not None else [])
            for row in rows:
                queue_tree.insert(
                    "",
                    "end",
                    iid=row.item_id,
                    values=(row.file, row.direction, row.progress, row.speed, row.eta, row.status),
                )
            queue_tree.selection_set([item_id for item_id in selected if queue_tree.exists(item_id)])
            update_queue_actions()

        def act_on_selected_transfer(action: str) -> None:
            scheduler = current_transfer_scheduler()
            item = selected_transfer_item()
            if scheduler is None or item is None:
                return
            getattr(scheduler, action)(item.item_id)
            refresh_transfer_queue()

        queue_buttons["Pause"].configure(command=lambda: act_on_selected_transfer("pause"))
        queue_buttons["Resume"].configure(command=lambda: act_on_selected_transfer("resume"))
        queue_buttons["Cancel"].configure(command=lambda: act_on_selected_transfer("cancel"))
        queue_buttons["Retry"].configure(command=lambda: act_on_selected_transfer("retry"))

        def remove_completed_transfers() -> None:
            scheduler = current_transfer_scheduler()
            if scheduler is not None:
                scheduler.clear_completed()
                refresh_transfer_queue()

        queue_buttons["Remove Completed"].configure(command=remove_completed_transfers)
        queue_tree.bind("<<TreeviewSelect>>", update_queue_actions)
        self._sftp_transfer_queue_callbacks[view_id] = (record.session_id, refresh_transfer_queue)

        remote_cache = SFTPListingCache()

        def selected_paths(widget) -> list[str]:
            paths = []
            for item_id in widget.selection():
                tags = widget.item(item_id, "tags")
                if tags:
                    paths.append(str(tags[0]))
            return paths

        def selected_local_files():
            return selected_file_entries(local_entries, selected_paths(tree))

        def selected_remote_files():
            return selected_file_entries(remote_entries, selected_paths(remote_tree))

        def selected_local_items():
            return selected_browser_entries(local_entries, selected_paths(tree))

        def selected_remote_items():
            return selected_browser_entries(remote_entries, selected_paths(remote_tree))

        def selected_local_transfer_items():
            return selected_browser_entries(local_entries, selected_paths(tree))

        def selected_remote_transfer_items():
            return selected_browser_entries(remote_entries, selected_paths(remote_tree))

        def update_mutation_actions(_event=None) -> None:
            enabled = sftp_mutation_action_states(
                local_selection_count=len(selected_local_items()),
                remote_selection_count=len(selected_remote_items()),
                local_loading=state.local_loading,
                remote_loading=state.remote_loading,
                remote_available=state.remote_available and browser_client.is_alive(),
            )
            local_buttons["New Folder"].configure(state="normal" if enabled["local_new_folder"] else "disabled")
            local_buttons["Rename"].configure(state="normal" if enabled["local_rename"] else "disabled")
            remote_buttons["New Folder"].configure(state="normal" if enabled["remote_new_folder"] else "disabled")
            remote_buttons["Rename"].configure(state="normal" if enabled["remote_rename"] else "disabled")
            update_file_actions()

        def update_file_actions() -> None:
            enabled = sftp_file_action_states(
                local_selection_count=len(selected_local_items()),
                remote_selection_count=len(selected_remote_items()),
                local_loading=state.local_loading,
                remote_loading=state.remote_loading,
                remote_available=state.remote_available and browser_client.is_alive(),
            )
            for action, key in (
                ("Delete", "local_delete"),
                ("Properties", "local_properties"),
                ("Copy Path", "local_copy_path"),
            ):
                local_buttons[action].configure(state="normal" if enabled[key] else "disabled")
            for action, key in (
                ("Delete", "remote_delete"),
                ("Properties", "remote_properties"),
                ("Copy Path", "remote_copy_path"),
            ):
                remote_buttons[action].configure(state="normal" if enabled[key] else "disabled")

        def update_transfer_actions(_event=None) -> None:
            current = self._session_controller.get(record.session_id)
            state_inputs = {
                "local_selected": bool(selected_local_transfer_items()),
                "remote_selected": bool(selected_remote_transfer_items()),
                "connected": bool(current and current.state is SessionLifecycleState.CONNECTED),
                "client_available": state.remote_available and browser_client.is_alive(),
            }
            enabled = SFTPTransferRouter.action_states(
                **state_inputs,
            )
            upload_button.configure(state="normal" if enabled["upload"] else "disabled")
            download_button.configure(state="normal" if enabled["download"] else "disabled")
            reasons = SFTPTransferRouter.disabled_reasons(**state_inputs)
            previous = getattr(window, "_sshvault_transfer_disabled_reasons", {})
            if reasons != previous:
                profile_id = str(record.profile_snapshot.get("id", "unknown"))[:12]
                for action, reason in reasons.items():
                    if reason and previous.get(action) != reason:
                        log(
                            f"SFTP {action} disabled session={record.session_id[:12]} "
                            f"profile={profile_id} reason={reason}"
                        )
                window._sshvault_transfer_disabled_reasons = reasons

        def queue_uploads() -> None:
            try:
                queued = self._sftp_transfer_router(record).queue_uploads(
                    [entry.full_path for entry in selected_local_transfer_items()],
                    state.remote_current_path,
                )
            except Exception as exc:
                log(f"SFTP upload queue failure session={record.session_id[:12]} type={type(exc).__name__}")
                transfer_status_var.set("Transfer could not be queued")
                return
            transfer_status_var.set(f"Queued {len(queued)} upload(s).")

        def queue_downloads() -> None:
            try:
                queued = self._sftp_transfer_router(record).queue_downloads(
                    selected_remote_transfer_items(),
                    state.local_current_path,
                    browser_client=browser_client,
                )
            except Exception:
                transfer_status_var.set("Download could not be queued.")
                return
            transfer_status_var.set(f"Queued {len(queued)} download(s).")

        upload_button.configure(command=queue_uploads)
        download_button.configure(command=queue_downloads)

        def route_drop(source_pane: str, target_pane: str) -> str:
            current = self._session_controller.get(record.session_id)
            try:
                router = SFTPDragDropRouter(self._sftp_transfer_router(record))
                queued = router.route_drop(
                    source_pane=source_pane,
                    target_pane=target_pane,
                    connected=bool(current and current.state is SessionLifecycleState.CONNECTED),
                    client_available=state.remote_available and browser_client.is_alive(),
                    local_paths=[item.full_path for item in selected_local_files()],
                    remote_entries=selected_remote_files(),
                    local_directory=state.local_current_path,
                    remote_directory=state.remote_current_path,
                )
            except Exception:
                transfer_status_var.set("Transfer could not be queued.")
                return "none"
            if queued:
                direction = "upload" if source_pane == "local" else "download"
                transfer_status_var.set(f"Queued {len(queued)} {direction}(s).")
                return "copy"
            return "none"

        def install_native_drag_drop() -> bool:
            required_methods = (
                "drag_source_register",
                "drop_target_register",
                "dnd_bind",
            )
            if not all(
                callable(getattr(widget, method, None)) for widget in (tree, remote_tree) for method in required_methods
            ):
                transfer_status_var.set("Drag-and-drop unsupported; use Upload/Download.")
                return False
            local_type = "SSHVAULT_LOCAL_SELECTION"
            remote_type = "SSHVAULT_REMOTE_SELECTION"
            try:
                tree.drag_source_register(1, local_type)
                remote_tree.drop_target_register(local_type)
                remote_tree.drag_source_register(1, remote_type)
                tree.drop_target_register(remote_type)
                tree.dnd_bind(
                    "<<DragInitCmd>>",
                    lambda _event: ("copy", local_type, view_id),
                )
                remote_tree.dnd_bind(
                    "<<DragInitCmd>>",
                    lambda _event: ("copy", remote_type, view_id),
                )
                remote_tree.dnd_bind(
                    "<<Drop>>",
                    lambda _event: route_drop("local", "remote"),
                )
                tree.dnd_bind(
                    "<<Drop>>",
                    lambda _event: route_drop("remote", "local"),
                )
            except (AttributeError, RuntimeError, tk.TclError):
                transfer_status_var.set("Drag-and-drop unsupported; use Upload/Download.")
                return False
            transfer_status_var.set("Drag selected files between panes to transfer.")
            return True

        install_native_drag_drop()
        tree.bind("<<TreeviewSelect>>", update_transfer_actions, add="+")
        tree.bind("<<TreeviewSelect>>", update_mutation_actions, add="+")
        remote_tree.bind("<<TreeviewSelect>>", update_transfer_actions, add="+")
        remote_tree.bind("<<TreeviewSelect>>", update_mutation_actions, add="+")

        def local_new_folder() -> None:
            name = simpledialog_ask("New Folder", "Folder name:")
            if name is None:
                return
            try:
                create_local_browser_folder(state.local_current_path, name)
            except (OSError, ProfileError):
                status_var.set("Could not create local folder.")
                return
            local_cache.clear()
            load(force=True)

        def local_rename() -> None:
            selected = selected_local_items()
            if len(selected) != 1:
                return
            name = simpledialog_ask("Rename", "New name:", selected[0].name)
            if name is None:
                return
            try:
                rename_local_browser_entry(selected[0].full_path, name)
            except (OSError, ProfileError):
                status_var.set("Could not rename local item.")
                return
            local_cache.clear()
            load(force=True)

        def show_properties(item) -> None:
            dialog = tk.Toplevel(window)
            dialog.title(f"Properties — {item.name}")
            dialog.transient(window)
            dialog.resizable(False, False)
            frame = ttk.Frame(dialog, padding=10)
            frame.pack(fill="both", expand=True)
            for row, (label, value) in enumerate(browser_entry_properties(item).items()):
                ttk.Label(frame, text=label).grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=2)
                ttk.Label(frame, text=value).grid(row=row, column=1, sticky="nw", pady=2)
            ttk.Button(frame, text="Close", command=dialog.destroy).grid(
                row=len(browser_entry_properties(item)),
                column=1,
                sticky="e",
                pady=(8, 0),
            )

        def copy_path(path: str, status) -> None:
            try:
                window.clipboard_clear()
                window.clipboard_append(path)
                status.set("Path copied.")
            except tk.TclError:
                status.set("Could not copy path.")

        def local_delete() -> None:
            selected = selected_local_items()
            if not selected:
                return
            selected = confirmed_sftp_delete_entries(
                selected,
                messagebox.askyesno(
                    "Delete",
                    f"Delete {len(selected)} selected local item(s)?",
                    parent=window,
                ),
            )
            if not selected:
                return
            try:
                delete_local_browser_entries(selected)
            except (OSError, ProfileError):
                status_var.set("Could not delete selected local item(s).")
                return
            local_cache.clear()
            load(force=True)

        def local_properties() -> None:
            selected = selected_local_items()
            if len(selected) == 1:
                show_properties(selected[0])

        def local_copy_path() -> None:
            path = selected_browser_path(local_entries, selected_paths(tree))
            if path is not None:
                copy_path(path, status_var)

        local_buttons["New Folder"].configure(command=local_new_folder)
        local_buttons["Rename"].configure(command=local_rename)
        local_buttons["Delete"].configure(command=local_delete)
        local_buttons["Properties"].configure(command=local_properties)
        local_buttons["Copy Path"].configure(command=local_copy_path)

        def render_remote() -> None:
            sorted_entries = sort_browser_entries(
                remote_entries,
                state.remote_sort_column,
                state.remote_sort_descending,
            )
            remote_tree.delete(*remote_tree.get_children())
            for batch in batch_browser_entries(sorted_entries):
                for item in batch:
                    remote_tree.insert(
                        "",
                        "end",
                        values=(
                            item.name,
                            item.size if item.size is not None else "—",
                            item.modified_time or "—",
                            item.type_label,
                            item.permissions,
                            item.owner,
                        ),
                        tags=(item.full_path, "dir" if item.is_directory else "file"),
                    )
            remote_status_var.set(f"{len(sorted_entries)} items")
            update_transfer_actions()
            update_mutation_actions()

        def load_remote(
            requested_path: str | None = None,
            *,
            history_action: str = "new",
        ) -> None:
            if not state.remote_available:
                remote_status_var.set("Disconnected")
                return
            if remote_mutating["active"]:
                return
            generation = state.begin_remote_listing()
            requested = remote_path_var.get() if requested_path is None else requested_path
            remote_status_var.set("Loading…")
            remote_buttons["Refresh"].configure(state="disabled")
            update_mutation_actions()

            def worker() -> None:
                try:
                    if not browser_client.is_alive():
                        raise ProfileError("SFTP channel unavailable")
                    home = browser_client.home_directory()
                    target = normalize_remote_path(requested, home)
                    cache_key = f"{target}|{bool(options.get('show_hidden', False))}"
                    cached = None if history_action == "refresh" else remote_cache.get(cache_key)
                    if cached is not None:
                        entries = cached
                    else:
                        entries = list_remote_browser_entries(
                            browser_client,
                            target,
                            bool(options.get("show_hidden", False)),
                        )
                    error = None
                except ProfileError as exc:
                    target = state.remote_current_path
                    entries = []
                    error = str(exc)
                except Exception:
                    target = state.remote_current_path
                    entries = []
                    error = "Directory listing failed"

                def apply_result() -> None:
                    view_open = view_id in self._sftp_views
                    accepted = state.complete_remote_listing(
                        generation,
                        target,
                        error=error,
                        view_open=view_open,
                        update_path=False,
                    )
                    if not view_open or not state.generation_current(generation, True):
                        return
                    remote_buttons["Refresh"].configure(state="normal")
                    if not accepted:
                        remote_path_var.set(state.remote_current_path)
                        remote_status_var.set(error or "Directory listing failed")
                        update_mutation_actions()
                        return
                    if history_action == "back":
                        state.navigate_back(True)
                    elif history_action == "forward":
                        state.navigate_forward(True)
                    elif history_action == "new":
                        state.navigate_new(target, True)
                    elif history_action == "initial":
                        state.remote_current_path = target
                    remote_entries[:] = entries
                    remote_cache.put(cache_key, entries)
                    remote_path_var.set(state.remote_current_path)
                    render_remote()

                try:
                    self.after(0, apply_result)
                except (RuntimeError, tk.TclError):
                    return

            threading.Thread(
                target=worker,
                daemon=True,
                name=f"sshvault-sftp-list-{view_id[:8]}",
            ).start()

        def run_remote_mutation(operation, failure_message: str) -> None:
            if not state.remote_available or state.remote_loading:
                return
            generation = state.next_generation(True)
            state.remote_loading = True
            remote_mutating["active"] = True
            remote_status_var.set("Working…")
            for label in ("Back", "Forward", "Up", "Home", "Refresh"):
                remote_buttons[label].configure(state="disabled")
            remote_entry.configure(state="disabled")
            update_mutation_actions()

            def worker() -> None:
                try:
                    operation()
                    failed = False
                except Exception:
                    failed = True

                def completed() -> None:
                    if view_id not in self._sftp_views or not state.generation_current(generation, True):
                        return
                    state.remote_loading = False
                    remote_mutating["active"] = False
                    if failed:
                        remote_status_var.set(failure_message)
                        for label in ("Back", "Forward", "Up", "Home", "Refresh"):
                            remote_buttons[label].configure(state="normal")
                        remote_entry.configure(state="normal")
                        update_mutation_actions()
                        return
                    remote_cache.clear()
                    for label in ("Back", "Forward", "Up", "Home", "Refresh"):
                        remote_buttons[label].configure(state="normal")
                    remote_entry.configure(state="normal")
                    load_remote(state.remote_current_path, history_action="refresh")

                try:
                    self.after(0, completed)
                except (RuntimeError, tk.TclError):
                    return

            threading.Thread(
                target=worker,
                daemon=True,
                name=f"sshvault-sftp-mutate-{view_id[:8]}",
            ).start()

        def remote_new_folder() -> None:
            name = simpledialog_ask("New Folder", "Folder name:")
            if name is None:
                return
            try:
                validated = validate_sftp_item_name(name)
            except ProfileError:
                remote_status_var.set("Enter a valid folder name.")
                return
            run_remote_mutation(
                lambda: create_remote_browser_folder(
                    browser_client,
                    state.remote_current_path,
                    validated,
                ),
                "Could not create remote folder.",
            )

        def remote_rename() -> None:
            selected = selected_remote_items()
            if len(selected) != 1:
                return
            name = simpledialog_ask("Rename", "New name:", selected[0].name)
            if name is None:
                return
            try:
                validated = validate_sftp_item_name(name)
            except ProfileError:
                remote_status_var.set("Enter a valid item name.")
                return
            run_remote_mutation(
                lambda: rename_remote_browser_entry(
                    browser_client,
                    selected[0].full_path,
                    validated,
                ),
                "Could not rename remote item.",
            )

        def remote_delete() -> None:
            selected = list(selected_remote_items())
            if not selected:
                return
            selected = confirmed_sftp_delete_entries(
                selected,
                messagebox.askyesno(
                    "Delete",
                    f"Delete {len(selected)} selected remote item(s)?",
                    parent=window,
                ),
            )
            if not selected:
                return
            run_remote_mutation(
                lambda: delete_remote_browser_entries(browser_client, selected),
                "Could not delete selected remote item(s).",
            )

        def remote_properties() -> None:
            selected = selected_remote_items()
            if len(selected) == 1:
                show_properties(selected[0])

        def remote_copy_path() -> None:
            path = selected_browser_path(remote_entries, selected_paths(remote_tree))
            if path is not None:
                copy_path(path, remote_status_var)

        def remote_back() -> None:
            if state.remote_back_history:
                load_remote(state.remote_back_history[-1], history_action="back")

        def remote_forward() -> None:
            if state.remote_forward_history:
                load_remote(state.remote_forward_history[-1], history_action="forward")

        def remote_up() -> None:
            current = state.remote_current_path or "/"
            load_remote(posixpath.dirname(current) or "/", history_action="new")

        def remote_home() -> None:
            load_remote("", history_action="new")

        def remote_refresh() -> None:
            load_remote(state.refresh(True), history_action="refresh")

        def sort_remote(column: str) -> None:
            if not state.remote_available:
                return
            update_browser_sort(state, column, remote=True)
            render_remote()

        def open_remote_selected(_event=None) -> None:
            selection = remote_tree.selection()
            if len(selection) != 1:
                return
            tags = remote_tree.item(selection[0], "tags")
            target = selected_directory_target(remote_entries, [str(tags[0])] if tags else [])
            if target is not None:
                load_remote(target, history_action="new")

        for label, command in (
            ("Back", remote_back),
            ("Forward", remote_forward),
            ("Up", remote_up),
            ("Home", remote_home),
            ("Refresh", remote_refresh),
        ):
            remote_buttons[label].configure(command=command)
        remote_buttons["New Folder"].configure(command=remote_new_folder)
        remote_buttons["Rename"].configure(command=remote_rename)
        remote_buttons["Delete"].configure(command=remote_delete)
        remote_buttons["Properties"].configure(command=remote_properties)
        remote_buttons["Copy Path"].configure(command=remote_copy_path)
        for column in remote_columns:
            remote_tree.heading(column, command=lambda name=column: sort_remote(name))
        bind_path_shortcuts(remote_entry, lambda _event: load_remote(remote_path_var.get()))
        remote_tree.bind("<Double-Button-1>", open_remote_selected)
        remote_tree.bind("<Return>", open_remote_selected)
        bind_list_navigation(remote_tree)
        bind_list_navigation(queue_tree)

        def sync_remote_session(session_state: SessionLifecycleState) -> None:
            connected = session_state is SessionLifecycleState.CONNECTED and browser_client.is_alive()
            if connected:
                state.mark_remote_reconnected(True)
            else:
                state.mark_remote_disconnected()
                remote_mutating["active"] = False
            widget_state = "normal" if connected else "disabled"
            for button in remote_buttons.values():
                button.configure(state=widget_state)
            remote_entry.configure(state=widget_state)
            remote_tree.state(("!disabled",) if connected else ("disabled",))
            remote_scrollbar.state(("!disabled",) if connected else ("disabled",))
            if not connected:
                remote_status_var.set("Disconnected")
            update_transfer_actions()
            update_mutation_actions()

        self._sftp_view_state_callbacks[view_id] = (record.session_id, sync_remote_session)
        load()
        load_remote(history_action="initial")
        refresh_transfer_queue()
        update_transfer_actions()
        update_mutation_actions()

        def close() -> None:
            state.next_generation(True)
            self._session_controller.unregister_sftp_view(record.session_id, view_id)
            self._sftp_views.pop(view_id, None)
            self._sftp_view_state_callbacks.pop(view_id, None)
            self._sftp_transfer_status_callbacks.pop(view_id, None)
            self._sftp_transfer_queue_callbacks.pop(view_id, None)
            window.destroy()
            self._refresh_sessions()
            threading.Thread(
                target=self._sftp_browser_clients.close_view,
                args=(record.session_id, view_id),
                daemon=True,
                name="sshvault-sftp-view-close",
            ).start()

        window.protocol("WM_DELETE_WINDOW", close)
        self._refresh_sessions()
        return view_id

    def _open_selected_session_tunnel(self):
        record = self._selected_session_record()
        tab = self._conn_tabs.get(record.session_id) if record else None
        if tab:
            tab._open_tunnels()

    def _on_profile_selection(self, _event=None):
        self._update_profile_actions()
        idx = self._selected_idx()
        if idx is None:
            self._profile_selection_note.set("")
            return
        selected = self._vault.entries[idx]
        self.selected_profile_id = str(selected.get("id"))
        self._runtime_settings["last_selected_profile_id"] = self.selected_profile_id
        self._save_runtime_settings()
        self.loaded_profile_snapshot = json.loads(json.dumps(selected))
        self.working_profile = json.loads(json.dumps(selected))
        self.profile_dirty = False
        self.profile_validation_errors = []
        self._refresh_login_tab()
        self._refresh_options_tab()
        self._refresh_terminal_tab()
        self._refresh_services_tab()
        self._refresh_ssh_tab()
        self._refresh_profile_heading()
        self._select_session_for_profile(self.selected_profile_id)
        active = None
        try:
            active = self._conn_notebook.nametowidget(self._conn_notebook.select())
        except (tk.TclError, KeyError):
            pass
        if isinstance(active, ConnectionTab) and active._entry.get("id") != selected.get("id"):
            self._profile_selection_note.set(
                "Selected profile differs from the open connection; the active session remains connected."
            )
        else:
            self._profile_selection_note.set("")

    def _validate_working_profile(self) -> bool:
        if self.working_profile is None:
            self.profile_validation_errors = ["No selected profile."]
            return False
        try:
            validate_profile(self.working_profile, check_key_exists=False)
        except ProfileError as exc:
            self.profile_validation_errors = [str(exc)]
            return False
        self.profile_validation_errors = []
        return True

    # Canonical B1 working-copy API.  Widgets adapt to this model; it never
    # writes the vault until commit_working_profile is called.
    def load_profile_working_copy(self, profile_id: str) -> bool:
        profile = next((item for item in self._vault.entries if item.get("id") == profile_id), None)
        if profile is None:
            self.clear_working_profile()
            return False
        self.selected_profile_id = profile_id
        self.loaded_profile_snapshot = json.loads(json.dumps(profile))
        self.working_profile = json.loads(json.dumps(profile))
        self.profile_dirty = False
        self.profile_validation_errors = []
        self._refresh_options_tab()
        self._refresh_terminal_tab()
        self._refresh_sftp_tab()
        self._refresh_services_tab()
        self._refresh_ssh_tab()
        self._refresh_profile_heading()
        self._select_session_for_profile(profile_id)
        return True

    def update_working_profile_field(self, field: str, value) -> bool:
        if self.working_profile is None or field not in self.working_profile:
            return False
        self.working_profile[field] = value
        self.recalculate_profile_dirty()
        self._validate_working_profile()
        self._refresh_action_states()
        return True

    def recalculate_profile_dirty(self) -> bool:
        self.profile_dirty = bool(self.working_profile != self.loaded_profile_snapshot)
        self._refresh_profile_heading()
        return self.profile_dirty

    def commit_working_profile(self) -> bool:
        before = self.profile_dirty
        self._save_working_profile()
        return before and not self.profile_dirty

    def discard_working_profile_changes(self) -> None:
        self.working_profile = (
            json.loads(json.dumps(self.loaded_profile_snapshot)) if self.loaded_profile_snapshot else None
        )
        self.profile_dirty = False
        self.profile_validation_errors = []
        self._refresh_options_tab()
        self._refresh_terminal_tab()
        self._refresh_sftp_tab()
        self._refresh_services_tab()
        self._refresh_ssh_tab()
        self._refresh_profile_heading()

    def clear_working_profile(self) -> None:
        self.selected_profile_id = None
        self.loaded_profile_snapshot = None
        self.working_profile = None
        self.profile_dirty = False
        self.profile_validation_errors = []
        self._refresh_services_tab()
        self._refresh_ssh_tab()
        self._refresh_profile_heading()

    def _save_working_profile(self):
        if self.working_profile is None or not self.profile_dirty or not self._validate_working_profile():
            return
        idx = next(
            (i for i, item in enumerate(self._vault.entries) if item.get("id") == self.selected_profile_id), None
        )
        if idx is None:
            return
        try:
            self._vault.update(idx, self.working_profile)
        except ProfileError as exc:
            self.profile_validation_errors = [str(exc)]
            return
        self.loaded_profile_snapshot = json.loads(json.dumps(self._vault.entries[idx]))
        self.working_profile = json.loads(json.dumps(self._vault.entries[idx]))
        self.profile_dirty = False
        self._refresh_list()
        self._refresh_profile_heading()

    def _show_profile_context_menu(self, event):
        # The retired sidebar Treeview no longer owns a context menu.  Profile
        # actions remain available from the single toolbar.
        return None

    def _is_text_input_focus(self) -> bool:
        focus = self.focus_get()
        if focus is None:
            return False
        if isinstance(focus, tk.Text):
            return True
        return not application_shortcut_allowed(focus.winfo_class())

    def _profile_shortcut(self, event, action):
        if self._is_text_input_focus():
            return None
        action()
        return "break"

    def _bind_profile_shortcuts(self):
        self.bind_all("<Control-n>", lambda event: self._profile_shortcut(event, self._add_entry), add="+")
        self.bind_all(
            "<Control-f>",
            lambda event: self._profile_shortcut(event, self._toolbar_buttons["Load profile"].focus_set),
            add="+",
        )
        self.bind_all("<Control-e>", lambda event: self._profile_shortcut(event, self._edit_entry), add="+")
        self.bind_all("<Control-d>", lambda event: self._profile_shortcut(event, self._duplicate_entry), add="+")
        self.bind_all("<Delete>", lambda event: self._profile_shortcut(event, self._delete_entry), add="+")
        self.bind_all("<F5>", lambda event: self._profile_shortcut(event, self._refresh_list), add="+")

    def _add_entry(self):
        dlg = EntryDialog(self)
        if dlg.result:
            try:
                self._vault.add(dlg.result, dlg.secret or "")
            except ProfileError as exc:
                messagebox.showerror("Could not save connection", str(exc))
                return
            self._refresh_list()
            self._update_statusbar()

    def _edit_entry(self):
        idx = self._selected_idx()
        if idx is None:
            return
        dlg = EntryDialog(self, self._vault.entries[idx])
        if dlg.result:
            try:
                self._vault.update(idx, dlg.result, dlg.secret, remove_password=dlg.remove_secret)
            except ProfileError as exc:
                messagebox.showerror("Could not save connection", str(exc))
                return
            self._refresh_list()

    def _duplicate_entry(self):
        source = self.working_profile
        if source is None or not self._validate_working_profile():
            return
        state = ProfileSidebarState(self._vault.entries)
        duplicate = {key: value for key, value in source.items() if key not in {"id", "password", "passphrase"}}
        duplicate["name"] = state.duplicate_name(source)
        try:
            created = self._vault.add(duplicate)
        except ProfileError as exc:
            messagebox.showerror("Could not duplicate connection", str(exc))
            return
        self.load_profile_working_copy(str(created["id"]))
        self._refresh_list()
        self._tree.selection_set(str(created["id"]))
        self._update_statusbar()

    def _delete_entry(self):
        idx = self._selected_idx()
        if idx is None:
            return
        name = self._vault.entries[idx].get("name", "entry")
        if not confirm_delete_enabled(self._runtime_settings) or messagebox.askyesno("Delete", f"Delete '{name}'?"):
            self._vault.delete(idx)
            self._refresh_list()
            self._update_statusbar()

    def _export_selected(self):
        idx = self._selected_idx()
        if idx is None:
            return
        profile = dict(self._vault.entries[idx])
        self._export_profiles(
            [profile], initialfile=f"{profile.get('name', 'ssh-profile')}.json", title="Export selected SSH profile"
        )

    def _export_all(self):
        """Export a snapshot of every stored profile without touching the sidebar."""
        self._export_profiles(
            [dict(profile) for profile in self._vault.entries],
            initialfile="sshvault-profiles.json",
            title="Export all SSH profiles",
        )

    def _export_profiles(self, profiles: list[dict], *, initialfile: str, title: str) -> None:
        """Choose a destination on Tk, then atomically export on a worker."""
        if not profiles:
            messagebox.showinfo("Export", "There are no profiles to export.")
            return
        destination = filedialog.asksaveasfilename(
            title=title, defaultextension=".json", filetypes=(("JSON files", "*.json"),), initialfile=initialfile
        )
        if not destination:
            return
        target = Path(destination)
        overwrite = target.exists()
        if overwrite and confirm_overwrite_enabled(self._runtime_settings):
            if not messagebox.askyesno("Replace export", "Replace the existing export file?"):
                return
        self._profile_export_generation = getattr(self, "_profile_export_generation", 0) + 1
        generation = self._profile_export_generation

        def dispatch(callback) -> None:
            try:
                self.after(0, callback)
            except (RuntimeError, tk.TclError):
                return

        def is_current() -> bool:
            if generation != getattr(self, "_profile_export_generation", 0):
                return False
            try:
                return bool(self.winfo_exists())
            except tk.TclError:
                return False

        def worker() -> None:
            try:
                count = self._vault._store.export(target, profiles, overwrite=overwrite)
                dispatch(lambda: completed(count))
            except Exception as exc:
                dispatch(lambda error=exc: failed(error))

        def completed(count: int) -> None:
            if not is_current():
                return
            self._status_var.set(f"Exported {count} profile(s) to {target.name}")
            messagebox.showinfo("Export complete", f"Exported {count} profile(s) to {target.name}.")

        def failed(exc: BaseException) -> None:
            if not is_current():
                return
            detail = redact_secrets(friendly_connection_error(exc))
            self._status_var.set("Profile export failed")
            messagebox.showerror("Export failed", f"Could not export profiles: {detail}")
            log(f"Profile export failed: {redact_secrets(str(exc))}")

        threading.Thread(target=worker, daemon=True).start()

    def _create_profile_backup(self) -> None:
        """Create a credential-free vault backup without blocking the Tk loop."""
        self._backup_generation = getattr(self, "_backup_generation", 0) + 1
        generation = self._backup_generation

        def dispatch(callback) -> None:
            try:
                self.after(0, callback)
            except (RuntimeError, tk.TclError):
                return

        def current() -> bool:
            if generation != getattr(self, "_backup_generation", 0):
                return False
            try:
                return bool(self.winfo_exists())
            except tk.TclError:
                return False

        def worker() -> None:
            try:
                path, count = self._vault._store.create_backup()
                dispatch(lambda: done(path, count))
            except Exception as exc:
                dispatch(lambda error=exc: failed(error))

        def done(path: Path, count: int) -> None:
            if not current():
                return
            self._status_var.set(f"Created backup {path.name}")
            messagebox.showinfo("Backup complete", f"Created {path.name} with {count} profile(s).")

        def failed(exc: BaseException) -> None:
            if not current():
                return
            detail = redact_secrets(friendly_connection_error(exc))
            self._status_var.set("Profile backup failed")
            messagebox.showerror("Backup failed", f"Could not create a backup: {detail}")
            log(f"Profile backup failed: {redact_secrets(str(exc))}")

        threading.Thread(target=worker, daemon=True).start()

    def _restore_profile_backup(self) -> None:
        """Preview a backup on a worker and require confirmation before restore."""
        source = filedialog.askopenfilename(title="Restore profile backup", filetypes=(("JSON files", "*.json"),))
        if not source:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Restore Backup")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog._closed = False
        dialog._running = False
        status = tk.StringVar(value="Validating backup…")
        details = tk.StringVar()
        tk.Label(dialog, textvariable=status, bg=BG, fg=TEXT, font=FONT).pack(anchor="w", padx=14, pady=(14, 6))
        tk.Label(dialog, textvariable=details, bg=BG, fg=MUTED, font=FONT, justify="left").pack(
            anchor="w", padx=14, pady=4
        )
        buttons = ttk.Frame(dialog)
        buttons.pack(fill="x", padx=14, pady=(10, 14))
        restore_button = ttk.Button(buttons, text="Restore backup", state="disabled")
        restore_button.pack(side="right")

        def alive() -> bool:
            if getattr(dialog, "_closed", True):
                return False
            try:
                return bool(dialog.winfo_exists())
            except tk.TclError:
                return False

        def close_dialog() -> None:
            dialog._closed = True
            dialog.destroy()

        ttk.Button(buttons, text="Close", command=close_dialog).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        generation = [0]
        preview = [None]

        def dispatch(callback) -> None:
            try:
                self.after(0, callback)
            except (RuntimeError, tk.TclError):
                return

        def show_preview(value) -> None:
            if not alive():
                return
            preview[0] = value
            details.set(
                f"Schema version: {value.schema_version}\nProfiles: {value.profile_count}\n"
                f"Valid: {value.valid_profiles}   Invalid: {value.invalid_profiles}   Conflicts: {value.conflicts}"
            )
            if value.profile_count and not value.valid_profiles:
                status.set("No valid profiles are available to restore.")
                restore_button.configure(state="disabled")
            else:
                status.set("Review the backup, then confirm restoration.")
                restore_button.configure(state="normal")

        def preview_failed(exc: BaseException) -> None:
            if not alive():
                return
            status.set("This file cannot be restored.")
            log(f"Restore preview failed: {redact_secrets(str(exc))}")

        def validate_worker() -> None:
            try:
                value = self._vault._store.preview_restore(Path(source))
                dispatch(lambda: show_preview(value))
            except Exception as exc:
                dispatch(lambda error=exc: preview_failed(error))

        def restore() -> None:
            if not alive() or preview[0] is None or dialog._running:
                return
            if not messagebox.askyesno(
                "Restore backup",
                "Replace current saved profiles? A backup of the current vault will be created first.",
                parent=dialog,
            ):
                return
            dialog._running = True
            generation[0] += 1
            attempt = generation[0]
            status.set("Restoring backup…")
            restore_button.configure(state="disabled")

            def restore_worker() -> None:
                try:
                    summary = self._vault._store.restore_backup(Path(source))
                    dispatch(lambda: restore_done(summary, attempt))
                except Exception as exc:
                    dispatch(lambda error=exc: restore_failed(error, attempt))

            threading.Thread(target=restore_worker, daemon=True).start()

        def restore_done(summary, attempt: int) -> None:
            if not alive() or attempt != generation[0]:
                return
            self._vault.entries = self._vault._store.entries
            self._refresh_list()
            self._update_statusbar()
            close_dialog()
            messagebox.showinfo(
                "Restore complete", f"Restored {summary.restored}; skipped {summary.skipped}; failed {summary.failed}."
            )

        def restore_failed(exc: BaseException, attempt: int) -> None:
            if not alive() or attempt != generation[0]:
                return
            dialog._running = False
            status.set("Restore failed; current profiles were not changed.")
            restore_button.configure(state="normal")
            log(f"Restore failed: {redact_secrets(str(exc))}")

        restore_button.configure(command=restore)
        threading.Thread(target=validate_worker, daemon=True).start()

    def _connect(self):
        if not paramiko:
            messagebox.showerror("Missing", "Run: pip install paramiko")
            return
        idx = self._selected_idx()
        if idx is not None:
            self._connect_by_idx(idx)

    def _selected_native_profile(self) -> dict | None:
        idx = self._selected_idx()
        if idx is None:
            return None
        profile = dict(self._vault.entries[idx])
        profile["timeout"] = self._runtime_settings.get("connection_timeout", 15)
        return profile

    def _open_selected_terminal(self):
        """Route terminal creation through the selected SessionRecord owner."""
        self._open_selected_session_terminal()

    def _open_selected_terminal_tab(self):
        self._open_selected_session_terminal()

    def _open_selected_terminal_window(self):
        self._open_selected_terminal()

    def _connect_by_idx(self, idx: int):
        if not paramiko:
            return
        profile = self._vault.entries[idx]
        self._status_var.set(f"Connecting to {profile.get('name', profile.get('host', 'profile'))}…")
        # Profiles remain secret-free. ConnectionTab receives only a short-
        # lived in-memory copy when password authentication needs a credential.
        entry = json.loads(json.dumps(profile))
        entry["timeout"] = self._runtime_settings.get("connection_timeout", 15)
        if profile.get("auth_method") == "password":
            try:
                password = self._vault.secret_for(profile) or ""
            except ProfileError:
                password = ""
            if not password:
                password = simpledialog_ask(
                    "Password required",
                    f"Enter the password for {profile.get('user', '')}@{profile.get('host', '')}",
                    secret=True,
                )
            if not password:
                self._status_var.set("Connection cancelled: no password was provided.")
                return
            # This is used by this connection attempt only; it is never added
            # to the profile data or written to a local file.
            entry["password"] = password
        runtime_entries = []
        for candidate in self._vault.entries:
            runtime = dict(candidate)
            if candidate.get("auth_method") == "password":
                try:
                    runtime["password"] = self._vault.secret_for(candidate) or ""
                except ProfileError:
                    runtime["password"] = ""
            runtime_entries.append(runtime)
        session = self._session_controller.create_session(entry, user_initiated=True)
        # This application-only path belongs to the ConnectionTab adapter, not
        # the validated profile/session snapshot.
        entry["default_download_directory"] = self._runtime_settings.get("download_directory", "")
        connection_parent = (
            self._ensure_connection_view_host()
            if hasattr(self, "_ensure_connection_view_host")
            else self._conn_notebook
        )
        tab = ConnectionTab(
            connection_parent,
            entry,
            vault_entries=runtime_entries,
            session_controller=self._session_controller,
            session_id=session.session_id,
        )
        # Each click starts an independent session, even for the same profile.
        self._session_serial += 1
        tab_id = session.session_id
        self._conn_tabs[tab_id] = tab
        label = entry.get("name", entry["host"])
        duplicates = sum(
            1
            for open_tab in self._conn_tabs.values()
            if open_tab._entry is not entry
            and open_tab._entry.get("host") == entry.get("host")
            and open_tab._entry.get("port", 22) == entry.get("port", 22)
            and open_tab._entry.get("user", "root") == entry.get("user", "root")
        )
        if duplicates:
            label = f"{label} ({duplicates + 1})"
        self._conn_notebook.add(tab, text=f"  {label}  ")
        self._conn_notebook.select(tab)
        self._status_var.set(f"Connecting to {label}...")
        self._update_statusbar()
        tab.start_connection()
        self._selected_session_id = session.session_id
        self._refresh_sessions()

    def _show_connection_tab_menu(self, event):
        """Show actions for the outer connection workspace tabs."""
        try:
            tab_index = self._conn_notebook.index(f"@{event.x},{event.y}")
        except tk.TclError:
            return

        tab_id = self._conn_notebook.tabs()[tab_index]
        tab = self._conn_notebook.nametowidget(tab_id)
        self._conn_notebook.select(tab)
        label = self._conn_notebook.tab(tab, "text").strip()
        self._connection_tab_menu.delete(0, "end")
        self._connection_tab_menu.add_command(
            label=f"Close {label}", command=lambda target=tab: self._close_connection_tab(target)
        )
        try:
            self._connection_tab_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._connection_tab_menu.grab_release()

    def _start_connection_tab_drag(self, event):
        """Remember the outer workspace tab clicked by the user."""
        if not self._conn_notebook.identify(event.x, event.y):
            self._dragged_connection_tab = None
            return
        try:
            tab_index = self._conn_notebook.index(f"@{event.x},{event.y}")
            self._dragged_connection_tab = self._conn_notebook.tabs()[tab_index]
        except tk.TclError:
            self._dragged_connection_tab = None

    def _drag_connection_tab(self, event):
        """Move the clicked workspace tab as it is dragged across other tabs."""
        if self._dragged_connection_tab is None:
            return
        try:
            target_index = self._conn_notebook.index(f"@{event.x},{event.y}")
        except tk.TclError:
            return
        target_box = self._conn_notebook.bbox(target_index)
        if target_box and event.x >= target_box[0] + target_box[2] / 2:
            target_index += 1
        if self._conn_notebook.index(self._dragged_connection_tab) != target_index:
            self._conn_notebook.insert(target_index, self._dragged_connection_tab)

    def _finish_connection_tab_drag(self, _event):
        self._dragged_connection_tab = None

    def _close_connection_tab(self, tab):
        """Close an outer workspace tab and release its SSH resources."""
        if str(tab) not in self._conn_notebook.tabs():
            return

        label = self._conn_notebook.tab(tab, "text").strip()
        self._conn_notebook.forget(tab)
        for tab_id, connection_tab in list(self._conn_tabs.items()):
            if connection_tab is tab:
                del self._conn_tabs[tab_id]
                break
        tab.destroy()
        self._status_var.set(f"Closed {label}")
        self._update_statusbar()

    def _import_profiles_preview(self):
        """Preview a secret-free import and collect explicit collision choices."""
        path = filedialog.askopenfilename(title="Preview profile import", filetypes=(("JSON files", "*.json"),))
        if not path:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Import Profiles")
        dialog.configure(bg=BG)
        dialog.minsize(760, 430)
        dialog._closed = False
        dialog._import_running = False
        status = tk.StringVar(value="Loading import preview…")
        tk.Label(dialog, textvariable=status, bg=BG, fg=TEXT, font=FONT).pack(anchor="w", padx=12, pady=(10, 6))
        tree = ttk.Treeview(
            dialog, columns=("name", "identity", "status", "error", "decision"), show="headings", height=12
        )
        for key, label, width in (
            ("name", "Profile", 170),
            ("identity", "Identity", 180),
            ("status", "Status", 90),
            ("error", "Details", 230),
            ("decision", "Decision", 100),
        ):
            tree.heading(key, text=label)
            tree.column(key, width=width, stretch=key in {"name", "identity", "error"})
        tree.pack(fill="both", expand=True, padx=12, pady=4)

        controls = ttk.LabelFrame(dialog, text="Collision decision", padding=8)
        decision_var = tk.StringVar(value="Skip")
        rename_var = tk.StringVar()
        target_var = tk.StringVar()
        controls.columnconfigure(3, weight=1)
        ttk.Label(controls, text="Action:").grid(row=0, column=0, sticky="w")
        decision_box = ttk.Combobox(
            controls, textvariable=decision_var, values=("Skip", "Rename", "Replace"), state="readonly", width=12
        )
        decision_box.grid(row=0, column=1, sticky="w", padx=(6, 12))
        rename_label = ttk.Label(controls, text="New name:")
        rename_entry = ttk.Entry(controls, textvariable=rename_var, width=28)
        target_label = ttk.Label(controls, textvariable=target_var, foreground=MUTED)
        inline_error = tk.StringVar()
        ttk.Label(controls, textvariable=inline_error, foreground=RED).grid(
            row=1, column=0, columnspan=4, sticky="w", pady=(5, 0)
        )

        buttons = ttk.Frame(dialog)
        buttons.pack(fill="x", padx=12, pady=10)
        apply_button = ttk.Button(buttons, text="Apply import", state="disabled")
        apply_button.pack(side="right")

        def alive() -> bool:
            if getattr(dialog, "_closed", True):
                return False
            try:
                return bool(dialog.winfo_exists())
            except tk.TclError:
                return False

        def dispatch(callback) -> None:
            """Schedule a worker result only while the Tk application is alive."""
            try:
                self.after(0, callback)
            except (RuntimeError, tk.TclError):
                # The application is already closing; worker results are stale.
                return

        def close_dialog():
            dialog._closed = True
            dialog.destroy()

        ttk.Button(buttons, text="Close", command=close_dialog).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        row_by_index: dict[int, ImportPreviewRow] = {}
        current_index: list[int | None] = [None]
        model: list[ImportDecisionModel | None] = [None]

        def identity(profile: dict) -> str:
            port = profile.get("port", 22)
            suffix = f":{port}" if port != 22 else ""
            return f"{profile.get('user', '')}@{profile.get('host', '')}{suffix}"

        def refresh_apply() -> None:
            current_model = model[0]
            if not current_model:
                return
            errors = current_model.errors()
            inline_error.set(errors.get(current_index[0], ""))
            for index, row in row_by_index.items():
                if row.status == "Collision":
                    action = current_model.decisions.get(index, "skip")
                    tree.set(str(index), "decision", action.title())
                    tree.set(str(index), "error", errors.get(index, ""))
            enabled = not dialog._import_running and not errors and current_model.eligible_count() > 0
            apply_button.configure(state="normal" if enabled else "disabled")

        def show_controls(index: int | None) -> None:
            current_index[0] = index
            row = row_by_index.get(index) if index is not None else None
            if not row or row.status != "Collision" or not model[0]:
                controls.pack_forget()
                inline_error.set("")
                return
            controls.pack(fill="x", padx=12, pady=(0, 4), before=buttons)
            action = model[0].decisions.get(index, "skip")
            decision_var.set(action.title())
            rename_label.grid_remove()
            rename_entry.grid_remove()
            target_label.grid_remove()
            if action == "rename":
                rename_label.grid(row=0, column=2, sticky="w")
                rename_entry.grid(row=0, column=3, sticky="ew", padx=(6, 0))
                rename_var.set(model[0].rename_names.get(index, model[0].default_rename(row)))
            elif action == "replace":
                targets = model[0].collision_targets(row)
                target = next(
                    (item for item in targets if item.get("id") == model[0].replace_targets.get(index)),
                    targets[0] if targets else None,
                )
                target_var.set(
                    f"Replaces: {target.get('name', '')} ({identity(target)})"
                    if target
                    else "No valid replacement target"
                )
                target_label.grid(row=0, column=2, columnspan=2, sticky="w", padx=(6, 0))
            refresh_apply()

        def selection_changed(_event=None) -> None:
            selected = tree.selection()
            show_controls(int(selected[0]) if selected else None)

        def decision_changed(_event=None) -> None:
            index = current_index[0]
            if index is None or not model[0]:
                return
            action = decision_var.get().casefold()
            model[0].decisions[index] = action
            row = row_by_index[index]
            if action == "rename":
                model[0].rename_names.setdefault(index, model[0].default_rename(row))
            elif action == "replace":
                targets = model[0].collision_targets(row)
                if targets:
                    model[0].replace_targets[index] = targets[0]["id"]
            show_controls(index)

        def rename_changed(*_args) -> None:
            index = current_index[0]
            if index is not None and model[0] and model[0].decisions.get(index) == "rename":
                model[0].rename_names[index] = rename_var.get()
                refresh_apply()

        tree.bind("<<TreeviewSelect>>", selection_changed)
        decision_box.bind("<<ComboboxSelected>>", decision_changed)
        rename_var.trace_add("write", rename_changed)

        def apply_import():
            current_model = model[0]
            if (
                not current_model
                or current_model.errors()
                or current_model.eligible_count() <= 0
                or dialog._import_running
            ):
                return
            dialog._import_running = True
            refresh_apply()
            status.set("Importing profiles…")
            decisions = current_model.to_import_mapping()
            rename_names = current_model.rename_mapping()
            replace_targets = current_model.replace_mapping()

            def run():
                try:
                    summary = self._vault._store.import_profiles(Path(path), decisions, rename_names, replace_targets)
                    dispatch(lambda: import_done(summary))
                except Exception as exc:
                    dispatch(lambda error=exc: import_failed(error))

            threading.Thread(target=run, daemon=True).start()

        def import_done(summary):
            if not alive():
                return
            self._vault.entries = self._vault._store.entries
            self._refresh_list()
            self._update_statusbar()
            close_dialog()
            messagebox.showinfo(
                "Import complete",
                f"Imported {summary.imported}; renamed {summary.renamed}; replaced {summary.replaced}; skipped {summary.skipped}; failed {summary.failed}",
            )

        def import_failed(exc):
            if not alive():
                return
            dialog._import_running = False
            status.set("Import failed; no profiles were changed.")
            refresh_apply()
            log(f"Import failed: {redact_secrets(str(exc))}")

        apply_button.configure(command=apply_import)

        def preview_failed(exc):
            if alive():
                status.set("Could not read the import file.")
                log(f"Import preview failed: {redact_secrets(str(exc))}")

        def show_preview(rows):
            if not alive():
                return
            for row in rows:
                row_by_index[row.index] = row
                profile = row.profile or {}
                tree.insert(
                    "",
                    "end",
                    iid=str(row.index),
                    values=(
                        profile.get("name", f"Profile {row.index + 1}"),
                        identity(profile),
                        row.status,
                        row.error,
                        "Skip" if row.status == "Collision" else "",
                    ),
                )
            model[0] = ImportDecisionModel(rows, [dict(profile) for profile in self._vault.entries])
            status.set(f"{len(rows)} profile(s) previewed. Select a collision to choose an action.")
            refresh_apply()

        def preview_worker():
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                if not isinstance(data, dict) or data.get("version") != 2 or not isinstance(data.get("profiles"), list):
                    raise ProfileError("Unsupported import format.")
                rows = build_import_preview(data["profiles"], [dict(profile) for profile in self._vault.entries])
                dispatch(lambda: show_preview(rows))
            except Exception as exc:
                dispatch(lambda error=exc: preview_failed(error))

        threading.Thread(target=preview_worker, daemon=True).start()

    def _import_ssh_config(self):
        cfg_path = Path.home() / ".ssh" / "config"
        if not cfg_path.exists() or not paramiko:
            messagebox.showinfo("Import", "~/.ssh/config not found or paramiko missing.")
            return
        cfg = paramiko.SSHConfig()
        with open(cfg_path) as f:
            cfg.parse(f)
        existing = {(e.get("host"), e.get("port", 22), e.get("user", "root")) for e in self._vault.entries}
        added = skipped = 0
        for alias in cfg.get_hostnames():
            if alias in ("*", ""):
                continue
            info = cfg.lookup(alias)
            hostname = info.get("hostname", alias)
            port = int(info.get("port", 22))
            user = info.get("user", "root")
            proxy = info.get("proxyjump", "")
            key_path = ""
            for f in info.get("identityfile", []):
                p = Path(str(f).replace("%d", str(Path.home())))
                if p.exists():
                    key_path = str(p)
                    break
            if (hostname, port, user) in existing:
                skipped += 1
                continue
            self._vault.add(
                {
                    "name": alias,
                    "host": hostname,
                    "port": port,
                    "user": user,
                    "auth_method": "key" if key_path else "agent",
                    "key_path": key_path,
                    "proxy_jump": proxy,
                    "tags": ["ssh-config"] + (["proxyjump"] if proxy else []),
                    "notes": "Imported from ~/.ssh/config" + (f" | ProxyJump: {proxy}" if proxy else ""),
                }
            )
            added += 1
        self._refresh_list()
        self._update_statusbar()
        messagebox.showinfo("Import", f"Imported {added}, skipped {skipped}.")

    def _keygen(self):
        if not paramiko:
            messagebox.showerror("Key gen", "paramiko not installed.")
            return
        KeyGenDialog(self)

    def _sftp_server_settings(self):
        SFTPServerSettingsDialog(self)

    def _open_log(self):
        dialog = tk.Toplevel(self)
        dialog.title("SSHVault — Activity Log")
        dialog.geometry("820x480")
        LogViewerPanel(dialog).pack(fill="both", expand=True)

    def _open_settings(self):
        SettingsDialog(self)

    def _open_host_keys(self):
        HostKeyManagerDialog(self)

    def _open_diagnostics(self):
        DiagnosticsDialog(self)

    def _restore_session(self):
        """Load a clean-shutdown restore list without ever connecting on startup."""
        self._pending_restore_profile_ids: list[str] = []
        self._pending_restore_records: list[dict] = []
        self._pending_restore_indices: list[int] = []  # compatibility for old callers/tests
        if not SESSION_FILE.exists():
            if hasattr(self, "_update_profile_actions"):
                self._update_profile_actions()
            return
        try:
            saved = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            if hasattr(self, "_update_profile_actions"):
                self._update_profile_actions()
            return
        if not isinstance(saved, dict) or not saved.get("clean_shutdown"):
            if hasattr(self, "_update_profile_actions"):
                self._update_profile_actions()
            return
        ids = None
        legacy_profile_ids = False
        records = saved.get("sessions")
        if isinstance(records, list):
            self._pending_restore_records = [
                dict(record)
                for record in records
                if isinstance(record, dict)
                and record.get("restore_eligible") is True
                and record.get("was_connected") is True
                and isinstance(record.get("profile_id"), str)
                and any(entry.get("id") == record["profile_id"] for entry in self._vault.entries)
            ]
            self._pending_restore_profile_ids = [record["profile_id"] for record in self._pending_restore_records]
        else:
            ids = saved.get("profile_ids")
            if isinstance(ids, list):
                legacy_profile_ids = True
                self._pending_restore_profile_ids = [
                    profile_id
                    for profile_id in ids
                    if isinstance(profile_id, str) and any(e.get("id") == profile_id for e in self._vault.entries)
                ]
                self._pending_restore_records = [
                    {"profile_id": profile_id, "restore_eligible": True, "was_connected": True}
                    for profile_id in self._pending_restore_profile_ids
                ]
            else:
                ids = None
        if ids is None and not self._pending_restore_records:
            # Legacy snapshots used unstable list positions.  Convert only the
            # snapshot, retain a backup, and never touch the profile vault.
            indices = saved.get("open_indices", [])
            self._pending_restore_indices = [
                idx for idx in indices if isinstance(idx, int) and 0 <= idx < len(self._vault.entries)
            ]
            self._pending_restore_profile_ids = [
                str(self._vault.entries[idx].get("id")) for idx in self._pending_restore_indices
            ]
            self._pending_restore_records = [
                {"profile_id": profile_id, "restore_eligible": True, "was_connected": True}
                for profile_id in self._pending_restore_profile_ids
            ]
            if self._pending_restore_indices:
                backup = SESSION_FILE.with_suffix(".pre-id-migration.json")
                suffix = 2
                while backup.exists():
                    backup = SESSION_FILE.with_suffix(f".pre-id-migration-{suffix}.json")
                    suffix += 1
                try:
                    shutil.copy2(SESSION_FILE, backup)
                    atomic_json_write(
                        SESSION_FILE,
                        {"schema_version": 2, "clean_shutdown": True, "sessions": self._pending_restore_records},
                    )
                except OSError:
                    pass
        elif legacy_profile_ids:
            backup = SESSION_FILE.with_suffix(".pre-session-schema-migration.json")
            suffix = 2
            while backup.exists():
                backup = SESSION_FILE.with_suffix(f".pre-session-schema-migration-{suffix}.json")
                suffix += 1
            try:
                shutil.copy2(SESSION_FILE, backup)
                atomic_json_write(
                    SESSION_FILE,
                    {"schema_version": 2, "clean_shutdown": True, "sessions": self._pending_restore_records},
                )
            except OSError:
                pass
        # If this run crashes, the older snapshot must not be mistaken for
        # the immediately preceding clean shutdown.  The in-memory list still
        # supports the explicit Restore Previous Sessions command.
        try:
            atomic_json_write(
                SESSION_FILE, {"schema_version": 2, "clean_shutdown": False, "sessions": self._pending_restore_records}
            )
        except OSError:
            pass
        if hasattr(self, "_update_profile_actions"):
            self._update_profile_actions()

    def _restore_previous_sessions(self, startup: bool = False):
        """Explicitly restore only clean-shutdown connected sessions once."""
        restored = 0
        for profile_id in list(self._pending_restore_profile_ids):
            idx = next((i for i, profile in enumerate(self._vault.entries) if profile.get("id") == profile_id), None)
            if idx is None:  # deleted profiles are intentionally not resurrected
                continue
            self._connect_by_idx(idx)
            restored += 1
        # Legacy tests and integrations may still set the old pending indices.
        for idx in list(self._pending_restore_indices):
            if idx not in range(len(self._vault.entries)):
                continue
            if str(self._vault.entries[idx].get("id")) not in self._pending_restore_profile_ids:
                self._connect_by_idx(idx)
                restored += 1
        self._pending_restore_profile_ids = []
        self._pending_restore_indices = []
        if hasattr(self, "_update_profile_actions"):
            self._update_profile_actions()
        if startup:
            self._status_var.set(
                f"Restoring {restored} previous session(s)…" if restored else "No sessions to restore."
            )
        elif restored:
            self._status_var.set(f"Restoring {restored} previous session(s)…")
        else:
            self._status_var.set("No clean previous sessions to restore.")

    def _save_session(self):
        sessions = [
            record.restoration_record()
            for record in self._session_controller.sessions.values()
            if record.state is SessionLifecycleState.CONNECTED
            and any(item.get("id") == record.profile_id for item in self._vault.entries)
        ]
        atomic_json_write(SESSION_FILE, {"schema_version": 2, "clean_shutdown": True, "sessions": sessions})

    def _on_close(self):
        self._save_session()
        # Disconnect every open session before tearing down the window;
        # otherwise SSH clients/channels and their panels are left dangling
        # and the app can linger instead of closing completely.
        for tab in list(self._conn_tabs.values()):
            try:
                tab.shutdown()
            except Exception:
                pass
        for scheduler in self._sftp_transfer_schedulers.values():
            scheduler.shutdown()
        self._native_terminal_backend.close()
        self.destroy()


def main() -> None:
    """Launch the SSHVault desktop application."""
    # Desktop launchers may inherit a stale agent variable; select a live
    # user-session socket before any connection or native terminal starts.
    prepare_agent_environment()
    app = SSHVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
