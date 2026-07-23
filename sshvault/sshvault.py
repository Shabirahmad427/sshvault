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
from sshvault_security import (
    ChangedHostKeyRejected,
    KnownHostsStore,
    SSHConnectionManager,
    TrustDecision,
    UnknownHostCancelled,
    ProxyConnectionContext,
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
    TunnelFormState,
    TunnelRuntime,
    CommandExecutionState,
    atomic_json_write,
    validate_settings,
    AppearanceState,
    confirm_multiline_paste_enabled,
    confirm_delete_enabled,
    confirm_overwrite_enabled,
    SessionDashboardState,
    ImportPreviewRow,
    ImportDecisionModel,
    build_import_preview,
    friendly_connection_error,
    redact_secrets,
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
        )
        sb = ttk.Scrollbar(self, command=self._text.yview)
        self._text.configure(yscrollcommand=sb.set)
        self._text.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
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
        self._input_mode_tail = ""
        self._find_matches: list[str] = []
        self._find_index = -1
        self.on_resize = None

        if pyte:
            self._screen = _ScrollbackScreen(cols, rows, self._queue_scrollback)
            self._stream = pyte.Stream(self._screen)
        else:
            self._screen = None
            self._stream = None

        for _ in range(rows):
            self._text.insert("end", "\n")
        self._text.mark_set("live_start", "1.0")

        self._text.bind("<Key>", self._on_key)
        # Bind these explicitly so Tk does not use Tab for focus traversal;
        # the remote shell receives it for command and path completion.
        self._text.bind("<Tab>", self._on_key)
        self._text.bind("<Shift-Tab>", self._on_key)
        self._text.bind("<Control-v>", self._on_paste)
        self._text.bind("<Control-V>", self._on_paste)
        self._text.bind("<Control-Shift-V>", self._on_paste)
        self._text.bind("<Shift-Insert>", self._on_paste)
        self._text.bind("<Button-2>", self._on_paste)
        self._text.bind("<Button-3>", self._show_context_menu)
        self._text.bind("<Configure>", self._on_configure)
        self._text.bind("<Button-1>", self._on_click)
        self._text.bind("<Motion>", self._on_motion)
        self._text.bind("<MouseWheel>", self._on_scroll)
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
            self._stream.feed(data)
            self._redraw_pending = True

    def _fallback_append(self, data):
        self._text.configure(state="normal")
        self._text.insert("end", re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07", "", data))
        self._refresh_links()
        self._text.see("end")

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
            self.after(0, lambda g=generation: self._terminal_state.ended(g, lost=True))

    @staticmethod
    def _writer(channel, stop, outbound):
        """Serialize writes: Channel.send() is allowed to be partial."""
        while not stop.is_set() and not channel.closed:
            try:
                data = outbound.get(timeout=0.1)
                if data is None:
                    break
                channel.sendall(data)
            except queue.Empty:
                continue
            except Exception:
                break

    def _send(self, data: str):
        if data and self._channel and not self._channel.closed:
            self._outbound.put(data)

    def _track_input_modes(self, data: str):
        """Remember DECSET 2004 even when its escape sequence is split."""
        scan = self._input_mode_tail + data
        for enabled in re.findall(r"\x1b\[\?2004([hl])", scan):
            self._bracketed_paste = enabled == "h"
        self._input_mode_tail = scan[-16:]

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
        fg = _NAME_COLORS.get(ch.fg, TEXT) if ch.fg != "default" else TEXT
        bg = _NAME_COLORS.get(ch.bg, _TERM_BG) if ch.bg != "default" else _TERM_BG
        if ch.reverse:
            fg, bg = bg, fg
        key = (fg, bg, ch.bold, ch.underscore)
        tagname = self._tag_cache.get(key)
        if tagname is None:
            tagname = f"style{len(self._tag_cache)}"
            opts = {"foreground": fg, "background": bg}
            if ch.bold:
                opts["font"] = (MONO[0], MONO[1], "bold")
            if ch.underscore:
                opts["underline"] = True
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

        at_bottom = self._text.yview()[1] >= 0.999
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
            self._text.tag_configure("cursor", background=ACCENT, foreground=BG)
            self._cursor_range = (cpos, cend)

        if touched_lines:
            self._refresh_links(touched_lines)
        if scrollback and at_bottom:
            self._terminal_state.follow_output = True
        if scrollback and self._terminal_state.follow_output:
            self._text.see("end")

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
        seq = _KEY_SEQS.get(ks)
        # xterm's modified navigation sequences are needed by readline, tmux,
        # vim, and full-screen programs. Tk exposes modifiers in state bits.
        modifiers = event.state & (0x0001 | 0x0004 | 0x0008)  # Shift, Ctrl, Alt
        if modifiers and ks in ("Up", "Down", "Right", "Left", "Home", "End"):
            mod = 1 + bool(modifiers & 0x0001) + 4 * bool(modifiers & 0x0004) + 2 * bool(modifiers & 0x0008)
            suffix = {"Up": "A", "Down": "B", "Right": "C", "Left": "D", "Home": "H", "End": "F"}[ks]
            seq = f"\x1b[1;{mod}{suffix}"
        if seq is None:
            seq = event.char
            if ks == "space" and modifiers & 0x0004:
                seq = "\x00"
            elif seq and modifiers & 0x0008:
                seq = "\x1b" + seq
        if seq:
            self._send(seq)
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
        self._terminal_state.follow_output = self._text.yview()[1] >= 0.999
        self._text.yview_scroll(-1 if event.delta > 0 else 1, "units")
        return "break"

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
        self._context_menu.add_command(label="Select all", command=self._select_all)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="Clear terminal", command=self.clear)
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

    def _select_all(self):
        self._text.tag_add("sel", "1.0", "end-1c")
        self._text.mark_set("insert", "end-1c")
        self._text.see("insert")

    def _on_click(self, event):
        url = self._url_at_index(f"@{event.x},{event.y}")
        if url:
            try:
                subprocess.Popen(["xdg-open", url])
            except Exception:
                pass
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
        # Rebuild only the live grid.  Incremental newline arithmetic here
        # used to delete an extra row on shrink, and inserting after a mark
        # with right gravity could move live_start below the terminal grid.
        grid_start = self._text.index("live_start")
        self._text.delete(grid_start, "end")
        self._text.insert("end", "\n" * rows)
        self._text.mark_set("live_start", grid_start)
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
        self._text.delete("1.0", "end")
        self._cursor_range = None
        for _ in range(self._rows):
            self._text.insert("end", "\n")
        # Set the mark *after* creating the grid. Its right gravity is
        # intentional for scrollback, but would otherwise move it to the end.
        self._text.mark_set("live_start", "1.0")
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
class SFTPPanel(tk.Frame):
    def __init__(self, parent, sftp, default_local_directory=None, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._sftp = sftp
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
        self._transfer_cancel = threading.Event()
        self._closed = False
        self._remote_generation = 0
        self._sftp_state = SFTPPanelState()
        self._local_load_state = DirectoryLoadState()
        self._local_load_lock = threading.Lock()
        self._local_load_path = self._local_cwd
        self._remote_navigation_busy = False
        self._path_menu = tk.Menu(self, tearoff=0)
        self._completion_menu = tk.Menu(self, tearoff=0)
        self._build()
        self._transfer_thread = threading.Thread(target=self._transfer_worker, daemon=True)
        self._transfer_thread.start()
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

    def _build(self):
        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x", padx=4, pady=2)
        tk.Label(top, text="SFTP", bg=PANEL, fg=ACCENT, font=FONT_B).pack(side="left")
        self._progress_var = tk.DoubleVar()
        self._progress = ttk.Progressbar(top, variable=self._progress_var, maximum=100, length=200)
        self._progress.pack(side="right", padx=8)
        self._status_var = tk.StringVar(value="Disconnected")
        tk.Label(top, textvariable=self._status_var, bg=PANEL, fg=MUTED, font=FONT).pack(side="right", padx=4)

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
        self._transfer_cancel.set()
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
        """Return the hidden, resumable staging path for a local file."""
        return local.parent / f".{local.name}.sshvault-partial"

    def _remote_size(self, remote: str):
        try:
            return self._sftp.stat(remote).st_size
        except (FileNotFoundError, IOError, OSError):
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
        except (IOError, OSError, NotImplementedError):
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
            while chunk := source.read(256 * 1024):
                target.write(chunk)
                transferred += len(chunk)
                self._progress_cb(transferred, total)

        if not self._same_file(local, partial, total):
            raise IOError(f"Upload verification failed for {local.name}")

        # paramiko's standard rename is not guaranteed to overwrite an existing
        # target, so replace the known incomplete target before finalizing.
        try:
            self._sftp.remove(remote)
        except (FileNotFoundError, IOError, OSError):
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
            while chunk := source.read(256 * 1024):
                target.write(chunk)
                transferred += len(chunk)
                self._progress_cb(transferred, total)

        if not self._same_file(partial, remote, total):
            raise IOError(f"Download verification failed for {local.name}")
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
                self._transfer_queue.put(
                    lambda local_path=local, r=remote, n=name, replace=decision == "replace": (
                        self._upload_with_cleanup(Path(local_path), r, replace),
                        self.after(0, self._refresh_remote),
                    )
                )

    def _upload_folder(self):
        sel = self._local_tree.selection()
        if not sel:
            return
        for name in sel:
            if name == "..":
                continue
            local = Path(self._local_cwd) / name
            if local.is_dir():
                self._set_status(f"Uploading folder {name}…")
                self._transfer_queue.put(
                    lambda local_path=local, n=name: (
                        self._upload_dir(local_path, self._remote_join(self._remote_cwd, n)),
                        self.after(0, self._refresh_remote),
                    )
                )

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
            decision, local = self._download_collision_decision(name, local)
            if decision == "skip":
                continue
            self._transfer_cancel.clear()
            self._sftp_state.start_transfer(name, now=time.monotonic())
            self._update_transfer_actions()
            self._set_status(f"Downloading {name}…")
            self._transfer_queue.put(
                lambda r=remote, local_path=local, replace=decision == "replace": (
                    self._download_with_cleanup(r, local_path, replace),
                    self.after(0, self._refresh_local),
                )
            )

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
            self._set_status(f"Downloading folder {name}…")
            self._transfer_queue.put(
                lambda r=remote, local_path=local: (
                    self._download_dir(r, local_path),
                    self.after(0, self._refresh_local),
                )
            )

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
    def __init__(self, parent, client, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._client = client
        self._tunnels: list[dict] = []
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

        tk.Button(
            self, text="Stop selected", command=self._stop_tunnel, bg=RED, fg=BG, font=FONT, relief="flat", padx=8
        ).pack(anchor="w", padx=8, pady=4)
        tk.Button(
            self, text="Stop all", command=self._stop_all_tunnels, bg=PANEL, fg=TEXT, font=FONT, relief="flat", padx=8
        ).pack(anchor="w", padx=8, pady=(0, 4))
        self._validate_tunnel()

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
    def __init__(self, parent, entry: dict, vault_entries: list | None = None, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._entry = entry
        self._vault_entries = vault_entries or []
        self._client: "paramiko.SSHClient | None" = None
        self._sftp = None
        self._recording = False
        self._terminals: list[TerminalWidget] = []
        self._sftp_panel = None
        self._ftp_bridge_panel = None
        self._tunnels_panel = None
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
        self._sftp_opening = False
        self._sftp_open_thread = None
        self._trust_broker = TrustDecisionBroker(self)
        self._build()
        self._connect()

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
            ("Reconnect", self._connect),
            ("Disconnect", self._disconnect),
        ):
            ttk.Button(terminal_toolbar, text=label, command=command).pack(side="right", padx=3, pady=3)
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

    def _connect(self):
        if self._workspace_state.status in {"connecting", "disconnecting", "connected"}:
            return
        if not paramiko:
            self._set_workspace_status("failed", "SSH support is unavailable in this installation.")
            self._terminal.write("[error] paramiko not installed\n", "err")
            return
        self._session_generation += 1
        generation = self._session_generation
        self._set_workspace_status("connecting")
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
            secure_profile = dict(self._entry)
            secure_profile["auth_method"] = (
                "key" if self._entry.get("key_path") else "password" if self._entry.get("password") else "agent"
            )
            secure_profile.setdefault("timeout", 15)
            secure_profile.setdefault("compression", False)
            secure_profile["host_role"] = "Destination host"
            extra = {}
            # ProxyJump
            proxy_alias = self._entry.get("proxy_jump", "").strip()
            if proxy_alias:
                extra["sock"] = self._make_proxy_sock(
                    proxy_alias, self._entry["host"], int(self._entry.get("port", 22)), generation
                )
            if secure_profile["auth_method"] == "agent":
                # no explicit credential — collect all default keys from ~/.ssh/
                # and also check ~/.ssh/config for this host's IdentityFile
                key_files = []
                ssh_cfg = paramiko.SSHConfig()
                cfg_path = Path.home() / ".ssh" / "config"
                if cfg_path.exists():
                    with open(cfg_path) as f:
                        ssh_cfg.parse(f)
                cfg_info = ssh_cfg.lookup(self._entry.get("name", self._entry["host"]))
                for raw in cfg_info.get("identityfile", []):
                    p = Path(str(raw).replace("%d", str(Path.home()))).expanduser()
                    if p.exists():
                        key_files.append(str(p))
                for name in ("id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"):
                    p = Path.home() / ".ssh" / name
                    if p.exists() and str(p) not in key_files:
                        key_files.append(str(p))
                if key_files:
                    extra["key_filename"] = key_files
            manager = SSHConnectionManager(
                KnownHostsStore(KNOWN_HOSTS_FILE), secure_profile["host"], secure_profile["port"]
            )
            client = manager.connect(
                secure_profile, self._trust_broker.request, self._entry.get("password") or None, extra
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
            "compression": False,
            "host_role": "Jump host",
        }
        manager = SSHConnectionManager(KnownHostsStore(KNOWN_HOSTS_FILE), proxy_host, proxy_port)
        try:
            proxy_client = manager.connect(proxy_profile, self._trust_broker.request, proxy_pass)
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
        self._terminal.write("[connected]\n", "ok")
        self._attach_shell(self._terminal)

    def _attach_shell(self, terminal: TerminalWidget):
        if not self._client:
            return
        channel = self._client.invoke_shell(term="xterm-256color", width=terminal._cols, height=terminal._rows)
        terminal.attach_channel(channel)

    def _open_terminal(self):
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
        self._set_workspace_status("failed", message)
        self._terminal.write(f"[error] {message}\n", "err")
        log(f"Error: {err}")

    def _disconnect(self):
        if self._workspace_state.status in {"disconnected", "disconnecting"}:
            return
        self._set_workspace_status("disconnecting")
        self._session_generation += 1
        self._sftp_opening = False
        sftp_thread = self._sftp_open_thread
        if sftp_thread is not None and sftp_thread is not threading.current_thread() and sftp_thread.is_alive():
            sftp_thread.join(timeout=0.25)
        self._sftp_open_thread = None
        self._cleanup_connection_panels()
        for terminal in list(self._terminals):
            terminal.detach()
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
        self._terminal.write("\n[disconnected]\n", "info")

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
            self._sftp_panel = SFTPPanel(self._nb, sftp, self._entry.get("default_download_directory"))
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
        self._select_or_create("_tunnels_panel", lambda: PortForwardPanel(self._nb, self._client), "Tunnels")

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
        self._f = tk.Frame(self, bg=BG)
        self._f.pack(padx=8, pady=8)
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
        }
        try:
            if SETTINGS_FILE.exists():
                values.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
        self._vars = {
            key: tk.StringVar(value=str(values[key]))
            for key in ("scrollback_limit", "connection_timeout", "download_directory")
        }
        self._bools = {
            key: tk.BooleanVar(value=bool(values[key]))
            for key in ("confirm_multiline_paste", "confirm_delete", "confirm_overwrite")
        }
        self._appearance = AppearanceState.from_settings(values)
        form = tk.Frame(self, bg=BG)
        form.pack(padx=16, pady=14, fill="both")
        for row, (key, label) in enumerate(
            (
                ("scrollback_limit", "Terminal scrollback lines"),
                ("connection_timeout", "Connection timeout (seconds)"),
                ("download_directory", "Default download directory"),
            )
        ):
            tk.Label(form, text=label, bg=BG, fg=TEXT, font=FONT).grid(row=row, column=0, sticky="w", pady=3)
            tk.Entry(form, textvariable=self._vars[key], bg=PANEL, fg=TEXT, insertbackground=TEXT).grid(
                row=row, column=1, sticky="ew", padx=8
            )
        ttk.Button(form, text="Browse", command=self._browse).grid(row=2, column=2)
        appearance_row = 3
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
        return {
            **{k: v.get() for k, v in self._vars.items()},
            **{k: v.get() for k, v in self._bools.items()},
            "theme": self._theme_var.get().casefold(),
            "application_font_size": self._app_font_var.get(),
            "terminal_font_size": self._term_font_var.get(),
        }

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
        self.configure(bg=BG)
        self.geometry("1200x750")
        self.minsize(900, 550)
        self._apply_style()
        self._runtime_settings = self._load_settings()
        self._apply_appearance(self._runtime_settings)
        self._vault = Vault()
        self._conn_tabs: dict[str, ConnectionTab] = {}
        self._session_serial = 0
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_menu()
        self._build_ui()
        self._build_statusbar()
        self._restore_session()

    def _load_settings(self):
        try:
            return (
                validate_settings(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
                if SETTINGS_FILE.exists()
                else validate_settings({})
            )
        except (OSError, json.JSONDecodeError, ProfileError):
            return validate_settings({})

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
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Generate Key Pair", command=self._keygen)
        tools_menu.add_command(label="Built-in SFTP Server Settings", command=self._sftp_server_settings)
        tools_menu.add_command(label="Activity Log", command=self._open_log)
        tools_menu.add_command(label="Settings", command=self._open_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo(
            "About SSHVault",
            "SSHVault — Bitvise-inspired SSH/SFTP workspace\nProfiles, terminal, SFTP, tunneling, key management.",
        )

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=PANEL, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self._status_var, bg=PANEL, fg=MUTED, font=FONT, anchor="w").pack(
            side="left", padx=8
        )
        self._profile_count_var = tk.StringVar()
        tk.Label(bar, textvariable=self._profile_count_var, bg=PANEL, fg=MUTED, font=FONT, anchor="e").pack(
            side="right", padx=8
        )
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

    def _build_ui(self):
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        sidebar = tk.Frame(pane, bg=PANEL, width=390)
        sidebar.pack_propagate(False)
        header = tk.Frame(sidebar, bg=PANEL)
        header.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(header, text="SSHVault", bg=PANEL, fg=TEXT, font=("TkDefaultFont", 15, "bold")).pack(anchor="w")
        tk.Label(header, text="Saved SSH connections", bg=PANEL, fg=MUTED, font=FONT).pack(anchor="w", pady=(2, 0))
        self._session_count_var = tk.StringVar(value="0 saved")
        tk.Label(header, textvariable=self._session_count_var, bg=PANEL, fg=MUTED, font=("TkDefaultFont", 9)).pack(
            anchor="w", pady=(3, 0)
        )
        self._profile_selection_note = tk.StringVar()
        tk.Label(
            header,
            textvariable=self._profile_selection_note,
            bg=PANEL,
            fg=YELLOW,
            font=("TkDefaultFont", 8),
            anchor="w",
            wraplength=345,
        ).pack(anchor="w", pady=(4, 0))

        search_row = tk.Frame(sidebar, bg=PANEL)
        search_row.pack(fill="x", padx=16, pady=(4, 8))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh_list())
        self._search_entry = ttk.Entry(search_row, textvariable=self._search_var)
        self._search_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(search_row, text="Clear", width=6, command=self._clear_search).pack(side="left", padx=(6, 0))
        sort_row = tk.Frame(sidebar, bg=PANEL)
        sort_row.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(sort_row, text="Sort", bg=PANEL, fg=MUTED, font=FONT).pack(side="left")
        self._sort_var = tk.StringVar(value="Name")
        self._sort_var.trace_add("write", lambda *_: self._refresh_list())
        ttk.Combobox(
            sort_row, textvariable=self._sort_var, values=("Name", "Hostname", "Username"), state="readonly", width=15
        ).pack(side="right")

        tree_frame = tk.Frame(sidebar, bg=PANEL)
        tree_frame.pack(fill="both", expand=True, padx=16)
        columns = ("profile", "details", "auth", "tags")
        self._tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse", style="Profile.Treeview"
        )
        for column, label, width in (
            ("profile", "Profile", 145),
            ("details", "User / host", 170),
            ("auth", "Auth", 78),
            ("tags", "Tags", 120),
        ):
            self._tree.heading(column, text=label)
            self._tree.column(column, width=width, minwidth=65, stretch=column in {"profile", "details", "tags"})
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll.set)
        self._tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._tree.bind("<<TreeviewSelect>>", self._on_profile_selection)
        self._tree.bind("<Double-Button-1>", lambda _event: self._connect())
        self._tree.bind("<Return>", lambda _event: self._connect())
        self._tree.bind("<Button-3>", self._show_profile_context_menu)
        self._empty_profiles = tk.Frame(tree_frame, bg=PANEL)
        self._empty_message = tk.StringVar()
        tk.Label(
            self._empty_profiles,
            textvariable=self._empty_message,
            bg=PANEL,
            fg=MUTED,
            font=FONT,
            justify="center",
            wraplength=310,
        ).pack(pady=(38, 10), padx=20)
        ttk.Button(self._empty_profiles, text="Add Profile", command=self._add_entry).pack()

        actions = tk.Frame(sidebar, bg=PANEL)
        actions.pack(fill="x", padx=16, pady=(12, 16))
        self._add_btn = ttk.Button(actions, text="Add", command=self._add_entry)
        self._add_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4), pady=2)
        self._edit_btn = ttk.Button(actions, text="Edit", command=self._edit_entry)
        self._edit_btn.grid(row=0, column=1, sticky="ew", padx=4, pady=2)
        self._duplicate_btn = ttk.Button(actions, text="Duplicate", command=self._duplicate_entry)
        self._duplicate_btn.grid(row=0, column=2, sticky="ew", padx=(4, 0), pady=2)
        self._delete_btn = ttk.Button(actions, text="Delete", command=self._delete_entry)
        self._delete_btn.grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=2)
        self._import_btn = ttk.Button(actions, text="Import", command=self._import_profiles_preview)
        self._import_btn.grid(row=1, column=1, sticky="ew", padx=4, pady=2)
        self._export_btn = ttk.Button(actions, text="Export Selected", command=self._export_selected)
        self._export_btn.grid(row=1, column=2, sticky="ew", padx=(4, 0), pady=2)
        self._export_all_btn = ttk.Button(actions, text="Export All", command=self._export_all)
        self._export_all_btn.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self._backup_btn = ttk.Button(actions, text="Create Backup", command=self._create_profile_backup)
        self._backup_btn.grid(row=3, column=0, sticky="ew", padx=(0, 4), pady=(6, 0))
        self._restore_btn = ttk.Button(actions, text="Restore Backup", command=self._restore_profile_backup)
        self._restore_btn.grid(row=3, column=1, columnspan=2, sticky="ew", padx=(4, 0), pady=(6, 0))
        self._connect_btn = ttk.Button(actions, text="Connect", command=self._connect)
        self._connect_btn.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        for column in range(3):
            actions.columnconfigure(column, weight=1)
        pane.add(sidebar, weight=0)

        # right notebook
        right = tk.Frame(pane, bg=BG)
        self._conn_notebook = ttk.Notebook(right)
        self._conn_notebook.pack(fill="both", expand=True)
        self._conn_notebook.bind("<Button-3>", self._show_connection_tab_menu)
        self._conn_notebook.bind("<Button-1>", self._start_connection_tab_drag)
        self._conn_notebook.bind("<B1-Motion>", self._drag_connection_tab)
        self._conn_notebook.bind("<ButtonRelease-1>", self._finish_connection_tab_drag)
        self._dragged_connection_tab = None
        self._connection_tab_menu = tk.Menu(self, tearoff=0)
        pane.add(right, weight=1)

        self._profile_context_menu = tk.Menu(self, tearoff=0)
        for label, command in (
            ("Connect", self._connect),
            ("Edit", self._edit_entry),
            ("Duplicate", self._duplicate_entry),
            ("Delete", self._delete_entry),
            ("Export selected profile", self._export_selected),
        ):
            self._profile_context_menu.add_command(label=label, command=command)
        self._bind_profile_shortcuts()
        self._refresh_list()

    def _refresh_list(self):
        selected = self._selected_idx()
        selected_id = self._vault.entries[selected].get("id") if selected is not None else None
        state = ProfileSidebarState(self._vault.entries, self._search_var.get(), self._sort_var.get(), selected_id)
        self._tree.delete(*self._tree.get_children())
        visible = state.visible_profiles()
        for entry in visible:
            index = self._vault.entries.index(entry)
            host = entry.get("host", "")
            details = f"{entry.get('user', '')}@{host}" + (
                f":{entry.get('port')}" if entry.get("port", 22) != 22 else ""
            )
            auth = {"agent": "Agent", "password": "Password", "key": "Key"}.get(entry.get("auth_method"), "Agent")
            self._tree.insert(
                "",
                "end",
                iid=str(index),
                values=(entry.get("name", host), details, auth, ", ".join(entry.get("tags", []))),
            )
        if selected_id:
            for index, entry in enumerate(self._vault.entries):
                if entry.get("id") == selected_id and self._tree.exists(str(index)):
                    self._tree.selection_set(str(index))
                    self._tree.focus(str(index))
                    break
        empty = state.empty_state()
        if empty:
            self._empty_message.set(empty)
            self._empty_profiles.place(relx=0, rely=0, relwidth=1, relheight=1)
        else:
            self._empty_profiles.place_forget()
        if hasattr(self, "_session_count_var"):
            total = len(self._vault.entries)
            self._session_count_var.set(
                f"{len(visible)} of {total} saved" if self._search_var.get() else f"{total} saved"
            )
        self._update_profile_actions()

    def _selected_idx(self) -> int | None:
        sel = self._tree.selection()
        return int(sel[0]) if sel else None

    def _clear_search(self):
        self._search_var.set("")
        self._search_entry.focus_set()

    def _update_profile_actions(self):
        selected = self._selected_idx() is not None
        for button in (self._edit_btn, self._duplicate_btn, self._delete_btn, self._export_btn, self._connect_btn):
            button.configure(state="normal" if selected else "disabled")

    def _on_profile_selection(self, _event=None):
        self._update_profile_actions()
        idx = self._selected_idx()
        if idx is None:
            self._profile_selection_note.set("")
            return
        selected = self._vault.entries[idx]
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

    def _show_profile_context_menu(self, event):
        item = self._tree.identify_row(event.y)
        if item:
            self._tree.selection_set(item)
            self._tree.focus(item)
            self._update_profile_actions()
            self._profile_context_menu.tk_popup(event.x_root, event.y_root)

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
        self.bind_all("<Control-f>", lambda event: self._profile_shortcut(event, self._search_entry.focus_set), add="+")
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
        idx = self._selected_idx()
        if idx is None:
            return
        source = self._vault.entries[idx]
        state = ProfileSidebarState(self._vault.entries)
        duplicate = {key: value for key, value in source.items() if key not in {"id", "password", "passphrase"}}
        duplicate["name"] = state.duplicate_name(source)
        dlg = EntryDialog(self, duplicate)
        if dlg.result:
            try:
                self._vault.add(dlg.result, dlg.secret or "")
            except ProfileError as exc:
                messagebox.showerror("Could not duplicate connection", str(exc))
                return
            self._refresh_list()
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

    def _connect_by_idx(self, idx: int):
        if not paramiko:
            return
        profile = self._vault.entries[idx]
        self._status_var.set(f"Connecting to {profile.get('name', profile.get('host', 'profile'))}…")
        # Profiles remain secret-free. ConnectionTab receives only a short-
        # lived in-memory copy when password authentication needs a credential.
        entry = dict(profile)
        entry["timeout"] = self._runtime_settings.get("connection_timeout", 15)
        entry["default_download_directory"] = self._runtime_settings.get("download_directory", "")
        if profile.get("auth_method") == "password":
            entry["password"] = self._vault.secret_for(profile) or ""
        runtime_entries = []
        for candidate in self._vault.entries:
            runtime = dict(candidate)
            if candidate.get("auth_method") == "password":
                runtime["password"] = self._vault.secret_for(candidate) or ""
            runtime_entries.append(runtime)
        tab = ConnectionTab(self._conn_notebook, entry, vault_entries=runtime_entries)
        # Each click starts an independent SSH connection, even for the same
        # saved profile. A serial key keeps the session registry unambiguous.
        self._session_serial += 1
        tab_id = f"session-{self._session_serial}"
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
        panel = LogViewerPanel(self._conn_notebook)
        self._conn_notebook.add(panel, text="  Log  ")
        self._conn_notebook.select(panel)

    def _open_settings(self):
        SettingsDialog(self)

    def _restore_session(self):
        if not SESSION_FILE.exists():
            return
        try:
            indices = json.loads(SESSION_FILE.read_text())
        except Exception:
            return
        for idx in indices:
            if isinstance(idx, int) and idx < len(self._vault.entries):
                self._connect_by_idx(idx)

    def _save_session(self):
        open_indices = []
        for tab_id, tab in self._conn_tabs.items():
            e = tab._entry
            for i, ve in enumerate(self._vault.entries):
                if (
                    ve.get("host") == e.get("host")
                    and ve.get("port", 22) == e.get("port", 22)
                    and ve.get("user", "root") == e.get("user", "root")
                ):
                    open_indices.append(i)
                    break
        SESSION_FILE.write_text(json.dumps(open_indices))

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
        self.destroy()


def main() -> None:
    """Launch the SSHVault desktop application."""
    app = SSHVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
