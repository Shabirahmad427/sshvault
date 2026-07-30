"""GTK/VTE control-plane helper.  Terminal bytes never leave this process."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sys
from typing import Any
from uuid import uuid4


NATIVE_VTE_CLOSE_TAB_LABEL = "Close This Terminal"


def _terminal_tab_label(Gtk: Any, title: str, close_callback: Any) -> Any:
    """Build a compact per-tab label with an independent close control."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
    label = Gtk.Label(label=title)
    close_button = Gtk.Button(label="×")
    close_button.set_relief(Gtk.ReliefStyle.NONE)
    close_button.set_focus_on_click(False)
    close_button.set_tooltip_text(NATIVE_VTE_CLOSE_TAB_LABEL)
    close_button.connect("clicked", close_callback)
    box.pack_start(label, True, True, 0)
    box.pack_start(close_button, False, False, 0)
    box.show_all()
    return box


def _send(connection: socket.socket, message: dict[str, Any]) -> None:
    connection.sendall((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))


def _environment() -> list[str]:
    names = {
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "LANG",
        "LANGUAGE",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
    }
    names.update(name for name in os.environ if name.startswith("LC_"))
    return [f"{name}={os.environ[name]}" for name in sorted(names) if os.environ.get(name)]


def _load_gtk() -> tuple[Any, Any, Any]:
    try:
        import gi

        gi.require_version("Gtk", "3.0")
        gi.require_version("Vte", "2.91")
        from gi.repository import GLib, Gtk, Vte
    except (ImportError, ValueError) as exc:
        raise RuntimeError(f"GI/VTE import failed: {exc}") from exc
    return GLib, Gtk, Vte


def probe() -> int:
    try:
        _load_gtk()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def main(socket_path: str, token: str) -> int:
    try:
        GLib, Gtk, Vte = _load_gtk()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    path = Path(socket_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(1)
        connection, _ = listener.accept()
        connection.setblocking(False)
        Vte.Terminal()  # validate display and typelib before readiness
        _send(connection, {"type": "ready", "token": token})
    except (OSError, RuntimeError, TypeError) as exc:
        print(f"display unavailable or IPC socket could not be created: {exc}", file=sys.stderr)
        listener.close()
        return 3

    windows: dict[str, Any] = {}
    terminals: dict[str, dict[str, Any]] = {}
    title_counts: dict[str, int] = {}
    pending = b""
    child_envv = _environment()

    def response(request_id: Any, ok: bool, **data: Any) -> None:
        _send(connection, {"type": "response", "token": token, "request_id": request_id, "ok": ok, **data})

    def maybe_quit() -> None:
        if not terminals:
            Gtk.main_quit()

    def new_window() -> str:
        window_id = str(uuid4())
        window = Gtk.Window(title="SSHVault — Native VTE")
        notebook = Gtk.Notebook()
        window.add(notebook)
        window.set_default_size(1000, 700)
        windows[window_id] = {"window": window, "notebook": notebook, "tabs": []}

        def destroyed(_window: Any) -> None:
            container = windows.pop(window_id, {})
            for terminal_id in list(container.get("tabs", [])):
                close_tab(terminal_id)
            maybe_quit()

        window.connect("destroy", destroyed)
        return window_id

    def close_tab(terminal_id: str) -> bool:
        item = terminals.pop(terminal_id, None)
        if item is None:
            return False
        try:
            pid = item.get("pid")
            if isinstance(pid, int) and pid > 0:
                os.kill(pid, signal.SIGHUP)
        except OSError:
            pass
        container = windows.get(item["window_id"])
        if container:
            notebook = container["notebook"]
            notebook.remove_page(notebook.page_num(item["page"]))
            container["tabs"].remove(terminal_id)
            if not container["tabs"]:
                container["window"].destroy()
        return True

    def open_terminal(message: dict[str, Any], force_new_window: bool) -> tuple[str, str]:
        argv = message.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
            raise ValueError("invalid OpenSSH command")
        requested = message.get("window_id")
        window_id = (
            str(requested) if not force_new_window and isinstance(requested, str) and requested in windows else ""
        )
        if not window_id:
            window_id = new_window()
        terminal_id = str(uuid4())
        terminal = Vte.Terminal()
        options = message.get("terminal_options")
        options = options if isinstance(options, dict) else {}
        try:
            scrollback = int(options.get("scrollback", 10000))
        except (TypeError, ValueError):
            scrollback = 10000
        terminal.set_scrollback_lines(max(0, min(scrollback, 100000)))
        terminal.set_scroll_on_output(bool(options.get("scroll_on_output", False)))
        terminal.set_scroll_on_keystroke(bool(options.get("scroll_on_keystroke", True)))
        try:
            terminal.set_audible_bell(options.get("bell", "System bell") == "System bell")
        except AttributeError:
            pass
        base = str(message.get("title", "SSHVault"))
        title_counts[base] = title_counts.get(base, 0) + 1
        title = base if title_counts[base] == 1 else f"{base} ({title_counts[base]})"
        page = Gtk.ScrolledWindow()
        page.add(terminal)
        container = windows[window_id]
        tab_label = _terminal_tab_label(
            Gtk,
            title,
            lambda _button, current=terminal_id: close_tab(current),
        )
        container["notebook"].append_page(page, tab_label)
        container["tabs"].append(terminal_id)
        terminals[terminal_id] = {
            "terminal": terminal,
            "page": page,
            "window_id": window_id,
            "title": title,
            "pid": None,
        }

        def spawned(_terminal: Any, pid: int, error: Any, _data: Any) -> None:
            if error is not None:
                return
            if terminal_id in terminals:
                terminals[terminal_id]["pid"] = pid

        terminal.spawn_async(
            Vte.PtyFlags.DEFAULT,
            None,
            argv,
            child_envv,
            GLib.SpawnFlags.SEARCH_PATH,
            None,
            None,
            -1,
            None,
            spawned,
            None,
        )

        def keypress(widget: Any, event: Any) -> bool:
            ctrl, shift = bool(event.state & 4), bool(event.state & 1)
            if ctrl and shift and event.keyval in (ord("c"), ord("C")):
                if widget.get_has_selection():
                    widget.copy_clipboard()
                return True
            if ctrl and shift and event.keyval in (ord("v"), ord("V")):
                widget.paste_clipboard()
                return True
            if ctrl and event.keyval == 65379:  # Insert
                if widget.get_has_selection():
                    widget.copy_clipboard()
                return True
            if shift and event.keyval == 65379:
                widget.paste_clipboard()
                return True
            return False  # notably preserves Ctrl-C and native selection keys

        terminal.connect("key-press-event", keypress)

        def menu(_widget: Any, event: Any) -> bool:
            if event.button != 3:
                return False
            popup = Gtk.Menu()
            has_selection = terminal.get_has_selection()
            copy = Gtk.MenuItem(label="Copy")
            copy.set_sensitive(has_selection)
            copy.connect("activate", lambda *_: terminal.copy_clipboard())
            paste = Gtk.MenuItem(label="Paste")
            paste.connect("activate", lambda *_: terminal.paste_clipboard())
            select_all = Gtk.MenuItem(label="Select All")
            select_all.connect("activate", lambda *_: terminal.select_all())
            clear = Gtk.MenuItem(label="Clear Selection")
            clear.set_sensitive(has_selection)
            clear.connect("activate", lambda *_: terminal.unselect_all())
            for item in (copy, paste, select_all, clear):
                popup.append(item)
            popup.append(Gtk.SeparatorMenuItem())
            close = Gtk.MenuItem(label=NATIVE_VTE_CLOSE_TAB_LABEL)
            close.connect(
                "activate",
                lambda *_args, current=terminal_id: close_tab(current),
            )
            popup.append(close)
            try:
                link = terminal.hyperlink_check_event(event)
            except AttributeError:
                link = None
            if isinstance(link, str) and link.startswith(("https://", "http://")):
                open_link = Gtk.MenuItem(label="Open Link")
                open_link.connect("activate", lambda *_: Gtk.show_uri_on_window(None, link, event.time))
                popup.append(open_link)
            popup.show_all()
            popup.popup_at_pointer(event)
            return True

        terminal.connect("button-press-event", menu)
        terminal.connect("focus-in-event", lambda widget, _event: (widget.grab_focus(), False)[1])
        container["window"].show_all()
        terminal.grab_focus()
        return terminal_id, window_id

    def handle(message: dict[str, Any]) -> None:
        request_id = message.get("request_id")
        if not isinstance(request_id, str) or message.get("token") != token:
            return
        try:
            kind = message.get("type")
            if kind == "ping":
                response(request_id, True, terminals=list_terminals())
            elif kind == "shutdown":
                response(request_id, True)
                Gtk.main_quit()
            elif kind == "open_tab":
                terminal_id, window_id = open_terminal(message, False)
                response(request_id, True, terminal_id=terminal_id, window_id=window_id)
            elif kind == "open_window":
                terminal_id, window_id = open_terminal(message, True)
                response(request_id, True, terminal_id=terminal_id, window_id=window_id)
            elif kind == "close_tab":
                response(request_id, close_tab(str(message.get("terminal_id", ""))))
            elif kind == "close_window":
                window_id = str(message.get("window_id", ""))
                window = windows.get(window_id)
                if window:
                    window["window"].destroy()
                    response(request_id, True)
                else:
                    response(request_id, False, error="unknown window")
            elif kind == "focus_tab":
                item = terminals.get(str(message.get("terminal_id", "")))
                if not item:
                    response(request_id, False, error="unknown terminal")
                else:
                    windows[item["window_id"]]["window"].present()
                    item["terminal"].grab_focus()
                    response(request_id, True)
            elif kind == "list_terminals":
                response(request_id, True, terminals=list_terminals())
            else:
                response(request_id, False, error="unknown command")
        except (TypeError, ValueError, OSError) as exc:
            response(request_id, False, error=str(exc))

    def list_terminals() -> list[dict[str, Any]]:
        return [
            {"terminal_id": key, "window_id": value["window_id"], "title": value["title"], "pid": value["pid"]}
            for key, value in terminals.items()
        ]

    def poll() -> bool:
        nonlocal pending
        try:
            data = connection.recv(65536)
        except BlockingIOError:
            return True
        if not data:
            Gtk.main_quit()
            return False
        pending += data
        lines = pending.split(b"\n")
        pending = lines.pop()
        for line in lines:
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(message, dict):
                handle(message)
        return True

    GLib.timeout_add(25, poll)
    Gtk.main()
    connection.close()
    listener.close()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--socket")
    parser.add_argument("--token")
    arguments = parser.parse_args()
    if arguments.probe:
        raise SystemExit(probe())
    if not arguments.socket or not arguments.token:
        parser.error("--socket and --token are required")
    raise SystemExit(main(arguments.socket, arguments.token))
