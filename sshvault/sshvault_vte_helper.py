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


def _terminal_shortcut_action(control: bool, shift: bool, keyval: int, has_selection: bool) -> str | None:
    if control and shift and keyval in (ord("c"), ord("C")):
        return "copy" if has_selection else "handled"
    if control and shift and keyval in (ord("v"), ord("V")):
        return "paste"
    if control and keyval == 65379:
        return "copy" if has_selection else "handled"
    if shift and keyval == 65379:
        return "paste"
    return None


def _dispatch_terminal_keypress(widget: Any, event: Any) -> bool:
    """Handle only local shortcuts; ordinary input goes straight to VTE's PTY."""
    control, shift = bool(event.state & 4), bool(event.state & 1)
    action = _terminal_shortcut_action(control, shift, event.keyval, widget.get_has_selection())
    if action == "copy":
        widget.copy_clipboard()
    elif action == "paste":
        widget.paste_clipboard()
    return action is not None


def _read_control_messages(
    connection: socket.socket,
    pending: bytes,
) -> tuple[bytes, list[dict[str, Any]], bool]:
    """Drain all available control bytes in one GTK wakeup.

    Terminal output is intentionally absent from this socket: VTE reads its
    child PTY directly.  The loop only batches sparse helper control messages.
    """
    chunks: list[bytes] = []
    connected = True
    while True:
        try:
            data = connection.recv(65536)
        except BlockingIOError:
            break
        if not data:
            connected = False
            break
        chunks.append(data)
    if chunks:
        pending += b"".join(chunks)
    lines = pending.split(b"\n")
    pending = lines.pop()
    messages: list[dict[str, Any]] = []
    for line in lines:
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(message, dict):
            messages.append(message)
    return pending, messages, connected


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


def _load_gtk() -> tuple[Any, Any, Any, Any, Any]:
    try:
        import gi

        gi.require_version("Gtk", "3.0")
        gi.require_version("Gdk", "3.0")
        gi.require_version("Pango", "1.0")
        gi.require_version("Vte", "2.91")
        from gi.repository import Gdk, GLib, Gtk, Pango, Vte
    except (ImportError, ValueError) as exc:
        raise RuntimeError(f"GI/VTE import failed: {exc}") from exc
    return GLib, Gdk, Gtk, Pango, Vte


def _sanitized_error(error: BaseException) -> str:
    """Return one useful line without control characters or a home path."""
    detail = " ".join(str(error).split())
    home = str(Path.home())
    if home and home != "/":
        detail = detail.replace(home, "<home>")
    return detail[:1000]


def probe_details() -> dict[str, object]:
    """Report GI separately from VTE so fallback diagnostics are precise."""
    details: dict[str, object] = {
        "python": sys.executable,
        "gi_available": False,
        "vte_available": False,
        "error": "",
    }
    try:
        import gi  # noqa: F401
    except (ImportError, ValueError) as exc:
        details["error"] = _sanitized_error(exc)
        return details
    details["gi_available"] = True
    try:
        _load_gtk()
    except RuntimeError as exc:
        details["error"] = _sanitized_error(exc)
        return details
    details["vte_available"] = True
    return details


def _apply_terminal_appearance(
    terminal: Any,
    options: dict[str, Any],
    Gdk: Any,
    Pango: Any,
    Vte: Any,
) -> list[str]:
    """Apply validated appearance values and report unsupported VTE capabilities."""
    warnings: list[str] = []
    try:
        description = Pango.FontDescription()
        description.set_family(str(options.get("font", "Monospace")))
        description.set_size(int(options.get("font_size", 10)) * Pango.SCALE)
        terminal.set_font(description)
    except (AttributeError, TypeError, ValueError):
        warnings.append("Terminal font is unsupported; using the VTE default.")
    try:
        shapes = {
            "Block": Vte.CursorShape.BLOCK,
            "I-Beam": Vte.CursorShape.IBEAM,
            "Underline": Vte.CursorShape.UNDERLINE,
        }
        terminal.set_cursor_shape(shapes[str(options.get("cursor_shape", "Block"))])
        blink = Vte.CursorBlinkMode.ON if bool(options.get("cursor_blink", True)) else Vte.CursorBlinkMode.OFF
        terminal.set_cursor_blink_mode(blink)
    except (AttributeError, KeyError, TypeError, ValueError):
        warnings.append("Terminal cursor style is unsupported; using the VTE default.")
    try:
        foreground, background = Gdk.RGBA(), Gdk.RGBA()
        if not foreground.parse(str(options.get("foreground", "#f1f3f4"))) or not background.parse(
            str(options.get("background", "#202124"))
        ):
            raise ValueError("invalid color")
        terminal.set_color_foreground(foreground)
        terminal.set_color_background(background)
    except (AttributeError, TypeError, ValueError):
        warnings.append("Terminal colors are unsupported; using the VTE default.")
    return warnings


def probe() -> int:
    details = probe_details()
    print(json.dumps(details, separators=(",", ":")))
    if not details["vte_available"]:
        print(f"GI/VTE import failed: {details['error']}", file=sys.stderr)
        return 2
    return 0


def main(socket_path: str, token: str) -> int:
    try:
        GLib, Gdk, Gtk, Pango, Vte = _load_gtk()
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

    def new_window(title: str) -> str:
        window_id = str(uuid4())
        window = Gtk.Window(title=title)
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

    def open_terminal(message: dict[str, Any], force_new_window: bool) -> tuple[str, str, list[str]]:
        argv = message.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
            raise ValueError("invalid OpenSSH command")
        requested = message.get("window_id")
        window_id = (
            str(requested) if not force_new_window and isinstance(requested, str) and requested in windows else ""
        )
        if not window_id:
            window_id = new_window(str(message.get("title", "SSHVault")))
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
        appearance_warnings = _apply_terminal_appearance(terminal, options, Gdk, Pango, Vte)
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
            "session_id": str(message.get("session_id", "")),
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

        terminal.connect("key-press-event", _dispatch_terminal_keypress)

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
        container["window"].show_all()
        terminal.grab_focus()
        return terminal_id, window_id, appearance_warnings

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
                terminal_id, window_id, warnings = open_terminal(message, False)
                response(request_id, True, terminal_id=terminal_id, window_id=window_id, warnings=warnings)
            elif kind == "open_window":
                terminal_id, window_id, warnings = open_terminal(message, True)
                response(request_id, True, terminal_id=terminal_id, window_id=window_id, warnings=warnings)
            elif kind == "close_tab":
                terminal_id = str(message.get("terminal_id", ""))
                closed = close_tab(terminal_id)
                response(request_id, closed, **({} if closed else {"error": "unknown terminal"}))
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
            {
                "terminal_id": key,
                "window_id": value["window_id"],
                "title": value["title"],
                "session_id": value["session_id"],
                "pid": value["pid"],
            }
            for key, value in terminals.items()
        ]

    def control_ready(_source: Any, condition: Any) -> bool:
        nonlocal pending
        if condition & (GLib.IO_HUP | GLib.IO_ERR):
            Gtk.main_quit()
            return False
        pending, messages, connected = _read_control_messages(connection, pending)
        for message in messages:
            handle(message)
        if not connected:
            Gtk.main_quit()
            return False
        return True

    # Wake only when control data is ready.  VTE owns terminal PTY reads/writes,
    # so neither terminal output nor keystrokes are delayed by helper polling.
    GLib.io_add_watch(connection.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, control_ready)
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
