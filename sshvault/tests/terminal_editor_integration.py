"""Opt-in terminal-editor smoke test; never runs as part of the test suite.

Run only against a disposable test account, for example:
    SSHVAULT_TEST_HOST=localhost SSHVAULT_TEST_USER=tester \
        python tests/terminal_editor_integration.py --run --editor nano
"""

from __future__ import annotations

import argparse
import os
import time

import paramiko


def _drain(channel: paramiko.Channel, seconds: float = 0.4) -> str:
    deadline = time.monotonic() + seconds
    chunks: list[bytes] = []
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunks.append(channel.recv(32768))
        else:
            time.sleep(0.02)
    return b"".join(chunks).decode("utf-8", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly permit connection to SSHVAULT_TEST_HOST")
    parser.add_argument("--editor", choices=("nano", "vi"), default="nano")
    args = parser.parse_args()
    if not args.run:
        parser.error("disabled by default; pass --run for a disposable test host")

    host = os.environ.get("SSHVAULT_TEST_HOST")
    user = os.environ.get("SSHVAULT_TEST_USER")
    if not host or not user:
        parser.error("SSHVAULT_TEST_HOST and SSHVAULT_TEST_USER are required")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_system_host_keys()
    client.connect(host, username=user, port=int(os.environ.get("SSHVAULT_TEST_PORT", "22")), allow_agent=True)
    path = ""
    try:
        _, stdout, _ = client.exec_command("mktemp /tmp/sshvault-terminal-editor.XXXXXX")
        path = stdout.read().decode().strip()
        if not path:
            raise RuntimeError("test host did not create a temporary file")
        client.exec_command(f"printf 'before\\n' > {path}")[1].channel.recv_exit_status()
        channel = client.invoke_shell(term="xterm-256color", width=120, height=32)
        channel.sendall(f"{args.editor} {path}\r".encode())
        _drain(channel)
        if args.editor == "nano":
            channel.sendall(b"\x0bchanged\x0f\r\x18")
        else:
            channel.sendall(b"\x1bgg0cwchanged\x1b:wq\r")
        _drain(channel, 1.0)
        _, stdout, _ = client.exec_command(f"cat {path}")
        if stdout.read().decode() != "changed\n":
            raise RuntimeError("remote editor did not save the expected content")
        print("terminal editor save verified")
        return 0
    finally:
        if path:
            client.exec_command(f"rm -f {path}")
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
