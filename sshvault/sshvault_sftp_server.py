"""Isolated runtime for SSHVault's opt-in built-in SFTP server."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hmac
import os
from pathlib import Path, PurePosixPath
import socket
import threading
from typing import Any, Mapping, cast

import paramiko
from paramiko.common import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)
from paramiko.sftp import SFTP_OK, SFTP_PERMISSION_DENIED


SERVER_STOPPED = "Stopped"
SERVER_RUNNING = "Running"
SERVER_FAILED = "Failed"


class RootEscapeError(ValueError):
    """Raised when a client path would escape the configured SFTP root."""


@dataclass(frozen=True)
class BuiltinSFTPServerConfig:
    listen_host: str
    port: int
    username: str
    root: Path

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BuiltinSFTPServerConfig:
        host = str(value.get("listen_host", "127.0.0.1")).strip()
        username = str(value.get("username", "sftpuser")).strip()
        try:
            port = int(value.get("port", 2222))
        except (TypeError, ValueError) as exc:
            raise ValueError("Port must be between 1 and 65535.") from exc
        if not host:
            raise ValueError("Listen address is required.")
        if not 0 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if not username:
            raise ValueError("Virtual username is required.")
        root = Path(str(value.get("root", ""))).expanduser().resolve()
        if not root.is_dir():
            raise ValueError("Root directory must exist and be a directory.")
        return cls(host, port, username, root)


class RootedSFTPServer(paramiko.SFTPServerInterface):
    """Paramiko filesystem adapter whose visible namespace is exactly one root."""

    def __init__(self, server: paramiko.ServerInterface, *args: Any, root: Path, **kwargs: Any) -> None:
        super().__init__(server, *args, **kwargs)
        self.root = root.resolve()

    def _local_path(self, remote_path: str, *, follow_final: bool = True) -> Path:
        if "\x00" in remote_path:
            raise RootEscapeError("NUL is not valid in an SFTP path")
        parts = PurePosixPath(remote_path.replace("\\", "/")).parts
        if ".." in parts:
            raise RootEscapeError("parent traversal is not allowed")
        relative_parts = [part for part in parts if part not in ("/", ".", "")]
        candidate = self.root.joinpath(*relative_parts)
        if follow_final:
            checked = candidate.resolve(strict=False)
        else:
            checked_parent = candidate.parent.resolve(strict=False)
            checked = checked_parent / candidate.name
        try:
            checked.relative_to(self.root)
        except ValueError as exc:
            raise RootEscapeError("path is outside the configured root") from exc
        return checked

    @staticmethod
    def _failure(exc: OSError | RootEscapeError) -> int:
        if isinstance(exc, RootEscapeError):
            return SFTP_PERMISSION_DENIED
        return paramiko.SFTPServer.convert_errno(exc.errno or errno.EIO)

    def list_folder(self, path: str) -> list[paramiko.SFTPAttributes] | int:
        try:
            local = self._local_path(path)
            result = []
            for name in os.listdir(local):
                attr = paramiko.SFTPAttributes.from_stat(os.lstat(local / name))
                attr.filename = name
                result.append(attr)
            return result
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def stat(self, path: str) -> paramiko.SFTPAttributes | int:
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._local_path(path)))
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def lstat(self, path: str) -> paramiko.SFTPAttributes | int:
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(self._local_path(path, follow_final=False)))
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def open(self, path: str, flags: int, attr: paramiko.SFTPAttributes) -> paramiko.SFTPHandle | int:
        fd = -1
        try:
            local = self._local_path(path)
            fd = os.open(local, flags, 0o666)
            if attr is not None:
                paramiko.SFTPServer.set_file_attr(str(local), attr)
            if flags & os.O_RDWR:
                mode = "r+b"
            elif flags & os.O_WRONLY:
                mode = "ab" if flags & os.O_APPEND else "wb"
            else:
                mode = "rb"
            stream = os.fdopen(fd, mode)
            fd = -1
            handle = paramiko.SFTPHandle(flags)
            if flags & os.O_WRONLY or flags & os.O_RDWR:
                cast(Any, handle).writefile = stream
            if not flags & os.O_WRONLY or flags & os.O_RDWR:
                cast(Any, handle).readfile = stream
            return handle
        except (OSError, RootEscapeError) as exc:
            if fd >= 0:
                os.close(fd)
            return self._failure(exc)

    def remove(self, path: str) -> int:
        try:
            os.remove(self._local_path(path, follow_final=False))
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def rename(self, oldpath: str, newpath: str) -> int:
        try:
            os.rename(
                self._local_path(oldpath, follow_final=False),
                self._local_path(newpath, follow_final=False),
            )
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def posix_rename(self, oldpath: str, newpath: str) -> int:
        try:
            os.replace(
                self._local_path(oldpath, follow_final=False),
                self._local_path(newpath, follow_final=False),
            )
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def mkdir(self, path: str, attr: paramiko.SFTPAttributes) -> int:
        try:
            local = self._local_path(path, follow_final=False)
            os.mkdir(local, getattr(attr, "st_mode", None) or 0o777)
            if attr is not None:
                paramiko.SFTPServer.set_file_attr(str(local), attr)
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def rmdir(self, path: str) -> int:
        try:
            os.rmdir(self._local_path(path))
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def chattr(self, path: str, attr: paramiko.SFTPAttributes) -> int:
        try:
            paramiko.SFTPServer.set_file_attr(str(self._local_path(path)), attr)
            return SFTP_OK
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def readlink(self, path: str) -> str | int:
        try:
            local = self._local_path(path, follow_final=False)
            target = os.readlink(local)
            resolved = (local.parent / target).resolve(strict=False)
            relative = resolved.relative_to(self.root)
            return "/" + relative.as_posix()
        except ValueError:
            return SFTP_PERMISSION_DENIED
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)

    def symlink(self, target_path: str, path: str) -> int:
        try:
            link = self._local_path(path, follow_final=False)
            normalized_target = target_path.replace("\\", "/")
            target_parts = PurePosixPath(normalized_target).parts
            if PurePosixPath(normalized_target).is_absolute() or ".." in target_parts:
                raise RootEscapeError("symlink target must remain below root")
            target = (link.parent / target_path).resolve(strict=False)
            target.relative_to(self.root)
            os.symlink(target_path, link)
            return SFTP_OK
        except ValueError:
            return SFTP_PERMISSION_DENIED
        except (OSError, RootEscapeError) as exc:
            return self._failure(exc)


class _PasswordOnlyServer(paramiko.ServerInterface):
    """Authentication boundary used only by the local built-in server."""

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        valid = hmac.compare_digest(username, self._username) and hmac.compare_digest(password, self._password)
        return AUTH_SUCCESSFUL if valid else AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return OPEN_SUCCEEDED if kind == "session" else OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class BuiltinSFTPServerRuntime:
    """Own one listener and all of its transports/threads, independent of SSH sessions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._worker_threads: set[threading.Thread] = set()
        self._transports: set[paramiko.Transport] = set()
        self._host_key: paramiko.PKey | None = None
        self._status = SERVER_STOPPED
        self._error = ""
        self._config: BuiltinSFTPServerConfig | None = None
        self._password = ""

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def error(self) -> str:
        with self._lock:
            return self._error

    @property
    def bound_address(self) -> tuple[str, int] | None:
        with self._lock:
            if self._listener is None:
                return None
            address = self._listener.getsockname()
            return str(address[0]), int(address[1])

    @property
    def has_live_resources(self) -> bool:
        with self._lock:
            listener_alive = self._listener_thread is not None and self._listener_thread.is_alive()
            return bool(
                self._listener or listener_alive or self._transports or any(t.is_alive() for t in self._worker_threads)
            )

    def start(self, config: BuiltinSFTPServerConfig, password: str) -> None:
        if not password:
            self._set_failed("A runtime password is required.")
            raise ValueError("A runtime password is required.")
        with self._lock:
            if self._status == SERVER_RUNNING:
                return
            needs_cleanup = self._status == SERVER_FAILED or self.has_live_resources
        if needs_cleanup:
            self.stop()
        with self._lock:
            self._stop_event.clear()
            self._error = ""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((config.listen_host, config.port))
            listener.listen(16)
            listener.settimeout(0.2)
            if self._host_key is None:
                self._host_key = paramiko.RSAKey.generate(2048)
        except OSError as exc:
            listener.close()
            self._set_failed(str(exc))
            raise RuntimeError(f"Could not bind {config.listen_host}:{config.port}: {exc}") from exc
        with self._lock:
            self._listener = listener
            self._config = config
            self._password = password
            self._status = SERVER_RUNNING
            thread = threading.Thread(target=self._accept_loop, name="sshvault-sftp-listener", daemon=False)
            self._listener_thread = thread
            thread.start()

    def _set_failed(self, error: str) -> None:
        with self._lock:
            self._status = SERVER_FAILED
            self._error = error

    def _accept_loop(self) -> None:
        unexpected_error = ""
        try:
            while not self._stop_event.is_set():
                with self._lock:
                    listener = self._listener
                if listener is None:
                    break
                try:
                    client, _address = listener.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not self._stop_event.is_set():
                        unexpected_error = str(exc)
                    break
                worker = threading.Thread(
                    target=self._serve_client,
                    args=(client,),
                    name="sshvault-sftp-client",
                    daemon=False,
                )
                with self._lock:
                    self._worker_threads.add(worker)
                worker.start()
        finally:
            if unexpected_error:
                self._set_failed(unexpected_error)

    def _serve_client(self, client: socket.socket) -> None:
        transport: paramiko.Transport | None = None
        try:
            with self._lock:
                if self._stop_event.is_set():
                    return
                config = self._config
                password = self._password
                host_key = self._host_key
                transport = paramiko.Transport(client)
                self._transports.add(transport)
            if config is None:
                return
            if host_key is None:
                raise RuntimeError("server host key is unavailable")
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, RootedSFTPServer, root=config.root)
            transport.start_server(server=_PasswordOnlyServer(config.username, password))
            while transport.is_active() and not self._stop_event.wait(0.1):
                pass
        except (OSError, EOFError, RuntimeError, paramiko.SSHException):
            pass
        finally:
            if transport is not None:
                transport.close()
                with self._lock:
                    self._transports.discard(transport)
            else:
                client.close()
            current = threading.current_thread()
            with self._lock:
                self._worker_threads.discard(current)

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            listener = self._listener
            self._listener = None
            listener_thread = self._listener_thread
            transports = tuple(self._transports)
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
        for transport in transports:
            transport.close()
        if listener_thread is not None and listener_thread is not threading.current_thread():
            listener_thread.join(timeout=2.0)
        with self._lock:
            workers = tuple(self._worker_threads)
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=2.0)
        with self._lock:
            self._worker_threads = {worker for worker in self._worker_threads if worker.is_alive()}
            listener_alive = listener_thread is not None and listener_thread.is_alive()
            self._listener_thread = listener_thread if listener_alive else None
            self._config = None
            self._password = ""
            if listener_alive or self._worker_threads or self._transports:
                self._status = SERVER_FAILED
                self._error = "Server shutdown did not complete."
            else:
                self._status = SERVER_STOPPED
                self._error = ""
