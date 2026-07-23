"""UI-free SSH host-key verification and Paramiko connection support."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import queue
from typing import Any, Callable

import paramiko

from sshvault_core import ProfileError, connection_kwargs


class TrustDecision(str, Enum):
    TRUST_ONCE = "trust_once"
    TRUST_AND_SAVE = "trust_and_save"
    CANCEL = "cancel"


@dataclass
class SecurityRequest:
    identifier: int
    kind: str
    payload: Any
    event: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    resolved: bool = False


class SecurityRequestQueue:
    """Thread-safe UI-free queue for host-key prompts and warnings."""

    def __init__(self) -> None:
        self._pending: queue.Queue[SecurityRequest] = queue.Queue()
        self._active: SecurityRequest | None = None
        self._closed = False
        self._next_id = 0
        self._lock = threading.Lock()

    def submit(self, kind: str, payload: Any) -> SecurityRequest:
        with self._lock:
            self._next_id += 1
            request = SecurityRequest(self._next_id, kind, payload)
            if self._closed:
                request.result = TrustDecision.CANCEL if kind == "unknown" else None
                request.resolved = True
                request.event.set()
            else:
                self._pending.put(request)
            return request

    def next(self) -> SecurityRequest | None:
        with self._lock:
            if self._closed or self._active:
                return None
            try:
                self._active = self._pending.get_nowait()
            except queue.Empty:
                return None
            return self._active

    def resolve(self, identifier: int, result: Any = None) -> bool:
        with self._lock:
            request = self._active
            if self._closed or not request or request.identifier != identifier or request.resolved:
                return False
            request.result, request.resolved = result, True
            request.event.set()
            self._active = None
            return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            items = [self._active] if self._active else []
            self._active = None
            while True:
                try:
                    items.append(self._pending.get_nowait())
                except queue.Empty:
                    break
            for request in items:
                if request and not request.resolved:
                    request.result = TrustDecision.CANCEL if request.kind == "unknown" else None
                    request.resolved = True
                    request.event.set()


class UnknownHostCancelled(paramiko.SSHException):
    """The user declined an unknown server identity."""


class ChangedHostKeyRejected(paramiko.SSHException):
    """A changed server identity was shown and the connection remained blocked."""


class KnownHostsError(ProfileError):
    """Application known-host storage could not be safely used."""


def host_lookup_name(hostname: str, port: int) -> str:
    return hostname if port == 22 else f"[{hostname}]:{port}"


def sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


@dataclass(frozen=True)
class HostKeyTrustRequest:
    profile_name: str
    host_role: str
    hostname: str
    port: int
    key_type: str
    fingerprint: str


@dataclass(frozen=True)
class ChangedHostKeyRequest:
    profile_name: str
    host_role: str
    hostname: str
    port: int
    key_type: str
    saved_fingerprint: str
    received_fingerprint: str


@dataclass
class ProxyConnectionContext:
    """Owns all resources for one proxied destination session."""

    jump_client: Any | None = None
    proxy_channel: Any | None = None
    destination_client: Any | None = None
    closed: bool = False

    def close(self) -> list[str]:
        if self.closed:
            return []
        self.closed = True
        errors = []
        for attribute in ("destination_client", "proxy_channel", "jump_client"):
            resource = getattr(self, attribute)
            if resource:
                try:
                    resource.close()
                except Exception as exc:
                    errors.append(str(exc))
            setattr(self, attribute, None)
        return errors


class KnownHostsStore:
    """Dedicated, atomic Paramiko-compatible application known-host store."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> paramiko.HostKeys:
        keys = paramiko.HostKeys()
        if not self.path.exists():
            return keys
        try:
            keys.load(str(self.path))
        except Exception as exc:
            raise KnownHostsError(
                f"Application known-hosts file is malformed and was not changed: {self.path}"
            ) from exc
        return keys

    def save_key(self, hostname: str, port: int, key: paramiko.PKey) -> None:
        keys = self.load()
        keys.add(host_lookup_name(hostname, port), key.get_name(), key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent, text=True)
        try:
            os.close(fd)
            keys.save(temporary)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except OSError as exc:
            raise KnownHostsError("Could not safely save the server identity.") from exc
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept only an explicit callback decision for a missing host key."""

    def __init__(
        self,
        manager: "SSHConnectionManager",
        profile: dict[str, Any],
        decide: Callable[[HostKeyTrustRequest], TrustDecision],
    ) -> None:
        self.manager, self.profile, self.decide = manager, profile, decide

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        request = HostKeyTrustRequest(
            self.profile.get("name", hostname),
            self.profile.get("host_role", "Destination host"),
            self.manager.hostname,
            self.manager.port,
            key.get_name(),
            sha256_fingerprint(key),
        )
        decision = self.decide(request)
        if decision is TrustDecision.TRUST_ONCE:
            return
        if decision is TrustDecision.TRUST_AND_SAVE:
            self.manager.known_hosts.save_key(self.manager.hostname, self.manager.port, key)
            return
        raise UnknownHostCancelled("Unknown host key was not trusted")


class SSHConnectionManager:
    """Creates SSH clients through one host-key verification workflow."""

    def __init__(self, known_hosts: KnownHostsStore, hostname: str, port: int) -> None:
        self.known_hosts, self.hostname, self.port = known_hosts, hostname, port

    def connect(
        self,
        profile: dict[str, Any],
        decide_trust: Callable[[HostKeyTrustRequest], TrustDecision],
        password: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        self.known_hosts.load()
        if self.known_hosts.path.exists():
            client.load_host_keys(str(self.known_hosts.path))
        client.set_missing_host_key_policy(InteractiveHostKeyPolicy(self, profile, decide_trust))
        kwargs = connection_kwargs(profile, password)
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        client.connect(**kwargs)
        return client

    def changed_request(self, profile: dict[str, Any], error: paramiko.BadHostKeyException) -> ChangedHostKeyRequest:
        return ChangedHostKeyRequest(
            profile.get("name", self.hostname),
            profile.get("host_role", "Destination host"),
            self.hostname,
            self.port,
            error.key.get_name(),
            sha256_fingerprint(error.expected_key),
            sha256_fingerprint(error.key),
        )
