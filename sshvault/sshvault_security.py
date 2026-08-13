"""UI-free SSH host-key verification and Paramiko connection support."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import queue
from typing import Any, Callable, Iterator, Sequence
from datetime import datetime, timezone

import paramiko

from sshvault_core import (
    HostKeySessionStatus,
    ProfileError,
    SSHRuntimePreferences,
    connection_kwargs,
    ssh_runtime_preferences,
)


_AGENT_ENV_LOCK = threading.Lock()


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


@dataclass(frozen=True)
class AgentAuthenticationDiagnostic:
    """Public-only details for one SSH-agent identity offer."""

    host_role: str
    username: str
    fingerprint: str
    key_count: int = 0
    accepted_fingerprint: str = ""
    rejection_category: str = ""

    def sanitized_message(self) -> str:
        return (
            f"{self.host_role} agent authentication: username={self.username} "
            f"agent_keys={self.key_count} offered_key={self.fingerprint} "
            f"accepted_key={self.accepted_fingerprint or 'none'} "
            f"rejection={self.rejection_category or 'none'}"
        )


def _agent_socket_candidates(environment: dict[str, str] | None = None) -> tuple[str, ...]:
    """Return user-session agent sockets without guessing temporary paths."""
    env = os.environ if environment is None else environment
    runtime = str(env.get("XDG_RUNTIME_DIR", "")).strip()
    candidates = [str(env.get("SSH_AUTH_SOCK", "")).strip()]
    if runtime:
        candidates.extend(
            [
                os.path.join(runtime, "gcr", "ssh"),
                os.path.join(runtime, "keyring", "ssh"),
                os.path.join(runtime, "keyring", ".ssh"),
                os.path.join(runtime, "gnupg", "S.gpg-agent.ssh"),
            ]
        )
    return tuple(dict.fromkeys(path for path in candidates if path))


def _read_agent_socket(path: str) -> tuple[tuple[Any, ...], str]:
    """Read only public agent metadata while temporarily selecting ``path``."""
    previous = os.environ.get("SSH_AUTH_SOCK")
    with _AGENT_ENV_LOCK:
        os.environ["SSH_AUTH_SOCK"] = path
        agent = None
        try:
            agent = paramiko.Agent()
            keys = tuple(agent.get_keys())
        except Exception as exc:
            return (), type(exc).__name__
        finally:
            if agent is not None:
                agent.close()
            if previous is None:
                os.environ.pop("SSH_AUTH_SOCK", None)
            else:
                os.environ["SSH_AUTH_SOCK"] = previous
    return keys, ""


def agent_environment_diagnostics(environment: dict[str, str] | None = None) -> dict[str, Any]:
    """Return socket, public key fingerprints, and availability warnings."""
    current = str((os.environ if environment is None else environment).get("SSH_AUTH_SOCK", "")).strip()
    reports: list[tuple[str, tuple[Any, ...]]] = []
    errors: dict[str, str] = {}
    for candidate in _agent_socket_candidates(environment):
        if not os.path.exists(candidate):
            errors[candidate] = "missing socket"
            continue
        keys, error = _read_agent_socket(candidate)
        if error:
            errors[candidate] = error
            continue
        reports.append((candidate, keys))
    selected = max(reports, key=lambda item: (len(item[1]), item[0] == current), default=(current, ()))
    warning = ""
    if not reports:
        warning = "SSH agent socket is unavailable."
    elif current and selected[0] != current:
        warning = (
            "The inherited SSH_AUTH_SOCK was stale or had fewer visible keys; selected an active user-session socket."
        )
    return {
        "ssh_auth_sock": selected[0],
        "inherited_ssh_auth_sock": current,
        "agent_socket_available": bool(reports),
        "key_count": len(selected[1]),
        "keys": [{"type": key.get_name(), "fingerprint": sha256_fingerprint(key)} for key in selected[1]],
        "warning": warning,
        "socket_errors": errors,
    }


def prepare_agent_environment(environment: dict[str, str] | None = None) -> dict[str, Any]:
    """Select the active user-session agent socket for subsequent Paramiko calls."""
    diagnostics = agent_environment_diagnostics(environment)
    selected = str(diagnostics["ssh_auth_sock"])
    if selected and diagnostics["agent_socket_available"]:
        os.environ["SSH_AUTH_SOCK"] = selected
    return diagnostics


def host_lookup_name(hostname: str, port: int) -> str:
    return hostname if port == 22 else f"[{hostname}]:{port}"


def sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


class IndependentAgentAuthStrategy(paramiko.auth_strategy.AuthStrategy):
    """Enumerate a fresh agent snapshot for exactly one SSH connection."""

    def __init__(
        self,
        username: str,
        host_role: str,
        diagnose: Callable[[AgentAuthenticationDiagnostic], None],
        agent_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(ssh_config=paramiko.SSHConfig())
        self.username = username
        self.host_role = host_role
        self._diagnose = diagnose
        self._agent_factory = agent_factory
        self._keys: tuple[paramiko.PKey, ...] = ()

    def get_sources(self) -> Iterator[Any]:
        return iter(())

    def authenticate(self, transport: Any) -> Any:
        factory = self._agent_factory or paramiko.Agent
        agent = factory()
        try:
            # Materialize a connection-owned snapshot.  In particular, a
            # jump host accepting one key does not select or cache that key
            # for the destination connection.
            self._keys = tuple(agent.get_keys())
            key_count = len(self._keys)
            for key in self._keys:
                fingerprint = sha256_fingerprint(key)
                try:
                    transport.auth_publickey(self.username, key)
                except paramiko.AuthenticationException as exc:
                    self._diagnose(
                        AgentAuthenticationDiagnostic(
                            self.host_role,
                            self.username,
                            fingerprint,
                            key_count,
                            rejection_category=type(exc).__name__,
                        )
                    )
                    continue
                if transport.is_authenticated():
                    self._diagnose(
                        AgentAuthenticationDiagnostic(
                            self.host_role,
                            self.username,
                            fingerprint,
                            key_count,
                            accepted_fingerprint=fingerprint,
                        )
                    )
                    return None
            raise paramiko.AuthenticationException(f"SSH agent authentication rejected all {key_count} identities")
        finally:
            agent.close()


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


@dataclass(frozen=True)
class HostKeyRecord:
    hostname: str
    port: int
    algorithm: str
    fingerprint: str
    first_trusted: str
    last_used: str
    associated_profiles: tuple[str, ...] = ()


class HostKeyRepository:
    """Read-only metadata facade over the application known-host file."""

    def __init__(self, path: Path, profiles: list[dict[str, Any]] | None = None) -> None:
        self.path = path
        self.profiles = profiles or []

    def list_records(self) -> list[HostKeyRecord]:
        keys = KnownHostsStore(self.path).load()
        stamp = (
            datetime.fromtimestamp(self.path.stat().st_mtime, timezone.utc).isoformat() if self.path.exists() else ""
        )
        records: list[HostKeyRecord] = []
        for lookup, algorithms in keys.items():
            host, port = self._split_lookup(lookup)
            associations = tuple(
                sorted(
                    str(p.get("name", ""))
                    for p in self.profiles
                    if str(p.get("host", "")) == host and int(p.get("port", 22)) == port
                )
            )
            for algorithm, key in algorithms.items():
                records.append(
                    HostKeyRecord(host, port, algorithm, sha256_fingerprint(key), stamp, stamp, associations)
                )
        return records

    @staticmethod
    def _split_lookup(lookup: str) -> tuple[str, int]:
        if lookup.startswith("[") and "]:" in lookup:
            host, port = lookup[1:].rsplit("]:", 1)
            return host, int(port)
        return lookup, 22

    def remove(self, record: HostKeyRecord) -> None:
        keys = KnownHostsStore(self.path).load()
        lookup = host_lookup_name(record.hostname, record.port)
        if (
            lookup not in keys
            or record.algorithm not in keys[lookup]
            or sha256_fingerprint(keys[lookup][record.algorithm]) != record.fingerprint
        ):
            raise KnownHostsError("The selected host-key entry was not found.")
        rebuilt = paramiko.HostKeys()
        for host_name, algorithms in keys.items():
            for algorithm, key in algorithms.items():
                if host_name == lookup and algorithm == record.algorithm:
                    continue
                rebuilt.add(host_name, algorithm, key)
        keys = rebuilt
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent, text=True)
            os.close(fd)
            keys.save(temporary)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except OSError as exc:
            raise KnownHostsError("Could not safely remove the host-key entry.") from exc
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def export(self, destination: Path) -> None:
        payload = {
            "schema_version": 1,
            "kind": "sshvault-application-known-hosts",
            "entries": [r.__dict__ for r in self.list_records()],
        }
        temporary = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent, text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2)
                stream.write("\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        except OSError as exc:
            raise KnownHostsError("Could not export host-key data.") from exc
        finally:
            if temporary and os.path.exists(temporary):
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
            self.manager.last_host_key_verification = HostKeySessionStatus(
                request.host_role,
                request.hostname,
                request.key_type,
                request.fingerprint,
                "Unknown key trusted once",
            )
            return
        if decision is TrustDecision.TRUST_AND_SAVE:
            self.manager.known_hosts.save_key(self.manager.hostname, self.manager.port, key)
            self.manager.last_host_key_verification = HostKeySessionStatus(
                request.host_role,
                request.hostname,
                request.key_type,
                request.fingerprint,
                "Unknown key trusted and saved",
            )
            return
        self.manager.last_host_key_verification = HostKeySessionStatus(
            request.host_role,
            request.hostname,
            request.key_type,
            request.fingerprint,
            "Unknown key rejected",
            connected=False,
        )
        raise UnknownHostCancelled("Unknown host key was not trusted")


class SSHConnectionManager:
    """Creates SSH clients through one host-key verification workflow."""

    def __init__(self, known_hosts: KnownHostsStore, hostname: str, port: int) -> None:
        self.known_hosts, self.hostname, self.port = known_hosts, hostname, port
        self.last_runtime_preferences: SSHRuntimePreferences | None = None
        self.last_host_key_verification: HostKeySessionStatus | None = None
        self.agent_diagnostics: list[AgentAuthenticationDiagnostic] = []

    def connect(
        self,
        profile: dict[str, Any],
        decide_trust: Callable[[HostKeyTrustRequest], TrustDecision],
        password: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
        diagnose_agent_key: Callable[[AgentAuthenticationDiagnostic], None] | None = None,
    ) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        self.known_hosts.load()
        if self.known_hosts.path.exists():
            client.load_host_keys(str(self.known_hosts.path))
        client.set_missing_host_key_policy(InteractiveHostKeyPolicy(self, profile, decide_trust))
        try:
            runtime = ssh_runtime_preferences(profile)
            kwargs = connection_kwargs(profile, password)
        except ProfileError:
            client.close()
            raise
        kwargs["compress"] = runtime.compression
        if profile.get("auth_method") == "agent":
            prepare_agent_environment()
            self.agent_diagnostics = []

            def record_diagnostic(event: AgentAuthenticationDiagnostic) -> None:
                self.agent_diagnostics.append(event)
                if diagnose_agent_key is not None:
                    diagnose_agent_key(event)

            # Bypass SSHClient's legacy implicit authentication sequence so
            # this connection owns a complete, fresh agent-key enumeration.
            # Explicitly keep filesystem key discovery disabled as well.
            kwargs["allow_agent"] = False
            kwargs["look_for_keys"] = False
            kwargs["auth_strategy"] = IndependentAgentAuthStrategy(
                str(profile["user"]),
                str(profile.get("host_role", "Destination host")),
                record_diagnostic,
            )
        if runtime.algorithm_preferences:
            kwargs["transport_factory"] = preferred_transport_factory(runtime)
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        try:
            client.connect(**kwargs)
        except ProfileError:
            client.close()
            raise
        transport = client.get_transport()
        if transport is None:
            client.close()
            raise ProfileError("SSH transport was not established.")
        try:
            apply_ssh_runtime_preferences(transport, runtime)
        except ProfileError:
            client.close()
            raise
        self.last_runtime_preferences = runtime
        if self.last_host_key_verification is None:
            try:
                key = transport.get_remote_server_key()
                algorithm = key.get_name()
                fingerprint = sha256_fingerprint(key)
            except (AttributeError, TypeError, ValueError):
                pass
            else:
                self.last_host_key_verification = HostKeySessionStatus(
                    str(profile.get("host_role", "Destination host")),
                    self.hostname,
                    algorithm,
                    fingerprint,
                    "Verified against known hosts",
                )
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


def _preferred_first(
    available: Sequence[str],
    preferred: str | None,
    label: str,
) -> tuple[str, ...]:
    current = tuple(available)
    if preferred is None:
        return current
    if preferred not in current:
        raise ProfileError(f"Preferred SSH {label} is unsupported by this backend.")
    return (preferred, *(item for item in current if item != preferred))


def preferred_transport_factory(runtime: SSHRuntimePreferences) -> Callable[..., paramiko.Transport]:
    """Create a Transport factory that only reorders explicitly selected algorithms."""

    def factory(sock: Any, **kwargs: Any) -> paramiko.Transport:
        transport = paramiko.Transport(sock, **kwargs)
        options = transport.get_security_options()
        try:
            options.kex = _preferred_first(
                options.kex,
                runtime.preferred_key_exchange,
                "key-exchange algorithm",
            )
            options.key_types = _preferred_first(
                options.key_types,
                runtime.preferred_host_key,
                "host-key algorithm",
            )
            options.ciphers = _preferred_first(
                options.ciphers,
                runtime.preferred_cipher,
                "cipher",
            )
            options.digests = _preferred_first(
                options.digests,
                runtime.preferred_mac,
                "MAC",
            )
        except ProfileError:
            transport.close()
            raise
        except (TypeError, ValueError) as exc:
            transport.close()
            raise ProfileError("SSH algorithm preferences could not be applied.") from exc
        return transport

    return factory


def apply_ssh_runtime_preferences(
    transport: Any,
    runtime: SSHRuntimePreferences,
) -> None:
    """Apply transport-level keepalive policy without changing authentication."""
    try:
        transport.set_keepalive(runtime.keepalive_interval)
        transport.sshvault_maximum_missed_keepalives = runtime.maximum_missed_keepalives
        sock = getattr(transport, "sock", None)
        if sock is not None and hasattr(sock, "setsockopt"):
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_KEEPALIVE,
                1 if runtime.tcp_keepalive else 0,
            )
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise ProfileError("SSH keepalive preferences could not be applied.") from exc


def request_agent_forwarding(channel: Any, profile: dict[str, Any]) -> Any | None:
    """Request forwarding only when enabled in this channel's session snapshot."""
    if not ssh_runtime_preferences(profile).agent_forwarding:
        return None
    try:
        return paramiko.agent.AgentRequestHandler(channel)
    except Exception as exc:
        raise ProfileError("SSH agent forwarding request failed.") from exc
