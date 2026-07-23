# SSHVault

## License

SSHVault is released under the [MIT License](LICENSE).

SSHVault is a Tkinter desktop SSH connection manager with secure host-key
verification, profile storage, terminal, SFTP, tunnels, remote commands, and
backup/import workflows.

## Screenshots

Screenshots can be added to `docs/screenshots/` as the interface evolves. The
project intentionally does not ship screenshots containing real hosts or user
data.

## Install and launch

Python 3.10+ and Tk are required. Install from a checkout with:

```bash
python -m pip install .
sshvault
```

The direct development launch remains available: `python sshvault/sshvault.py`.

To install a built wheel:

```bash
python -m pip install dist/sshvault-0.3.2-py3-none-any.whl
```

## Usage

Launch SSHVault, create a profile, choose SSH agent, password, or private-key
authentication, and connect. The workspace then exposes Terminal, SFTP, Remote
Command, and Tunnels actions. Use Settings for appearance, timeout, scrollback,
download-directory, and confirmation preferences.

## Profiles and authentication

Profiles contain a name, host, port, username, authentication method, tags, and
notes. Authentication can use the SSH agent, a private key, or a password. The
password and key passphrase are stored through the operating-system keyring when
available; they are never written to profile JSON, exports, backups, or logs.

## Connections and security

Unknown host keys show the host, port, key type, and SHA-256 fingerprint. Users
can trust once or trust and save. Changed keys are blocked and require separate
known-host management. ProxyJump verifies the jump and destination hosts
independently. The application does not modify the global `~/.ssh/known_hosts`
automatically.

The terminal uses a bounded pyte screen and scrollback. SFTP transfers run in
workers and use verified sessions. Local, remote, and SOCKS tunnels reuse the
verified transport. Remote commands stream output in a cancellable worker.

## Data and settings

Runtime data is stored below the platform configuration directory (typically
`~/.config/sshvault` on Linux): vault, settings, application known-hosts,
backups, logs, and session state. Settings control scrollback, timeout,
download directory, and confirmation preferences. Secrets are kept separately
in the OS keyring.

Profiles can be imported/exported as versioned, secret-free JSON. Backups are
timestamped and never overwrite an earlier backup. Restore previews data and
creates a safety backup before replacing profiles.

## Troubleshooting

Check the redacted application log for diagnostics. Authentication failures,
timeouts, DNS errors, changed host keys, and malformed vaults are reported
separately. Ensure Tk is installed, the keyring service is available, and the
private-key path is readable. If the keyring is unavailable, SSHVault does not
fall back to plaintext storage.

## Tests and development

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sshvault python -m unittest discover -s sshvault/tests -v
python -m py_compile sshvault/sshvault.py sshvault/sshvault_core.py sshvault/sshvault_security.py
```

Optional tooling is declared in the `dev` extra (`build`, `pytest`, `ruff`, and
`mypy`). Known limitations include platform-specific keyring behavior, limited
transfer-speed reporting, and the requirement for a desktop Tk display.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and
[SECURITY.md](SECURITY.md) for vulnerability reporting.
