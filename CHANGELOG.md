# Changelog

## 0.3.2

- Added a session dashboard state model with safe connection event history.
- Added a connection-log view for non-sensitive session events.

## 0.3.1

- Added centralized appearance preferences for System, Light, and Dark themes.
- Added bounded application and terminal font-size controls with reset support.

## 0.3.0

- Secure SHA-256 host-key verification with trust-once, trust-and-save, and
  dedicated changed-key blocking.
- Independent verification for both ProxyJump hops.
- OS-keyring-backed secret storage with secret-free profile files, exports, and
  backups.
- Profile management with validation, duplicate detection, import/export, and
  timestamped backup/restore workflows.
- Worker-based terminal, SFTP, tunnel, and remote command workflows with
  bounded cleanup and stale-result suppression.
- Settings for scrollback, timeouts, download location, and confirmations.
- Packaging metadata, development tooling, and the `sshvault` console command.

Known limitations: UI typing remains partially relaxed for dynamic Tk widgets;
the remaining diagnostics are tracked in `typing-baseline.md`. Keyring behavior
varies by operating system, transfer speeds may be unavailable, and a desktop
Tk display is required to run the application.
