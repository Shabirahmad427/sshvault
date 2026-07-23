# Security policy

Please report suspected vulnerabilities privately to the project maintainer
before opening a public issue. Include a description, affected version, safe
reproduction steps, and impact. Do not include passwords, private keys, tokens,
or live host data.

SSHVault keeps host-key verification enabled, blocks changed keys, stores
passwords/passphrases through the OS keyring when available, and writes
secret-free profile/export/backup JSON. The application does not automatically
modify the global SSH known-hosts file. Keyring availability and platform UI
behavior remain environment-dependent.

