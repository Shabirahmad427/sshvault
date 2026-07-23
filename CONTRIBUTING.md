# Contributing to SSHVault

1. Create a virtual environment and install development tools:
   `python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'`.
2. Run the checks before opening a pull request:
   `ruff check sshvault`, `ruff format --check sshvault`, the staged Mypy gate,
   and `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sshvault python3 -m unittest discover -s sshvault/tests -v`.
3. Keep security-sensitive changes small and add display-free tests.
4. Never commit vaults, credentials, private keys, logs, or machine-specific paths.
5. Describe behavior changes and limitations in the pull request.

Do not change host-key verification or secret handling without focused tests and
review. Pull requests should not include generated wheels or build directories.

