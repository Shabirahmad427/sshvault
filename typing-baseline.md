# Mypy typing baseline

`sshvault_core.py` and `sshvault_security.py` pass the configured Mypy gate.
The UI module `sshvault.py` currently has 29 diagnostics under the configured
temporary UI relaxation (34 before the latest low-risk fixes).

The temporary UI relaxation disables only `attr-defined` and `misc`, which are
dominated by dynamic Tkinter attributes and callback/lambda inference. Other
checks remain active, including undefined names, invalid calls, return types,
and optional-value errors. The UI baseline is intentionally not claimed as a
clean type gate.

Remaining UI categories include dynamic Tkinter attributes, callback inference,
optional Paramiko transports, dynamic containers, and a small number of
third-party API typing mismatches. The planned removal sequence is to annotate
session-bound widgets and worker callbacks, add explicit Optional guards, then
replace dynamic dictionaries with TypedDicts.
