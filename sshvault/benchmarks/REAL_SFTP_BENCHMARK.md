# Real SFTP benchmark

Run this only from a development session that already owns an authenticated,
worker-safe SFTP client. `SFTPBenchmarkRunner` accepts a client factory and
never reads profiles, credentials, keys, or payload data.

Use the same host and a disposable 256 MiB or 1 GiB remote test object. Delete
the remote and local benchmark files after a successful run.

For an external comparison, invoke these yourself with the same account and
test file; SSHVault never executes them automatically:

```sh
sftp user@host
scp user@host:/remote/benchmark.bin /tmp/benchmark.bin
rsync -e ssh --progress user@host:/remote/benchmark.bin /tmp/benchmark.bin
```

Compare elapsed time and bytes transferred. If all three external tools are
similarly slow, the likely limit is the server, network path, disk, cipher CPU,
or SSH policy rather than SSHVault.
