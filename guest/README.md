# Guest service

`agent.c` is a dependency-free Linux C service. It speaks protocol v1 as newline-delimited JSON over its standard input/output. QEMU uses a virtio-serial character device for bulk throughput; VirtualBox can use `/dev/ttyS0` through a UART named pipe. Only the service writes protocol responses; Linux boot messages use the VGA console.

The service configures a serial TTY to raw 115200 baud, ignores carrier changes, and waits through character-device disconnects, including non-TTY virtio ports. `--stdio` enables normal EOF termination for local tests. The PID 1 init powers off after the service handles `shutdown`.

Virtio ports require one duplex open shared by stdin and stdout. `poll` gates input; each character-device read temporarily enables nonblocking mode to handle connection races, then restores blocking mode before any response. Raw UART input uses `VMIN=1`. Output stays blocking so serial backpressure cannot truncate JSON responses.

The service sleeps indefinitely when idle. Linux `signalfd` delivers child-exit and asynchronous device notifications; active jobs arm only their next deadline. A disconnected virtio port is removed from `poll` until its SIGIO reconnect notification, avoiding repeated HUP wakeups. This follows the connection-change and FASYNC behavior in the [Linux virtio-console driver](https://raw.githubusercontent.com/torvalds/linux/v6.18/drivers/char/virtio_console.c).

Build a static x86-64 musl executable:

```text
zig cc -target x86_64-linux-musl -Os -static -s -std=c11 -Wall -Wextra -Werror guest/agent.c -o agentd
```

Root must explicitly request `--uid 1000 --gid 1000`. The service clears supplementary groups, sets GID and UID, and refuses to run if privilege dropping fails. Init creates and assigns `/workspace` before launching it. `PR_SET_NO_NEW_PRIVS` prevents gaining privileges through subsequent execs.

`--profile command` is the default and preserves the small command guest limits. The desktop image explicitly starts the service with `--profile desktop`; individual RPCs cannot select or relax a profile. Desktop commands receive `DISPLAY=:0`, `XAUTHORITY=/workspace/.Xauthority`, `XDG_RUNTIME_DIR=/run/user/1000`, and `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus`, alongside the shared `PATH`, `HOME=/workspace`, and `LANG=C.UTF-8`. These are explicit values, not inherited host environment variables. Init owns the X server, Xauthority cookie and session bus, and starts the desktop outside the agent's execution job process groups.

| Child resource | Command profile | Desktop profile |
| --- | --- | --- |
| Virtual address space | 128 MiB | Unlimited; Chromium requires sparse address reservations |
| Maximum single file | 32 MiB | 128 MiB |
| Open descriptors | 64 | 1024 |
| Processes/threads for UID 1000 | 64 | 256, including the desktop session |
| Core dumps | Disabled | Disabled |
| Persistent jobs (`timeout_ms=0`) | Rejected | Explicitly permitted until cancellation/shutdown |

The VM's physical RAM allocation bounds desktop memory; an unlimited virtual address space does not allocate that amount of physical memory. There is no claim that `RLIMIT_RSS` limits browser memory. Chromium must retain its user-namespace sandbox; `NoNewPrivs` remains enabled and the service never inserts `--no-sandbox`. The image must provide user namespace and sandbox kernel support. The `ping` display value describes configuration, so the host separately verifies the actual X server and window manager before reporting desktop readiness.

## Protocol

Every request has `{"v":1,"id":"request-id","op":"ping"}`. Success replies are `{"v":1,"id":"request-id","ok":true,"result":{...}}`; failures replace `result` with `"error":{"code":"...","message":"..."}` and set `ok` false. Request IDs are at most 128 bytes. Each request occupies one line, at most 2 MiB excluding its newline. No shell is inserted by the service.

| Operation | Request fields | Result |
| --- | --- | --- |
| `ping` | None | `protocol`, `uid`, `gid`, `pid`, `profile`, `display`, configured limits |
| `exec` | `argv` (1–64 strings), optional `cwd`, `timeout_ms` (1–300000, default 30000; explicit 0 only in desktop profile), `output_limit` (0–65536 per stream, default 65536) | `job_id` immediately |
| `poll` | `job_id`, optional `wait_ms` (0–1000) | `state` (`running`/`exited`), cumulative `stdout_b64`, `stderr_b64`, truncation/timeout/cancellation flags; exited jobs add `exit_code` and `signal` |
| `cancel` | `job_id` | `job_id`, `cancelled`; sends SIGKILL to the job process group |
| `forget` | `job_id` | `forgotten`; only completed jobs can be forgotten |
| `read_file` | `path` | `size`, `data_b64` |
| `write_file` | `path`, `data_b64` | `size`; atomic replacement, mode 0600 |
| `stat` | `path` | `type` (`file`, `directory`, `other`), `size` |
| `shutdown` | None | `shutting_down`, then service exits |

Exit status for a signal is `128 + signal`; a missing executable yields 127. Captures continue draining after their byte cap to avoid blocking a child. Commands have `/dev/null` stdin and the profile's explicit environment and limits. The service supports at most two active jobs and eight retained snapshots; callers should forget completed jobs. A timeout, cancellation, normal parent exit, or shutdown terminates the associated process group. A persistent desktop application must remain in the foreground of its tracked job; a launcher that backgrounds a child then exits causes that child's process group to be terminated. The Linux subreaper collects orphaned descendants. Cancellation affects the tracked job, not the independently supervised X server, window manager or session bus.

File RPCs accept paths relative to `/workspace` or absolute paths beginning with `/workspace/`. They reject parent traversal and symlink traversal. Directory walks use file descriptors with `openat` and `O_NOFOLLOW`; writes use a temporary file and `renameat`. Regular-file transfers are capped at 1 MiB. Workspace ownership and the guest memory budget bound the disposable environment.

The VM is the isolation boundary. Ordinary commands can access files readable by guest UID 1000 outside `/workspace`; the file RPC path policy does not confine `exec`. A program that creates a new session can escape its original process group; hostile workloads require a cgroup-backed job supervisor before multi-tenant use. This prototype intentionally uses no network, shared folders, host clipboard, credentials, or guest privilege escalation.

## Real-service checks

`test_agent.py` exercises the real service through Linux stdin/stdout, a Windows named pipe, or a loopback TCP serial connection. It checks identity, actual `/proc` resource limits and `NoNewPrivs`, the environment allowlist, invalid requests, argv handling, exit status, separate output, truncation, timeout, cancellation and descendant reaping, concurrency, binary file transfers, size limits, path traversal, symlinks, and workspace directories. Desktop profile checks include a persistent job that survives without a deadline and can be cancelled. TCP tests disconnect and reconnect while a command is active, then verify the service and retained job survived. They also verify a deadline terminates a command while both its output pipes and the host connection are closed.

```text
python3 guest/test_agent.py --binary ./agentd --extended --report guest-test-report.json
python guest/test_agent.py --pipe \\.\pipe\agenticvm-PROFILE --report runtime/guest-test-report.json
python guest/test_agent.py --tcp 127.0.0.1:43210 --report runtime/guest-test-report.json
python guest/test_agent.py --tcp 127.0.0.1:43210 --profile desktop --report runtime/desktop-guest-test-report.json
```

Local tests require UID/GID 1000 or root to drop to 1000. Pipe tests leave the service running unless `--shutdown` is requested. `--extended` includes a maximum-size 1 MiB file transfer, which may take several minutes over a real serial link.
