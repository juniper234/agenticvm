r"""Black-box checks for the real guest service, with no third-party packages.

Linux: python3 guest/test_agent.py --binary ./agentd
Windows VM: python guest/test_agent.py --pipe \\.\pipe\agenticvm-PROFILE
Local QEMU: python guest/test_agent.py --socket C:\path\to\AgenticVM\runtime\SESSION\s
Legacy QEMU: python guest/test_agent.py --tcp 127.0.0.1:43210

The socket and pipe modes use the production controller's framed transports to
test a running VM. Tests modify only /workspace/agent-test-* and retained jobs.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, BinaryIO


class Rpc:
    def __init__(self, reader: BinaryIO, writer: BinaryIO):
        self.reader, self.writer = reader, writer
        self.responses: queue.Queue[Any] = queue.Queue(maxsize=32)
        self.sequence = 0
        self.transfer_metrics: dict[str, Any] = {}
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        pending = bytearray()
        try:
            while True:
                chunk = self.reader.read(4096)
                if not chunk:
                    raise EOFError("Guest transport closed")
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    if len(line) > 2 * 1024 * 1024:
                        raise ValueError("Guest frame exceeds 2 MiB")
                    try:
                        response = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue  # Bounded boot messages may precede the agent.
                    self.responses.put(response, timeout=10)
                if len(pending) > 2 * 1024 * 1024:
                    raise ValueError("Guest frame exceeds 2 MiB")
        except BaseException as exc:
            try:
                self.responses.put(exc, timeout=1)
            except queue.Full:
                pass

    def call_raw(self, body: dict[str, Any], *, timeout: float = 15) -> dict[str, Any]:
        self.sequence += 1
        request = {"v": 1, "id": f"test-{self.sequence}", **body}
        encoded = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        view = memoryview(encoded)
        while view:
            n = self.writer.write(view)
            if not n:
                raise EOFError("Cannot write guest request")
            view = view[n:]
        self.writer.flush()
        end = time.monotonic() + timeout
        while True:
            response = self.responses.get(timeout=max(0.01, end - time.monotonic()))
            if isinstance(response, BaseException):
                raise response
            if response.get("id") == request["id"]:
                assert response["v"] == 1, response
                return response
            if time.monotonic() >= end:
                raise TimeoutError("No matching guest response")

    def call(self, op: str, **fields: Any) -> dict[str, Any]:
        response = self.call_raw({"op": op, **fields})
        assert response.get("ok") is True, response
        return response["result"]

    def error(self, op: str, code: str, **fields: Any) -> None:
        response = self.call_raw({"op": op, **fields})
        assert response.get("ok") is False, response
        assert response["error"]["code"] == code, response

    def finish(self, job: str, *, timeout: float = 8) -> dict[str, Any]:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = self.call("poll", job_id=job, wait_ms=100)
            if result["state"] == "exited":
                self.call("forget", job_id=job)
                return result
        raise TimeoutError(f"Job {job} did not finish")

    def execute(self, argv: list[str], **fields: Any) -> dict[str, Any]:
        return self.finish(self.call("exec", argv=argv, **fields)["job_id"])


class PipeRpc(Rpc):
    """Use a production framed transport with no concurrent reader thread.

    A pending synchronous read can serialize a duplex Windows handle and stop
    its first request from being written. Timed overlapped operations avoid
    that deadlock; issuing the write before reads also keeps ownership simple.
    Filesystem sockets share the same write/readline/close contract.
    """

    def __init__(self, transport: Any):
        self.transport = transport
        self.sequence = 0
        self.transfer_metrics: dict[str, Any] = {}

    def call_raw(self, body: dict[str, Any], *, timeout: float = 15) -> dict[str, Any]:
        self.sequence += 1
        request = {"v": 1, "id": f"test-{self.sequence}", **body}
        encoded = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > 2 * 1024 * 1024:
            raise ValueError("Guest request exceeds 2 MiB")
        deadline = time.monotonic() + timeout
        self.transport.write(encoded, timeout)
        for _ in range(128):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("No matching guest response")
            raw = self.transport.readline(remaining, 2 * 1024 * 1024)
            try:
                response = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            if isinstance(response, dict) and response.get("id") == request["id"]:
                assert response["v"] == 1, response
                return response
        raise TimeoutError("Too many unrelated guest response frames")


def check_service(rpc: Rpc, *, extended: bool = False, expected_profile: str | None = None) -> list[str]:
    passed: list[str] = []

    def record(name: str) -> None:
        passed.append(name)
        print(f"PASS {name}", flush=True)

    info = rpc.call("ping")
    assert info["protocol"] == 1 and info["uid"] == 1000 and info["gid"] == 1000, info
    record("protocol negotiation and unprivileged identity")
    profile = info["profile"]
    assert profile in ("command", "desktop"), info
    if expected_profile:
        assert profile == expected_profile, info
    assert info["display"] == (":0" if profile == "desktop" else None), info
    assert info["limits"]["persistent_jobs"] == (profile == "desktop"), info
    result = rpc.execute(["/bin/sh", "-c", "env"])
    assert result["exit_code"] == 0, result
    environment = dict(line.split("=", 1) for line in base64.b64decode(result["stdout_b64"]).decode().splitlines())
    expected = {"PATH": "/bin:/usr/bin:/sbin:/usr/sbin", "HOME": "/workspace", "LANG": "C.UTF-8"}
    if profile == "desktop":
        expected.update(DISPLAY=":0", XAUTHORITY="/workspace/.Xauthority", XDG_RUNTIME_DIR="/run/user/1000",
                        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus")
    # A shell can add PWD, OLDPWD, SHLVL and _, but must not inherit host/session
    # secrets or a display/session bus in the command profile.
    assert {k: v for k, v in environment.items() if k not in ("PWD", "OLDPWD", "SHLVL", "_")} == expected, environment
    result = rpc.execute(["/bin/sh", "-c", "cat /proc/self/limits; cat /proc/self/status"])
    assert result["exit_code"] == 0, result
    status = base64.b64decode(result["stdout_b64"]).decode()
    def limit_values(name: str) -> list[str]:
        return next(line[len(name):].split() for line in status.splitlines() if line.startswith(name))[:2]
    assert limit_values("Max address space") == (["unlimited", "unlimited"] if profile == "desktop" else ["134217728"] * 2), status
    assert limit_values("Max open files") == (["1024"] * 2 if profile == "desktop" else ["64"] * 2), status
    assert limit_values("Max processes") == (["256"] * 2 if profile == "desktop" else ["64"] * 2), status
    assert limit_values("Max file size") == (["134217728"] * 2 if profile == "desktop" else ["33554432"] * 2), status
    assert limit_values("Max core file size") == ["0", "0"], status
    assert "NoNewPrivs:\t1" in status, status
    record(f"{profile} profile uses explicit environment, real resource limits and NoNewPrivs")
    assert rpc.call_raw({"op": "ping", "id": "test-\U0001f680"})["ok"] is True

    response = rpc.call_raw({"op": "ping", "v": 2})
    assert response["ok"] is False and response["error"]["code"] == "unsupported_version", response
    rpc.error("absent", "unknown_operation")
    rpc.error("exec", "invalid_argument", argv=[])
    if profile == "command":
        rpc.error("exec", "invalid_argument", argv=["true"], timeout_ms=0)
    else:
        job = rpc.call("exec", argv=["/bin/sleep", "20"], timeout_ms=0)["job_id"]
        snapshot = rpc.call("poll", job_id=job, wait_ms=200)
        assert snapshot["state"] == "running" and not snapshot["timed_out"], snapshot
        rpc.call("cancel", job_id=job)
        assert rpc.finish(job)["cancelled"] is True
        record("desktop persistent job stays alive until explicit cancellation")
    rpc.error("exec", "invalid_argument", argv=["true"], output_limit=65537)
    record("invalid protocol and command bounds")

    result = rpc.execute(["/bin/sh", "-c", "printf 'hello'; printf 'oops' >&2; exit 7"])
    assert result["exit_code"] == 7 and result["signal"] == 0, result
    assert base64.b64decode(result["stdout_b64"], validate=True) == b"hello", result
    assert base64.b64decode(result["stderr_b64"], validate=True) == b"oops", result
    record("separate stdout/stderr and nonzero exit")

    result = rpc.execute(["/agenticvm-absent-command"])
    assert result["exit_code"] == 127, result
    assert b"exec:" in base64.b64decode(result["stderr_b64"]), result
    record("missing executable reports exit 127")

    # This verifies argv is never interpreted as a shell command by the agent.
    literal = "a b;$(echo wrong)\n\U0001f680"
    result = rpc.execute(["/bin/printf", "%s", literal])
    assert base64.b64decode(result["stdout_b64"]) == literal.encode(), result
    record("literal argv, JSON escapes and Unicode")

    result = rpc.execute(["/bin/sh", "-c", "yes x | head -c 10000; yes y | head -c 10000 >&2"], output_limit=37)
    assert len(base64.b64decode(result["stdout_b64"])) == 37, result
    assert len(base64.b64decode(result["stderr_b64"])) == 37, result
    assert result["stdout_truncated"] and result["stderr_truncated"], result
    record("bounded output with continued pipe draining")

    result = rpc.execute(["/bin/sh", "-c", "sleep 20"], timeout_ms=100)
    assert result["timed_out"] and result["signal"] == 9, result
    record("deadline terminates the command process group")

    job = rpc.call("exec", argv=["/bin/sh", "-c", "sleep 20 & child=$!; printf '%s' \"$child\" > agent-test-child.pid; wait"])["job_id"]
    # Wait until the descendant exists before testing cancellation.
    end = time.monotonic() + 3
    while True:
        response = rpc.call_raw({"op": "read_file", "path": "agent-test-child.pid"})
        if response.get("ok") and response["result"]["size"]:
            child = base64.b64decode(response["result"]["data_b64"]).decode("ascii")
            break
        assert time.monotonic() < end, response
        time.sleep(0.02)
    rpc.error("forget", "busy", job_id=job)
    assert rpc.call("cancel", job_id=job)["cancelled"] is True
    result = rpc.finish(job)
    assert result["cancelled"] and result["signal"] == 9, result
    result = rpc.execute(["/bin/sh", "-c", f"! kill -0 {int(child)} 2>/dev/null"])
    assert result["exit_code"] == 0, result
    record("cancellation also reaps a command descendant")

    a = rpc.call("exec", argv=["/bin/sleep", "20"])["job_id"]
    b = rpc.call("exec", argv=["/bin/sleep", "20"])["job_id"]
    rpc.error("exec", "busy", argv=["/bin/true"])
    for job in (a, b):
        rpc.call("cancel", job_id=job)
        rpc.finish(job)
    record("two-job concurrency cap")

    contents = bytes(range(256)) * 16
    path = "/workspace/agent-test-binary.dat"
    result = rpc.call("write_file", path=path, data_b64=base64.b64encode(contents).decode())
    assert result["size"] == len(contents), result
    result = rpc.call("read_file", path="agent-test-binary.dat")
    assert base64.b64decode(result["data_b64"], validate=True) == contents, result
    assert rpc.call("stat", path=path) == {"type": "file", "size": len(contents)}
    assert rpc.call("stat", path="/workspace")["type"] == "directory"
    rpc.error("write_file", "invalid_argument", path=path, data_b64="A===")
    rpc.error("write_file", "invalid_argument", path=path, data_b64="YR==")  # Noncanonical padding bits.
    record("binary file round trip and strict base64")

    result = rpc.execute(["/bin/sh", "-c", "mkdir -p agent-test-real; ln -sfn /etc agent-test-linkdir; ln -sfn /etc/passwd agent-test-link; dd if=/dev/zero of=agent-test-large bs=1024 count=1025 2>/dev/null"])
    assert result["exit_code"] == 0, result
    for path in ("../etc/passwd", "/etc/passwd", "/workspace/../etc/passwd"):
        rpc.error("read_file", "invalid_path", path=path)
    rpc.error("read_file", "invalid_path", path="agent-test-link")
    rpc.error("read_file", "invalid_path", path="agent-test-linkdir/passwd")
    rpc.error("write_file", "invalid_path", path="agent-test-link", data_b64="YQ==")
    rpc.error("stat", "invalid_path", path="agent-test-link")
    rpc.error("exec", "invalid_path", argv=["/bin/pwd"], cwd="agent-test-linkdir")
    rpc.error("exec", "invalid_path", argv=["/bin/pwd"], cwd="/workspace/../")
    rpc.error("read_file", "size_limit", path="agent-test-large")
    record("traversal, symlink and file-size boundaries")

    result = rpc.execute(["/bin/pwd"], cwd="/workspace/agent-test-real")
    assert base64.b64decode(result["stdout_b64"]).rstrip().endswith(b"/agent-test-real"), result
    record("workspace-relative execution directory")

    if extended:
        contents = b"x" * (1024 * 1024)
        # A real serial link can take several minutes for a maximum-size file.
        transfer_start = time.monotonic()
        response = rpc.call_raw({"op": "write_file", "path": "agent-test-1m", "data_b64": base64.b64encode(contents).decode()}, timeout=300)
        assert response["ok"] and response["result"]["size"] == len(contents), response
        write_elapsed = time.monotonic() - transfer_start
        read_start = time.monotonic()
        response = rpc.call_raw({"op": "read_file", "path": "agent-test-1m"}, timeout=300)
        assert response["ok"] and base64.b64decode(response["result"]["data_b64"]) == contents, response
        read_elapsed = time.monotonic() - read_start
        rpc.transfer_metrics = {"file_bytes": len(contents), "write_seconds": round(write_elapsed, 6),
                                "read_seconds": round(read_elapsed, 6),
                                "round_trip_seconds": round(write_elapsed + read_elapsed, 6),
                                "payload_bytes_per_second": round(2 * len(contents) / (write_elapsed + read_elapsed))}
        record("maximum 1 MiB file transfer")

    result = rpc.execute(["/bin/sh", "-c", "rm -rf agent-test-child.pid agent-test-binary.dat agent-test-real agent-test-linkdir agent-test-link agent-test-large agent-test-1m"])
    assert result["exit_code"] == 0, result
    record("test workspace cleanup")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--binary", type=Path)
    target.add_argument("--pipe")
    target.add_argument("--socket", help="Owned filesystem socket path from the running QEMU session")
    target.add_argument("--tcp", help="Loopback HOST:PORT, for the QEMU development backend")
    parser.add_argument("--extended", action="store_true")
    parser.add_argument("--profile", choices=("command", "desktop"), help="Expected guest profile; also selects a local --binary launch profile")
    parser.add_argument("--shutdown", action="store_true", help="Shut down the service after passing (VM init may power off)")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    process = None
    temporary = None
    pipe = None
    connection = None
    started = time.time()
    try:
        if args.binary:
            if os.name != "posix":
                parser.error("--binary requires Linux; use --socket or --pipe for a Windows-hosted VM")
            temporary = tempfile.TemporaryDirectory(prefix="agenticvm-test-")
            workspace = Path(temporary.name)
            if os.getuid() == 0:
                os.chown(workspace, 1000, 1000)
            elif os.getuid() != 1000 or os.getgid() != 1000:
                parser.error("Local tests require UID/GID 1000, or root to drop to 1000")
            process = subprocess.Popen([str(args.binary.resolve()), "--stdio", "--workspace", str(workspace), "--uid", "1000", "--gid", "1000", "--profile", args.profile or "command"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            assert process.stdout and process.stdin
            rpc = Rpc(process.stdout, process.stdin)
        elif args.pipe:
            if not args.pipe.startswith("\\\\.\\pipe\\"):
                parser.error("--pipe must be an explicit Windows named-pipe path")
            # Import the project's audited overlapped implementation explicitly,
            # even when this script is run without installing the host package.
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
            from agenticvm.transport import WindowsPipeTransport
            pipe = WindowsPipeTransport(args.pipe, timeout=15)
            rpc = PipeRpc(pipe)
        elif args.socket:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
            from agenticvm.transport import SocketTransport
            pipe = SocketTransport(args.socket, timeout=15)
            rpc = PipeRpc(pipe)
        else:
            host, separator, port = args.tcp.rpartition(":")
            if not separator or host not in ("127.0.0.1", "localhost", "::1", "[::1]") or not port.isdecimal() or not 1 <= int(port) <= 65535:
                parser.error("--tcp must use a loopback HOST:PORT")
            connection = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
            connection.settimeout(None)
            pipe = connection.makefile("rwb", buffering=0)
            rpc = Rpc(pipe, pipe)
        passed = check_service(rpc, extended=args.extended, expected_profile=args.profile)
        if args.tcp or args.socket:
            previous_pid = rpc.call("ping")["pid"]
            retained_job = rpc.call("exec", argv=["/bin/sleep", "20"])["job_id"]
            deadline_job = rpc.call("exec", argv=["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 0.3; : > agent-test-timeout-survival"], timeout_ms=100)["job_id"]
            previous_metrics = rpc.transfer_metrics
            if connection:
                connection.shutdown(socket.SHUT_RDWR)
            pipe.close()
            if connection:
                connection.close()
            time.sleep(0.5)  # No RPC can wake the guest during this job deadline.
            if args.socket:
                pipe = SocketTransport(args.socket, timeout=10)
                rpc = PipeRpc(pipe)
                pipe.write(b"\n", timeout=10)  # Resynchronize a prior partial frame.
            else:
                connection = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
                connection.settimeout(None)
                pipe = connection.makefile("rwb", buffering=0)
                rpc = Rpc(pipe, pipe)
                pipe.write(b"\n")
            rpc.transfer_metrics = previous_metrics
            assert rpc.call("ping")["pid"] == previous_pid
            assert rpc.call("cancel", job_id=retained_job)["cancelled"] is True
            assert rpc.finish(retained_job)["cancelled"] is True
            passed.append("serial reconnect preserves service and active jobs")
            print("PASS serial reconnect preserves service and active jobs", flush=True)
            result = rpc.finish(deadline_job)
            assert result["timed_out"] and result["signal"] == 9, result
            rpc.error("read_file", "invalid_path", path="agent-test-timeout-survival")
            passed.append("deadline runs with closed output and disconnected host")
            print("PASS deadline runs with closed output and disconnected host", flush=True)
        if args.shutdown or process:
            assert rpc.call("shutdown")["shutting_down"] is True
        if process:
            assert process.wait(timeout=5) == 0, process.stderr.read().decode(errors="replace")
        transport = ("stdio" if args.binary else "Windows named pipe" if args.pipe
                     else "filesystem socket serial" if args.socket else "loopback TCP serial")
        report = {"passed": passed, "count": len(passed), "elapsed_seconds": round(time.time() - started, 3),
                  "transport": transport, "extended": args.extended}
        if rpc.transfer_metrics:
            report["transfer"] = rpc.transfer_metrics
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"{len(passed)} real-service checks passed.")
        return 0
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if pipe:
            pipe.close()
        if connection:
            connection.close()
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
