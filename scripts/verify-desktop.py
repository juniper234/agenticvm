"""Black-box desktop checks through the public CLI and real guest input devices.

The default creates its own persistent test workspace. --existing controls an
already running workspace and deliberately skips reset/stop persistence checks.
No browser debugger, DOM automation or host desktop automation is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--existing", action="store_true")
    parser.add_argument("--memory", type=int, default=768)
    parser.add_argument("--image", type=Path, help="Explicit boot ISO; retained across reset and fresh start checks")
    parser.add_argument("--input-position", type=int, nargs=2, default=(400, 266))
    parser.add_argument("--submit-position", type=int, nargs=2, default=(60, 316))
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    workspace = (args.workspace or ROOT / "runtime" / ("desktop-check-" + uuid4().hex[:10])).resolve()
    if args.existing and not args.workspace:
        parser.error("--existing requires an explicit --workspace")
    if not args.existing and (workspace / "sessions/default.json").exists():
        parser.error("Use a fresh workspace for lifecycle checks; existing state is preserved")
    workspace.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    prefix = [sys.executable, "-m", "agenticvm", "--workspace", str(workspace)]
    report = {"workspace": str(workspace), "real_linux_desktop": True,
              "browser_debugger_used": False, "checks": [], "commands": [], "passed": False}
    output = workspace / ("desktop-verification-" + uuid4().hex[:8] + ".json")
    image_options = ["--image", args.image.resolve()] if args.image else []

    def save():
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def command(*argv, expected=0):
        begin = time.monotonic()
        result = subprocess.run([*prefix, *map(str, argv)], cwd=ROOT, env=environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=180)
        try:
            data = json.loads(result.stdout)
        except ValueError:
            raise AssertionError({"argv": argv, "stdout": result.stdout, "stderr": result.stderr})
        record = {"argv": list(map(str, argv)), "exit_code": result.returncode,
                  "result": data, "elapsed_seconds": time.monotonic() - begin}
        report["commands"].append(record)
        save()
        assert result.returncode == expected and data["ok"], record
        return data["result"]

    def check(description):
        report["checks"].append(description)
        save()
        print("PASS " + description, flush=True)

    def await_title(needle, timeout=30):
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = command("exec", "--", "/usr/bin/xdotool", "getactivewindow", "getwindowname")["stdout"].strip()
            if needle in last:
                return last
            time.sleep(0.2)
        raise AssertionError(f"Browser title did not contain {needle!r}: {last!r}")

    try:
        if not args.existing:
            started = command("start", "--profile", "desktop", "--persistent", "--network", "--memory", args.memory, *image_options)
            report["boot_to_ready_seconds"] = report["commands"][-1]["elapsed_seconds"]
        else:
            started = command("status")
        assert started.get("profile") == "desktop"
        assert started["guest"]["uid"] == 1000
        assert command("desktop-ready")["ready"]
        check("Real desktop and browser are ready; guest agent runs as UID 1000")
        release = command("exec", "--", "/bin/cat", "/etc/os-release")["stdout"]
        assert "ID=debian" in release and 'VERSION_ID="13"' in release, release
        report["guest_os_release"] = release
        check("Guest userspace identifies as Debian 13")

        command("open-url", "http://127.0.0.1:8080/")
        await_title("AgenticVM Desktop Ready")
        command("screenshot", workspace / "desktop-before.png", "--overwrite")
        value = "AgenticVM works: café 中文 🚀"
        command("click", *args.input_position)
        command("type", value)
        command("click", *args.submit_position)
        actual_title = await_title("Passed: " + value)
        report["verified_browser_title"] = actual_title
        command("screenshot", workspace / "desktop-input-passed.png", "--overwrite")
        check("QMP mouse clicks and literal Unicode typing submit the real browser form")
        command("open-url", "http://127.0.0.1:8080/?scroll=1")
        await_title("AgenticVM Desktop Ready")
        command("scroll", 3)
        scroll_title = await_title("AgenticVM Scrolled:")
        assert int(re.search(r"AgenticVM Scrolled: (\d+)", scroll_title).group(1)) > 0
        command("scroll", -32)
        await_title("AgenticVM Scrolled: 0")
        check("Virtual mouse wheel moves the real browser page and returns to the top")
        command("key", "ctrl+l")
        command("type", "https://www.debian.org/")
        command("key", "enter")
        await_title("Debian", timeout=45)
        check("Guest browser reaches an external HTTPS site using NAT and keyboard input")

        terminal = command("exec", "--async", "--", "/usr/bin/xfce4-terminal", "--disable-server",
                           "--title", "AgenticVM Input Check", "--execute", "/bin/sh", "-c",
                           'IFS= read -r line; printf "%s" "$line" > /workspace/desktop-terminal-input.txt; sleep 30')
        try:
            await_title("AgenticVM Input Check")
            terminal_value = "Terminal café 中文 🚀 $(id)"
            command("type", terminal_value)
            command("key", "enter")
            deadline = time.monotonic() + 8
            while True:
                probe = subprocess.run([*prefix, "exec", "--", "/bin/test", "-f", "/workspace/desktop-terminal-input.txt"],
                                       cwd=ROOT, env=environment, capture_output=True, timeout=15)
                if probe.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("The real terminal did not receive its input")
                time.sleep(0.1)
            terminal_output = workspace / "desktop-terminal-input.txt"
            command("get", "desktop-terminal-input.txt", terminal_output, "--overwrite")
            assert terminal_output.read_bytes() == terminal_value.encode("utf-8")
            check("Literal Unicode input reaches a real Linux terminal without shell expansion")
        finally:
            command("cancel", terminal["job_id"])
            for _ in range(20):
                snapshot = command("poll", terminal["job_id"], "--wait-ms", "100")
                if snapshot["state"] == "exited":
                    break
            assert snapshot["state"] == "exited"
            command("forget", terminal["job_id"])
        command("open-url", "http://127.0.0.1:8080/")
        await_title("AgenticVM Desktop Ready")

        payload = bytes(range(256)) * 4096
        source, downloaded = workspace / "desktop-input.bin", workspace / "desktop-output.bin"
        source.write_bytes(payload)
        command("put", source, "desktop-persistence-marker.bin")
        command("get", "desktop-persistence-marker.bin", downloaded, "--overwrite")
        assert downloaded.read_bytes() == payload
        report["file_sha256"] = hashlib.sha256(payload).hexdigest()
        check("One MiB binary host/guest file round trip preserves every byte")

        # Closing the browser is normal user behavior. Opening a URL must recover it.
        command("key", "alt+f4")
        deadline = time.monotonic() + 8
        while command("desktop-ready")["ready"] and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not command("desktop-ready")["ready"]
        command("open-url", "http://127.0.0.1:8080/")
        await_title("AgenticVM Desktop Ready")
        check("Opening a URL restarts a browser closed through the desktop")

        if not args.existing:
            command("exec", "--", "/bin/touch", "/tmp/agenticvm-reset-marker")
            reset = command("reset")
            assert reset["uuid"] != started["uuid"]
            report["reset_to_ready_seconds"] = report["commands"][-1]["elapsed_seconds"]
            command("exec", "--", "/bin/test", "!", "-e", "/tmp/agenticvm-reset-marker")
            command("get", "desktop-persistence-marker.bin", downloaded, "--overwrite")
            assert downloaded.read_bytes() == payload
            check("Reset replaces the VM, clears temporary data and preserves workspace bytes")
            command("stop")
            state = command("status")
            assert state["status"] == "stopped" and state["registered"] is False
            command("start", "--profile", "desktop", "--persistent", "--network", "--memory", args.memory, *image_options)
            command("get", "desktop-persistence-marker.bin", downloaded, "--overwrite")
            assert downloaded.read_bytes() == payload
            check("A clean stop and fresh start preserve the persistent workspace")
        command("open-url", "http://127.0.0.1:8080/")
        await_title("AgenticVM Desktop Ready")
        command("screenshot", workspace / "desktop-final.png", "--overwrite")
        report["passed"] = True
    finally:
        if not args.existing and not args.keep_running:
            try:
                command("stop")
            except Exception as error:
                report["cleanup_error"] = str(error)
                report["passed"] = False
        save()
    print(json.dumps({key: value for key, value in report.items() if key != "commands"}, indent=2, ensure_ascii=True))
    print("Evidence: " + str(output))


if __name__ == "__main__":
    main()
