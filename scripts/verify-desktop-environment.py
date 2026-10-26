"""Read-only checks of a running desktop guest and its owned host process.

Uses public guest CLI commands, actual Linux process metadata, and Windows TCP
inventory. Does not start, stop, reset, or change the guest image or settings.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.qemu import QemuBackend
from agenticvm.state import StateStore


CONTENT_PROCESS_SCRIPT = r"""set -eu
for proc in /proc/[0-9]*; do
    [ -r "$proc/cmdline" ] || continue
    cmd=$(/usr/bin/tr '\000' ' ' < "$proc/cmdline" 2>/dev/null) || continue
    case "$cmd" in
        '/usr/lib/firefox-esr/firefox-esr -contentproc'*)
            status=$(/usr/bin/awk '
                /^Uid:/ {real=$2; effective=$3; saved=$4; filesystem=$5}
                /^NoNewPrivs:/ {nnp=$2}
                /^Seccomp:/ {seccomp=$2}
                END {printf "%s %s %s %s %s %s", real,effective,saved,filesystem,nnp,seccomp}
                ' "$proc/status" 2>/dev/null) || continue
            printf '%s\t%s\t%s\n' "${proc##*/}" "$status" "$cmd"
            ;;
    esac
done
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    store = StateStore(workspace)
    state = store.load()
    if state.get("backend") != "qemu" or state.get("profile") != "desktop":
        parser.error("A running, controller-owned QEMU desktop session is required")
    backend = QemuBackend(store, Path(state["executable"]))
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    prefix = [sys.executable, "-m", "agenticvm", "--workspace", str(workspace)]
    output = workspace / "environment-verification.json"
    report = {"workspace": str(workspace), "uuid": state["uuid"], "guest_memory_mib": state["memory_mib"],
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "passed": False, "checks": [], "failures": [], "commands": [], "observed": {}}

    def save():
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def command(argv, *, timeout=60, cli=False):
        started = time.monotonic()
        result = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True,
                                text=True, encoding="utf-8", timeout=timeout)
        entry = {"argv": argv, "exit_code": result.returncode,
                 "elapsed_seconds": round(time.monotonic() - started, 6),
                 "stdout": result.stdout, "stderr": result.stderr}
        report["commands"].append(entry)
        save()
        assert result.returncode == 0, entry
        data = json.loads(result.stdout)
        if cli:
            assert data.get("ok") is True, entry
            return data["result"]
        return data

    def guest(*argv, timeout_ms=30000):
        return command([*prefix, "exec", "--timeout-ms", str(timeout_ms), "--", *argv], cli=True)

    def check(description):
        report["checks"].append(description)
        save()

    started = time.monotonic()
    try:
        with backend._process(state) as process:
            assert process.alive(), "The owned VM is not running"
            status = command([*prefix, "status"], cli=True)
            assert status.get("status") == "running" and status.get("guest", {}).get("uid") == 1000, status
            report["observed"]["host_process"] = {"pid": state["pid"], "created": process.created,
                                                   "executable": str(process.executable),
                                                   "control_transport": state.get("host_control_transport")}

            tls = guest("/usr/bin/curl", "--fail", "--silent", "--show-error", "--max-time", "15",
                        "--output", "/dev/null", "--write-out", "%{http_code} %{ssl_verify_result}",
                        "https://www.debian.org/")
            assert tls["stdout"].strip() == "200 0", tls
            report["observed"]["system_https"] = {"url": "https://www.debian.org/", "http_code": 200,
                                                   "ssl_verify_result": 0}
            check("System HTTPS validates the certificate chain and returns HTTP 200")

            snapshot = guest("/bin/sh", "-c", CONTENT_PROCESS_SCRIPT)
            contents = []
            firefox_processes = []
            for line in snapshot["stdout"].splitlines():
                pid, fields, cmdline = line.split("\t", 2)
                values = [int(value) for value in fields.split()]
                assert len(values) == 6, line
                assert values[:4] == [1000] * 4, line
                # Firefox also passes -contentproc to its forkserver and other
                # helpers. The final argv identifies real browser tab content.
                role = cmdline.split()[-1]
                item = {"pid": int(pid), "uids": values[:4], "no_new_privs": values[4],
                        "seccomp": values[5], "role": role, "cmdline": cmdline}
                firefox_processes.append(item)
                if role == "tab":
                    assert values[4:] == [1, 2], line
                    contents.append(item)
            assert contents, "No actual Firefox content process was observed"
            report["observed"]["firefox_content_processes"] = contents
            report["observed"]["firefox_helper_processes"] = [item for item in firefox_processes if item["role"] != "tab"]
            check("Firefox content processes run as UID 1000 with NoNewPrivs and seccomp filtering")

            chinese = guest("/usr/bin/fc-match", "-f", "%{family}\n", ":lang=zh")["stdout"].strip()
            emoji = guest("/usr/bin/fc-match", "-f", "%{family}\n", ":charset=1f680")["stdout"].strip()
            requested_codepoints = (0x4E2D, 0x6587, 0x4F60, 0x597D, 0x3002)
            pattern = ":lang=zh-cn:charset=" + " ".join(f"{value:x}" for value in requested_codepoints)
            match = guest("/usr/bin/fc-match", "-f", "%{family}\n%{file}\n%{index}\n", pattern)["stdout"].splitlines()
            assert len(match) == 3, match
            family, fontfile, index = match
            assert index.isdecimal() and fontfile.startswith("/usr/share/fonts/"), match
            font_charset = guest("/usr/bin/fc-query", "--index", index, "-f", "%{charset}\n", fontfile)["stdout"].strip()
            ranges = []
            for item in font_charset.split():
                bounds = item.split("-")
                assert len(bounds) in (1, 2), item
                low, high = int(bounds[0], 16), int(bounds[-1], 16)
                assert 0 <= low <= high <= 0x10FFFF, item
                ranges.append((low, high))
            coverage = {f"U+{value:04X}": any(low <= value <= high for low, high in ranges)
                        for value in requested_codepoints}
            report["observed"]["fonts"] = {
                "generic_language_match_informational": chinese,
                "chinese_charset_match": {"pattern": pattern, "family": family, "file": fontfile,
                                          "index": int(index), "verified_glyph_coverage": coverage},
                "rocket_emoji": emoji,
                "method": "A language preference alone can select a Latin face; actual text fallback must match its character set."}
            if "Noto" in family and "CJK" in family and all(coverage.values()) and "Noto Color Emoji" in emoji:
                check("Chinese glyph fallback selects Noto CJK with verified character coverage; rocket emoji selects Noto Color Emoji")
            else:
                report["failures"].append({"check": "Fontconfig Chinese and rocket emoji coverage",
                                           "observed": report["observed"]["fonts"]})
                save()

            disksize = int(guest("/bin/cat", "/sys/block/zram0/disksize")["stdout"].strip())
            mm_stat = guest("/bin/cat", "/sys/block/zram0/mm_stat")["stdout"].strip()
            # mem_limit itself is root-only. Linux exposes the same configured
            # limit as mm_stat's fourth field to the unprivileged guest agent.
            mm_fields = [int(value) for value in mm_stat.split()]
            assert len(mm_fields) >= 4, mm_stat
            mem_limit = mm_fields[3]
            swaps = guest("/bin/cat", "/proc/swaps")["stdout"]
            meminfo = guest("/bin/cat", "/proc/meminfo")["stdout"]
            assert disksize == 256 * 1024 * 1024 and mem_limit == 128 * 1024 * 1024, (disksize, mem_limit)
            assert "/dev/zram0" in swaps, swaps
            report["observed"]["zram"] = {"disksize_bytes": disksize, "mem_limit_bytes": mem_limit,
                                          "mm_stat": mm_stat, "proc_swaps": swaps, "proc_meminfo": meminfo}
            check("Compressed swap is active with 256 MiB capacity and a 128 MiB memory limit")

            pid = int(state["pid"])
            assert pid > 0
            script = ("$ErrorActionPreference = 'Stop'\n"
                      "$connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { "
                      f"$_.OwningProcess -eq {pid} -and $_.State -eq 'Listen'"
                      " } | Select-Object LocalAddress, LocalPort, OwningProcess, State)\n"
                      "ConvertTo-Json -InputObject $connections -Depth 4 -Compress")
            listeners = command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=30)
            assert listeners == [], listeners
            assert state.get("host_control_transport") == "unix", state
            assert process.alive() and store.load()["uuid"] == state["uuid"], "The VM changed during verification"
            report["observed"]["qemu_tcp_listeners"] = listeners
            check("The validated QEMU process has no TCP listening socket")
        report["passed"] = not report["failures"]
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        # Windows console code pages may not represent guest font metadata.
        print(json.dumps({"passed": report["passed"], "checks": report["checks"],
                          "failures": report["failures"], "report": str(output),
                          "elapsed_seconds": report["elapsed_seconds"]}, ensure_ascii=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
