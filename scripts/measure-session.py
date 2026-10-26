"""Read-only idle measurements of the exact controller-owned QEMU process."""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.qemu import QemuBackend
from agenticvm.resources import memory_status
from agenticvm.state import StateStore


def summarize(state: dict, samples: list[dict]) -> dict:
    """Keep lifetime peaks separate from maxima observed in the sample window."""
    if len(samples) < 2:
        raise ValueError("At least two process samples are required")
    last, first = samples[-1], samples[0]
    window = last["elapsed_seconds"] - first["elapsed_seconds"]
    if window <= 0:
        raise ValueError("Process samples must span a positive time window")
    return {"kind": "idle development-host process sample", "guest_memory_mib": state["memory_mib"],
        "backend": "QEMU 11.1.0 / WHPX", "guest_profile": state.get("profile", "command"),
        "control_transport": state.get("control_transport"), "uuid": state["uuid"],
        "samples": samples, "sample_count": len(samples), "window_seconds": window,
        "median_private_commit_mib": statistics.median(x["private_commit_bytes"] for x in samples) / 1048576,
        "median_working_set_mib": statistics.median(x["working_set_bytes"] for x in samples) / 1048576,
        "max_private_commit_mib_in_window": max(x["private_commit_bytes"] for x in samples) / 1048576,
        "max_working_set_mib_in_window": max(x["working_set_bytes"] for x in samples) / 1048576,
        "peak_private_commit_mib_lifetime": max(x["peak_private_commit_bytes_lifetime"] for x in samples) / 1048576,
        "peak_working_set_mib_lifetime": max(x["peak_working_set_bytes_lifetime"] for x in samples) / 1048576,
        "process_cpu_percent_one_core": 100 * (last["process_cpu_seconds_lifetime"] - first["process_cpu_seconds_lifetime"]) / window,
        "physical_4gb_host_tested": False,
        "limits": "Process counters exclude other processes and unaccounted kernel/hypervisor memory. Working set is not commit; guest RAM is not added to either. Lifetime peaks include boot and activity before this sample window."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 5 <= args.seconds <= 60:
        parser.error("Sampling duration must be 5–60 seconds")
    store = StateStore(args.workspace)
    state = store.load()
    backend = QemuBackend(store, Path(state["executable"]))
    class Counters(C.Structure):
        _fields_ = [("cb", W.DWORD), ("faults", W.DWORD)] + [(name, C.c_size_t) for name in
            ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]
    psapi = C.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, C.POINTER(Counters), W.DWORD]
    psapi.GetProcessMemoryInfo.restype = W.BOOL
    samples = []
    begin = time.monotonic()
    with backend._process(state) as process:
        if not process.alive():
            raise RuntimeError("The owned VM is not running")
        while time.monotonic() - begin < args.seconds:
            if not process.alive():
                raise RuntimeError("The owned VM exited during measurement")
            counters = Counters(cb=C.sizeof(Counters))
            if not psapi.GetProcessMemoryInfo(process.handle, C.byref(counters), C.sizeof(counters)):
                raise C.WinError(C.get_last_error())
            created, exited, kernel, user = (W.FILETIME() for _ in range(4))
            if not process.api.GetProcessTimes(process.handle, C.byref(created), C.byref(exited), C.byref(kernel), C.byref(user)):
                raise C.WinError(C.get_last_error())
            units = lambda value: (value.dwHighDateTime << 32) | value.dwLowDateTime
            samples.append({"elapsed_seconds": time.monotonic() - begin,
                "private_commit_bytes": counters.private, "working_set_bytes": counters.ws,
                # PSAPI calls this PeakPagefileUsage, but Windows documents it
                # as peak process commit charge, not bytes stored in a pagefile.
                "peak_private_commit_bytes_lifetime": counters.peak_pagefile,
                "peak_working_set_bytes_lifetime": counters.peak_ws,
                "process_cpu_seconds_lifetime": (units(kernel) + units(user)) / 10_000_000,
                "host": memory_status()})
            time.sleep(0.5)
    report = summarize(state, samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "samples"}))


if __name__ == "__main__":
    main()
