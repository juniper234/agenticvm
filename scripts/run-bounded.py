"""Run explicit argv in a Windows Job Object; preserve bounded logs and resource evidence.

Example: python -I scripts/run-bounded.py --output runtime/build-demo -- python -c "print('ok')"
The entire child tree shares a commit cap and two allowed CPUs. No shell is used.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024
LOG_CAP = MIB


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run(args, output, argv):
    if os.name != "nt":
        raise RuntimeError("Windows Job Object enforcement is required")
    k = C.WinDLL("kernel32", use_last_error=True)

    class Memory(C.Structure):
        _fields_ = [("length", W.DWORD), ("load", W.DWORD)] + [(n, C.c_ulonglong) for n in
            ("total", "available", "total_page", "available_page", "total_virtual", "available_virtual", "extended")]

    class Basic(C.Structure):
        _fields_ = [("process_time", C.c_longlong), ("job_time", C.c_longlong), ("flags", W.DWORD),
                    ("min_ws", C.c_size_t), ("max_ws", C.c_size_t), ("process_limit", W.DWORD),
                    ("affinity", C.c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]

    class Extended(C.Structure):
        _fields_ = [("basic", Basic), ("io", C.c_ulonglong * 6)] + [
            (n, C.c_size_t) for n in ("process_limit", "job_limit", "peak_process", "peak_job")]

    class Accounting(C.Structure):
        _fields_ = [(n, C.c_longlong) for n in ("user", "kernel", "period_user", "period_kernel")] + [
            (n, W.DWORD) for n in ("page_faults", "total_processes", "active", "terminated")]

    class Startup(C.Structure):
        _fields_ = [("cb", W.DWORD), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR), ("title", W.LPWSTR)] + [
            (n, W.DWORD) for n in ("x", "y", "xsize", "ysize", "xchars", "ychars", "fill", "flags")] + [
            ("show", W.WORD), ("cbreserved", W.WORD), ("reserved2", C.c_void_p),
            ("stdin", W.HANDLE), ("stdout", W.HANDLE), ("stderr", W.HANDLE)]

    class Process(C.Structure):
        _fields_ = [("process", W.HANDLE), ("thread", W.HANDLE), ("pid", W.DWORD), ("tid", W.DWORD)]

    signatures = {
        "CreateJobObjectW": ([C.c_void_p, W.LPCWSTR], W.HANDLE),
        "SetInformationJobObject": ([W.HANDLE, C.c_int, C.c_void_p, W.DWORD], W.BOOL),
        "QueryInformationJobObject": ([W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p], W.BOOL),
        "AssignProcessToJobObject": ([W.HANDLE, W.HANDLE], W.BOOL),
        "CreateProcessW": ([W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD,
                            C.c_void_p, W.LPCWSTR, C.POINTER(Startup), C.POINTER(Process)], W.BOOL),
        "ResumeThread": ([W.HANDLE], W.DWORD), "TerminateJobObject": ([W.HANDLE, W.UINT], W.BOOL),
        "TerminateProcess": ([W.HANDLE, W.UINT], W.BOOL), "CloseHandle": ([W.HANDLE], W.BOOL),
        "WaitForSingleObject": ([W.HANDLE, W.DWORD], W.DWORD),
        "GetExitCodeProcess": ([W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
        "GlobalMemoryStatusEx": ([C.POINTER(Memory)], W.BOOL),
        "GetCurrentProcess": ([], W.HANDLE),
        "GetProcessAffinityMask": ([W.HANDLE, C.POINTER(C.c_size_t), C.POINTER(C.c_size_t)], W.BOOL)}
    for name, (arguments, result) in signatures.items():
        getattr(k, name).argtypes, getattr(k, name).restype = arguments, result

    def check(ok):
        if not ok:
            raise C.WinError(C.get_last_error())

    result = {"status": "not-started", "job_limit_bytes": args.memory_mib * MIB,
              "job_memory_metric": "committed bytes, not resident working set", "log_cap_bytes_each": LOG_CAP}
    memory = Memory(length=C.sizeof(Memory))
    job, proc, assigned, started = None, Process(), False, None
    pipes, readers, inherited, counts = [], [], [], {}

    def drain(fd, name):
        total = retained = 0
        try:
            with (output / (name + ".txt")).open("wb") as stream:
                while chunk := os.read(fd, 65536):
                    total += len(chunk)
                    part = chunk[:max(0, LOG_CAP - retained)]
                    stream.write(part)
                    retained += len(part)
        finally:
            os.close(fd)
            counts[name] = {"received_bytes": total, "retained_bytes": retained, "truncated": total > retained}

    try:
        check(k.GlobalMemoryStatusEx(C.byref(memory)))
        result["preflight_available_bytes"] = memory.available
        if memory.available < 4096 * MIB:
            raise RuntimeError("Preflight refused: less than 4 GiB available host RAM")
        job = k.CreateJobObjectW(None, None)
        check(job)
        limits = Extended()
        limits.basic.flags = 0x2000 | 0x200 | 0x400  # kill-on-close, per-process and whole-job commit
        limits.process_limit = limits.job_limit = args.memory_mib * MIB
        allowed, system = C.c_size_t(), C.c_size_t()
        if k.GetProcessAffinityMask(k.GetCurrentProcess(), C.byref(allowed), C.byref(system)):
            bits = [1 << i for i in range(C.sizeof(C.c_size_t) * 8) if allowed.value & (1 << i)]
            if bits:
                limits.basic.affinity = sum(bits[:2])
                limits.basic.flags |= 0x10
                result["affinity_mask"] = hex(limits.basic.affinity)
        check(k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
        verified = Extended()
        check(k.QueryInformationJobObject(job, 9, C.byref(verified), C.sizeof(verified), None))
        if verified.job_limit != limits.job_limit or verified.basic.flags & limits.basic.flags != limits.basic.flags:
            raise RuntimeError("Required job controls were not applied")
        import msvcrt
        for name in ("stdout", "stderr"):
            read_fd, write_fd = os.pipe()
            os.set_inheritable(write_fd, True)
            pipes.append((read_fd, write_fd, name))
            inherited.append(write_fd)
        null = os.open(os.devnull, os.O_RDONLY)
        os.set_inheritable(null, True)
        inherited.append(null)
        startup = Startup(cb=C.sizeof(Startup), flags=0x100 | 1, show=0,
                          stdin=msvcrt.get_osfhandle(null), stdout=msvcrt.get_osfhandle(pipes[0][1]),
                          stderr=msvcrt.get_osfhandle(pipes[1][1]))
        command = C.create_unicode_buffer(subprocess.list2cmdline(argv))
        check(k.CreateProcessW(argv[0], command, None, None, True, 0x4 | 0x08000000,
                               None, str(ROOT), C.byref(startup), C.byref(proc)))
        check(k.AssignProcessToJobObject(job, proc.process))  # Child remains suspended until protected.
        assigned = True
        for fd in inherited:
            os.close(fd)
        inherited.clear()
        for read_fd, _, name in pipes:
            reader = threading.Thread(target=drain, args=(read_fd, name), daemon=True)
            reader.start()
            readers.append(reader)
        if k.ResumeThread(proc.thread) == 0xffffffff:
            raise C.WinError(C.get_last_error())
        started, result["status"], result["pid"] = time.monotonic(), "running", proc.pid
        while True:
            account = Accounting()
            check(k.QueryInformationJobObject(job, 1, C.byref(account), C.sizeof(account), None))
            result["total_processes"] = account.total_processes
            if not account.active:
                result["status"] = "process-tree-exited"
                break
            check(k.GlobalMemoryStatusEx(C.byref(memory)))
            result["minimum_available_host_bytes"] = min(result.get("minimum_available_host_bytes", memory.available), memory.available)
            if time.monotonic() - started >= args.seconds or memory.available < 1024 * MIB:
                timeout = time.monotonic() - started >= args.seconds
                result["status"] = "wall-timeout" if timeout else "host-memory-floor"
                result["exit_code"] = 124 if timeout else 125
                check(k.TerminateJobObject(job, result["exit_code"]))
                break
            time.sleep(0.1)
        k.WaitForSingleObject(proc.process, 5000)
        code = W.DWORD()
        check(k.GetExitCodeProcess(proc.process, C.byref(code)))
        result.setdefault("exit_code", code.value)
    except BaseException as error:
        result.update(status="controller-error", exit_code=127, error=repr(error))
        if assigned:
            k.TerminateJobObject(job, 127)
        elif proc.process:
            k.TerminateProcess(proc.process, 127)
    finally:
        if job:
            final = Extended()
            if k.QueryInformationJobObject(job, 9, C.byref(final), C.sizeof(final), None):
                result["peak_job_memory_bytes"] = final.peak_job
            k.CloseHandle(job)  # Kill every owned descendant, including on controller failure.
        for handle in (proc.thread, proc.process):
            if handle:
                k.CloseHandle(handle)
        for fd in inherited:
            os.close(fd)
        for reader in readers:
            reader.join(5)
        if not readers:
            for read_fd, _, _ in pipes:
                os.close(read_fd)
        result.update(logs=counts, elapsed_seconds=round(time.monotonic() - started, 3) if started else 0)
        save(output / "resource-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mib", type=int, default=1536)
    parser.add_argument("--seconds", type=float, default=240)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv or not 64 <= args.memory_mib <= 4096 or not 0.1 <= args.seconds <= 3600:
        parser.error("Explicit argv, memory 64..4096 MiB, and duration 0.1..3600 seconds are required")
    executable = shutil.which(argv[0])
    if not executable or Path(executable).suffix.lower() not in (".exe", ".com"):
        parser.error("Executable must resolve to a native .exe/.com; shell scripts are not accepted")
    argv[0] = str(Path(executable).resolve())
    output = args.output.resolve()
    if output.parent != (ROOT / "runtime").resolve() or not output.name.startswith("build-"):
        parser.error("Output must be a fresh runtime/build-<name> directory")
    output.mkdir(parents=True, exist_ok=False)
    save(output / "run-config.json", {"argv": argv, "cwd": str(ROOT), "memory_mib": args.memory_mib,
         "seconds": args.seconds, "preflight_available_mib": 4096, "host_floor_mib": 1024})
    result = run(args, output, argv)
    print(json.dumps({"output": str(output), **result}))
    raise SystemExit(result["exit_code"])


if __name__ == "__main__":
    main()
