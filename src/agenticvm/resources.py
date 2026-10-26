"""Conservative launch checks for a small guest on a constrained Windows host."""
from __future__ import annotations

import os
from pathlib import Path

from .errors import AgenticVMError


def whpx_status() -> dict:
    """Query the native capability API without enabling features or creating a VM."""
    if os.name != "nt":
        return {"available": False, "reason": "Windows host required"}
    import ctypes
    from ctypes import wintypes
    try:
        api = ctypes.WinDLL(str(Path(os.environ["SystemRoot"]) / "System32/WinHvPlatform.dll"))
        api.WHvGetCapability.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.WHvGetCapability.restype = ctypes.c_long
        present, written = wintypes.BOOL(), wintypes.DWORD()
        result = api.WHvGetCapability(0, ctypes.byref(present), ctypes.sizeof(present), ctypes.byref(written))
        return {"available": result == 0 and bool(present.value), "hypervisor_present": bool(present.value),
                "hresult": f"0x{result & 0xffffffff:08x}", "settings_changed": False}
    except (OSError, AttributeError) as error:
        return {"available": False, "reason": str(error), "settings_changed": False}


def memory_status() -> dict:
    if os.name != "nt":
        raise AgenticVMError("Memory preflight currently supports Windows hosts.", "unsupported_host")
    import ctypes
    from ctypes import wintypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD),
                    ("total_physical", ctypes.c_uint64), ("available_physical", ctypes.c_uint64),
                    ("total_commit", ctypes.c_uint64), ("available_commit", ctypes.c_uint64),
                    ("total_virtual", ctypes.c_uint64), ("available_virtual", ctypes.c_uint64),
                    ("available_extended_virtual", ctypes.c_uint64)]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
    api.GlobalMemoryStatusEx.restype = wintypes.BOOL
    if not api.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise AgenticVMError("Cannot inspect available host memory.", "memory_probe_failed")
    return {"total_physical_mib": status.total_physical // (1024 * 1024),
            "available_physical_mib": status.available_physical // (1024 * 1024),
            "available_commit_mib": status.available_commit // (1024 * 1024)}


def check_memory_budget(memory_mib: int) -> dict:
    status = memory_status()
    # This is a launch guard, not a claim that a given host can handle a workload.
    required_physical = memory_mib + 512
    required_commit = memory_mib + 384
    if status["available_physical_mib"] < required_physical or status["available_commit_mib"] < required_commit:
        raise AgenticVMError(
            f"Insufficient free host memory: need at least {required_physical} MiB physical and "
            f"{required_commit} MiB commit available for this profile; found "
            f"{status['available_physical_mib']} MiB physical and {status['available_commit_mib']} MiB commit. "
            "Close other applications or choose a smaller guest.", "insufficient_host_memory")
    return {**status, "required_available_physical_mib": required_physical,
            "required_available_commit_mib": required_commit}
