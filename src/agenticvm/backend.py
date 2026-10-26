"""Hypervisor adapter with a deliberately small, offline first profile."""
from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from uuid import uuid4

from .errors import AgenticVMError
from .resources import check_memory_budget
from .state import StateStore

VERIFIED_VERSION = "7.2.20r175154"
VERIFIED_VBOXMANAGE_SHA256 = "6852390a57d454d3b7c9ae27e66e45c367699faf2807b450de084b1f7d0203c1"


def parse_machine_info(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([^=\r\n]+)=(.*)', line)
        if not match:
            continue
        key, value = match.groups()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        result[key] = value
    return result


def find_vboxmanage(explicit: str | None = None) -> Path:
    candidates = [explicit, os.environ.get("AGENTICVM_VBOXMANAGE")]
    if os.environ.get("ProgramFiles"):
        candidates.append(str(Path(os.environ["ProgramFiles"]) / "Oracle" / "VirtualBox" / "VBoxManage.exe"))
    candidates.extend([shutil.which("VBoxManage"), str(Path.cwd() / "vendor" / "virtualbox-7.2.20" / "windows-amd64" / "VBoxManage.exe")])
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise AgenticVMError("VBoxManage was not found. Install VirtualBox 7.2.20 or supply --vboxmanage PATH.", "backend_missing")


class VMBackend(ABC):
    @abstractmethod
    def doctor(self) -> dict: ...

    @abstractmethod
    def start(self, iso: Path, memory_mib: int = 512) -> dict: ...

    @abstractmethod
    def status(self) -> dict: ...

    @abstractmethod
    def stop(self) -> dict: ...


class VirtualBoxBackend(VMBackend):
    def __init__(self, store: StateStore, executable: Path, *, runner=None, process_probe=None):
        self.store = store
        self.executable = executable.resolve()
        self.runner = runner or subprocess.run
        self.process_probe = process_probe or self._vbox_processes

    def _run(self, *arguments: str, timeout: float = 30, check: bool = True):
        environment = os.environ.copy()
        environment["VBOX_USER_HOME"] = str(self.store.root / "vbox-user")
        try:
            result = self.runner([str(self.executable), *map(str, arguments)], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=timeout, env=environment,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), shell=False)
        except subprocess.TimeoutExpired as error:
            raise AgenticVMError(f"VBoxManage {arguments[0]} timed out.", "backend_timeout") from error
        except OSError as error:
            raise AgenticVMError(f"Cannot run VBoxManage: {error}", "backend_error") from error
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "No diagnostic was returned.").strip()[-4096:]
            code = "backend_unregistered" if "REGDB_E_CLASSNOTREG" in detail else "backend_error"
            raise AgenticVMError(f"VBoxManage {arguments[0]} failed: {detail}", code)
        return result

    @staticmethod
    def _vbox_processes() -> list[dict]:
        if os.name != "nt":
            raise AgenticVMError("The first VirtualBox backend supports Windows hosts.", "unsupported_host")
        try:
            result = subprocess.run(["tasklist.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                                    timeout=10, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        except (OSError, subprocess.SubprocessError) as error:
            raise AgenticVMError(f"Cannot verify VirtualBox process isolation: {error}", "process_probe_failed") from error
        names = {"vboxsvc.exe", "vboxheadless.exe", "virtualboxvm.exe", "virtualbox.exe"}
        return [{"name": row[0], "pid": row[1]} for row in csv.reader(io.StringIO(result.stdout))
                if len(row) > 1 and row[0].lower() in names]

    def doctor(self) -> dict:
        version = self._run("--version").stdout.strip()
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        return {"backend": "virtualbox", "executable": str(self.executable), "version": version,
                "verified_version": version == VERIFIED_VERSION,
                "verified_binary": digest == VERIFIED_VBOXMANAGE_SHA256,
                "sha256": digest, "host": os.name, "windows_host": os.name == "nt",
                "profile": {"cpus": 1, "memory_mib": 512, "network": "none", "disk": "none"}}

    def _owned_info(self, state: dict) -> dict:
        self.store.validate(state)
        info = parse_machine_info(self._run("showvminfo", state["uuid"], "--machinereadable").stdout)
        if (info.get("UUID", "").lower() != state["uuid"].lower()
                or info.get("name") != state["name"]
                or Path(info.get("CfgFile", "")).resolve() != Path(state["config_file"]).resolve()):
            raise AgenticVMError("VirtualBox VM ownership does not match saved metadata; refusing control.", "ownership_mismatch")
        return info

    def start(self, iso: Path, memory_mib: int = 512) -> dict:
        with self.store.lock():
            return self._start(iso, memory_mib)

    def _start(self, iso: Path, memory_mib: int = 512) -> dict:
        iso = iso.resolve()
        if not iso.is_file() or iso.suffix.lower() != ".iso":
            raise AgenticVMError("Supply an existing Linux agent .iso image.", "invalid_image")
        if not 128 <= memory_mib <= 1024:
            raise AgenticVMError("This low-memory profile accepts 128–1024 MiB of guest RAM.", "invalid_memory")
        previous = self.store.load(required=False)
        if previous and previous.get("registered", True):
            raise AgenticVMError("A session is already registered. Run stop or reset first.", "session_exists")
        self.store.prepare()
        processes = self.process_probe()
        # VBoxSVC can linger briefly after this controller unregisters its VM.
        # Wait for it to exit naturally; never terminate a shared COM server.
        if previous and not previous.get("registered", True):
            deadline = time.monotonic() + 15
            while processes and all(item["name"].lower() == "vboxsvc.exe" for item in processes) and time.monotonic() < deadline:
                time.sleep(0.1)
                processes = self.process_probe()
        if processes:
            names = ", ".join(f'{item["name"]} (PID {item["pid"]})' for item in processes)
            raise AgenticVMError(f"Close existing VirtualBox applications/VMs before starting the isolated profile: {names}.", "virtualbox_busy")
        preflight = check_memory_budget(memory_mib)
        version = self._run("--version").stdout.strip()
        if version != VERIFIED_VERSION:
            raise AgenticVMError(f"This prototype was validated against {VERIFIED_VERSION}; found {version}.", "unsupported_backend_version")
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        if digest != VERIFIED_VBOXMANAGE_SHA256:
            raise AgenticVMError("VBoxManage does not match the verified Oracle 7.2.20 amd64 payload.", "unverified_backend_binary")
        identifier = str(uuid4())
        name = f"AgenticVM-{identifier}"
        state = {"schema": 1, "backend": "virtualbox", "session": self.store.session, "workspace": str(self.store.root),
                 "uuid": identifier, "name": name, "memory_mib": memory_mib, "iso": str(iso),
                 "pipe": "\\\\.\\pipe\\agenticvm-" + identifier,
                 "vbox_user_home": str(self.store.root / "vbox-user"),
                 "config_file": str(self.store.root / "vms" / name / f"{name}.vbox"),
                 "boot_log": str(self.store.root / "vms" / name / "boot.log"),
                 "status": "creating", "registered": False, "created_at": time.time(),
                 "backend_version": version, "backend_sha256": digest, "memory_preflight": preflight}
        self.store.save(state)
        try:
            self._run("createvm", "--name", name, "--ostype", "Linux_64", "--uuid", identifier,
                      "--basefolder", str(self.store.root / "vms"), "--register")
            state["registered"] = True
            self.store.save(state)
            self._owned_info(state)
            self._run("modifyvm", identifier, "--memory", str(memory_mib), "--cpus", "1", "--vram", "8",
                      "--firmware", "bios", "--boot1", "dvd", "--boot2", "none", "--boot3", "none", "--boot4", "none",
                      "--nic1", "none", "--nic2", "none", "--nic3", "none", "--nic4", "none",
                      "--nic5", "none", "--nic6", "none", "--nic7", "none", "--nic8", "none",
                      "--audio-enabled", "off", "--usb-ohci", "off", "--usb-ehci", "off", "--usb-xhci", "off",
                      "--clipboard-mode", "disabled", "--drag-and-drop", "disabled",
                      "--uart1", "0x3f8", "4", "--uart-mode1", "server", state["pipe"],
                      "--uart2", "0x2f8", "3", "--uart-mode2", "file", state["boot_log"])
            self._run("storagectl", identifier, "--name", "AgenticDVD", "--add", "ide", "--controller", "PIIX4")
            self._run("storageattach", identifier, "--storagectl", "AgenticDVD", "--port", "0", "--device", "0",
                      "--type", "dvddrive", "--medium", str(iso))
            self._run("startvm", identifier, "--type", "headless", timeout=60)
            state["status"] = "running"
            self.store.save(state)
            return state
        except BaseException:
            state["status"] = "failed"
            # A failed creation can leave an owned registration; retain evidence if
            # ownership cannot be proved rather than controlling a different VM.
            if state["registered"]:
                try:
                    info = self._owned_info(state)
                    if info.get("VMState") not in {"poweroff", "aborted", "saved"}:
                        self._run("controlvm", identifier, "poweroff")
                    self._owned_info(state)
                    self._run("unregistervm", identifier)
                    state["registered"] = False
                except AgenticVMError:
                    pass
            self.store.save(state)
            raise

    def status(self) -> dict:
        state = self.store.load()
        result = {"session": self.store.session, "uuid": state["uuid"], "status": state["status"],
                  "registered": state.get("registered", True), "memory_mib": state["memory_mib"],
                  "cpus": 1, "network": "none", "disk": "none", "iso": state["iso"]}
        if "boot_log" in state:
            result["boot_log"] = state["boot_log"]
        if state.get("registered", True):
            info = self._owned_info(state)
            result["vm_state"] = info.get("VMState", "unknown")
            result["status"] = "running" if result["vm_state"] == "running" else result["vm_state"]
        return result

    def stop(self) -> dict:
        with self.store.lock():
            return self._stop()

    def _stop(self) -> dict:
        state = self.store.load()
        if state.get("registered", True):
            info = self._owned_info(state)
            if info.get("VMState") not in {"poweroff", "aborted", "saved"}:
                self._run("controlvm", state["uuid"], "poweroff")
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if self._owned_info(state).get("VMState") in {"poweroff", "aborted", "saved"}:
                        break
                    time.sleep(0.1)
                else:
                    raise AgenticVMError("Owned VM did not stop in time.", "backend_timeout")
            self._owned_info(state)
            self._run("unregistervm", state["uuid"])
        state.update(status="stopped", registered=False, stopped_at=time.time())
        self.store.save(state)
        return {"session": self.store.session, "uuid": state["uuid"], "status": "stopped", "vm_files_retained": True}
