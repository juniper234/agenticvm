"""Portable QEMU/WHPX backend; no host driver installation or TCG fallback."""
from __future__ import annotations

import hashlib
import json
import os
from os import cpu_count
import shutil
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .backend import VMBackend
from .errors import AgenticVMError
from .resources import check_memory_budget, whpx_status
from .state import StateStore, qemu_socket_directory, validate_isolated_link, validate_serial_link
from .transport import SocketTransport, TcpTransport


def find_qemu(explicit: str | None = None) -> Path:
    candidates = [explicit, os.environ.get("AGENTICVM_QEMU")]
    for root in (Path(__file__).resolve().parents[2], Path.cwd()):
        candidates.extend(str(root / "tools" / "qemu" / suffix / "qemu-system-x86_64.exe")
                          for suffix in ("11.1.0", "", "qemu", "bin"))
    candidates.append(shutil.which("qemu-system-x86_64"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise AgenticVMError("QEMU was not found. Supply --qemu PATH to qemu-system-x86_64.exe.", "backend_missing")


def binary_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class WindowsProcess:
    """Hold a process handle while proving identity and optionally stopping it."""

    def __init__(self, pid: int, *, terminate: bool = False):
        if os.name != "nt":
            raise AgenticVMError("The QEMU/WHPX backend currently supports Windows hosts.", "unsupported_host")
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes = ctypes, wintypes
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
        self.api.GetProcessTimes.restype = wintypes.BOOL
        self.api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.api.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.WaitForSingleObject.restype = wintypes.DWORD
        self.api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.TerminateProcess.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.OpenProcess(0x1000 | 0x100000 | (1 if terminate else 0), False, pid)
        self.created, self.executable = None, None
        if not self.handle:
            code = ctypes.get_last_error()
            if code == 87:  # An exited process has no PID to open.
                return
            raise AgenticVMError(f"Cannot inspect VM process {pid} (Windows error {code}).", "process_probe_failed")
        try:
            if not self.alive():
                return
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            if not self.api.GetProcessTimes(self.handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                if not self.alive():
                    return
                raise AgenticVMError("Cannot read VM process creation time.", "process_probe_failed")
            self.created = str((created.dwHighDateTime << 32) | created.dwLowDateTime)
            buffer, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
            if not self.api.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)):
                # Windows can stop serving a terminating process's image path
                # just before its process handle becomes signalled. Give that
                # transition a bounded grace period; never control an unknown
                # live process on the strength of a failed identity query.
                if self.wait(0.25):
                    return
                raise AgenticVMError("Cannot read VM process executable path.", "process_probe_failed")
            self.executable = Path(buffer.value).resolve()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def alive(self) -> bool:
        if not self.handle:
            return False
        result = self.api.WaitForSingleObject(self.handle, 0)
        if result not in (0, 258):
            raise AgenticVMError("Cannot verify VM process liveness.", "process_probe_failed")
        return result == 258

    def wait(self, seconds: float) -> bool:
        if not self.handle:
            return True
        result = self.api.WaitForSingleObject(self.handle, max(0, int(seconds * 1000)))
        if result not in (0, 258):
            raise AgenticVMError("Cannot wait for VM process exit.", "process_probe_failed")
        return result == 0

    def terminate(self):
        if self.alive() and not self.api.TerminateProcess(self.handle, 1):
            raise AgenticVMError("Cannot stop the owned QEMU process.", "backend_error")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def qmp_endpoint(state: dict) -> Path | int:
    """Select a validated session's private socket or legacy offline endpoint."""
    if state.get("host_control_transport") == "unix":
        return Path(state["qmp_socket"])
    if state.get("network", "none") != "none":
        raise AgenticVMError("A networked guest requires private local control sockets.", "invalid_state")
    return state["qmp_port"]


def _prepare_socket_directory(identifier: str) -> Path:
    directory = qemu_socket_directory(identifier)
    if any(len(str(directory / name).encode("utf-8")) >= 108 for name in ("s", "q", "c", "n")):
        raise AgenticVMError("The temporary folder path is too long for private VM sockets (107 UTF-8 bytes maximum): " + str(directory), "invalid_endpoint")
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in (directory.parent, directory):
        if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
            raise AgenticVMError("Private VM socket directories must not redirect to another path.", "invalid_state")
    # Python 3.13 on Windows applies a user/administrator-only DACL for 0700.
    directory.mkdir(mode=0o700)
    return directory


def prepare_pair_directory(identifier: str) -> Path:
    """Allocate a fresh private pair fabric; its orchestrator owns final cleanup."""
    return _prepare_socket_directory(identifier)


def cleanup_pair_directory(identifier: str) -> bool:
    """After both exact VM processes exited, remove only known shared sockets."""
    directory = qemu_socket_directory(identifier)
    validate_isolated_link({"pair_uuid": identifier, "role": "listen"})
    try:
        for name in ("n", "b"):
            leaf = directory / name
            if leaf.is_dir() or getattr(leaf, "is_junction", lambda: False)():
                return False
            leaf.unlink(missing_ok=True)
        if directory.exists():
            directory.rmdir()
        return True
    except OSError:
        return False


def _cleanup_socket_directory(state: dict) -> bool:
    """Remove only this exited process's two owned leaves; never recurse."""
    if state.get("host_control_transport") != "unix":
        return True
    expected = qemu_socket_directory(state["uuid"])
    if (state.get("socket_dir") != str(expected)
            or any(state.get(key) != str(expected / leaf) for key, leaf in (("serial_socket", "s"), ("qmp_socket", "q")))):
        raise AgenticVMError("Refusing cleanup of an unowned socket directory.", "invalid_state")
    try:
        for parent in (expected.parent, expected):
            if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
                return False
        leaves = ("s", "q", "c") if state.get("peer_channel") else ("s", "q")
        if state.get("peer_channel") and state.get("peer_socket") != str(expected / "c"):
            raise AgenticVMError("Refusing cleanup of an unowned peer endpoint.", "invalid_state")
        for name in leaves:
            leaf = expected / name
            if leaf.is_dir() or getattr(leaf, "is_junction", lambda: False)():
                return False
            leaf.unlink(missing_ok=True)
        if expected.exists():
            expected.rmdir()
        return True
    except OSError:
        return False


def qmp_sequence(endpoint: Path | str | int, operations: list[tuple[str, dict]], timeout: float = 3, *, interval: float = 0) -> list[dict]:
    """Run bounded, allowlisted operations over one negotiated QMP connection.

    This is an internal transport. Callers must prove session/process ownership
    before using its monitor socket. Integer ports exist only for legacy offline
    sessions; new VMs always use private filesystem sockets.
    """
    allowed = {"query-status", "quit", "screendump", "input-send-event", "send-key"}
    if type(endpoint) is int:
        endpoint_valid = 1024 <= endpoint <= 65535
    elif isinstance(endpoint, (str, Path)):
        endpoint = str(endpoint)
        endpoint_valid = Path(endpoint).is_absolute() and "\0" not in endpoint and len(endpoint.encode("utf-8")) < 108
    else:
        endpoint_valid = False
    if not endpoint_valid or not 0 < timeout <= 30:
        raise AgenticVMError("Invalid QMP endpoint or deadline.", "backend_error")
    if not operations or len(operations) > 128:
        raise AgenticVMError("QMP operation count exceeds its limit.", "backend_error")
    if not 0 <= interval <= 0.1:
        raise AgenticVMError("QMP operation pacing exceeds its limit.", "backend_error")
    for name, arguments in operations:
        if name not in allowed or not isinstance(arguments, dict):
            raise AgenticVMError("Unsupported QMP operation.", "backend_error")
        if len(json.dumps(arguments).encode("utf-8")) > 60000:
            raise AgenticVMError("QMP arguments exceed their size limit.", "request_too_large")
    deadline = time.monotonic() + timeout
    try:
        with (TcpTransport("127.0.0.1", endpoint, timeout) if type(endpoint) is int
              else SocketTransport(endpoint, timeout)) as connection:

            def receive():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("QMP timed out")
                line = connection.readline(remaining, 65536)
                result = json.loads(line)
                if not isinstance(result, dict):
                    raise ValueError("QMP frame is not an object")
                return result

            if "QMP" not in receive():
                raise AgenticVMError("Endpoint did not identify itself as QMP.", "protocol_error")
            results = []
            for name, arguments in [("qmp_capabilities", {}), *operations]:
                identifier = uuid4().hex
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("QMP timed out")
                request = {"execute": name, "id": identifier}
                if arguments:
                    request["arguments"] = arguments
                connection.write(json.dumps(request).encode() + b"\n", remaining)
                for _ in range(128):
                    response = receive()
                    if response.get("id") != identifier:
                        continue
                    if "error" in response:
                        raise AgenticVMError(f"QMP {name} failed: {response['error']}", "backend_error")
                    if "return" not in response:
                        raise AgenticVMError("QMP response has no result.", "protocol_error")
                    break
                else:
                    raise AgenticVMError("Too many unrelated QMP messages.", "protocol_error")
                if not isinstance(response["return"], dict):
                    raise AgenticVMError("QMP result is not an object.", "protocol_error")
                if name != "qmp_capabilities":
                    results.append(response["return"])
                    if interval:
                        if deadline - time.monotonic() < interval:
                            raise TimeoutError("QMP timed out while pacing guest input")
                        time.sleep(interval)
            return results
    except AgenticVMError as error:
        if error.code in {"guest_timeout", "guest_disconnected"}:
            raise AgenticVMError(f"Cannot communicate with the VM monitor: {error}", "backend_unavailable") from error
        raise
    except (OSError, ValueError) as error:
        raise AgenticVMError(f"Cannot communicate with the VM monitor: {error}", "backend_unavailable") from error


def qmp_call(endpoint: Path | str | int, command: str, timeout: float = 3, *, arguments: dict | None = None) -> dict:
    """Negotiate QMP and execute one fixed controller operation."""
    return qmp_sequence(endpoint, [(command, arguments or {})], timeout)[0]


def unused_ports() -> tuple[int, int]:
    sockets = []
    try:
        for _ in range(2):
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(stream)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                stream.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            stream.bind(("127.0.0.1", 0))
        return tuple(stream.getsockname()[1] for stream in sockets)
    finally:
        for stream in sockets:
            stream.close()


class QemuBackend(VMBackend):
    def __init__(self, store: StateStore, executable: Path):
        self.store, self.executable = store, executable.resolve()

    def doctor(self) -> dict:
        try:
            result = subprocess.run([str(self.executable), "--version"], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=10, check=False,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), shell=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise AgenticVMError(f"Cannot run QEMU: {error}", "backend_error") from error
        if result.returncode or not result.stdout.startswith("QEMU emulator version "):
            raise AgenticVMError(f"QEMU version check failed: {(result.stderr or result.stdout)[-2048:]}", "backend_error")
        return {"backend": "qemu", "executable": str(self.executable), "version": result.stdout.splitlines()[0],
                "sha256": binary_sha256(self.executable), "host": os.name, "windows_host": os.name == "nt",
                "accelerator": "whpx", "whpx": whpx_status(), "software_emulation_fallback": False,
                "control_transport": "virtio-serial",
                "host_control_transport": "unix",
                "profile": {"cpus": 1, "memory_mib": 512, "network": "none", "disk": "none"}}

    def _process(self, state: dict, *, terminate: bool = False):
        self.store.validate(state)
        if state.get("backend") != "qemu":
            raise AgenticVMError("Session belongs to another backend.", "backend_mismatch")
        process = WindowsProcess(state["pid"], terminate=terminate)
        if process.alive() and (process.created != state["process_created"] or process.executable != Path(state["executable"]).resolve()):
            process.close()
            raise AgenticVMError("VM process identity no longer matches its saved creation time and path; refusing control.", "ownership_mismatch")
        return process

    def start(self, iso: Path, memory_mib: int = 512, *, profile: str = "command", root_disk: Path | None = None,
              workspace_disk: Path | None = None, network: bool = False, width: int = 1024, height: int = 768, cpus: int = 1,
              peer_channel: bool = False, isolated_link: dict | None = None, serial_link: dict | None = None) -> dict:
        with self.store.lock():
            return self._start(iso, memory_mib, profile=profile, root_disk=root_disk, workspace_disk=workspace_disk,
                               network=network, width=width, height=height, cpus=cpus,
                               peer_channel=peer_channel, isolated_link=isolated_link, serial_link=serial_link)

    def _start(self, iso: Path, memory_mib: int, *, profile: str = "command", root_disk: Path | None = None,
               workspace_disk: Path | None = None, network: bool = False, width: int = 1024, height: int = 768, cpus: int = 1,
               peer_channel: bool = False, isolated_link: dict | None = None, serial_link: dict | None = None) -> dict:
        iso = iso.resolve()
        if not iso.is_file() or iso.suffix.lower() != ".iso":
            raise AgenticVMError("Supply an existing Linux agent .iso image.", "invalid_image")
        if type(memory_mib) is not int or not 128 <= memory_mib <= (16384 if profile == "desktop" else 1024):
            raise AgenticVMError("Memory is outside this profile's supported range.", "invalid_memory")
        if profile not in {"command", "desktop", "agent"} or type(network) is not bool or type(peer_channel) is not bool:
            raise AgenticVMError("Select the command, desktop or agent profile and explicit network booleans.", "invalid_profile")
        if peer_channel and profile != "agent":
            raise AgenticVMError("The dedicated peer channel requires the headless agent profile.", "invalid_profile")
        if serial_link is not None:
            if profile != "agent" or network or peer_channel or isolated_link is not None:
                raise AgenticVMError("Direct serial pairs require offline agents and an exclusive peer port.", "invalid_network")
            serial_link = validate_serial_link(serial_link)
            if not qemu_socket_directory(serial_link["pair_uuid"]).is_dir():
                raise AgenticVMError("Prepare the owned pair directory first.", "invalid_network")
        if isolated_link is not None:
            if profile != "agent" or network:
                raise AgenticVMError("Isolated Ethernet requires the agent profile without NAT.", "invalid_network")
            isolated_link = validate_isolated_link(isolated_link)
            pair_dir = qemu_socket_directory(isolated_link["pair_uuid"])
            if not pair_dir.is_dir():
                raise AgenticVMError("Prepare the owned pair directory before starting its VMs.", "invalid_network")
        if profile == "agent" and network:
            raise AgenticVMError("Headless agent networking is isolated; NAT is unavailable.", "invalid_network")
        if profile == "command" and (root_disk is not None or workspace_disk is not None or network):
            raise AgenticVMError("Root disks and networking require the desktop profile.", "invalid_profile")
        if type(width) is not int or type(height) is not int or not 640 <= width <= 1920 or not 480 <= height <= 1080:
            raise AgenticVMError("Desktop resolution must be 640–1920 by 480–1080 pixels.", "invalid_display")
        if profile in {"desktop", "agent"}:
            if profile == "desktop" and memory_mib < 512:
                raise AgenticVMError("The desktop profile needs at least 512 MiB of guest RAM.", "invalid_memory")
            if root_disk is None or not Path(root_disk).is_file():
                raise AgenticVMError("The desktop profile requires an existing raw root filesystem image.", "invalid_image")
            root_disk = Path(root_disk).resolve()
            if workspace_disk is not None:
                expected_workspace = self.store.root / "data" / f"{self.store.session}.ext2"
                workspace_disk = Path(workspace_disk).resolve()
                if (not workspace_disk.is_file() or workspace_disk != expected_workspace.absolute()
                        or expected_workspace.is_symlink() or expected_workspace.parent.is_symlink()):
                    raise AgenticVMError("Workspace disk must be the existing managed data/<session>.ext2 image.", "invalid_image")
        if type(cpus) is not int or not 1 <= cpus <= min(8, cpu_count() or 1) or (profile != "desktop" and cpus != 1):
            raise AgenticVMError("Choose 1–8 CPUs; headless profiles use one CPU.", "invalid_cpu")
        previous = self.store.load(required=False)
        if previous and previous.get("registered", True):
            raise AgenticVMError("A session already exists. Run stop or reset first.", "session_exists")
        info = self.doctor()
        if not info.get("whpx", {}).get("available", False):
            raise AgenticVMError("Windows Hypervisor Platform is unavailable. Enable it in Windows Features with firmware virtualization enabled, then restart if Windows requests it. AgenticVM does not change these settings.", "whpx_unavailable")
        if os.name != "nt":
            raise AgenticVMError("The QEMU/WHPX backend currently supports Windows hosts.", "unsupported_host")
        preflight = check_memory_budget(memory_mib)
        identifier = str(uuid4())
        name = f"AgenticVM-{identifier}"
        directory = self.store.root / "vms" / name
        directory.mkdir(parents=True, mode=0o700)
        socket_directory = _prepare_socket_directory(identifier)
        serial, qmp = socket_directory / "s", socket_directory / "q"
        state = {"schema": 1, "backend": "qemu", "session": self.store.session, "workspace": str(self.store.root),
                 "uuid": identifier, "name": name, "memory_mib": memory_mib, "cpus": cpus, "iso": str(iso), "run_dir": str(directory),
                 "host_control_transport": "unix", "socket_dir": str(socket_directory),
                 "serial_socket": str(serial), "qmp_socket": str(qmp),
                 "control_transport": "virtio-serial",
                 "profile": profile, "network": "nat" if network else "none",
                 "disk": ("read-only-base,guest-tmpfs-overlay" + (",persistent-workspace" if workspace_disk else "")) if root_disk else "none",
                 "root_disk": str(root_disk) if root_disk else None,
                 "workspace_disk": str(workspace_disk) if workspace_disk else None,
                 "display_width": width, "display_height": height,
                 "boot_log": str(directory / "boot.log"),
                 "pid": 0, "process_created": "0", "executable": str(self.executable),
                 "backend_sha256": info["sha256"], "backend_version": info["version"],
                 "status": "creating", "registered": False, "created_at": time.time(), "memory_preflight": preflight}
        if peer_channel:
            state.update(peer_channel=True, peer_socket=str(socket_directory / "c"))
        if serial_link is not None:
            state["serial_link"] = serial_link
        if isolated_link is not None:
            state.update(network="isolated", isolated_link=isolated_link)
            if isolated_link.get("capture"):
                state["packet_capture"] = str(directory / "peer.pcap")
        command = [str(self.executable), "-L", str(self.executable.parent / "share"), "-name", name, "-machine", "q35", "-accel", "whpx", "-m", str(memory_mib),
                   "-smp", str(cpus), "-display", "none", "-monitor", "none", "-nodefaults",
                   "-device", f"VGA,vgamem_mb={16 if profile == 'desktop' else 8},xres={width},yres={height}",
                   "-chardev", f"socket,id=agent,path={str(serial).replace(',', ',,')},server=on,wait=off",
                   "-device", "virtio-serial-pci,id=agentbus",
                   "-device", "virtserialport,bus=agentbus.0,nr=1,chardev=agent,name=org.agenticvm.agent",
                   "-chardev", "file,id=boot,path=" + str(directory / "boot.log").replace(",", ",,"),
                   "-device", "isa-serial,index=1,chardev=boot",
                   "-chardev", f"socket,id=qmp,path={str(qmp).replace(',', ',,')},server=on,wait=off",
                   "-mon", "chardev=qmp,mode=control",
                   "-cdrom", str(iso), "-boot", "order=d,menu=off", "-no-reboot"]
        if peer_channel:
            command.extend(["-chardev", f"socket,id=peer,path={str(socket_directory / 'c').replace(',', ',,')},server=on,wait=off",
                            "-device", "virtserialport,bus=agentbus.0,nr=2,chardev=peer,name=org.agenticvm.peer"])
        if serial_link is not None:
            endpoint = str(qemu_socket_directory(serial_link["pair_uuid"]) / "b").replace(",", ",,")
            listener = serial_link["role"] == "listen"
            command.extend(["-chardev", f"socket,id=peer,path={endpoint},server={'on,wait=off' if listener else 'off'}",
                            "-device", "virtserialport,bus=agentbus.0,nr=2,chardev=peer,name=org.agenticvm.peer"])
        if isolated_link is not None:
            listener = isolated_link["role"] == "listen"
            endpoint = str(qemu_socket_directory(isolated_link["pair_uuid"]) / "n").replace(",", ",,")
            command.extend(["-netdev", f"stream,id=peernet,addr.type=unix,addr.path={endpoint},server={'on' if listener else 'off'}",
                            "-device", f"e1000,netdev=peernet,romfile=,mac=52:54:00:41:56:{'01' if listener else '02'}",
                            "-fw_cfg", f"name=opt/agenticvm/peer-role,string={isolated_link['role']}"])
            if isolated_link.get("capture"):
                command.extend(["-object", "filter-dump,id=peertrace,netdev=peernet,file=" + str(directory / "peer.pcap").replace(",", ",,")])
        elif network:
            # The guest already boots its local ISO. Disable the e1000 PXE ROM
            # explicitly so networking needs no EFI/PXE firmware payload.
            command.extend(["-netdev", "user,id=desktopnet,ipv6=off",
                            "-device", "e1000,netdev=desktopnet,romfile="])
        else:
            command.extend(["-nic", "none"])
        if profile in {"desktop", "agent"}:
            # Linux mounts this immutable image read-only and uses a tmpfs
            # overlay. QEMU also enforces read-only access to the host base.
            command.extend(["-drive", f"file={str(root_disk).replace(',', ',,')},format=raw,if=virtio,readonly=on"])
            if profile == "desktop":
                command.extend(["-device", "qemu-xhci,id=usb", "-device", "usb-tablet,bus=usb.0", "-device", "usb-kbd,bus=usb.0"])
            if workspace_disk:
                command.extend(["-drive", f"file={str(workspace_disk).replace(',', ',,')},format=raw,if=virtio"])
        child = None
        try:
            (directory / "launch.json").write_text(json.dumps({"argv": command, "accelerator": "whpx", "profile": profile}, indent=2) + "\n", encoding="utf-8")
            self.store.save(state)
            with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False,
                                         creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
                                         close_fds=True)
            with WindowsProcess(child.pid) as process:
                if not process.alive() or process.executable != self.executable:
                    raise AgenticVMError("QEMU exited before its identity could be recorded.", "backend_start_failed")
                state.update(pid=child.pid, process_created=process.created, registered=True)
            self.store.save(state)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise AgenticVMError("QEMU exited during startup; inspect the session stderr.log.", "backend_start_failed")
                try:
                    monitor = qmp_call(qmp, "query-status", timeout=2)
                    if monitor.get("status") == "running":
                        break
                except AgenticVMError:
                    pass
                time.sleep(0.05)
            else:
                raise AgenticVMError("QEMU monitor did not become ready; inspect the session stderr.log.", "backend_start_failed")
            state["status"] = "running"
            self.store.save(state)
            return state
        except BaseException:
            if child is not None and child.poll() is None:
                child.terminate()  # This is the exact Popen handle created above.
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            state.update(status="failed", registered=child is not None and child.poll() is None)
            if not state["registered"]:
                state["socket_cleanup"] = _cleanup_socket_directory(state)
            self.store.save(state)
            raise

    def status(self) -> dict:
        state = self.store.load()
        result = {"backend": "qemu", "session": self.store.session, "uuid": state["uuid"], "status": state["status"],
                  "registered": state["registered"], "memory_mib": state["memory_mib"], "cpus": state.get("cpus", 1),
                  "network": state.get("network", "none"), "disk": state.get("disk", "none"),
                  "profile": state.get("profile", "command"), "iso": state["iso"], "accelerator": "whpx", "pid": state["pid"]}
        if state.get("profile") in {"desktop", "agent"}:
            result.update(root_disk=state["root_disk"], workspace_disk=state.get("workspace_disk"),
                          display_width=state["display_width"], display_height=state["display_height"])
        if state.get("peer_channel"):
            result.update(peer_channel=True, peer_socket=state["peer_socket"])
        if state.get("isolated_link"):
            result["isolated_link"] = state["isolated_link"]
        if state.get("serial_link"):
            result["serial_link"] = state["serial_link"]
        if state.get("packet_capture"):
            result["packet_capture"] = state["packet_capture"]
        result["control_transport"] = state.get("control_transport", "uart")
        result["host_control_transport"] = state.get("host_control_transport", "tcp")
        if state.get("boot_log"):
            result["boot_log"] = state["boot_log"]
        if state["registered"]:
            with self._process(state) as process:
                if not process.alive():
                    result.update(status="exited", vm_state="poweroff")
                else:
                    monitor = qmp_call(qmp_endpoint(state), "query-status")
                    result["vm_state"] = monitor.get("status", "unknown")
                    result["status"] = result["vm_state"]
        return result

    def stop(self) -> dict:
        with self.store.lock():
            state = self.store.load()
            if state["registered"]:
                with self._process(state, terminate=True) as process:
                    if process.alive():
                        try:
                            qmp_call(qmp_endpoint(state), "quit")
                        except AgenticVMError:
                            pass
                        if not process.wait(5):
                            process.terminate()
                            if not process.wait(5):
                                raise AgenticVMError("Owned QEMU process did not stop.", "backend_timeout")
            state.update(status="stopped", registered=False, stopped_at=time.time())
            state["socket_cleanup"] = _cleanup_socket_directory(state)
            self.store.save(state)
            return {"backend": "qemu", "session": self.store.session, "uuid": state["uuid"], "status": "stopped", "vm_files_retained": True,
                    "socket_cleanup": state["socket_cleanup"]}
