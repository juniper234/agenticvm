"""Atomic metadata and strict paths for controller-owned disposable VMs."""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from .errors import AgenticVMError


def contained(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def qemu_socket_directory(identifier: str) -> Path:
    """Short, user-private host IPC paths; unrelated to the guest's network."""
    if str(UUID(identifier)) != identifier:
        raise ValueError("Non-canonical session UUID")
    configured = os.environ.get("AGENTICVM_SOCKET_ROOT")
    if configured:
        root = Path(configured)
        if not root.is_absolute() or str(root).startswith("\\\\"):
            raise AgenticVMError("VM socket root must be a local absolute path.", "invalid_endpoint")
        root = root.resolve()
        if len(str(root / identifier / 'q').encode('utf-8')) >= 108:
            # Keep IPC inside the installation, even when AppData is protected.
            # Full UUID/process creation evidence stays in the ownership record.
            leaf = hashlib.sha256(identifier.encode('ascii')).hexdigest()[:16]
            compact = root / leaf
            if len(str(compact / 'q').encode('utf-8')) >= 108:
                raise AgenticVMError('Install AgenticVM in a shorter folder for private VM sockets.', 'invalid_endpoint')
            return compact
        return root / identifier
    return Path(tempfile.gettempdir()).resolve() / "AgenticVM" / identifier


def validate_isolated_link(link: dict) -> dict:
    """Only a private, canonical pair socket is a permitted Ethernet fabric."""
    if not isinstance(link, dict) or set(link) - {"pair_uuid", "role", "capture"} or not {"pair_uuid", "role"} <= set(link):
        raise AgenticVMError("An isolated link needs a pair UUID and listen/connect role.", "invalid_network")
    try:
        directory = qemu_socket_directory(link["pair_uuid"])
    except (ValueError, TypeError, AttributeError):
        raise AgenticVMError("Invalid isolated pair UUID.", "invalid_network") from None
    if not isinstance(link["role"], str) or link["role"] not in {"listen", "connect"} or type(link.get("capture", False)) is not bool or len(str(directory / "n").encode("utf-8")) >= 108:
        raise AgenticVMError("Invalid isolated pair endpoint.", "invalid_network")
    for parent in (directory.parent, directory):
        if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
            raise AgenticVMError("Isolated pair directories must not redirect paths.", "invalid_network")
    return {"pair_uuid": link["pair_uuid"], "role": link["role"], **({"capture": True} if link.get("capture") else {})}


def validate_serial_link(link: dict) -> dict:
    """A direct VM-to-VM byte stream has no address supplied by callers."""
    if not isinstance(link, dict) or set(link) != {"pair_uuid", "role"}:
        raise AgenticVMError("A serial pair needs only its UUID and role.", "invalid_network")
    return validate_isolated_link(link)


class StateStore:
    def __init__(self, root: Path, session: str = "default"):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", session):
            raise AgenticVMError("Session names need 1–64 letters, digits, dashes or underscores.", "invalid_session")
        self.root = root.resolve()
        self.session = session
        self.path = self.root / "sessions" / f"{session}.json"
        self._thread_lock = threading.RLock()
        self._lock_depth = 0

    @contextmanager
    def lock(self):
        """Serialize lifecycle mutations, including across separate CLI processes."""
        with self._thread_lock:
            if self._lock_depth:
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                return
            self.prepare()
            stream = (self.root / ".controller.lock").open("a+b")
            try:
                if stream.seek(0, os.SEEK_END) == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise AgenticVMError("Another lifecycle operation is in progress; retry when it finishes.", "session_busy") from error
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
                    stream.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(stream, fcntl.LOCK_UN)
            finally:
                stream.close()

    def prepare(self) -> None:
        for path in (self.root, self.root / "sessions", self.root / "vms", self.root / "vbox-user"):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                path.chmod(0o700)

    def load(self, required: bool = True) -> dict | None:
        try:
            if self.path.stat().st_size > 65536:
                raise AgenticVMError("Session metadata exceeds its size limit.", "invalid_state")
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if not required:
                return None
            raise AgenticVMError("No session exists. Run start first.", "no_session") from None
        except (ValueError, OSError) as error:
            raise AgenticVMError(f"Cannot read session metadata: {error}", "invalid_state") from error
        self.validate(data)
        return data

    def validate(self, data: dict) -> None:
        try:
            if not isinstance(data, dict) or not isinstance(data.get("uuid"), str):
                raise ValueError("invalid UUID type")
            identifier = str(UUID(data["uuid"]))
            valid = type(data["schema"]) is int and data["schema"] == 1 and data["session"] == self.session
            valid = valid and data["uuid"] == identifier
            valid = valid and data["workspace"] == str(self.root)
            valid = valid and data["name"] == f"AgenticVM-{identifier}"
            vm_dir = self.root / "vms" / data["name"]
            valid = valid and contained(vm_dir, self.root / "vms")
            backend = data.get("backend", "virtualbox")
            if backend == "virtualbox":
                valid = valid and Path(data["config_file"]).resolve() == (vm_dir / f'{data["name"]}.vbox').resolve()
                if "boot_log" in data:
                    valid = valid and Path(data["boot_log"]).resolve() == (vm_dir / "boot.log").resolve()
                valid = valid and data["pipe"] == "\\\\.\\pipe\\agenticvm-" + identifier
                valid = valid and data["vbox_user_home"] == str(self.root / "vbox-user")
            elif backend == "qemu":
                profile = data.get("profile", "command")
                if "serial_link" in data:
                    validate_serial_link(data["serial_link"])
                    valid = valid and profile == "agent" and data.get("network") == "none" and data.get("host_control_transport") == "unix" and not data.get("peer_channel") and "peer_socket" not in data
                valid = valid and profile in {"command", "desktop", "agent"}
                valid = valid and data.get("network", "none") in ({"none"} if profile == "command" else {"none", "isolated"} if profile == "agent" else {"none", "nat"})
                if data.get("network") == "isolated":
                    validate_isolated_link(data.get("isolated_link"))
                    if data["isolated_link"].get("capture"):
                        valid = valid and data.get("packet_capture") == str(vm_dir / "peer.pcap")
                    elif "packet_capture" in data:
                        valid = False
                elif "isolated_link" in data:
                    valid = False
                elif "packet_capture" in data:
                    valid = False
                if profile in {"desktop", "agent"}:
                    valid = valid and isinstance(data.get("root_disk"), str) and Path(data["root_disk"]).is_absolute()
                    valid = valid and all(type(data.get(key)) is int and minimum <= data[key] <= maximum
                                          for key, minimum, maximum in (("display_width", 640, 1920), ("display_height", 480, 1080)))
                    if data.get("workspace_disk") is not None:
                        valid = valid and isinstance(data["workspace_disk"], str) and Path(data["workspace_disk"]).is_absolute()
                        valid = valid and Path(data["workspace_disk"]).resolve() == (self.root / "data" / f"{self.session}.ext2").absolute()
                    if profile == "agent" and ("browser_job_id" in data or "browser_started_at" in data):
                        valid = False
                    if "browser_job_id" in data:
                        valid = valid and isinstance(data["browser_job_id"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", data["browser_job_id"]) is not None
                        valid = valid and int(data["browser_job_id"]) <= 2**64 - 1
                    if "browser_started_at" in data:
                        started = data["browser_started_at"]
                        valid = valid and "browser_job_id" in data and type(started) in {int, float} and 0 <= started <= 2**63 - 1 and math.isfinite(started)
                elif "browser_job_id" in data or "browser_started_at" in data:
                    valid = False
                valid = valid and Path(data["run_dir"]).resolve() == vm_dir.resolve()
                if "boot_log" in data:
                    valid = valid and Path(data["boot_log"]).resolve() == (vm_dir / "boot.log").resolve()
                host_transport = data.get("host_control_transport", "tcp")
                if host_transport == "unix":
                    expected = qemu_socket_directory(identifier)
                    valid = valid and data["socket_dir"] == str(expected)
                    valid = valid and data["serial_socket"] == str(expected / "s")
                    valid = valid and data["qmp_socket"] == str(expected / "q")
                    if "peer_channel" in data:
                        valid = valid and type(data["peer_channel"]) is bool
                    if data.get("peer_channel", False):
                        valid = valid and profile == "agent" and data.get("peer_channel") is True and data.get("peer_socket") == str(expected / "c")
                    elif "peer_socket" in data:
                        valid = False
                    valid = valid and all(len(str(expected / name).encode("utf-8")) < 108 for name in ("s", "q"))
                    valid = valid and not any(key in data for key in ("serial_host", "serial_port", "qmp_port"))
                    for parent in (expected.parent, expected):
                        valid = valid and not parent.is_symlink() and not getattr(parent, "is_junction", lambda: False)()
                elif host_transport == "tcp":
                    # Older offline sessions remain inspectable/stoppable. A
                    # networked guest must never reach its host control plane
                    # through slirp's host-loopback alias.
                    valid = valid and (data.get("network", "none") == "none" or (data["status"] == "stopped" and data["registered"] is False))
                    valid = valid and data["serial_host"] == "127.0.0.1"
                    valid = valid and all(type(data[key]) is int and 1024 <= data[key] <= 65535 for key in ("serial_port", "qmp_port"))
                    valid = valid and data["serial_port"] != data["qmp_port"]
                    valid = valid and not any(key in data for key in ("socket_dir", "serial_socket", "qmp_socket"))
                    valid = valid and not data.get("peer_channel") and "peer_socket" not in data
                else:
                    valid = False
                valid = valid and type(data["pid"]) is int and data["pid"] >= 0
                valid = valid and isinstance(data["process_created"], str) and data["process_created"].isdigit()
                valid = valid and Path(data["executable"]).is_absolute()
                valid = valid and isinstance(data["backend_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", data["backend_sha256"]) is not None
                valid = valid and (not data["registered"] or data["pid"] > 0)
            else:
                valid = False
            valid = valid and isinstance(data["memory_mib"], int) and not isinstance(data["memory_mib"], bool) and data["memory_mib"] in range(128, 16385 if data.get("profile") == "desktop" else 1025)
            valid = valid and type(data.get("cpus", 1)) is int and 1 <= data.get("cpus", 1) <= 8
            valid = valid and isinstance(data["iso"], str)
            valid = valid and isinstance(data["registered"], bool)
            valid = valid and data["status"] in {"creating", "running", "stopped", "failed"}
            if not valid:
                raise ValueError("invalid ownership")
        except (KeyError, TypeError, ValueError, OSError, AgenticVMError):
            raise AgenticVMError("Session ownership or paths are invalid; refusing VM control.", "invalid_state") from None

    def save(self, data: dict) -> None:
        self.validate(data)
        self.prepare()
        descriptor, temporary = tempfile.mkstemp(prefix=".session-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(data, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
