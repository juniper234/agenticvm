"""Owned Android Emulator guests and bounded ADB control, separate from Linux RPC."""
from __future__ import annotations

import base64
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from uuid import UUID, uuid4

from .errors import AgenticVMError
from .qemu import WindowsProcess
from .resources import check_memory_budget, whpx_status
from .state import StateStore, contained

ROOT = Path(os.environ.get("AGENTICVM_HOME", Path(__file__).resolve().parents[2])).resolve()
SDK = ROOT / "tools/android/sdk"
MAX_FILE = 1024 * 1024
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fail(message, code="android_error"):
    raise AgenticVMError(message, code)


def runtime_paths(workspace, identifier):
    """Short owned caches avoid the emulator's legacy MAX_PATH lock-file loop."""
    root = Path(workspace)
    home = root / 'a' / identifier.replace('-', '')[:16]
    avd = home / 'v'
    name = 'AgenticVM_' + identifier.replace('-', '')
    paths = [root/'vms'/('AgenticVM-'+identifier)/'emulator.log',
             avd/(name+'.avd')/'config.ini',home/'e'/'emu-last-feature-flags.protobuf.lock']
    if any(len(str(path).encode('utf-16-le'))//2 >= 248 for path in paths):
        fail('The Android workspace path is too long. Use a shorter installation or session name.', 'android_path_too_long')
    from .control_store import checked
    checked(home, root)
    return home, avd


def check_start_log(path):
    if Path(path).stat().st_size > 16 * 1024**2:
        fail('Android startup produced excessive logs; the owned launch will be stopped. Inspect emulator.log.', 'android_log_limit')


def run(argv, *, timeout=30, env=None, check=True, input=None, output_limit=4 * 1024 * 1024):
    try:
        process = subprocess.Popen(list(map(str, argv)), stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, creationflags=FLAGS, shell=False)
        outputs = [bytearray(), bytearray()]
        def drain(stream, target):
            while block := stream.read(65536):
                target.extend(block[:max(0, output_limit + 1 - len(target))])
            stream.close()
        threads = [threading.Thread(target=drain, args=(stream, target), daemon=True)
                   for stream, target in zip((process.stdout, process.stderr), outputs)]
        for thread in threads:
            thread.start()
        if input is not None:
            def feed():
                try:
                    process.stdin.write(input)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            writer = threading.Thread(target=feed, daemon=True)
            threads.append(writer)
            writer.start()
        try:
            process.wait(timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(10)
            raise
        finally:
            for thread in threads:
                thread.join(10)
        result = subprocess.CompletedProcess(argv, process.returncode, bytes(outputs[0]), bytes(outputs[1]))
    except subprocess.TimeoutExpired as error:
        raise AgenticVMError("Android operation exceeded its deadline.", "android_timeout") from error
    except OSError as error:
        raise AgenticVMError(str(error), "android_tool_error") from error
    if check and result.returncode:
        fail((result.stderr + result.stdout).decode("utf-8", "replace")[-4096:], "android_command_failed")
    return result


def verify_assets(*, complete=True):
    receipt_path = SDK.parent / "prepared.json"
    if not receipt_path.is_file():
        fail("Prepare Android first: bundled python -I -B scripts/prepare-android.py --download", "android_missing")
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("source_lock_sha256") != sha256(ROOT / "tools/android-lock.json"):
        fail("Android source lock differs from the preparation receipt.", "android_integrity")
    required = {"emulator/emulator.exe", "emulator/qemu/windows-x86_64/qemu-system-x86_64.exe", "emulator/qemu/windows-x86_64/qemu-system-x86_64-headless.exe", "platform-tools/adb.exe",
                "system-images/android-35/default/x86_64/system.img", "system-images/android-35/default/x86_64/kernel-ranchu"}
    if not required <= set(receipt["files"]):
        fail("Incomplete Android asset receipt.", "android_integrity")
    for name, pin in receipt["files"].items():
        if not complete and name not in required:
            continue
        path = SDK / name
        if not contained(path, SDK) or path.is_symlink() or not path.is_file() or path.stat().st_size != pin["size"] or sha256(path) != pin["sha256"]:
            fail("Android asset changed: " + name, "android_integrity")
    return {"files_checked": len(receipt["files"]) if complete else len(required), "receipt_sha256": sha256(receipt_path)}


def verify_helper():
    folder = SDK.parent / "control"
    if not (folder / "receipt.json").is_file():
        fail("Build Android Unicode control first: scripts/build-android-control.py", "android_missing")
    receipt = json.loads((folder / "receipt.json").read_text(encoding="utf-8"))
    if sha256(folder / "control.apk") != receipt["apk_sha256"]:
        fail("Android control APK digest differs from its receipt.", "android_integrity")
    for name, pin in receipt["sources"].items():
        if not contained(ROOT / name, ROOT / "guest/android-control") or sha256(ROOT / name) != pin:
            fail("Android helper source changed; rebuild before launch.", "android_integrity")
    return receipt["apk_sha256"]


class AndroidStore(StateStore):
    def validate(self, data):
        if not isinstance(data, dict) or data.get("backend") != "android":
            return super().validate(data)
        try:
            identifier = str(UUID(data["uuid"]))
            folder = self.root / "vms" / ("AgenticVM-" + identifier)
            short = data.get('short_paths', False)
            avd = runtime_paths(self.root, identifier)[1] if short else folder/'avd'
            good = (data["schema"] == 1 and data["uuid"] == identifier and data["session"] == self.session
                    and data["workspace"] == str(self.root) and data["name"] == "AgenticVM-" + identifier
                    and data["run_dir"] == str(folder) and data["profile"] == "android"
                    and type(data["registered"]) is bool and data["status"] in {"creating", "running", "failed", "stopped"}
                    and type(data["memory_mib"]) is int and 2560 <= data["memory_mib"] <= 8192
                    and type(data.get("cpus", 1)) is int and 1 <= data.get("cpus", 1) <= 8
                    and data["network"] in {"none", "nat"} and type(data["persistent"]) is bool
                    and data["avd_name"] == "AgenticVM_" + identifier.replace("-", "")
                    and data["data_dir"] == str((self.root / "android-data" / self.session) if data["persistent"] else folder / "data")
                    and type(short) is bool and data["avd_home"] == str(avd) and data["adb_serial"] == "127.0.0.1:" + str(data["console_port"] + 1)
                    and type(data["console_port"]) is int and data["console_port"] in range(5554, 5683, 2)
                    and type(data["adb_server_port"]) is int and 1024 <= data["adb_server_port"] <= 65535
                    and data["adb_server_port"] not in {data["console_port"], data["console_port"] + 1})
            for item in data["processes"]:
                good = good and (type(item["pid"]) is int and item["pid"] > 0 and re.fullmatch(r"[0-9]+", item["created"]) is not None
                                 and Path(item["executable"]).resolve() in {SDK / "platform-tools/adb.exe", SDK / "emulator/emulator.exe", SDK / "emulator/qemu/windows-x86_64/qemu-system-x86_64.exe", SDK / "emulator/qemu/windows-x86_64/qemu-system-x86_64-headless.exe"})
            if "launcher" in data:
                item = data["launcher"]
                good = good and (type(item["pid"]) is int and item["pid"] > 0 and re.fullmatch(r"[0-9]+", item["created"]) is not None
                                 and Path(item["executable"]).resolve() == SDK / "emulator/emulator.exe")
            for path in [folder, Path(data["data_dir"]), Path(data["avd_home"])]:
                good = good and contained(path, self.root)
                for parent in [path, *path.parents]:
                    if parent == self.root.parent:
                        break
                    good = good and not parent.is_symlink() and not getattr(parent, "is_junction", lambda: False)()
            if not good:
                raise ValueError()
        except (KeyError, TypeError, ValueError, OSError):
            fail("Invalid Android ownership manifest; refusing control.", "invalid_state")


def process_pin(pid):
    with WindowsProcess(pid) as process:
        if not process.alive() or not process.created:
            fail("Android process exited before ownership could be recorded.", "android_exited")
        return {"pid": pid, "created": process.created, "executable": str(process.executable)}


@contextmanager
def owned_process(pin, *, terminate=False):
    with WindowsProcess(pin["pid"], terminate=terminate) as process:
        if process.alive() and (process.created != pin["created"] or process.executable != Path(pin["executable"]).resolve()):
            fail("Android process identity differs from its creation receipt.", "ownership_mismatch")
        yield process


def campaign_idle():
    """Acquire the existing native campaign mutex before any Android VM launch."""
    from .chain import exclusive
    folder = ROOT / "runtime/native-enrollment-runs"
    folder.mkdir(parents=True, exist_ok=True)
    return exclusive(folder)


def ports():
    for port in range(5554, 5683, 2):
        sockets = []
        try:
            for value in (port, port + 1, 0):
                sock = socket.socket()
                sockets.append(sock)
                if os.name == "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(("127.0.0.1", value))
            return port, sockets[-1].getsockname()[1]
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    fail("No free Android console/ADB port pair.", "android_ports_busy")


def guest_path(value):
    if not isinstance(value, str) or "\x00" in value or "\\" in value:
        fail("Invalid Android workspace path.", "invalid_path")
    if value == "/workspace" or value.startswith("/workspace/"):
        value = "/data/local/tmp/agenticvm" + value[len("/workspace"):]
    elif not value.startswith("/"):
        value = "/data/local/tmp/agenticvm/" + value
    path = PurePosixPath(value)
    if ".." in path.parts or not (str(path) == "/data/local/tmp/agenticvm" or str(path).startswith("/data/local/tmp/agenticvm/")):
        fail("Android transfers stay inside /workspace (/data/local/tmp/agenticvm).", "invalid_path")
    return str(path)


class AndroidBackend:
    def __init__(self, store):
        self.store = store

    def environment(self, state):
        env = os.environ.copy()
        home = runtime_paths(Path(state['workspace']), state['uuid'])[0] if state.get('short_paths') else Path(state['run_dir'])
        env.update({"ANDROID_HOME": str(SDK), "ANDROID_SDK_ROOT": str(SDK), "ANDROID_AVD_HOME": state["avd_home"],
                    "ANDROID_EMULATOR_HOME": str(home / ('e' if state.get('short_paths') else 'emulator-home')),
                    "ANDROID_USER_HOME": str(home / ('u' if state.get('short_paths') else 'android-home')),
                    "ANDROID_ADB_SERVER_PORT": str(state["adb_server_port"]), "ADB_SERVER_PORT": str(state["adb_server_port"])})
        return env

    def adb(self, state, *args, timeout=30, check=True, input=None):
        self.store.validate(state)
        if not state["registered"]:
            fail("Android session is stopped.", "session_stopped")
        for pin in state["processes"]:
            with owned_process(pin) as process:
                if not process.alive():
                    fail("An owned Android control process exited.", "android_exited")
        return run([SDK / "platform-tools/adb.exe", "-P", state["adb_server_port"], "-s", state["adb_serial"], *args],
                   env=self.environment(state), timeout=timeout, check=check, input=input)

    def shell(self, state, argv, *, timeout=30, check=True):
        if not argv or len(argv) > 64 or any(not isinstance(v, str) or "\x00" in v for v in argv) or sum(len(v.encode()) for v in argv) > 65536:
            fail("Android needs a bounded literal argv array.", "invalid_argv")
        # adb joins argv through the device shell. Quote every element, including
        # shell metacharacters, before handing one command string to adb.
        return self.adb(state, "shell", "-T", shlex.join(argv), timeout=timeout, check=check)

    def set_shell_identity(self, state, *, root):
        """ADB restarts its transport during root/unroot; require actual UID."""
        expected = b"0" if root else b"2000"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.adb(state, "root" if root else "unroot", timeout=5, check=False)
                self.adb(state, "connect", state["adb_serial"], timeout=5, check=False)
                if self.shell(state, ["id", "-u"], timeout=5, check=False).stdout.strip() == expected:
                    return
            except AgenticVMError as error:
                if error.code not in {"android_timeout", "android_command_failed"}:
                    raise
            time.sleep(0.2)
        fail("ADB did not establish the required guest UID " + expected.decode() + ".", "android_network_guard")

    def doctor(self):
        integrity = verify_assets()
        result = run([SDK / "emulator/emulator.exe", "-accel-check"], check=False)
        return {"backend": "android", "profile": "android", "android_api": 35, "abi": "x86_64", "integrity": integrity,
                "acceleration": result.stdout.decode("utf-8", "replace"), "whpx": whpx_status(),
                "default_memory_mib": 2560, "google_play": False, "control_apk_sha256": verify_helper()}

    def start(self, *, memory=2560, persistent=False, network=False, timeout=240, campaign_locked=False, cpus=1):
        if type(memory) is not int or not 2560 <= memory <= 8192 or type(cpus) is not int or not 1 <= cpus <= min(8, os.cpu_count() or 1) or type(persistent) is not bool or type(network) is not bool or not 1 <= timeout <= 600:
            fail("Android requires 2560–8192 MiB and a 1–600 second boot deadline.", "invalid_limits")
        with (nullcontext() if campaign_locked else campaign_idle()), self.store.lock():
            previous = self.store.load(required=False)
            if previous and previous.get("registered"):
                fail("Stop the registered session before starting Android.", "session_exists")
            if not whpx_status()["available"]:
                fail("Android requires already enabled Windows Hypervisor Platform.", "whpx_unavailable")
            preflight = check_memory_budget(memory + 512)
            if __import__("shutil").disk_usage(self.store.root if self.store.root.exists() else ROOT).free < 8 * 1024**3:
                fail("Android needs at least 8 GiB free disk before launch.", "insufficient_disk")
            integrity = verify_assets()
            helper_sha = verify_helper()
            identifier = str(uuid4())
            home, short_avd = runtime_paths(self.store.root, identifier)
            folder = self.store.root / "vms" / ("AgenticVM-" + identifier)
            folder.mkdir(parents=True)
            console, server = ports()
            state = {"schema": 1, "backend": "android", "profile": "android", "session": self.store.session,
                     "uuid": identifier, "name": "AgenticVM-" + identifier, "workspace": str(self.store.root),
                     "run_dir": str(folder), "status": "creating", "registered": False, "memory_mib": memory, "cpus": cpus,
                     "persistent": persistent, "network": "nat" if network else "none", "processes": [],
                     "console_port": console, "adb_server_port": server, "adb_serial": "127.0.0.1:" + str(console + 1),
                     "avd_name": "AgenticVM_" + identifier.replace("-", ""), "avd_home": str(short_avd), 'short_paths':True,
                     "data_dir": str(self.store.root / "android-data" / self.store.session if persistent else folder / "data"),
                     "created_at": time.time(), "memory_preflight": preflight, "integrity": integrity}
            self.store.save(state)
            data_dir, avd_home = Path(state["data_dir"]), Path(state["avd_home"])
            data_dir.mkdir(parents=True, exist_ok=True)
            avd_home.mkdir(parents=True)
            config_dir = data_dir / "avd"
            if not contained(config_dir, self.store.root) or config_dir.is_symlink() or getattr(config_dir, "is_junction", lambda: False)():
                fail("Android AVD content directory redirects outside its owner.", "invalid_path")
            config_dir.mkdir(exist_ok=True)
            image_dir = SDK / "system-images/android-35/default/x86_64"
            encryption = data_dir / "encryptionkey.img"
            if not encryption.exists():
                # Keep the key image and its writable overlay with userdata.
                # A fresh per-launch AVD directory must not reset either one.
                with (image_dir / "encryptionkey.img").open("rb") as source, encryption.open("xb") as target:
                    __import__("shutil").copyfileobj(source, target)
            (avd_home / (state["avd_name"] + ".ini")).write_text("avd.ini.encoding=UTF-8\npath=" + str(config_dir) + "\ntarget=android-35\n")
            config = {"avd.ini.encoding": "UTF-8", "AvdId": state["avd_name"], "abi.type": "x86_64", "hw.cpu.arch": "x86_64",
                      "image.sysdir.1": str(image_dir) + os.sep, "tag.id": "default", "target": "android-35", "hw.cpu.ncore": "1",
                      "hw.ramSize": str(memory), "hw.lcd.width": "720", "hw.lcd.height": "1280", "hw.lcd.density": "240",
                      "hw.gpu.enabled": "yes", "hw.gpu.mode": "software", "hw.keyboard": "yes", "hw.sdCard": "no", "hw.bluetooth": "no",
                      "hw.keyboard.lid": "no", "hw.mainKeys": "no", "hw.dPad": "no", "hw.trackBall": "no",
                      "hw.camera.back": "none", "hw.camera.front": "none", "hw.gps": "no", "hw.audioInput": "no", "hw.audioOutput": "no",
                      "disk.dataPartition.size": "6G", "disk.dataPartition.path": str(data_dir / "userdata-qemu.img"),
                      "disk.cachePartition.path": str(data_dir / "cache.img"), "disk.encryptionKeyPartition.path": str(encryption),
                      "firstboot.bootFromDownloadableSnapshot": "no", "firstboot.bootFromLocalSnapshot": "no", "firstboot.saveToLocalSnapshot": "no",
                      "fastboot.forceColdBoot": "yes", "PlayStore.enabled": "false"}
            (config_dir / "config.ini").write_text("".join(k + "=" + v + "\n" for k, v in config.items()))
            env = self.environment(state)
            for key in ("ANDROID_EMULATOR_HOME", "ANDROID_USER_HOME"):
                Path(env[key]).mkdir(parents=True, exist_ok=True)
            temporary = home / 't'
            temporary.mkdir()
            env.update(TEMP=str(temporary), TMP=str(temporary))
            try:
                adb_command = [str(SDK / "platform-tools/adb.exe"), "-L", f"tcp:{server}", "nodaemon", "server"]
                with (folder / "adb.log").open("wb") as log:
                    adb = subprocess.Popen(adb_command, stdout=log, stderr=log, stdin=subprocess.DEVNULL, env=env, creationflags=FLAGS)
                state["processes"].append(process_pin(adb.pid))
                self.store.save(state)
                command = [str(SDK / "emulator/emulator.exe"), "-avd", state["avd_name"], "-datadir", str(data_dir),
                           "-data", str(data_dir / "userdata-qemu.img"), "-cache", str(data_dir / "cache.img"), "-encryption-key", str(encryption),
                           "-port", str(console), "-memory", str(memory), "-cores", str(cpus), "-accel", "on", "-gpu", "swiftshader",
                           "-feature", "-BluetoothEmulation,-ModemSimulator,-Vulkan,-QuickbootFileBacked",
                           "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot", "-no-metrics", "-no-sim",
                           "-crash-report-mode", "disabled", "-wifi-user-mode-options", "ipv6=off,restrict=" + ("off" if network else "on"),
                           "-network-user-mode-options", "ipv6=off,restrict=" + ("off" if network else "on")]
                (folder / "launch.json").write_text(json.dumps({"argv": command, "adb_argv": adb_command}, indent=2))
                with (folder / "emulator.log").open("wb") as log:
                    emulator = subprocess.Popen(command, stdout=log, stderr=log, stdin=subprocess.DEVNULL, env=env, creationflags=FLAGS)
                state["launcher"] = process_pin(emulator.pid)
                self.store.save(state)
                # The launcher owns its qemu child; identify that child by its
                # unique AVD argument and exact prepared executable path.
                deadline = time.monotonic() + min(30, timeout)
                while time.monotonic() < deadline:
                    check_start_log(folder/'emulator.log')
                    query = "$p=Get-CimInstance Win32_Process; @($p | Where-Object { $_.Name -like 'qemu-system-x86_64*' -and $_.CommandLine -like '*" + state["avd_name"] + "*' } | Select-Object ProcessId,ParentProcessId,ExecutablePath) | ConvertTo-Json -Compress"
                    result = run(["powershell.exe", "-NoProfile", "-Command", query], timeout=15)
                    rows = json.loads(result.stdout or b"[]")
                    if isinstance(rows, dict):
                        rows = [rows]
                    if len(rows) == 1:
                        row = rows[0]
                        pin = process_pin(row["ProcessId"])
                        if Path(pin["executable"]).parent != SDK / "emulator/qemu/windows-x86_64" or Path(pin["executable"]).name not in {"qemu-system-x86_64.exe", "qemu-system-x86_64-headless.exe"} or row["ParentProcessId"] != emulator.pid:
                            fail("Android child lineage differs from the launcher.", "ownership_mismatch")
                        state["processes"].append(pin)
                        break
                    if emulator.poll() is not None:
                        fail("Android launcher exited; inspect emulator.log.", "android_exited")
                    time.sleep(0.25)
                else:
                    fail("Android QEMU child did not appear.", "android_timeout")
                state["registered"] = True
                state["status"] = "running"
                self.store.save(state)
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    check_start_log(folder/'emulator.log')
                    try:
                        self.adb(state, "connect", state["adb_serial"], timeout=min(5, max(0.1, deadline - time.monotonic())), check=False)
                        boot = self.shell(state, ["getprop", "sys.boot_completed"], timeout=min(5, max(0.1, deadline - time.monotonic())), check=False)
                    except AgenticVMError as error:
                        if error.code == "android_timeout":
                            time.sleep(0.2)
                            continue
                        raise
                    if boot.returncode == 0 and boot.stdout.strip() == b"1":
                        break
                    time.sleep(1)
                else:
                    fail("Android boot deadline exceeded; inspect emulator.log.", "android_timeout")
                observed_avd = self.shell(state, ["getprop", "ro.boot.qemu.avd_name"]).stdout.decode().strip()
                if observed_avd != state["avd_name"]:
                    fail("ADB target is not this launch's exact AVD identity.", "ownership_mismatch")
                meminfo = self.shell(state, ["cat", "/proc/meminfo"]).stdout.decode()
                actual_memory_kib = int(re.search(r"^MemTotal:\s+(\d+) kB", meminfo, re.MULTILINE).group(1))
                if actual_memory_kib > (memory + 16) * 1024:
                    fail("Emulator enlarged RAM beyond the preflighted allocation.", "android_memory_mismatch")
                state["guest_binding"] = {"avd_name": observed_avd, "observed_memory_kib": actual_memory_kib, "requested_memory_mib": memory}
                effective = dict(line.split("=", 1) for line in (config_dir / "hardware-qemu.ini").read_text(encoding="utf-8").splitlines() if "=" in line)
                effective = {key.strip(): value.strip() for key, value in effective.items()}
                disk_paths = {"disk.dataPartition.path": data_dir / "userdata-qemu.img", "disk.encryptionKeyPartition.path": encryption}
                if any(Path(effective.get(key, "")).resolve() != path.resolve() for key, path in disk_paths.items()):
                    fail("Emulator disk paths differ from this session's owned data directory.", "android_disk_mismatch")
                state["guest_binding"]["disk_paths"] = {key: str(path) for key, path in disk_paths.items()}
                # ADB control is local TCP. Block the emulator's host aliases
                # inside this owned debug guest before exposing it to APKs.
                self.set_shell_identity(state, root=True)
                self.shell(state, ["iptables", "-I", "OUTPUT", "1", "-d", "10.0.2.0/24", "-p", "tcp", "-j", "REJECT"])
                self.shell(state, ["iptables", "-I", "OUTPUT", "1", "-d", "10.0.2.0/24", "-p", "udp", "!", "--dport", "53", "-j", "REJECT"])
                if not network:
                    self.shell(state, ["iptables", "-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "REJECT"])
                self.shell(state, ["ip6tables", "-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "REJECT"])
                state["network_guard"] = {"ipv4": self.shell(state, ["iptables", "-S", "OUTPUT"]).stdout.decode(),
                                          "ipv6": self.shell(state, ["ip6tables", "-S", "OUTPUT"]).stdout.decode()}
                # This profile has no Bluetooth hardware/backend. Android 15
                # otherwise retries its system Bluetooth app and can cover the
                # guest with a repeated crash dialog.
                self.shell(state, ["settings", "put", "global", "bluetooth_on", "0"])
                self.shell(state, ["pm", "disable-user", "--user", "0", "com.android.bluetooth"])
                self.shell(state, ["am", "force-stop", "com.android.bluetooth"])
                disabled = self.shell(state, ["pm", "list", "packages", "-d", "com.android.bluetooth"]).stdout.splitlines()
                if b"package:com.android.bluetooth" not in disabled:
                    fail("Unsupported guest Bluetooth package remained enabled.", "android_device_configuration")
                state["disabled_guest_components"] = ["com.android.bluetooth"]
                self.set_shell_identity(state, root=False)
                self.shell(state, ["mkdir", "-p", "/data/local/tmp/agenticvm"])
                if network:
                    # An earlier offline boot can permanently disable autojoin
                    # for AndroidWifi. NAT is an explicit owner request to
                    # reconnect this emulator network, including saved sessions.
                    self.shell(state, ["svc", "wifi", "enable"])
                    self.shell(state, ["cmd", "wifi", "connect-network", "AndroidWifi", "open"])
                    state["nat_initialization"] = {"ssid": "AndroidWifi", "reconnect_requested": True}
                self.shell(state, ["svc", "power", "stayon", "true"])
                self.shell(state, ["input", "keyevent", "KEYCODE_WAKEUP"])
                self.shell(state, ["wm", "dismiss-keyguard"], check=False)
                self.shell(state, ["input", "keyevent", "KEYCODE_BACK"])
                install = self.adb(state, "install", "-r", "--no-streaming", str(SDK.parent / "control/control.apk"), timeout=120)
                if b"Success" not in install.stdout:
                    fail("Control APK installation was not confirmed.", "apk_install_failed")
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    methods = self.shell(state, ["ime", "list", "-a", "-s"]).stdout.decode().splitlines()
                    component = next((line.strip() for line in methods if line.strip().startswith("org.agenticvm.control/") and line.strip().endswith(".ControlIME")), None)
                    if component:
                        break
                    time.sleep(0.25)
                else:
                    fail("Installed Android input method did not register in time.", "android_ime_not_ready")
                self.shell(state, ["ime", "enable", component])
                self.shell(state, ["ime", "set", component])
                state["input_method"] = component
                state["control_apk_sha256"] = helper_sha
                self.shell(state, ["input", "keyevent", "KEYCODE_WAKEUP"])
                self.shell(state, ["wm", "dismiss-keyguard"], check=False)
                from .png_evidence import png_signal
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    painted, _ = self.screenshot_bytes()
                    signal = png_signal(painted)
                    if signal["nonblack_pixels"] >= 100:
                        break
                    time.sleep(0.25)
                else:
                    fail("Android display remained black after wake and boot.", "android_display_not_ready")
                (folder / "ready.png").write_bytes(painted)
                state["display_evidence"] = {**signal, "sha256": hashlib.sha256(painted).hexdigest()}
                state["guest"] = self.identity(state)
                state["guest_ready"] = True
                self.store.save(state)
                return self.status()
            except BaseException:
                state["status"] = "failed"
                self.store.save(state)
                self.stop()
                raise

    def identity(self, state):
        keys = ["ro.build.version.release", "ro.build.version.sdk", "ro.product.cpu.abi", "ro.build.fingerprint"]
        return {key: self.shell(state, ["getprop", key]).stdout.decode().strip() for key in keys}

    def status(self):
        state = self.store.load(required=False)
        if not state:
            return {"status": "stopped", "registered": False, "profile": "android", "guest_ready": False}
        alive = bool(state["processes"]) and state["registered"]
        for pin in state["processes"]:
            with owned_process(pin) as process:
                alive = alive and process.alive()
        result = {k: state.get(k) for k in ("uuid", "session", "backend", "profile", "memory_mib", "network", "persistent", "run_dir", "guest")}
        ready = False
        if alive:
            try:
                ready = self.shell(state, ["getprop", "sys.boot_completed"], timeout=5, check=False).stdout.strip() == b"1"
            except AgenticVMError:
                pass
        return {**result, "status": "running" if alive else "stopped", "registered": alive, "guest_ready": ready,
                "desktop_ready": ready, "cpus": state.get("cpus", 1), "persistent_workspace": state["persistent"], "display_width": 720, "display_height": 1280}

    def stop(self):
        with self.store.lock():
            state = self.store.load(required=False)
            if not state:
                return {"status": "stopped", "registered": False}
            if state.get("launcher"):
                # Include a child that appeared between a failed launch probe
                # and cleanup. A partial inventory must never count as stopped.
                query = "$p=Get-CimInstance Win32_Process; @($p | Where-Object { $_.Name -like 'qemu-system-x86_64*' -and $_.CommandLine -like '*" + state["avd_name"] + "*' } | Select-Object ProcessId,ParentProcessId) | ConvertTo-Json -Compress"
                rows = json.loads(run(["powershell.exe", "-NoProfile", "-Command", query], timeout=15).stdout or b"[]")
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    pin = process_pin(row["ProcessId"])
                    if row["ParentProcessId"] != state["launcher"]["pid"] or not 0 <= int(pin["created"]) - int(state["launcher"]["created"]) <= 30 * 10**7:
                        fail("Android child lineage changed during cleanup.", "ownership_mismatch")
                    if pin not in state["processes"]:
                        state["processes"].append(pin)
                self.store.save(state)  # Validation rejects every foreign binary.
            errors = []
            clean_shutdown = bool(state.get("last_stop_clean")) if not state["registered"] else False
            if state["registered"] and state["status"] == "running":
                try:
                    self.shell(state, ["sync"], timeout=10, check=False)
                    # Request a real guest power-off so the emulator closes its
                    # writable disk overlays. A forced process exit is cleanup,
                    # not evidence of durable app data.
                    self.shell(state, ["reboot", "-p"], timeout=10, check=False)
                except AgenticVMError:
                    pass  # Disconnect can be the result of a successful power-off.
                try:
                    qemu_stopped = []
                    for pin in reversed(state["processes"]):
                        if Path(pin["executable"]).name in {"qemu-system-x86_64.exe", "qemu-system-x86_64-headless.exe"}:
                            with owned_process(pin) as process:
                                qemu_stopped.append(process.wait(30))
                    clean_shutdown = bool(qemu_stopped) and all(qemu_stopped)
                except AgenticVMError:
                    pass  # Fall back only to the exact recorded process handles.
            # Only terminate processes proved by creation time AND executable.
            # QEMU first, then the dedicated ADB server; unrelated servers survive.
            pins = list(reversed(state["processes"]))
            if state.get("launcher"):
                pins.append(state["launcher"])
            for pin in pins:
                try:
                    with owned_process(pin, terminate=True) as process:
                        if process.alive():
                            process.terminate()
                            if not process.wait(15):
                                fail("Owned Android process did not stop.", "android_cleanup")
                except AgenticVMError as error:
                    errors.append(str(error))
            if errors:
                fail("; ".join(errors), "android_cleanup")
            state.update(status="stopped", registered=False, guest_ready=False, last_stop_clean=clean_shutdown)
            self.store.save(state)
            return {"status": "stopped", "registered": False, "uuid": state["uuid"], "persistent_workspace": state["persistent"],
                    "data_preserved": True, "owned_processes_stopped": True, "clean_shutdown": clean_shutdown,
                    "disk_durability": "clean_poweroff" if clean_shutdown else "not_proven_after_forced_cleanup"}

    def screenshot_bytes(self):
        state = self.store.load()
        data = self.adb(state, "exec-out", "screencap", "-p").stdout
        if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 4 * 1024 * 1024:
            fail("Android did not return a bounded PNG screenshot.", "invalid_screenshot")
        return data, {"width": 720, "height": 1280, "size": len(data)}


def execute_android(args):
    """Return None for Linux, or the same JSON result/exit tuple as the CLI."""
    store = AndroidStore(args.workspace, args.session)
    saved = store.load(required=False)
    selected = getattr(args, "profile", None) == "android" or args.backend == "android"
    if not selected and (not saved or saved.get("backend") != "android"):
        return None
    if args.backend not in {None, "qemu", "android"}:
        fail("The selected backend does not own Android.", "backend_mismatch")
    if saved and saved.get("backend") != "android" and args.command != "doctor":
        fail("This workspace contains a different backend; use a separate Android workspace.", "backend_mismatch")
    backend = AndroidBackend(store)
    cmd = args.command
    if cmd == "doctor":
        return backend.doctor(), 0
    if cmd in {"start", "reset"}:
        if cmd == "reset":
            if not saved:
                fail("No Android session to reset.", "no_session")
            backend.stop()
            return backend.start(memory=saved["memory_mib"], persistent=saved["persistent"], network=saved["network"] == "nat", timeout=args.ready_timeout, cpus=saved.get("cpus", 1)), 0
        if any(getattr(args, name, None) for name in ("image", "root_disk", "pair", "peer_channel", "peer_capture")):
            fail("Android uses its pinned AOSP image and does not accept Linux disks or peer options.", "invalid_profile")
        return backend.start(memory=args.memory if args.memory is not None else 2560, persistent=args.persistent, network=args.network, timeout=args.ready_timeout, cpus=args.cpus), 0
    if cmd == "status":
        return backend.status(), 0
    if cmd == "stop":
        return backend.stop(), 0
    state = store.load()
    if cmd == "screenshot":
        from .cli import _save_download
        data, info = backend.screenshot_bytes()
        destination = args.destination or Path(state["run_dir"]) / ("screen-" + str(time.time_ns()) + ".png")
        _save_download(destination, data, args.overwrite)
        return {**info, "path": str(destination.resolve())}, 0
    if cmd == "exec":
        if args.asynchronous:
            fail("Android commands are synchronous; background Linux job RPC is unavailable.", "unsupported_operation")
        if not 1 <= args.timeout_ms <= 300000 or not 1 <= args.output_limit <= 65536:
            fail("Invalid Android execution limits.", "invalid_limits")
        argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
        cwd = guest_path(args.cwd)
        if not argv or len(argv) > 64:
            fail("Supply a guest command after --.", "invalid_argv")
        result = backend.shell(state, ["timeout", "-s", "KILL", str(args.timeout_ms / 1000), "sh", "-c", "cd " + shlex.quote(cwd) + " && exec " + shlex.join(argv)], timeout=args.timeout_ms / 1000 + 5, check=False)
        out, err = result.stdout[:args.output_limit], result.stderr[:args.output_limit]
        return {"state": "exited", "exit_code": result.returncode, "stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace"),
                "stdout_b64": base64.b64encode(out).decode(), "stderr_b64": base64.b64encode(err).decode(),
                "output_truncated": len(result.stdout) > len(out) or len(result.stderr) > len(err)}, min(255, max(0, result.returncode))
    if cmd in {"put", "get"}:
        from .cli import _save_download
        path = guest_path(args.path)
        # readlink -f prevents following an in-guest link outside the workspace.
        resolved = backend.shell(state, ["readlink", "-f", path], check=False).stdout.decode().strip()
        if not resolved or guest_path(resolved) != resolved:
            fail("Android transfer path redirects outside the workspace.", "invalid_path")
        if cmd == "put":
            if args.source.stat().st_size > MAX_FILE:
                fail("Android transfer limit is 1 MiB.", "file_too_large")
            with args.source.open("rb") as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                fail("Android transfer limit is 1 MiB.", "file_too_large")
            # Push a bounded snapshot: exec-in argument joining differs from
            # adb shell and can silently execute a quoted redirection as text.
            with tempfile.TemporaryDirectory(prefix="transfer-", dir=state["run_dir"]) as temporary:
                snapshot = Path(temporary) / "payload.bin"
                snapshot.write_bytes(data)
                backend.adb(state, "push", str(snapshot), path)
        else:
            size = int(backend.shell(state, ["stat", "-c", "%s", path]).stdout)
            if size > MAX_FILE:
                fail("Android transfer limit is 1 MiB.", "file_too_large")
            # shell output on Windows may translate line endings. exec-out is
            # the raw channel also used for PNG screenshots.
            data = backend.adb(state, "exec-out", "cat", shlex.quote(path)).stdout
            if len(data) > MAX_FILE or len(data) != size:
                fail(f"Android file changed size during transfer: expected {size}, received {len(data)} bytes.", "file_too_large")
            _save_download(args.destination, data, args.overwrite)
        return {"path": args.path, "android_path": path, "size": len(data)}, 0
    if cmd == "click":
        if args.button != "left":
            fail("Android supports touch taps; choose the left button.", "unsupported_operation")
        if not 0 <= args.x < 720 or not 0 <= args.y < 1280:
            fail("Touch point is outside the Android display.", "invalid_coordinates")
        for _ in range(args.count):
            backend.shell(state, ["input", "tap", str(args.x), str(args.y)])
    elif cmd == "key":
        names = {"home": "HOME", "back": "BACK", "enter": "ENTER", "tab": "TAB", "escape": "ESCAPE", "backspace": "DEL", "delete": "FORWARD_DEL",
                 "arrowup": "DPAD_UP", "arrowdown": "DPAD_DOWN", "arrowleft": "DPAD_LEFT", "arrowright": "DPAD_RIGHT",
                 "up": "DPAD_UP", "down": "DPAD_DOWN", "left": "DPAD_LEFT", "right": "DPAD_RIGHT", "space": "SPACE", "power": "POWER", "menu": "MENU", "recent": "APP_SWITCH"}
        value = names.get(args.keys.lower(), args.keys.upper().removeprefix("KEYCODE_"))
        known = set(names.values()) | {"VOLUME_UP", "VOLUME_DOWN", "VOLUME_MUTE", "MUTE", "WAKEUP", "SLEEP", "SEARCH"}
        if value not in known and not re.fullmatch(r"[A-Z0-9]", value):
            fail("Use an Android key name; desktop chords are unavailable.", "invalid_keys")
        backend.shell(state, ["input", "keyevent", "KEYCODE_" + value])
    elif cmd == "type":
        if not isinstance(args.text, str) or "\x00" in args.text or len(args.text.encode("utf-8")) > 16384:
            fail("Android text must be valid Unicode up to 16 KiB without NUL.", "invalid_text")
        result = backend.shell(state, ["am", "broadcast", "--receiver-foreground", "-p", "org.agenticvm.control", "-a", "org.agenticvm.control.INPUT", "--es", "text", args.text])
        if b'result=0, data="committed"' not in result.stdout:
            fail("Click an editable Android text field before typing.", "android_input_unfocused")
    elif cmd == "swipe":
        if any(not 0 <= v < bound for v, bound in zip([args.x1, args.y1, args.x2, args.y2], [720, 1280, 720, 1280])) or not 1 <= args.duration_ms <= 10000:
            fail("Invalid Android swipe coordinates/duration.", "invalid_coordinates")
        backend.shell(state, ["input", "swipe", *map(str, [args.x1, args.y1, args.x2, args.y2, args.duration_ms])])
    elif cmd == "scroll":
        if not -20 <= args.steps <= 20 or not args.steps:
            fail("Scroll must be -20 to 20, excluding zero.", "invalid_limits")
        for _ in range(abs(args.steps)):
            backend.shell(state, ["input", "swipe", "360", "1000" if args.steps > 0 else "400", "360", "400" if args.steps > 0 else "1000", "300"])
    elif cmd == "open-url":
        from .input_validation import validate_http_url
        validate_http_url(args.url)
        result = backend.shell(state, ["am", "start", "-W", "-n", "org.agenticvm.control/.BrowserActivity", "-a", "android.intent.action.VIEW", "-d", args.url])
        if b"Status: ok" not in result.stdout:
            fail("Android browser launch was not confirmed.", "android_browser_failed")
    elif cmd == "desktop-ready":
        return backend.status(), 0
    elif cmd == "install-apk":
        if not args.apk.is_file() or args.apk.suffix.lower() != ".apk" or args.apk.stat().st_size > 512 * 1024 * 1024:
            fail("Supply an APK no larger than 512 MiB.", "invalid_apk")
        result = backend.adb(state, "install", "-r", "--no-streaming", str(args.apk.resolve()), timeout=180)
        if b"Success" not in result.stdout:
            fail("Package manager did not confirm APK installation.", "apk_install_failed")
        return {"installed": True, "apk": str(args.apk.resolve()), "sha256": sha256(args.apk), "output": result.stdout.decode()}, 0
    elif cmd == "launch-app":
        if not re.fullmatch(r"[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+", args.component):
            fail("Supply package/activity as an Android component.", "invalid_component")
        result = backend.shell(state, ["am", "start", "-W", "-n", args.component])
        if b"Error:" in result.stdout or b"Error type" in result.stdout:
            fail(result.stdout.decode(), "app_launch_failed")
        return {"component": args.component, "output": result.stdout.decode()}, 0
    else:
        fail("This Linux-only operation is not supported by the Android profile.", "unsupported_operation")
    return {"action": cmd, "completed": True}, 0
