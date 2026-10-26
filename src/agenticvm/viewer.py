"""Token-protected loopback desktop viewer. No host shell or third-party server."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit
import webbrowser

from .errors import AgenticVMError
from .input_validation import validate_http_url
from .state import StateStore

MAX_FILE = 1024 * 1024
MAX_BODY = 2 * MAX_FILE
ASSETS = Path(__file__).with_name("web")


class ViewerError(Exception):
    def __init__(self, message: str, code: str = "invalid_request", status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def text(value, field: str, maximum: int, *, empty: bool = False) -> str:
    try:
        valid = isinstance(value, str) and "\x00" not in value and (value or empty) and len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    if not valid:
        raise ViewerError(f"{field} must be text of at most {maximum} bytes.")
    return value


def number(value, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ViewerError(f"{field} must be {minimum}–{maximum}.")
    return value


class ViewerController:
    def __init__(self, workspace: Path, session: str = "default", *, application_root: Path | None = None):
        self.store = StateStore(workspace, session)
        self.workspace, self.session = self.store.root, self.store.session
        self.root = application_root or Path(__file__).resolve().parents[2]
        self.lock = threading.Lock()
        self.start_error: dict | None = None
        self.base_session = session
        self.profile = "desktop"
        self.os_id = None
        from .configuration import Configuration
        self.configuration = Configuration(self.workspace, self.root)
        self.preference_file = self.workspace / ("viewer-profile-" + session + ".json")
        if self.preference_file.is_file() and self.preference_file.stat().st_size < 1024:
            try:
                choice = json.loads(self.preference_file.read_text(encoding="utf-8"))
                self.select_profile(choice.get("profile", "desktop"), choice.get('os_id'))
            except (ValueError, AgenticVMError, ViewerError):
                pass

    def select_profile(self, profile, os_id=None):
        if profile not in {"desktop", "android", "windows", "custom"}:
            raise ViewerError("Choose Linux, Android or Windows.")
        if profile == 'custom':
            self.configuration.key(profile, os_id)
            from .custom_os import CustomStore
            self.profile, self.os_id = profile, os_id
            self.session = self.base_session[:40] + '-custom-' + os_id
            self.store = CustomStore(self.workspace, self.session)
            return
        from .android import AndroidStore
        self.profile = profile
        self.os_id = None
        self.session = self.base_session if profile == "desktop" else self.base_session[:48] + "-" + profile
        if profile == "windows":
            from .windows_desktop import WindowsDesktopStore
            self.store = WindowsDesktopStore(self.workspace, self.session)
        else:
            self.store = AndroidStore(self.workspace, self.session)

    def windows(self):
        from .windows_desktop import WindowsDesktopBackend
        return WindowsDesktopBackend(self.store)

    def custom(self):
        from .custom_os import CustomBackend
        return CustomBackend(self.store, self.root, self.os_id)

    def config_request(self, request=None):
        if request is None:
            return self.configuration.snapshot()
        # Keep the stopped check and save under the native lifecycle lock.
        with self.configuration.guard.lock():
            return self._config_mutation(request)

    def _config_mutation(self, request):
        if not isinstance(request, dict):
            raise ViewerError('Supply a configuration request.')
        saved = self.store.load(required=False)
        if saved and saved.get('registered'):
            raise ViewerError('Stop the current machine before saving settings or adding an OS.', 'session_exists', 409)
        from .control_sessions import Lease
        from .control_store import load_json
        import time
        lease = load_json(Lease(self).meta.path('lease.json'), default={})
        if lease.get('expires_at', 0) > time.time():
            raise ViewerError('Release the active agent lease before changing settings.', 'lease_conflict', 409)
        operation = request.get('operation')
        if operation == 'save' and set(request) == {'operation', 'profile', 'os_id', 'settings', 'revision'}:
            return self.configuration.save(request['profile'], request['os_id'], request['settings'], request['revision'])
        if operation == 'add_os' and set(request) == {'operation', 'name', 'filename', 'revision'}:
            return self.configuration.add_os(request['name'], request['filename'], request['revision'])
        raise ViewerError('Unknown configuration operation or field.')

    def cli(self, arguments: list[str], *, timeout: int = 180) -> dict:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(self.root / "src") + os.pathsep + environment.get("PYTHONPATH", "")
        command = [sys.executable, "-m", "agenticvm", "--workspace", str(self.workspace), "--session", self.session,
                   "--backend", "android" if self.profile == "android" else "qemu", *arguments]
        try:
            result = subprocess.run(command, cwd=self.root, env=environment, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=timeout, shell=False,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as error:
            raise ViewerError("The desktop did not respond in time. Check its status before retrying.", "controller_timeout", 504) from error
        try:
            if len(result.stdout) > MAX_BODY:
                raise ValueError("response too large")
            response = json.loads(result.stdout)
            if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                raise ValueError("invalid envelope")
        except (ValueError, UnicodeError) as error:
            raise ViewerError("The desktop controller returned an invalid response.", "controller_error", 502) from error
        return response

    def info(self) -> dict:
        labels = {'desktop':('Debian 13 · Xfce','Firefox ESR'),
            'android':('Android 15 · AOSP x86-64','AgenticVM WebView'),
            'windows':('Windows Server 2025 Evaluation','Microsoft Edge')}
        label = labels.get(self.profile, (self.configuration.load()['oses'].get(self.os_id, {}).get('name', 'Custom OS'), 'Guest browser'))
        return {"name": "AgenticVM", "workspace": str(self.workspace), "session": self.session,
                "os": label[0],"browser":label[1],
                "profile": self.profile, "max_file_bytes": MAX_FILE,"control_api":2,'version':'0.4.0-beta.1'}

    def _start_settings(self) -> dict:
        key = self.configuration.key(self.profile, self.os_id)
        if key in self.configuration.load()['machines'] or self.profile == 'custom':
            return self.configuration.settings(self.profile, self.os_id)
        saved = self.store.load(required=False)
        if self.profile == "windows":
            return {"memory": saved["memory_mib"] if saved else 2048,
                    "network": saved.get("network") == "nat" if saved else False, "persistent": True}
        if self.profile == "android":
            return {"memory": saved["memory_mib"] if saved else 2560, "network": saved.get("network") == "nat" if saved else False,
                    "persistent": saved["persistent"] if saved else True}
        if saved and saved.get("backend") == "qemu" and saved.get("profile") == "desktop":
            # The viewer offers the validated desktop sizes. CLI experiments
            # with smaller/intermediate allocations resume at the next size.
            memory = 768 if saved["memory_mib"] <= 768 else 1024
            return {"memory": memory, "network": saved.get("network") == "nat",
                    "persistent": bool(saved.get("workspace_disk"))}
        return {"memory": 768, "network": True, "persistent": True}

    def status(self) -> dict:
        response = {"ok": True, "result": self.custom().status()} if self.profile == 'custom' else {"ok": True, "result": self.windows().status()} if self.profile == "windows" else self.cli(["status"])
        if not response.get("ok") and response.get("error", {}).get("code") == "no_session":
            response = {"ok": True, "result": {"status": "stopped", "registered": False}}
        if response.get("ok"):
            response["result"]["settings"] = self._start_settings()
            from .configuration import defaults
            response['result']['settings'] = {**defaults(self.profile), **response['result']['settings']}
            response['result']['os_id'] = self.os_id
            response["result"].setdefault("profile", self.profile)
        if self.start_error:
            if response.get("ok"):
                response["result"]["startup_error"] = self.start_error
            else:
                response["error"] = self.start_error
        return response

    def check_target(self, profile=None, identifier=None):
        """Bind agent actions to the selected guest under the controller lock."""
        if profile is not None and (profile not in {'desktop', 'android', 'windows', 'custom'} or profile != self.profile):
            raise ViewerError('The selected VM changed. Check status first.', 'target_changed', 409)
        if identifier is not None:
            saved = self.store.load(required=False)
            if not saved or identifier != saved.get('uuid'):
                raise ViewerError('The VM session changed. Check status first.', 'target_changed', 409)

    def start_if_needed(self):
        try:
            with self.lock:
                response = self.cli(["status"])
                state = response.get("result", {})
                if not response.get("ok") or state.get("status") not in {"running", "paused"}:
                    self.action({"action": "start"})
        except (ViewerError, AgenticVMError, OSError) as error:
            self.start_error = {"code": getattr(error, "code", "startup_error"), "message": str(error)}

    def screen(self) -> bytes:
        if self.profile == 'custom':
            from .desktop import DesktopController
            return DesktopController(self.custom()).screenshot_bytes()[0]
        if self.profile == "windows":
            from .desktop import DesktopController
            return DesktopController(self.windows()).screenshot_bytes()[0]
        if self.profile == "android":
            from .android import AndroidBackend
            return AndroidBackend(self.store).screenshot_bytes()[0]
        from .desktop import DesktopController
        from .qemu import QemuBackend, find_qemu
        data, _ = DesktopController(QemuBackend(self.store, find_qemu(None))).screenshot_bytes()
        return data

    def action(self, request: dict) -> dict:
        action = text(request.get("action"), "action", 32)
        if self.profile == 'custom' and action not in {'start', 'reset', 'stop', 'click', 'move', 'key', 'type', 'scroll'}:
            raise ViewerError('This OS supports screen and keyboard control. Guest command/file tools are unavailable.', 'capability_unavailable')
        if action == 'reset':
            from .control_checkpoints import pending
            if pending(self):
                raise ViewerError('Recover the pending disk restore before starting this guest.','recovery_required',409)
        if action == "start":
            self.start_error = None
            profile = request.get("profile", self.profile)
            os_id = request.get('os_id', self.os_id if profile == self.profile else None)
            if profile != self.profile or os_id != self.os_id:
                current = self.store.load(required=False)
                if current and current.get("registered"):
                    observed = self.status()
                    state = observed.get('result', {})
                    if not observed.get('ok') or state.get('status') not in {'exited', 'stopped', 'failed'}:
                        raise ViewerError("Stop the current guest before changing operating systems.")
                    # Clean only the proven exited session before switching.
                    if self.profile == 'custom':
                        self.custom().stop()
                    elif self.profile == 'windows':
                        self.windows().stop()
                    else:
                        cleaned = self.cli(['stop'])
                        if not cleaned.get('ok'):
                            raise ViewerError('The previous VM could not be released.')
                self.select_profile(profile, os_id)
            from .control_checkpoints import pending
            if pending(self):
                raise ViewerError('Recover the pending disk restore before starting this guest.','recovery_required',409)
            defaults = self._start_settings()
            from .configuration import defaults as profile_defaults, validate_settings
            values = {**profile_defaults(self.profile), **defaults}
            values.update({key: request[key] for key in values if key in request})
            try:
                values = validate_settings(self.profile, values)
                if values['cpus'] > min(8, os.cpu_count() or 1):
                    raise AgenticVMError('CPU count exceeds the available host CPUs.', 'invalid_cpu')
            except AgenticVMError as error:
                raise ViewerError(str(error), error.code) from error
            memory = values['memory']
            network, persistent = request.get("network", defaults["network"]), request.get("persistent", defaults["persistent"])
            if type(network) is not bool or type(persistent) is not bool:
                raise ViewerError("Network and saved workspace must be boolean values.")
            args = ["start", "--profile", self.profile, "--memory", str(memory)]
            if values['cpus'] != 1:
                args.extend(['--cpus', str(values['cpus'])])
            if self.profile != 'android' and (values['width'], values['height']) != (1024, 768):
                args.extend(['--width', str(values['width']), '--height', str(values['height'])])
            if self.profile == "android":
                args.extend(["--ready-timeout", "240"])
            if network:
                args.append("--network")
            if persistent:
                args.append("--persistent")
        elif action in {"stop", "reset", "status"}:
            args = [action]
        elif action in {"click", "move"}:
            args = [action, str(number(request.get("x"), "X", 0, 4095)), str(number(request.get("y"), "Y", 0, 4095))]
            if action == "click":
                button = request.get("button", "left")
                if button not in {"left", "right", "middle"}:
                    raise ViewerError("Choose left, middle or right mouse button.")
                args.extend(["--button", button])
        elif action == "key":
            args = ["key", text(request.get("keys"), "Keys", 128)]
        elif action == "type":
            args = ["type", "--", text(request.get("text"), "Text", 4096)]
        elif action == "scroll":
            steps = number(request.get("steps"), "Scroll steps", -20, 20)
            if not steps:
                raise ViewerError("Scroll steps cannot be zero.")
            args = ["scroll", str(steps)]
        elif action == "open-url":
            url = text(request.get("url"), "URL", 4096)
            try:
                validate_http_url(url)
            except ValueError as error:
                raise ViewerError(str(error)) from error
            args = ["open-url", url]
        elif action == "exec":
            command = text(request.get("command"), "Linux command", 16384)
            args = ["exec", "--timeout-ms", "30000", "--", "sh" if self.profile == "android" else "/bin/sh", "-c", command]
        elif action == "swipe":
            if self.profile != "android":
                raise ViewerError("Swipes require Android.")
            args = ["swipe", str(number(request.get("x1"), "X1", 0, 719)), str(number(request.get("y1"), "Y1", 0, 1279)),
                    str(number(request.get("x2"), "X2", 0, 719)), str(number(request.get("y2"), "Y2", 0, 1279))]
        elif action == "upload":
            path = text(request.get("path"), "Workspace path", 4096)
            encoded = text(request.get("data_b64"), "File", ((MAX_FILE + 2) // 3) * 4, empty=True)
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ViewerError("The file is not valid base64.") from error
            if len(payload) > MAX_FILE:
                raise ViewerError("Choose a file no larger than 1 MiB.", "file_too_large", 413)
            if self.profile == "windows":
                return {"ok": True, "result": self.windows().action(request)}
            with tempfile.TemporaryDirectory(prefix="agenticvm-upload-") as folder:
                source = Path(folder) / "upload.bin"
                source.write_bytes(payload)
                return self.cli(["put", "--", str(source), path])
        else:
            raise ViewerError("Unknown desktop action.")
        if self.profile == 'custom':
            backend = self.custom()
            if action in {'start', 'reset'}:
                if action == 'reset':
                    prior = self.store.load()
                    values = prior['settings']
                    backend.stop()
                media, entry = self.configuration.media_file(self.os_id)
                response = {'ok': True, 'result': backend.start(values, media, entry)}
            else:
                response = {'ok': True, 'result': backend.action(request)}
        elif self.profile == "windows":
            response = {"ok": True, "result": self.windows().action({**request, **({'memory':memory, **values} if action == 'start' else {})})}
        else:
            response = self.cli(args, timeout=330) if self.profile == "android" and action in {"start", "reset"} else self.cli(args)
        if action in {"start", "reset"}:
            self.start_error = None if response.get("ok") else response.get("error")
            if response.get("ok"):
                self.workspace.mkdir(parents=True, exist_ok=True)
                temporary = self.preference_file.with_suffix(".tmp")
                temporary.write_text(json.dumps({"profile": self.profile, 'os_id': self.os_id}), encoding="utf-8")
                os.replace(temporary, self.preference_file)
        return response

    def install_apk(self, path):
        if self.profile != "android":
            raise ViewerError("Start Android before installing an APK.")
        return self.cli(["install-apk", "--", str(path)], timeout=200)

    def download(self, path: str) -> tuple[bytes, str]:
        if self.profile == 'custom':
            raise ViewerError('Guest file tools are unavailable for this imported OS.', 'capability_unavailable')
        path = text(path, "Workspace path", 4096)
        if self.profile == "windows":
            return self.windows().download(path)
        with tempfile.TemporaryDirectory(prefix="agenticvm-download-") as folder:
            destination = Path(folder) / "download.bin"
            response = self.cli(["get", "--", path, str(destination)])
            if not response["ok"]:
                error = response.get("error", {})
                raise ViewerError(error.get("message", "Cannot download this file."), error.get("code", "download_failed"), 400)
            if not destination.is_file() or destination.stat().st_size > MAX_FILE:
                raise ViewerError("The file exceeds the 1 MiB transfer limit.", "file_too_large", 413)
            name = path.replace("\\", "/").rsplit("/", 1)[-1] or "download.bin"
            return destination.read_bytes(), name


class ViewerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, controller: ViewerController, port: int = 8765):
        from .control_plane import ControlPlane
        self.controller, self.token = controller, secrets.token_urlsafe(32)
        self.control=ControlPlane(controller)
        super().__init__(("127.0.0.1", port), ViewerHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.url = self.origin + "/#token=" + self.token


class ViewerHandler(BaseHTTPRequestHandler):
    server: ViewerServer
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass  # No token, request body, guest output, or command history in logs.

    def send_body(self, status: int, body: bytes, content_type: str, *, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, data: dict):
        self.send_body(status, json.dumps(data, ensure_ascii=True).encode(), "application/json; charset=utf-8")

    def check_host(self):
        if self.headers.get("Host") != urlsplit(self.server.origin).netloc:
            raise ViewerError("This viewer only accepts its local address.", "invalid_host", 403)

    def authorize(self, *, mutation: bool = False):
        self.check_host()
        token = self.headers.get("X-AgenticVM-Token", "")
        if not token.isascii() or not secrets.compare_digest(token, self.server.token):
            raise ViewerError("Open the viewer using its launch link.", "unauthorized", 401)
        origin = self.headers.get("Origin")
        if (mutation and origin != self.server.origin) or (origin is not None and origin != self.server.origin):
            raise ViewerError("This request did not come from the local viewer.", "invalid_origin", 403)

    def guarded(self, operation):
        if not self.server.controller.lock.acquire(blocking=False):
            raise ViewerError("A desktop action is still running.", "busy", 409)
        try:
            self.server.controller.check_target(self.headers.get('X-AgenticVM-Profile'), self.headers.get('X-AgenticVM-Guest'))
            return operation()
        finally:
            self.server.controller.lock.release()

    def failure(self, error):
        self.close_connection = True
        if isinstance(error, ViewerError):
            self.send_json(error.status, {"ok": False, "error": {"code": error.code, "message": str(error)}})
        elif isinstance(error, AgenticVMError):
            self.send_json(409 if error.code in {'session_busy','target_changed','generation_changed','lease_required','lease_conflict','sync_conflict'} else 400,
                {"ok": False, "error": {"code": error.code, "message": str(error)}})
        else:
            self.send_json(500, {"ok": False, "error": {"code": "viewer_error", "message": "The desktop action could not complete."}})

    def do_GET(self):
        try:
            self.check_host()
            request = urlsplit(self.path)
            if request.path.startswith("/api/"):
                self.authorize()
                if request.path == "/api/info":
                    self.send_json(200, {"ok": True, "result": self.server.controller.info()})
                elif request.path == "/api/status":
                    self.send_json(200, self.guarded(self.server.controller.status))
                elif request.path == '/api/config':
                    self.send_json(200, {'ok':True, 'result':self.guarded(self.server.controller.config_request)})
                elif request.path == "/api/screen":
                    self.send_body(200, self.guarded(self.server.controller.screen), "image/png")
                elif request.path == "/api/download":
                    query = parse_qs(request.query, keep_blank_values=True)
                    if set(query) != {"path"} or len(query["path"]) != 1:
                        raise ViewerError("Choose one workspace path to download.")
                    data, filename = self.guarded(lambda: self.server.controller.download(query["path"][0]))
                    self.send_body(200, data, "application/octet-stream", extra={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(filename, safe="")})
                else:
                    raise ViewerError("Unknown viewer endpoint.", "not_found", 404)
                return
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8"),
                      "/glass-ui.js": ("glass-ui.js", "text/javascript; charset=utf-8"),
                      '/settings.js': ('settings.js', 'text/javascript; charset=utf-8'),
                      "/brand.png": ("brand.png", "image/png")}
            assets.update({"/icons/" + icon.name: ("icons/" + icon.name, "image/svg+xml")
                           for icon in (ASSETS / "icons").glob("*.svg")})
            if request.path not in assets:
                raise ViewerError("This page does not exist.", "not_found", 404)
            name, content_type = assets[request.path]
            self.send_body(200, (ASSETS / name).read_bytes(), content_type)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as error:
            self.failure(error)

    def do_POST(self):
        try:
            self.authorize(mutation=True)
            if self.path == "/api/apk":
                if len(self.headers.get_all("Content-Length", [])) != 1 or self.headers.get("Transfer-Encoding"):
                    raise ViewerError("Supply one bounded APK Content-Length.", "invalid_length", 411)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    raise ViewerError("Invalid APK length.") from None
                if not 1 <= length <= 512 * 1024 * 1024:
                    raise ViewerError("Choose an APK no larger than 512 MiB.", "file_too_large", 413)
                if self.headers.get("Content-Type") != "application/vnd.android.package-archive":
                    raise ViewerError("Upload an Android APK.", "invalid_content_type", 415)
                def install():
                    with tempfile.TemporaryDirectory(prefix="agenticvm-apk-") as folder:
                        path = Path(folder) / "upload.apk"
                        remaining = length
                        with path.open("xb") as stream:
                            while remaining:
                                block = self.rfile.read(min(65536, remaining))
                                if not block:
                                    raise ViewerError("APK upload ended early.")
                                stream.write(block)
                                remaining -= len(block)
                        return self.server.controller.install_apk(path)
                self.send_json(200, self.guarded(install))
                return
            if self.path not in {"/api/action","/api/control",'/api/config'}:
                raise ViewerError("Unknown viewer endpoint.", "not_found", 404)
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json" or self.headers.get("Transfer-Encoding"):
                raise ViewerError("Use a JSON request with a bounded Content-Length.", "invalid_content_type", 415)
            if len(self.headers.get_all("Content-Length", [])) != 1:
                raise ViewerError("Supply exactly one Content-Length.", "invalid_length", 411)
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError as error:
                raise ViewerError("Content-Length is required.", "invalid_length", 411) from error
            if not 1 <= length <= MAX_BODY:
                raise ViewerError("The request exceeds the 2 MiB envelope limit.", "request_too_large", 413)
            body = self.rfile.read(length)
            if len(body) != length:
                raise ViewerError("The request body is incomplete.")
            try:
                request = json.loads(body)
            except (ValueError, UnicodeError) as error:
                raise ViewerError("The request must contain valid JSON.") from error
            if not isinstance(request, dict):
                raise ViewerError("The request must be a JSON object.")
            response = ({'ok':True,'result':self.guarded(lambda:self.server.controller.config_request(request))} if self.path == '/api/config'
                else self.server.control.dispatch(request) if self.path=='/api/control' else self.guarded(lambda: self.server.controller.action(request)))
            self.send_json(200, response)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as error:
            self.failure(error)

    def do_OPTIONS(self):
        self.send_json(405, {"ok": False, "error": {"code": "method_not_allowed", "message": "Cross-origin access is disabled."}})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Open the local AgenticVM desktop workspace.")
    parser.add_argument("--workspace", type=Path, default=Path.cwd() / "runtime" / "desktop")
    parser.add_argument("--session", default="default")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", dest="open_browser")
    parser.add_argument("--auto-start", action="store_true")
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--quiet-launch", action="store_true", help="Keep the private launch token out of stdout")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("Port must be 0–65535.")
    controller = ViewerController(args.workspace, args.session)
    try:
        server = ViewerServer(controller, args.port)
    except OSError:
        # A second independent workspace can select a free loopback port.
        if not args.port:
            raise
        server = ViewerServer(controller, 0)
    if args.ready_file:
        args.ready_file.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.ready_file.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump({"pid": os.getpid(), "url": server.url, "workspace": str(controller.workspace), "session": controller.session}, stream)
        os.replace(temporary, args.ready_file)
    if args.quiet_launch:
        print(json.dumps({'ok': True, 'result': {'status': 'listening', 'pid': os.getpid(), 'port': server.server_port}}), flush=True)
    else:
        print(server.url, flush=True)
    if args.auto_start:
        threading.Thread(target=controller.start_if_needed, daemon=True).start()
    if args.open_browser:
        threading.Thread(target=lambda: webbrowser.open(server.url), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
