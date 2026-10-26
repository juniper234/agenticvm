"""Local stdio MCP bridge. It exposes guest operations, never a host shell."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from .input_validation import validate_http_url
import subprocess
import sys
import tempfile

MAX_LINE = 2 * 1024 * 1024
VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}


def schema(properties=None, required=()):
    return {"type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False}


STRING = {"type": "string"}
TOOLS = [
    {"name": "vm_start", "description": "Boot Linux or Android 15. Android supports screenshots, touch, Unicode input, shell, APKs and optional persistent app data; minimum 2560 MiB.",
     "inputSchema": schema({"memory_mib": {"type": "integer", "enum": [256, 512, 768, 1024, 2560, 3072, 4096]},
                            "profile": {"type": "string", "enum": ["command", "desktop", "agent", "android"]},
                            "network": {"type": "boolean"}, "persistent": {"type": "boolean"}})},
    {"name": "vm_status", "description": "Observe this VM's lifecycle and guest readiness.", "inputSchema": schema()},
    {"name": "vm_exec", "description": "Run a literal guest argv array (Linux UID 1000; Android shell UID 2000). Background jobs and poll/cancel are Linux-only.",
     "inputSchema": schema({"argv": {"type": "array", "items": STRING, "minItems": 1, "maxItems": 64},
                            "cwd": STRING, "timeout_ms": {"type": "integer", "minimum": 0, "maximum": 300000},
                            "background": {"type": "boolean"}}, ["argv"])},
    {"name": "vm_poll", "description": "Get bounded cumulative output and status for a background guest job.",
     "inputSchema": schema({"job_id": STRING, "wait_ms": {"type": "integer", "minimum": 0, "maximum": 1000}}, ["job_id"])},
    {"name": "vm_cancel", "description": "Kill this guest job's process group.", "inputSchema": schema({"job_id": STRING}, ["job_id"])},
    {"name": "vm_forget", "description": "Release the retained result of a completed guest job.", "inputSchema": schema({"job_id": STRING}, ["job_id"])},
    {"name": "vm_write_file", "description": "Write UTF-8 text into the guest workspace (at most 64 KiB).",
     "inputSchema": schema({"path": STRING, "text": STRING}, ["path", "text"])},
    {"name": "vm_read_file", "description": "Read a workspace file as base64 and optional UTF-8 text (at most 64 KiB).",
     "inputSchema": schema({"path": STRING}, ["path"])},
    {"name": "vm_reset", "description": "Restart the guest. Persistent Android apps/data and saved Linux workspace survive; temporary sessions start fresh.", "inputSchema": schema()},
    {"name": "vm_stop", "description": "Stop only this VM. Saved desktop workspace is preserved; temporary workspace is lost.", "inputSchema": schema()},
    {"name": "vm_screenshot", "description": "See the actual Linux or Android display as a PNG image.", "inputSchema": schema()},
    {"name": "vm_click", "description": "Click the guest desktop at pixel coordinates from a screenshot.",
     "inputSchema": schema({"x": {"type": "integer", "minimum": 0, "maximum": 1919},
                            "y": {"type": "integer", "minimum": 0, "maximum": 1279},
                            "button": {"type": "string", "enum": ["left", "right", "middle"]},
                            "count": {"type": "integer", "minimum": 1, "maximum": 2}}, ["x", "y"])},
    {"name": "vm_move", "description": "Move the guest pointer to screenshot pixel coordinates.",
     "inputSchema": schema({"x": {"type": "integer", "minimum": 0, "maximum": 1919},
                            "y": {"type": "integer", "minimum": 0, "maximum": 1079}}, ["x", "y"])},
    {"name": "vm_key", "description": "Press a guest key/chord such as ctrl+l, enter, alt+tab or ctrl+shift+t.",
     "inputSchema": schema({"keys": STRING}, ["keys"])},
    {"name": "vm_type", "description": "Type literal UTF-8 text into the focused guest window, at most 16 KiB.",
     "inputSchema": schema({"text": STRING}, ["text"])},
    {"name": "vm_scroll", "description": "Scroll the guest desktop by wheel steps; positive scrolls down.",
     "inputSchema": schema({"steps": {"type": "integer", "minimum": -32, "maximum": 32}}, ["steps"])},
    {"name": "vm_open_url", "description": "Open or focus the guest browser and navigate to an HTTP(S) URL.",
     "inputSchema": schema({"url": STRING}, ["url"])},
    {"name": "vm_desktop_ready", "description": "Check desktop readiness (Android: OS boot completed).", "inputSchema": schema()},
    {"name": "vm_install_apk", "description": "Install a local host APK (up to 512 MiB) in the owned Android guest.", "inputSchema": schema({"path": STRING}, ["path"])},
    {"name": "vm_launch_app", "description": "Launch an installed Android package/activity component.", "inputSchema": schema({"component": STRING}, ["component"])},
    {"name": "vm_swipe", "description": "Swipe on the Android display using screenshot pixel coordinates.",
     "inputSchema": schema({"x1": {"type": "integer", "minimum": 0, "maximum": 719}, "y1": {"type": "integer", "minimum": 0, "maximum": 1279},
                            "x2": {"type": "integer", "minimum": 0, "maximum": 719}, "y2": {"type": "integer", "minimum": 0, "maximum": 1279},
                            "duration_ms": {"type": "integer", "minimum": 1, "maximum": 10000}}, ["x1", "y1", "x2", "y2"])},
]


class Bridge:
    def __init__(self, args):
        self.args = args

    def cli(self, *arguments):
        command = [sys.executable, "-m", "agenticvm", "--workspace", str(self.args.workspace),
                   "--session", self.args.session, "--backend", self.args.backend, *map(str, arguments)]
        environment = os.environ.copy()
        # Keep checkout usage working without a global Python installation step.
        source = str(Path(__file__).resolve().parent.parent)
        environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=360, env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            data = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise ValueError("Controller returned an invalid response: " + result.stderr[-2048:])
        return data, result.returncode

    def call(self, name, values):
        tool = next((tool for tool in TOOLS if tool["name"] == name), None)
        if tool is None or not isinstance(values, dict):
            raise ValueError("Unknown tool or invalid arguments")
        allowed = tool["inputSchema"]["properties"]
        if set(values) - set(allowed) or any(key not in values for key in tool["inputSchema"]["required"]):
            raise ValueError("Unexpected or missing tool argument")
        for key, value in values.items():
            field = allowed[key]
            kind = field["type"]
            if ((kind == "string" and not isinstance(value, str)) or
                (kind == "integer" and (type(value) is not int or value < field.get("minimum", value) or value > field.get("maximum", value))) or
                (kind == "boolean" and type(value) is not bool) or
                (kind == "array" and (not isinstance(value, list) or not 1 <= len(value) <= 64 or not all(isinstance(x, str) for x in value)))):
                raise ValueError("Invalid argument type or range: " + key)
            if "enum" in field and value not in field["enum"]:
                raise ValueError("Unsupported value: " + key)
            if kind in {"string", "array"}:
                try:
                    for item in ([value] if kind == "string" else value):
                        item.encode("utf-8")
                except UnicodeError:
                    raise ValueError("Argument must contain valid UTF-8 text: " + key) from None
        if name == "vm_start":
            profile = values.get("profile", getattr(self.args, "profile", "command"))
            command = ["start", "--profile", profile, "--memory", values.get("memory_mib", 2560 if profile == "android" else 768 if profile == "desktop" else 256 if profile == "agent" else 512)]
            if profile == "android":
                command.extend(["--ready-timeout", 240])
            if self.args.image:
                command.extend(["--image", self.args.image])
            if profile in {"desktop", "android"}:
                if profile == "desktop" and getattr(self.args, "root_disk", None):
                    command.extend(["--root-disk", self.args.root_disk])
                if values.get("network", getattr(self.args, "network", False)):
                    command.append("--network")
                if values.get("persistent", getattr(self.args, "persistent", False)):
                    command.append("--persistent")
            elif values.get("network") or values.get("persistent"):
                raise ValueError("Networking and persistence require the desktop or Android profile")
            data, code = self.cli(*command)
        elif name == "vm_exec":
            command = ["exec", "--cwd", values.get("cwd", "/workspace"), "--timeout-ms", values.get("timeout_ms", 30000)]
            if values.get("background"):
                command.append("--async")
            data, code = self.cli(*command, "--", *values["argv"])
        elif name == "vm_install_apk":
            data, code = self.cli("install-apk", "--", values["path"])
        elif name == "vm_launch_app":
            data, code = self.cli("launch-app", values["component"])
        elif name == "vm_swipe":
            data, code = self.cli("swipe", values["x1"], values["y1"], values["x2"], values["y2"], "--duration-ms", values.get("duration_ms", 300))
        elif name in ("vm_poll", "vm_cancel", "vm_forget"):
            command = [name.removeprefix("vm_"), values["job_id"]]
            if name == "vm_poll":
                command.extend(["--wait-ms", values.get("wait_ms", 0)])
            data, code = self.cli(*command)
        elif name == "vm_screenshot":
            with tempfile.TemporaryDirectory(prefix="agenticvm-screen-") as temporary:
                path = Path(temporary) / "desktop.png"
                data, code = self.cli("screenshot", path)
                if code == 0:
                    image = path.read_bytes()
                    if len(image) > 4 * 1024 * 1024 or not image.startswith(b"\x89PNG\r\n\x1a\n"):
                        raise ValueError("Screenshot is not a bounded PNG image")
                    return {"content": [{"type": "image", "mimeType": "image/png", "data": base64.b64encode(image).decode("ascii")},
                                        {"type": "text", "text": json.dumps(data)}], "isError": False}
        elif name in ("vm_click", "vm_move"):
            command = [name.removeprefix("vm_"), values["x"], values["y"]]
            if name == "vm_click":
                command.extend(["--button", values.get("button", "left"), "--count", values.get("count", 1)])
            data, code = self.cli(*command)
        elif name in ("vm_key", "vm_type", "vm_scroll", "vm_open_url"):
            field = {"vm_key": "keys", "vm_type": "text", "vm_scroll": "steps", "vm_open_url": "url"}[name]
            if name == "vm_type" and len(values[field].encode("utf-8")) > 16384:
                raise ValueError("Desktop text exceeds 16 KiB")
            if name == "vm_open_url":
                validate_http_url(values[field])
            command = name.removeprefix("vm_").replace("_", "-")
            data, code = self.cli(command, "--", values[field]) if name == "vm_type" else self.cli(command, values[field])
        elif name in ("vm_write_file", "vm_read_file"):
            with tempfile.TemporaryDirectory(prefix="agenticvm-mcp-") as temporary:
                path = Path(temporary) / "transfer"
                if name == "vm_write_file":
                    content = values["text"].encode("utf-8")
                    if len(content) > 65536:
                        raise ValueError("MCP text transfer exceeds 64 KiB; use the CLI for larger files")
                    path.write_bytes(content)
                    data, code = self.cli("put", "--", path, values["path"])
                else:
                    data, code = self.cli("get", "--", values["path"], path)
                    if code == 0:
                        content = path.read_bytes()
                        if len(content) > 65536:
                            raise ValueError("MCP read exceeds 64 KiB; use the CLI for larger files")
                        data["data_b64"] = base64.b64encode(content).decode("ascii")
                        try:
                            data["text"] = content.decode("utf-8")
                        except UnicodeError:
                            pass
        else:
            data, code = self.cli(name.removeprefix("vm_").replace("_", "-"))
        return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=True)}], "isError": code != 0}

    def handle(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid JSON-RPC request"}}
        if "id" not in message:
            return None
        method, params = message["method"], message.get("params", {})
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32602, "message": "params must be an object"}}
        result = None
        if method == "initialize":
            version = params.get("protocolVersion")
            result = {"protocolVersion": version if version in VERSIONS else "2025-06-18",
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "agenticvm", "version": "0.1.0"},
                      "instructions": "Tools control one owned Linux or Android VM. Android needs at least 2560 MiB and supports touch, Unicode input, shell and APKs. Background job RPC and pointer hover are Linux-only. Saved workspace/app data survives reset/stop; temporary sessions start fresh."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                result = self.call(params.get("name"), params.get("arguments", {}))
            except Exception as error:
                result = {"content": [{"type": "text", "text": str(error)}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd() / "runtime/agenticvm")
    parser.add_argument("--session", default="default")
    parser.add_argument("--backend", choices=["qemu", "virtualbox", "android"], default="qemu")
    parser.add_argument("--image", type=Path)
    parser.add_argument("--profile", choices=["command", "desktop", "agent", "android"], default="command")
    parser.add_argument("--root-disk", type=Path)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--persistent", action="store_true")
    bridge = Bridge(parser.parse_args())
    while True:
        raw = sys.stdin.buffer.readline(MAX_LINE + 1)
        if not raw:
            break
        try:
            if len(raw) > MAX_LINE:
                while raw and not raw.endswith(b"\n"):
                    raw = sys.stdin.buffer.readline(MAX_LINE + 1)
                raise ValueError("Request exceeds 2 MiB")
            message = json.loads(raw)
            response = bridge.handle(message)
        except (ValueError, UnicodeError):
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON or oversized request"}}
        except Exception as error:
            response = {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                        "error": {"code": -32603, "message": str(error)}}
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
