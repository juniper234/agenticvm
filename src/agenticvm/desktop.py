"""Guest display and input through an owned QEMU monitor, never host UI APIs."""
from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import zlib
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .errors import AgenticVMError
from .qemu import QemuBackend, qmp_call, qmp_endpoint, qmp_sequence

MAX_SCREEN_BYTES = 32 * 1024 * 1024
MAX_SCREEN_DIMENSION = 4096
MAX_TEXT = 128
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_dimensions(data: bytes) -> tuple[int, int]:
    """Check bounded PNG structure/CRCs without allocating decompressed pixels."""
    if not 45 <= len(data) <= MAX_SCREEN_BYTES or not data.startswith(PNG_SIGNATURE):
        raise AgenticVMError("QEMU did not return a bounded PNG screenshot.", "invalid_screenshot")
    position, width, height, seen_image = 8, 0, 0, False
    while position + 12 <= len(data):
        length = struct.unpack_from(">I", data, position)[0]
        end = position + 12 + length
        if end > len(data):
            break
        kind = data[position + 4:position + 8]
        expected_crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        if zlib.crc32(data[position + 4:position + 8 + length]) & 0xffffffff != expected_crc:
            break
        if position == 8:
            if kind != b"IHDR" or length != 13:
                break
            width, height = struct.unpack_from(">II", data, position + 8)
            if not 1 <= width <= MAX_SCREEN_DIMENSION or not 1 <= height <= MAX_SCREEN_DIMENSION:
                break
        elif kind == b"IHDR":
            break
        if kind == b"IDAT":
            seen_image = True
        if kind == b"IEND":
            if length == 0 and end == len(data) and width and height and seen_image:
                return width, height
            break
        position = end
    raise AgenticVMError("QEMU returned an incomplete or invalid PNG screenshot.", "invalid_screenshot")


def _save_image(destination: Path, data: bytes, overwrite: bool) -> Path:
    destination = destination.expanduser().absolute()
    if destination.suffix.lower() != ".png":
        raise AgenticVMError("Screenshot destination must have a .png extension.", "invalid_destination")
    if destination.is_symlink():
        raise AgenticVMError("Refusing a screenshot destination that is a symbolic link.", "invalid_destination")
    if not destination.parent.is_dir():
        raise AgenticVMError("Screenshot destination directory does not exist.", "invalid_destination")
    if destination.exists() and not overwrite:
        raise AgenticVMError("Screenshot destination exists; use --overwrite to replace it.", "destination_exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".agenticvm-screen-", suffix=".png", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
            os.unlink(temporary)
        return destination
    except OSError as error:
        raise AgenticVMError(f"Cannot save the screenshot: {error}", "screenshot_write_failed") from error
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


_KEY_ALIASES = {
    "control": "ctrl", "ctrl_l": "ctrl", "ctrl_r": "ctrl_r",
    "shift_l": "shift", "alt_l": "alt", "option": "alt",
    "super": "meta_l", "meta": "meta_l", "win": "meta_l", "windows": "meta_l",
    "enter": "ret", "return": "ret", "escape": "esc", "space": "spc",
    "backspace": "backspace", "page_up": "pgup", "pageup": "pgup",
    "page_down": "pgdn", "pagedown": "pgdn", "del": "delete", "ins": "insert",
    "arrowleft": "left", "arrowright": "right", "arrowup": "up", "arrowdown": "down",
}
_KEY_CODES = set("abcdefghijklmnopqrstuvwxyz0123456789") | {
    "ctrl", "ctrl_r", "shift", "shift_r", "alt", "alt_r", "meta_l", "meta_r",
    "ret", "esc", "spc", "tab", "backspace", "delete", "insert", "home", "end", "pgup", "pgdn",
    "left", "right", "up", "down", "minus", "equal", "bracket_left", "bracket_right",
    "backslash", "semicolon", "apostrophe", "grave_accent", "comma", "dot", "slash",
    "caps_lock", "num_lock", "scroll_lock", "print", "pause", "menu", "kp_enter",
} | {f"f{number}" for number in range(1, 13)}
_PUNCTUATION = {
    " ": ("spc", False), "\t": ("tab", False), "\n": ("ret", False), "\r": ("ret", False),
    "-": ("minus", False), "_": ("minus", True), "=": ("equal", False), "+": ("equal", True),
    "[": ("bracket_left", False), "{": ("bracket_left", True), "]": ("bracket_right", False), "}": ("bracket_right", True),
    "\\": ("backslash", False), "|": ("backslash", True), ";": ("semicolon", False), ":": ("semicolon", True),
    "'": ("apostrophe", False), '"': ("apostrophe", True), "`": ("grave_accent", False), "~": ("grave_accent", True),
    ",": ("comma", False), "<": ("comma", True), ".": ("dot", False), ">": ("dot", True),
    "/": ("slash", False), "?": ("slash", True),
    **{symbol: (digit, True) for symbol, digit in zip("!@#$%^&*()", "1234567890")},
}


def _character_keys(character: str) -> list[str]:
    if character in "abcdefghijklmnopqrstuvwxyz0123456789":
        return [character]
    if character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        return ["shift", character.lower()]
    if character in _PUNCTUATION:
        key, shifted = _PUNCTUATION[character]
        return ["shift", key] if shifted else [key]
    raise AgenticVMError("QMP typing accepts printable ASCII, tabs and newlines; use guest text input for Unicode.", "invalid_text")


def _key_events(keys: list[str]) -> list[dict]:
    return [{"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": key}}}
            for down, codes in ((True, keys), (False, list(reversed(keys)))) for key in codes]


def normalize_keys(keys: list[str] | str) -> list[str]:
    if isinstance(keys, str):
        keys = keys.split("+")
    if not isinstance(keys, list) or not 1 <= len(keys) <= 4 or not all(isinstance(key, str) and key for key in keys):
        raise AgenticVMError("Supply one to four key names, for example ['ctrl', 'l'].", "invalid_keys")
    result = []
    for key in keys:
        name = _KEY_ALIASES.get(key.lower(), key.lower())
        if name not in _KEY_CODES:
            if len(key) == 1:
                result.extend(_character_keys(key))
                continue
            raise AgenticVMError(f"Unsupported guest key: {key!r}.", "invalid_keys")
        result.append(name)
    # Repeated modifiers are harmless in a chord, but repeated non-modifier
    # keys do not describe an unambiguous simultaneous key press.
    unique = list(dict.fromkeys(result))
    if len(unique) > 4:
        raise AgenticVMError("Guest key chord exceeds four keys.", "invalid_keys")
    return unique


class DesktopController:
    """Use the desktop profile only after validating its exact live process."""

    def __init__(self, backend: QemuBackend):
        if not isinstance(backend, QemuBackend):
            raise AgenticVMError("Desktop control requires the QEMU backend.", "unsupported_backend")
        self.backend = backend

    @contextmanager
    def _owned(self):
        # Serialize with stop/reset so a checked port cannot be recycled while
        # input is being sent. Hold the proven Windows process handle as well.
        with self.backend.store.lock():
            state = self.backend.store.load()
            if state.get("profile", "command") not in {"desktop", "windows", "custom"}:
                raise AgenticVMError("Start the desktop profile before using screenshots or input.", "desktop_required")
            if not state["registered"]:
                raise AgenticVMError("The desktop VM is stopped.", "vm_not_running")
            with self.backend._process(state) as process:
                if not process.alive():
                    raise AgenticVMError("The desktop VM has exited.", "vm_not_running")
                yield state

    def _capture(self, state: dict) -> tuple[bytes, dict]:
        temporary = Path(state["run_dir"]) / f".screen-{uuid4().hex}.png"
        try:
            qmp_call(qmp_endpoint(state), "screendump", timeout=5,
                     arguments={"filename": str(temporary), "format": "png"})
            if temporary.is_symlink() or temporary.stat().st_size > MAX_SCREEN_BYTES:
                raise AgenticVMError("QEMU screenshot exceeds its size limit.", "invalid_screenshot")
            data = temporary.read_bytes()
            width, height = png_dimensions(data)
            return data, {"width": width, "height": height, "format": "png", "mime_type": "image/png",
                          "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "uuid": state["uuid"]}
        except OSError as error:
            raise AgenticVMError(f"Cannot read the QEMU screenshot: {error}", "screenshot_failed") from error
        finally:
            temporary.unlink(missing_ok=True)

    def screenshot_bytes(self) -> tuple[bytes, dict]:
        """Capture for an MCP/image viewer without retaining poll frames."""
        with self._owned() as state:
            return self._capture(state)

    def screenshot(self, destination: Path | None = None, *, overwrite: bool = False) -> dict:
        with self._owned() as state:
            data, metadata = self._capture(state)
            if destination is None:
                folder = Path(state["run_dir"]) / "screenshots"
                folder.mkdir(mode=0o700, exist_ok=True)
                if folder.resolve().parent != Path(state["run_dir"]).resolve():
                    raise AgenticVMError("Screenshot directory escaped its owned VM directory.", "invalid_destination")
                destination = folder / f"frame-{uuid4().hex}.png"
            saved = _save_image(Path(destination), data, overwrite)
            return {**metadata, "path": str(saved)}

    @staticmethod
    def _coordinates(x: int, y: int, width: int, height: int) -> list[dict]:
        if type(x) is not int or type(y) is not int or not 0 <= x < width or not 0 <= y < height:
            raise AgenticVMError(f"Mouse coordinates must be inside the {width} × {height} screenshot.", "invalid_coordinates")
        return [{"type": "abs", "data": {"axis": axis, "value": round(value * 32767 / max(1, limit - 1))}}
                for axis, value, limit in (("x", x, width), ("y", y, height))]

    def mouse_move(self, x: int, y: int) -> dict:
        with self._owned() as state:
            _, frame = self._capture(state)
            events = self._coordinates(x, y, frame["width"], frame["height"])
            qmp_call(qmp_endpoint(state), "input-send-event", arguments={"events": events})
            return {"x": x, "y": y, "width": frame["width"], "height": frame["height"]}

    def mouse_button(self, button: str, down: bool) -> dict:
        if button not in {"left", "middle", "right"} or type(down) is not bool:
            raise AgenticVMError("Mouse button must be left, middle or right with a boolean down value.", "invalid_button")
        with self._owned() as state:
            qmp_call(qmp_endpoint(state), "input-send-event", arguments={"events": [{"type": "btn", "data": {"button": button, "down": down}}]})
        return {"button": button, "down": down}

    def click(self, x: int, y: int, button: str = "left", *, count: int = 1) -> dict:
        if button not in {"left", "middle", "right"} or type(count) is not int or not 1 <= count <= 2:
            raise AgenticVMError("Click accepts left/middle/right and a count of one or two.", "invalid_button")
        with self._owned() as state:
            _, frame = self._capture(state)
            movement = self._coordinates(x, y, frame["width"], frame["height"])
            operations = [("input-send-event", {"events": movement})]
            # USB tablet state can coalesce transitions between guest polls.
            # Keep each press/release long enough for the guest to consume it.
            for _ in range(count):
                for down in (True, False):
                    operations.append(("input-send-event", {"events": [{"type": "btn", "data": {"button": button, "down": down}}]}))
            try:
                qmp_sequence(qmp_endpoint(state), operations, interval=0.02)
            except AgenticVMError:
                try:
                    qmp_call(qmp_endpoint(state), "input-send-event", arguments={"events": [{"type": "btn", "data": {"button": button, "down": False}}]})
                except AgenticVMError:
                    pass
                raise
        return {"x": x, "y": y, "button": button, "count": count}

    def scroll(self, steps: int, *, horizontal: bool = False) -> dict:
        if type(steps) is not int or not -32 <= steps <= 32 or type(horizontal) is not bool:
            raise AgenticVMError("Scroll requires -32 to 32 steps and a boolean horizontal value.", "invalid_scroll")
        if not steps:
            return {"steps": 0, "horizontal": horizontal}
        button = ("wheel-right" if steps > 0 else "wheel-left") if horizontal else ("wheel-down" if steps > 0 else "wheel-up")
        operations = [("input-send-event", {"events": [{"type": "btn", "data": {"button": button, "down": down}}]})
                      for _ in range(abs(steps)) for down in (True, False)]
        with self._owned() as state:
            qmp_sequence(qmp_endpoint(state), operations, interval=0.02)
        return {"steps": steps, "horizontal": horizontal}

    def key(self, keys: list[str] | str) -> dict:
        normalized = normalize_keys(keys)
        with self._owned() as state:
            # USB HID has a 16-scancode queue. Let the guest consume each
            # transition, including extended keys, before sending the next.
            operations = [("input-send-event", {"events": [event]}) for event in _key_events(normalized)]
            try:
                qmp_sequence(qmp_endpoint(state), operations, interval=0.02)
            except AgenticVMError:
                try:
                    releases = [{"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": key}}}
                                for key in reversed(normalized)]
                    qmp_sequence(qmp_endpoint(state), [("input-send-event", {"events": [event]}) for event in releases], interval=0.02)
                except AgenticVMError:
                    pass
                raise
        return {"keys": normalized}

    def type_text(self, text: str) -> dict:
        if not isinstance(text, str) or len(text) > MAX_TEXT:
            raise AgenticVMError("QMP text input is limited to 128 ASCII characters; use guest text input for longer text.", "invalid_text")
        sequences = [_character_keys(character) for character in text]
        operations = [("input-send-event", {"events": _key_events(keys)}) for keys in sequences]
        if operations:
            with self._owned() as state:
                qmp_sequence(qmp_endpoint(state), operations, timeout=15, interval=0.06)
        return {"characters": len(text), "method": "qmp-us-keyboard"}
