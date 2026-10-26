"""Version 1 NDJSON protocol over an exclusively held serial connection."""
from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from uuid import uuid4

from .errors import AgenticVMError, GuestError

MAX_FRAME = 2 * 1024 * 1024
MAX_FILE = 1024 * 1024


def decode_data(value: str, limit: int = MAX_FILE) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise AgenticVMError("Guest data exceeds the permitted size.", "protocol_error")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise AgenticVMError("Guest returned invalid base64 data.", "protocol_error") from error
    if len(data) > limit:
        raise AgenticVMError("Guest data exceeds the permitted size.", "protocol_error")
    return data


class GuestClient:
    """Open per request so other clients can poll or cancel between requests."""

    def __init__(self, transport_factory: Callable):
        self.transport_factory = transport_factory

    def call(self, op: str, *, timeout: float = 5, **fields) -> dict:
        identifier = uuid4().hex
        request = {"v": 1, "id": identifier, "op": op, **fields}
        payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(payload) > MAX_FRAME:
            raise AgenticVMError("Request exceeds the 2 MiB protocol frame limit.", "request_too_large")
        deadline = time.monotonic() + timeout
        with self.transport_factory(timeout) as transport:
            # A disconnected client may have left a partial UART request behind.
            # A blank delimiter discards it before the next correlated request.
            transport.write(b"\n" + payload, max(0.01, deadline - time.monotonic()))
            for _ in range(128):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AgenticVMError("Guest response timed out.", "guest_timeout")
                raw = transport.readline(remaining, MAX_FRAME)
                try:
                    response = json.loads(raw)
                except (UnicodeError, ValueError):
                    # A bounded allowance for early boot messages or an interrupted frame.
                    continue
                if not isinstance(response, dict) or response.get("id") != identifier:
                    continue
                if response.get("v") != 1 or not isinstance(response.get("ok"), bool):
                    raise AgenticVMError("Guest returned an invalid protocol envelope.", "protocol_error")
                if not response["ok"]:
                    error = response.get("error")
                    if not isinstance(error, dict):
                        raise AgenticVMError("Guest returned an invalid error envelope.", "protocol_error")
                    raise GuestError(str(error.get("message", "Guest operation failed.")), str(error.get("code", "guest_error")))
                if not isinstance(response.get("result"), dict):
                    raise AgenticVMError("Guest result must be an object.", "protocol_error")
                return response["result"]
        raise AgenticVMError("Too many unrelated guest frames.", "protocol_error")

    def ready(self, timeout: float = 60, *, is_running: Callable[[], bool] | None = None) -> dict:
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            if is_running is not None and not is_running():
                raise AgenticVMError("The VM exited before the Linux guest became ready.", "guest_boot_failed")
            try:
                result = self.call("ping", timeout=min(3, max(0.05, deadline - time.monotonic())))
                if result.get("protocol") != 1:
                    raise AgenticVMError("Guest protocol version is unsupported.", "protocol_error")
                return result
            except AgenticVMError as error:
                last_error = error
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        raise AgenticVMError(f"Linux guest did not become ready: {last_error}", "guest_not_ready")
