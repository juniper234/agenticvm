"""Bounded Windows named-pipe I/O and local filesystem socket transports."""
from __future__ import annotations

import os
import select
import socket
import time

from .errors import AgenticVMError


def _connect_windows_filesystem_socket(stream: socket.socket, path: str, timeout: float):
    """Supply the AF_UNIX address encoder omitted from CPython Windows builds.

    Windows 11's native Winsock provider implements AF_UNIX. A Python socket
    created with its numeric address family still supports normal deadline-aware
    send/receive operations; only connecting to the pathname needs a native call.
    """
    import ctypes

    encoded = os.fsencode(path) if not isinstance(path, str) else path.encode("utf-8")
    if not encoded or b"\0" in encoded or len(encoded) >= 108:
        raise AgenticVMError("The local socket path must contain 1–107 UTF-8 bytes and no NUL.", "invalid_endpoint")

    class SockaddrUnix(ctypes.Structure):
        _fields_ = [("family", ctypes.c_ushort), ("path", ctypes.c_char * 108)]

    api = ctypes.WinDLL("ws2_32", use_last_error=True)
    api.connect.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    api.connect.restype = ctypes.c_int
    api.WSAGetLastError.argtypes = []
    api.WSAGetLastError.restype = ctypes.c_int
    address = SockaddrUnix(1, encoded)
    # settimeout() makes the Winsock handle nonblocking. Use the same timeout
    # for native connect completion; Python handles all later I/O normally.
    started = time.monotonic()
    if api.connect(stream.fileno(), ctypes.byref(address), 2 + len(encoded) + 1) == 0:
        return
    code = api.WSAGetLastError()
    if code not in (10035, 10036, 10037):  # WSAEWOULDBLOCK/INPROGRESS/ALREADY
        raise OSError(code, ctypes.FormatError(code))
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        raise TimeoutError("Local socket connection timed out")
    _, writable, exceptional = select.select([], [stream], [stream], remaining)
    if not writable and not exceptional:
        raise TimeoutError("Local socket connection timed out")
    code = stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if code:
        raise OSError(code, ctypes.FormatError(code))


class FramedTransport:
    def __init__(self):
        self.buffer = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def readline(self, timeout: float, limit: int) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            index = self.buffer.find(b"\n")
            if index >= 0:
                if index + 1 > limit:
                    raise AgenticVMError("Guest frame exceeds its size limit.", "protocol_error")
                line = bytes(self.buffer[:index])
                del self.buffer[: index + 1]
                return line
            if len(self.buffer) >= limit:
                raise AgenticVMError("Guest frame exceeds its size limit.", "protocol_error")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgenticVMError("Guest read timed out.", "guest_timeout")
            chunk = self.read(min(4096, limit - len(self.buffer)), remaining)
            if not chunk:
                raise AgenticVMError("Guest serial connection closed.", "guest_disconnected")
            self.buffer.extend(chunk)


class SocketTransport(FramedTransport):
    """Local filesystem stream, including native AF_UNIX on Windows 11.

    The controller validates endpoint ownership before constructing a transport.
    Creating this client never launches a VM or creates a listening endpoint.
    """

    def __init__(self, path: str, timeout: float):
        super().__init__()
        family = getattr(socket, "AF_UNIX", 1 if os.name == "nt" else None)
        if family is None:
            raise AgenticVMError("Local filesystem sockets are unavailable on this host.", "unsupported_host")
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        try:
            if os.name == "nt" and not hasattr(socket, "AF_UNIX"):
                _connect_windows_filesystem_socket(self.socket, path, timeout)
            else:
                self.socket.connect(path)
        except TimeoutError as error:
            self.socket.close()
            raise AgenticVMError("Local socket connection timed out.", "guest_timeout") from error
        except AgenticVMError:
            self.socket.close()
            raise
        except OSError as error:
            self.socket.close()
            raise AgenticVMError(f"Cannot connect to serial socket: {error}", "guest_disconnected") from error

    def read(self, size: int, timeout: float) -> bytes:
        self.socket.settimeout(timeout)
        try:
            return self.socket.recv(size)
        except TimeoutError as error:
            raise AgenticVMError("Guest read timed out.", "guest_timeout") from error
        except OSError as error:
            raise AgenticVMError(f"Guest socket failed: {error}", "guest_disconnected") from error

    def write(self, data: bytes, timeout: float):
        self.socket.settimeout(timeout)
        try:
            self.socket.sendall(data)
        except TimeoutError as error:
            raise AgenticVMError("Guest write timed out.", "guest_timeout") from error
        except OSError as error:
            raise AgenticVMError(f"Guest socket write failed: {error}", "guest_disconnected") from error

    def close(self):
        self.socket.close()


class TcpTransport(SocketTransport):
    """Loopback-only QEMU serial stream, using the same framed protocol."""

    def __init__(self, host: str, port: int, timeout: float):
        FramedTransport.__init__(self)
        if host != "127.0.0.1" or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise AgenticVMError("The serial endpoint must be a local controller-owned port.", "invalid_endpoint")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        try:
            self.socket.connect((host, port))
        except OSError as error:
            self.socket.close()
            raise AgenticVMError(f"Cannot connect to guest serial endpoint: {error}", "guest_disconnected") from error


class WindowsPipeTransport(FramedTransport):
    """A single overlapped operation at a time, cancelled before buffers are freed."""

    def __init__(self, path: str, timeout: float):
        super().__init__()
        if os.name != "nt":
            raise AgenticVMError("The VirtualBox backend currently requires Windows.", "unsupported_host")
        if not path.startswith("\\\\.\\pipe\\agenticvm-"):
            raise AgenticVMError("Refusing an unscoped serial pipe.", "invalid_pipe")
        import ctypes
        from ctypes import wintypes

        class Overlapped(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.Overlapped = Overlapped
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.api.CreateFileW.restype = wintypes.HANDLE
        self.api.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        self.api.WaitNamedPipeW.restype = wintypes.BOOL
        self.api.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        self.api.CreateEventW.restype = wintypes.HANDLE
        for name in ("ReadFile", "WriteFile"):
            function = getattr(self.api, name)
            function.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(Overlapped)]
            function.restype = wintypes.BOOL
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.WaitForSingleObject.restype = wintypes.DWORD
        self.api.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        self.api.GetOverlappedResult.restype = wintypes.BOOL
        self.api.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped)]
        self.api.CancelIoEx.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = None
        deadline = time.monotonic() + timeout
        invalid = ctypes.c_void_p(-1).value
        while time.monotonic() < deadline:
            handle = self.api.CreateFileW(path, 0xC0000000, 0, None, 3, 0x40000000, None)
            if handle != invalid:
                self.handle = handle
                return
            code = ctypes.get_last_error()
            if code not in (2, 231):
                raise AgenticVMError(f"Cannot open guest serial pipe (Windows error {code}).", "guest_disconnected")
            remaining_ms = max(1, min(100, int((deadline - time.monotonic()) * 1000)))
            self.api.WaitNamedPipeW(path, remaining_ms)
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))
        raise AgenticVMError("Guest serial pipe is not ready or is busy.", "guest_timeout")

    def _io(self, operation: str, data, size: int, timeout: float) -> int:
        ctypes, wintypes = self.ctypes, self.wintypes
        overlap = self.Overlapped()
        overlap.hEvent = self.api.CreateEventW(None, True, False, None)
        if not overlap.hEvent:
            raise AgenticVMError("Cannot allocate serial I/O event.", "transport_error")
        count = wintypes.DWORD()
        try:
            completed = getattr(self.api, operation)(self.handle, data, size, ctypes.byref(count), ctypes.byref(overlap))
            if not completed:
                code = ctypes.get_last_error()
                if code != 997:  # ERROR_IO_PENDING
                    raise AgenticVMError(f"Guest serial I/O failed (Windows error {code}).", "guest_disconnected")
                result = self.api.WaitForSingleObject(overlap.hEvent, max(1, min(0xFFFFFFFE, int(timeout * 1000))))
                if result != 0:
                    self.api.CancelIoEx(self.handle, ctypes.byref(overlap))
                    # Named-pipe cancellation completes the operation. Waiting here keeps
                    # the OVERLAPPED structure and byte buffer alive until the kernel is done.
                    self.api.GetOverlappedResult(self.handle, ctypes.byref(overlap), ctypes.byref(count), True)
                    raise AgenticVMError("Guest serial I/O timed out.", "guest_timeout")
                if not self.api.GetOverlappedResult(self.handle, ctypes.byref(overlap), ctypes.byref(count), False):
                    code = ctypes.get_last_error()
                    raise AgenticVMError(f"Guest serial I/O failed (Windows error {code}).", "guest_disconnected")
            return count.value
        finally:
            self.api.CloseHandle(overlap.hEvent)

    def read(self, size: int, timeout: float) -> bytes:
        buffer = self.ctypes.create_string_buffer(size)
        count = self._io("ReadFile", buffer, size, timeout)
        return buffer.raw[:count]

    def write(self, data: bytes, timeout: float):
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgenticVMError("Guest serial write timed out.", "guest_timeout")
            buffer = self.ctypes.create_string_buffer(data[offset:])
            count = self._io("WriteFile", buffer, len(data) - offset, remaining)
            if not count:
                raise AgenticVMError("Guest serial write was incomplete.", "guest_disconnected")
            offset += count

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None
