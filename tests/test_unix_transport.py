"""Exercise filesystem sockets using the real local OS, including Windows.

These tests create only short-lived local sockets; they never start a VM.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from agenticvm.errors import AgenticVMError
from agenticvm.transport import SocketTransport


def bind_filesystem_socket(listener, endpoint):
    if os.name != "nt" or hasattr(socket, "AF_UNIX"):
        listener.bind(endpoint)
        return
    # CPython's Windows builds omit AF_UNIX's pathname encoder, although the
    # native provider works. Use native bind only; accept/read/write stay Python.
    import ctypes

    class SockaddrUnix(ctypes.Structure):
        _fields_ = [("family", ctypes.c_ushort), ("path", ctypes.c_char * 108)]

    encoded = endpoint.encode("utf-8")
    if len(encoded) >= 108:
        raise AssertionError("Test endpoint exceeds the native pathname limit.")
    address = SockaddrUnix(1, encoded)
    api = ctypes.WinDLL("ws2_32", use_last_error=True)
    api.bind.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    api.bind.restype = ctypes.c_int
    api.WSAGetLastError.argtypes = []
    api.WSAGetLastError.restype = ctypes.c_int
    if api.bind(listener.fileno(), ctypes.byref(address), 2 + len(encoded) + 1):
        code = api.WSAGetLastError()
        raise OSError(code, ctypes.FormatError(code))


def accept_filesystem_socket(listener):
    if os.name != "nt" or hasattr(socket, "AF_UNIX"):
        return listener.accept()[0]
    # _accept() also tries to encode an address, so tests need native accept.
    import ctypes

    ready, _, _ = select.select([listener], [], [], 2)
    if not ready:
        raise TimeoutError("Test listener did not receive a connection.")
    api = ctypes.WinDLL("ws2_32", use_last_error=True)
    api.accept.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    api.accept.restype = ctypes.c_size_t
    api.WSAGetLastError.argtypes = []
    api.WSAGetLastError.restype = ctypes.c_int
    descriptor = api.accept(listener.fileno(), None, None)
    if descriptor == ctypes.c_size_t(-1).value:
        code = api.WSAGetLastError()
        raise OSError(code, ctypes.FormatError(code))
    return socket.socket(1, socket.SOCK_STREAM, fileno=descriptor)


@contextmanager
def local_server(handler, *, connections=1, filename="rpc.sock"):
    """Own the listener, thread, and socket file for the entire test."""
    with tempfile.TemporaryDirectory(prefix="avm-ipc-") as temporary:
        endpoint = str(Path(temporary) / filename)
        listener = socket.socket(getattr(socket, "AF_UNIX", 1), socket.SOCK_STREAM)
        listener.settimeout(2)
        bind_filesystem_socket(listener, endpoint)
        listener.listen(1)
        errors = []

        def serve():
            try:
                for index in range(connections):
                    connection = accept_filesystem_socket(listener)
                    with connection:
                        connection.settimeout(2)
                        handler(connection, index)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield endpoint
        finally:
            worker.join(3)
            listener.close()
            # AF_UNIX creates an NTFS reparse point on Windows. Remove only the
            # exact socket this helper created, after its listener is closed.
            try:
                os.unlink(endpoint)
            except FileNotFoundError:
                pass
            if worker.is_alive():
                raise AssertionError("Local socket server did not stop.")
            if errors:
                raise errors[0]


@unittest.skipUnless(hasattr(socket, "AF_UNIX") or os.name == "nt", "AF_UNIX is unavailable")
class FilesystemSocketTransportTests(unittest.TestCase):
    def test_new_connection_can_negotiate_after_each_close(self):
        """QMP-style greetings and replies survive per-request reconnects."""
        seen = []

        def respond(connection, index):
            connection.sendall(b'{"QMP":{"version":{}}}\r\n')
            with connection.makefile("rb") as stream:
                request = json.loads(stream.readline(4096))
                seen.append(request)
                response = {"return": {"sequence": index}, "id": request["id"]}
                # An event and correlated result may arrive in a single read.
                connection.sendall(b'{"event":"RESUME"}\r\n' + json.dumps(response).encode() + b"\r\n")

        with local_server(respond, connections=3) as endpoint:
            for index in range(3):
                with SocketTransport(endpoint, 1) as transport:
                    self.assertIn("QMP", json.loads(transport.readline(1, 4096)))
                    transport.write(json.dumps({"execute": "query-status", "id": str(index)}).encode() + b"\n", 1)
                    self.assertEqual(json.loads(transport.readline(1, 4096))["event"], "RESUME")
                    self.assertEqual(json.loads(transport.readline(1, 4096)),
                                     {"return": {"sequence": index}, "id": str(index)})
                # Closing an already-closed client is safe and owns no listener.
                transport.close()
        self.assertEqual([item["id"] for item in seen], ["0", "1", "2"])

    def test_fragmented_frames_and_buffered_followup_preserve_bytes(self):
        first = '{"text":"hello 世界"}'.encode()

        def respond(connection, _):
            # Split inside a UTF-8 code point as well as within JSON tokens.
            for part in (first[:5], first[5:17], first[17:19], first[19:] + b"\nnext\n"):
                connection.sendall(part)
                time.sleep(0.01)

        with local_server(respond) as endpoint:
            with SocketTransport(endpoint, 1) as transport:
                self.assertEqual(transport.readline(1, 128), first)
                self.assertEqual(transport.readline(1, 128), b"next")

    def test_native_socket_path_supports_utf8(self):
        def respond(connection, _):
            connection.sendall(b"ready\n")

        with local_server(respond, filename="\u03bb.sock") as endpoint:
            with SocketTransport(endpoint, 1) as transport:
                self.assertEqual(transport.readline(1, 128), b"ready")

    def test_partial_input_cannot_extend_the_total_frame_deadline(self):
        def respond(connection, _):
            try:
                for _ in range(20):
                    connection.sendall(b"x")
                    time.sleep(0.04)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        with local_server(respond) as endpoint:
            with SocketTransport(endpoint, 1) as transport:
                started = time.monotonic()
                with self.assertRaises(AgenticVMError) as caught:
                    transport.readline(0.14, 128)
                elapsed = time.monotonic() - started
                self.assertEqual(caught.exception.code, "guest_timeout")
                self.assertLess(elapsed, 1)
                self.assertGreater(elapsed, 0.09)

    def test_oversized_frame_is_rejected_before_unbounded_buffering(self):
        def respond(connection, _):
            connection.sendall(b"x" * 256 + b"\n")

        with local_server(respond) as endpoint:
            with SocketTransport(endpoint, 1) as transport:
                with self.assertRaises(AgenticVMError) as caught:
                    transport.readline(1, 32)
                self.assertEqual(caught.exception.code, "protocol_error")
                self.assertLessEqual(len(transport.buffer), 32)

    def test_peer_close_is_reported_as_disconnected(self):
        def respond(connection, _):
            connection.sendall(b"incomplete")

        with local_server(respond) as endpoint:
            with SocketTransport(endpoint, 1) as transport:
                with self.assertRaises(AgenticVMError) as caught:
                    transport.readline(1, 128)
                self.assertEqual(caught.exception.code, "guest_disconnected")

    def test_write_timeout_is_distinguished_from_peer_disconnection(self):
        # Winsock's AF_UNIX provider can buffer much more than SO_SNDBUF. Inject
        # backpressure rather than allocating unbounded data to fill the kernel.
        transport = SocketTransport.__new__(SocketTransport)
        transport.socket = Mock()
        transport.socket.sendall.side_effect = TimeoutError("deadline")
        with self.assertRaises(AgenticVMError) as caught:
            transport.write(b"request\n", 0.1)
        self.assertEqual(caught.exception.code, "guest_timeout")
        transport.socket.settimeout.assert_called_once_with(0.1)

    @unittest.skipUnless(os.name == "nt" and not hasattr(socket, "AF_UNIX"), "Native Windows encoder only")
    def test_native_encoder_rejects_unbounded_or_nul_paths(self):
        for path in ("x" * 108, "x\0y"):
            with self.subTest(path=repr(path)):
                with self.assertRaises(AgenticVMError) as caught:
                    SocketTransport(path, 1)
                self.assertEqual(caught.exception.code, "invalid_endpoint")


if __name__ == "__main__":
    unittest.main()
