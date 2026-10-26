"""Reachable-only negative fixture: one open TCP port, no garden code or state."""
from __future__ import annotations

import socket
import time


def main():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 8081))
    listener.listen(4)
    listener.settimeout(1)
    print('NEGATIVE_PORT_LISTEN 8081', flush=True)
    while True:
        try:
            connection, address = listener.accept()
            print('NEGATIVE_PORT_CONNECTION ' + str(address), flush=True)
            connection.close()
        except socket.timeout:
            continue


if __name__ == '__main__':
    main()
