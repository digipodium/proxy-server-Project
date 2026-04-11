#!/usr/bin/env python3
"""
Simple HTTP/HTTPS Proxy Server
Supports:
  - HTTP forwarding
  - HTTPS tunneling (CONNECT method)
  - Request/response logging
"""

import socket
import threading
import select
import logging

# --- Config ---
HOST = '0.0.0.0'
PORT = 8888
BUFFER_SIZE = 65536
TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)


def forward_data(src, dst):
    """Relay raw bytes between two sockets until one closes."""
    while True:
        try:
            readable, _, _ = select.select([src, dst], [], [], TIMEOUT)
            if not readable:
                break
            for sock in readable:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return
                other = dst if sock is src else src
                other.sendall(data)
        except (OSError, ConnectionResetError):
            break


def handle_https_tunnel(client_sock, host, port):
    """Handle CONNECT tunneling for HTTPS."""
    try:
        remote_sock = socket.create_connection((host, port), timeout=TIMEOUT)
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        log.info(f"[HTTPS] Tunnel → {host}:{port}")

        # Bidirectional relay in separate threads
        t1 = threading.Thread(target=forward_data, args=(client_sock, remote_sock), daemon=True)
        t2 = threading.Thread(target=forward_data, args=(remote_sock, client_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except Exception as e:
        log.warning(f"[HTTPS] Tunnel failed to {host}:{port} — {e}")
        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    finally:
        remote_sock.close() if 'remote_sock' in dir() else None


def handle_http_request(client_sock, request_data):
    """Forward a plain HTTP request and relay the response."""
    try:
        first_line = request_data.split(b'\r\n')[0].decode()
        method, url, _ = first_line.split(' ', 2)

        # Parse host and port from URL
        if url.startswith('http://'):
            url_stripped = url[7:]
        else:
            url_stripped = url

        if '/' in url_stripped:
            host_part, path = url_stripped.split('/', 1)
            path = '/' + path
        else:
            host_part, path = url_stripped, '/'

        host = host_part.split(':')[0]
        port = int(host_part.split(':')[1]) if ':' in host_part else 80

        # Rewrite request line to relative path
        modified = request_data.replace(
            f"{method} {url}".encode(),
            f"{method} {path}".encode(),
            1
        )

        log.info(f"[HTTP]  {method} {host}:{port}{path}")

        remote_sock = socket.create_connection((host, port), timeout=TIMEOUT)
        remote_sock.sendall(modified)

        while True:
            data = remote_sock.recv(BUFFER_SIZE)
            if not data:
                break
            client_sock.sendall(data)

        remote_sock.close()
    except Exception as e:
        log.warning(f"[HTTP]  Request failed — {e}")
        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")


def handle_client(client_sock, addr):
    """Entry point per connection."""
    try:
        client_sock.settimeout(TIMEOUT)
        data = client_sock.recv(BUFFER_SIZE)
        if not data:
            return

        first_line = data.split(b'\r\n')[0].decode(errors='replace')

        if first_line.startswith('CONNECT'):
            # HTTPS tunnel
            _, target, _ = first_line.split(' ', 2)
            host, port = target.split(':')
            handle_https_tunnel(client_sock, host, int(port))
        else:
            # Plain HTTP
            handle_http_request(client_sock, data)
    except Exception as e:
        log.debug(f"Client {addr} error: {e}")
    finally:
        client_sock.close()


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)
    log.info(f"Proxy listening on {HOST}:{PORT}")

    try:
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, addr),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down proxy.")
    finally:
        server.close()


if __name__ == '__main__':
    start_proxy()