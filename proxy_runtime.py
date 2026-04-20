import select
import socket
import sqlite3
import threading
from datetime import datetime
from contextlib import closing
from urllib.parse import urlparse


def get_real_local_ip(fallback_ip):
    if fallback_ip == '127.0.0.1' or fallback_ip == 'localhost':
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return fallback_ip
    return fallback_ip

BUFFER_SIZE = 65536
SOCKET_TIMEOUT = 15
PROXY_IP = "127.0.0.1"


def open_db(database_path):
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def normalize_host(host):
    return host.lower().strip().split(":", 1)[0]


def get_blocked_rules(database_path):
    with closing(open_db(database_path)) as db:
        return db.execute("SELECT url, reason FROM blocked_sites").fetchall()


def match_blocked_host(host, blocked_rules):
    host = normalize_host(host)
    for rule in blocked_rules:
        blocked_host = normalize_host(rule["url"])
        if host == blocked_host or host.endswith("." + blocked_host):
            return rule
    return None


def store_log(
    database_path,
    username,
    url,
    method,
    protocol,
    status,
    threat_level,
    bandwidth_kb,
    client_ip,
    proxy_ip,
    website_domain,
    target_ip="",
):
    requested_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(open_db(database_path)) as db:
        db.execute(
            """
            INSERT INTO logs (
                username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip, requested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip, requested_at),
        )
        db.commit()


def client_identity(address):
    return f"client@{address[0]}"


def resolve_username_from_client_ip(database_path, client_ip):
    try:
        with closing(open_db(database_path)) as db:
            row = db.execute(
                """
                SELECT username
                FROM client_sessions
                WHERE client_ip = ?
                  AND last_seen >= datetime('now', '-12 hours')
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                (client_ip,),
            ).fetchone()
            if row and row["username"]:
                return str(row["username"])
    except sqlite3.Error:
        return None
    return None


def domain_from_url(url):
    parsed = urlparse(url)
    return parsed.netloc or url


def extract_host_and_port_from_http(first_line, request_bytes):
    parts = first_line.split(" ")
    if len(parts) < 2:
        raise ValueError("Invalid HTTP request line")

    method = parts[0]
    raw_target = parts[1]
    parsed = urlparse(raw_target)

    if parsed.scheme and parsed.hostname:
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        url = raw_target
        protocol = parsed.scheme.upper()
        rewritten = request_bytes.replace(
            f"{method} {raw_target}".encode(),
            f"{method} {path}".encode(),
            1,
        )
        return method, host, port, protocol, url, rewritten

    headers = request_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    host_header = next((line for line in headers if line.lower().startswith("host:")), "")
    host_value = host_header.split(":", 1)[1].strip() if ":" in host_header else ""
    if not host_value:
        raise ValueError("Missing Host header")

    if ":" in host_value:
        host, port_text = host_value.rsplit(":", 1)
        port = int(port_text)
    else:
        host = host_value
        port = 80

    path = raw_target or "/"
    url = f"http://{host}{path}"
    rewritten = request_bytes
    return method, host, port, "HTTP", url, rewritten


def tunnel_https(client_socket, remote_socket):
    total_bytes = 0
    sockets = [client_socket, remote_socket]
    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, SOCKET_TIMEOUT)
        if exceptional or not readable:
            break
        for current in readable:
            data = current.recv(BUFFER_SIZE)
            if not data:
                return total_bytes
            target = remote_socket if current is client_socket else client_socket
            target.sendall(data)
            total_bytes += len(data)
    return total_bytes


def handle_https(client_socket, address, first_line, database_path):
    _, target, _ = first_line.split(" ", 2)
    if ":" in target:
        host, port_text = target.split(":", 1)
        port = int(port_text)
    else:
        host = target
        port = 443

    target_ip = ""
    try:
        target_ip = socket.gethostbyname(host)
    except socket.error:
        target_ip = "Unknown"

    blocked_rule = match_blocked_host(host, get_blocked_rules(database_path))
    client_ip = address[0]
    username = resolve_username_from_client_ip(database_path, client_ip) or client_identity(address)
    url = f"https://{host}:{port}"
    website_domain = host

    if blocked_rule:
        client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by proxy")
        store_log(database_path, username, url, "CONNECT", "HTTPS", "Blocked", "High", 0, client_ip, PROXY_IP, website_domain, target_ip)
        return

    remote_socket = None
    try:
        remote_socket = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        total_bytes = tunnel_https(client_socket, remote_socket)
        store_log(
            database_path,
            username,
            url,
            "CONNECT",
            "HTTPS",
            "Allowed",
            "Low",
            max(1, round(total_bytes / 1024)),
            client_ip,
            PROXY_IP,
            website_domain,
            target_ip,
        )
    except OSError:
        client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        store_log(database_path, username, url, "CONNECT", "HTTPS", "Blocked", "Critical", 0, client_ip, PROXY_IP, website_domain, target_ip)
    finally:
        if remote_socket is not None:
            remote_socket.close()


def handle_http(client_socket, address, request_bytes, first_line, database_path):
    method, host, port, protocol, url, forwarded_request = extract_host_and_port_from_http(
        first_line, request_bytes
    )
    target_ip = ""
    try:
        target_ip = socket.gethostbyname(host)
    except socket.error:
        target_ip = "Unknown"

    blocked_rule = match_blocked_host(host, get_blocked_rules(database_path))
    client_ip = address[0]
    username = resolve_username_from_client_ip(database_path, client_ip) or client_identity(address)
    website_domain = domain_from_url(url)

    if blocked_rule:
        body = f"Blocked by proxy: {blocked_rule['reason']}".encode()
        response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        client_socket.sendall(response)
        store_log(database_path, username, url, method, protocol, "Blocked", "High", 0, client_ip, PROXY_IP, website_domain, target_ip)
        return

    remote_socket = None
    total_bytes = 0
    try:
        remote_socket = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
        remote_socket.sendall(forwarded_request)
        while True:
            chunk = remote_socket.recv(BUFFER_SIZE)
            if not chunk:
                break
            client_socket.sendall(chunk)
            total_bytes += len(chunk)

        store_log(
            database_path,
            username,
            url,
            method,
            protocol,
            "Allowed",
            "Low",
            max(1, round(total_bytes / 1024)),
            client_ip,
            PROXY_IP,
            website_domain,
            target_ip,
        )
    except OSError:
        client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        store_log(database_path, username, url, method, protocol, "Blocked", "Critical", 0, client_ip, PROXY_IP, website_domain, target_ip)
    finally:
        if remote_socket is not None:
            remote_socket.close()


def handle_client(client_socket, address, database_path):
    with client_socket:
        try:
            client_socket.settimeout(SOCKET_TIMEOUT)
            request_bytes = client_socket.recv(BUFFER_SIZE)
            if not request_bytes:
                return

            first_line = request_bytes.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            if first_line.startswith("CONNECT "):
                handle_https(client_socket, address, first_line, database_path)
            else:
                handle_http(client_socket, address, request_bytes, first_line, database_path)
        except (ValueError, OSError):
            pass


def serve_forever(host, port, database_path):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)

    while True:
        client_socket, address = server_socket.accept()
        worker = threading.Thread(
            target=handle_client,
            args=(client_socket, address, database_path),
            daemon=True,
        )
        worker.start()


def start_proxy_server(database_path, host="127.0.0.1", port=8888):
    global PROXY_IP
    PROXY_IP = get_real_local_ip(host) if host in ("127.0.0.1", "localhost") else host
    if PROXY_IP == "0.0.0.0":
        PROXY_IP = get_real_local_ip("127.0.0.1")
    thread = threading.Thread(
        target=serve_forever,
        args=(host, port, database_path),
        daemon=True,
        name="proxy-server",
    )
    thread.start()
    return thread
