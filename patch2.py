import re
import socket

def get_real_ip_patch():
    return """
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
"""

with open('proxy_runtime.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add get_real_local_ip and import datetime if not there
if "from datetime import datetime" not in text:
    text = text.replace("import threading", "import threading\nfrom datetime import datetime")

if "def get_real_local_ip" not in text:
    marker = "BUFFER_SIZE = "
    text = text.replace(marker, get_real_ip_patch() + "\n" + marker)


# 2. Modify handle_client to use real IP
text = text.replace("def handle_client(client_socket, address, database_path):\n    with client_socket:\n        try:\n            client_socket.settimeout(SOCKET_TIMEOUT)",
"def handle_client(client_socket, address, database_path):\n    # Fix IP \n    real_ip = get_real_local_ip(address[0])\n    address = (real_ip, address[1])\n    with client_socket:\n        try:\n            client_socket.settimeout(SOCKET_TIMEOUT)")

# 3. Modify store_log parameters & SQL queries
# First, change the def
if "requested_at = datetime.now().strftime" not in text:
    old_def = """def store_log(
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
    with closing(open_db(database_path)) as db:"""
    
    new_def = """def store_log(
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
    with closing(open_db(database_path)) as db:"""
    text = text.replace(old_def, new_def)
    
    # Second, change the INSERT queries
    old_query1 = "username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip"
    new_query1 = "username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip, requested_at"
    text = text.replace(old_query1, new_query1)

    old_query2 = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    new_query2 = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    text = text.replace(old_query2, new_query2)

    old_query3 = "(username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip),"
    new_query3 = "(username, url, method, protocol, status, threat_level, bandwidth_kb, client_ip, proxy_ip, website_domain, target_ip, requested_at),"
    text = text.replace(old_query3, new_query3)

with open('proxy_runtime.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patch applied")
