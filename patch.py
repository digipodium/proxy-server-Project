import re
import socket

with open('proxy_runtime.py', 'r', encoding='utf-8') as f:
    code = f.read()

handle_https_ip_block = """    target_ip = ""
    try:
        target_ip = socket.gethostbyname(host)
    except socket.error:
        target_ip = "Unknown"

    blocked_rule = match_blocked_host(host, get_blocked_rules(database_path))"""

code = code.replace('    blocked_rule = match_blocked_host(host, get_blocked_rules(database_path))', handle_https_ip_block)

code = code.replace('website_domain)', 'website_domain, target_ip)')
code = code.replace('website_domain,\n        )', 'website_domain,\n            target_ip,\n        )')

with open('proxy_runtime.py', 'w', encoding='utf-8') as f:
    f.write(code)
