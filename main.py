import socket
import threading
import time
from datetime import datetime
from collections import deque
from flask import Flask, jsonify, render_template_string

# ── Shared state ──────────────────────────────────────────────────────────────
stats = {
    "total": 0,
    "active": 0,
    "errors": 0,
    "bytes_transferred": 0,
    "start_time": time.time(),
}
log = deque(maxlen=100)          # last 100 log lines
stats_lock = threading.Lock()

BUFFER = 4096

# ── Dashboard HTML ─────────────────────────────────────────────────────────────
DASHBOARD_HTML = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0c10;--surface:#111318;--border:#1e2230;
    --accent:#00f5c4;--accent2:#7b5ea7;--danger:#ff4d6d;
    --text:#e2e8f0;--muted:#4a5568;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh;padding:24px}
  header{display:flex;align-items:center;gap:16px;margin-bottom:32px;border-bottom:1px solid var(--border);padding-bottom:20px}
  .logo{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;letter-spacing:-0.5px}
  .logo span{color:var(--accent)}
  .pill{font-size:11px;background:#0d2f26;color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:3px 10px}
  .uptime{margin-left:auto;font-size:12px;color:var(--muted)}

  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px 24px;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
  .card.green::before{background:var(--accent)}
  .card.purple::before{background:var(--accent2)}
  .card.red::before{background:var(--danger)}
  .card.blue::before{background:#4fc3f7}
  .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
  .value{font-family:'Syne',sans-serif;font-size:32px;font-weight:800}
  .value.green{color:var(--accent)}
  .value.purple{color:var(--accent2)}
  .value.red{color:var(--danger)}
  .value.blue{color:#4fc3f7}

  .section-title{font-size:11px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);margin-bottom:12px}
  .log-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;height:340px;overflow-y:auto;padding:16px}
  .log-entry{font-size:12px;line-height:1.8;border-bottom:1px solid var(--border);padding:4px 0;display:flex;gap:12px}
  .log-entry:last-child{border-bottom:none}
  .ts{color:var(--muted);white-space:nowrap;flex-shrink:0}
  .lvl-INFO{color:var(--accent)}
  .lvl-ERROR{color:var(--danger)}
  .lvl-CONN{color:#4fc3f7}
  .msg{word-break:break-all}

  ::-webkit-scrollbar{width:4px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}

  .footer{margin-top:20px;font-size:11px;color:var(--muted);text-align:center}
</style>
</head><body>
<header>
  <div class="logo">proxy<span>.</span>monitor</div>
  <div class="pill">● LIVE</div>
  <div class="uptime" id="uptime">uptime: —</div>
</header>

<div class="grid">
  <div class="card green">
    <div class="label">Total Requests</div>
    <div class="value green" id="total">0</div>
  </div>
  <div class="card purple">
    <div class="label">Active Connections</div>
    <div class="value purple" id="active">0</div>
  </div>
  <div class="card red">
    <div class="label">Errors</div>
    <div class="value red" id="errors">0</div>
  </div>
  <div class="card blue">
    <div class="label">Data Transferred</div>
    <div class="value blue" id="bytes">0 B</div>
  </div>
</div>

<div class="section-title">Live Request Log</div>
<div class="log-box" id="logBox"></div>
<div class="footer">Proxy @ 127.0.0.1:8080 &nbsp;·&nbsp; Dashboard @ :5000 &nbsp;·&nbsp; auto-refresh every 2 s</div>

<script>
function fmt(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(2)+' MB'}
function fmtUp(s){let h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sc=Math.floor(s%60);return[h,m,sc].map(v=>String(v).padStart(2,'0')).join(':')}

async function refresh(){
  try{
    const r=await fetch('/api/stats');const d=await r.json();
    document.getElementById('total').textContent=d.total;
    document.getElementById('active').textContent=d.active;
    document.getElementById('errors').textContent=d.errors;
    document.getElementById('bytes').textContent=fmt(d.bytes_transferred);
    document.getElementById('uptime').textContent='uptime: '+fmtUp(d.uptime_seconds);

    const box=document.getElementById('logBox');
    const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<40;
    box.innerHTML=d.log.map(e=>`
      <div class="log-entry">
        <span class="ts">${e.time}</span>
        <span class="lvl-${e.level}">[${e.level}]</span>
        <span class="msg">${e.msg}</span>
      </div>`).join('');
    if(atBottom)box.scrollTop=box.scrollHeight;
  }catch{}
}
refresh();setInterval(refresh,2000);
</script>
</body></html>
"""

# ── Flask dashboard ────────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/stats")
def api_stats():
    with stats_lock:
        return jsonify({
            **stats,
            "uptime_seconds": round(time.time() - stats["start_time"]),
            "log": list(log),
        })

# ── Logging helper ─────────────────────────────────────────────────────────────
def record(level: str, msg: str):
    entry = {"time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg}
    with stats_lock:
        log.append(entry)
    print(f"[{level}] {msg}")

# ── Proxy core ─────────────────────────────────────────────────────────────────
def parse_target(request: bytes):
    """Return (host_str, port_int) from a raw HTTP request."""
    first_line = request.split(b'\n')[0]
    url = first_line.split(b' ')[1]

    if (pos := url.find(b'://')) != -1:
        url = url[pos + 3:]

    slash = url.find(b'/')
    if slash == -1:
        slash = len(url)
    colon = url.find(b':')

    if colon == -1 or slash < colon:
        return url[:slash].decode(), 80
    port = int(url[colon + 1: slash])
    return url[:colon].decode(), port


def handle_client(client_socket: socket.socket):
    with stats_lock:
        stats["active"] += 1
        stats["total"] += 1

    try:
        request = client_socket.recv(BUFFER)
        if not request:
            return

        host, port = parse_target(request)
        record("CONN", f"→ {host}:{port}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_sock:
            proxy_sock.connect((host, port))
            proxy_sock.sendall(request)

            while chunk := proxy_sock.recv(BUFFER):
                client_socket.sendall(chunk)
                with stats_lock:
                    stats["bytes_transferred"] += len(chunk)

    except Exception as exc:
        record("ERROR", str(exc))
        with stats_lock:
            stats["errors"] += 1
    finally:
        client_socket.close()
        with stats_lock:
            stats["active"] -= 1


def start_proxy(host="127.0.0.1", port=8080):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    record("INFO", f"Proxy listening on {host}:{port}")

    while True:
        client, addr = srv.accept()
        record("INFO", f"Connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Proxy thread
    threading.Thread(target=start_proxy, daemon=True).start()

    # Flask dashboard (main thread)
    print("Dashboard → http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, use_reloader=False)