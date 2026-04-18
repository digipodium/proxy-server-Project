import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, flash, g, redirect, render_template, request, session, url_for, jsonify, Response
import json
import traceback
from functools import wraps
from proxy_runtime import start_proxy_server

app = Flask(__name__)
app.secret_key = "secretkey"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", app.root_path)) / "CyberProxyDefender"
DATABASE = DATA_DIR / "users.db"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888
PROXY_PUBLIC_IP = "127.0.0.1"
proxy_thread = None
proxy_lock = Lock()
ADMIN_REGISTRATION_PASSCODE = "PROXY_ADMIN_2024"


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_db():
    ensure_data_dir()
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def ensure_column(db, table_name, column_name, definition):
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_db():
    ensure_data_dir()
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_column(db, "users", "full_name", "TEXT")
    ensure_column(db, "users", "email", "TEXT")
    ensure_column(db, "users", "role", "TEXT DEFAULT 'user'")
    ensure_column(db, "users", "status", "TEXT DEFAULT 'Active'")
    ensure_column(db, "users", "last_active_at", "TIMESTAMP")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            protocol TEXT NOT NULL DEFAULT 'HTTPS',
            status TEXT NOT NULL CHECK(status IN ('Allowed', 'Blocked')),
            threat_level TEXT NOT NULL DEFAULT 'Low',
            bandwidth_kb INTEGER NOT NULL DEFAULT 0,
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_column(db, "logs", "client_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'")
    ensure_column(db, "logs", "proxy_ip", f"TEXT NOT NULL DEFAULT '{PROXY_PUBLIC_IP}'")
    ensure_column(db, "logs", "website_domain", "TEXT NOT NULL DEFAULT ''")
    ensure_column(db, "logs", "target_ip", "TEXT DEFAULT ''")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    seed_demo_data(db)
    db.close()


def seed_demo_data(db):
    db.execute(
        """
        UPDATE logs
        SET client_ip = COALESCE(NULLIF(client_ip, ''), '127.0.0.1'),
            proxy_ip = COALESCE(NULLIF(proxy_ip, ''), ?),
            website_domain = CASE
                WHEN website_domain IS NULL OR website_domain = '' THEN
                    REPLACE(REPLACE(REPLACE(url, 'https://', ''), 'http://', ''), '/', '')
                ELSE website_domain
            END
        """,
        (PROXY_PUBLIC_IP,),
    )
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        db.execute(
            "INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
            ("admin", hash_password("admin123"), "System Administrator", "admin@cyclops-proxy.local", "admin"),
        )

    blocked_count = db.execute("SELECT COUNT(*) FROM blocked_sites").fetchone()[0]
    if blocked_count == 0:
        db.executemany(
            "INSERT INTO blocked_sites (url, reason) VALUES (?, ?)",
            [
                ("malware-example.net", "Malware distribution"),
                ("phishing-alert.org", "Phishing campaign"),
                ("social-media.local", "Restricted during work hours"),
                ("torrent-mirror.cc", "Unauthorized content sharing"),
                ("unknown-downloads.xyz", "Suspicious downloads"),
            ],
        )

    logs_count = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if logs_count == 0:
        db.executemany(
            """
            INSERT INTO logs (
                username, url, method, protocol, status, threat_level, bandwidth_kb, requested_at, client_ip, proxy_ip, website_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("admin", "https://intranet.company.local", "GET", "HTTPS", "Allowed", "Low", 320, "2026-04-10 08:15:00", "192.168.0.11", PROXY_PUBLIC_IP, "intranet.company.local"),
                ("admin", "https://mail.securehub.com", "POST", "HTTPS", "Allowed", "Low", 540, "2026-04-10 08:22:00", "192.168.0.11", PROXY_PUBLIC_IP, "mail.securehub.com"),
                ("admin", "http://malware-example.net/payload", "GET", "HTTP", "Blocked", "High", 0, "2026-04-10 08:29:00", "192.168.0.11", PROXY_PUBLIC_IP, "malware-example.net"),
                ("admin", "https://analytics.cloudsuite.io", "GET", "HTTPS", "Allowed", "Low", 410, "2026-04-10 09:02:00", "192.168.0.11", PROXY_PUBLIC_IP, "analytics.cloudsuite.io"),
                ("admin", "https://phishing-alert.org/login", "POST", "HTTPS", "Blocked", "Critical", 0, "2026-04-10 09:11:00", "192.168.0.11", PROXY_PUBLIC_IP, "phishing-alert.org"),
                ("auditor", "https://docs.python.org", "GET", "HTTPS", "Allowed", "Low", 680, "2026-04-10 09:45:00", "192.168.0.23", PROXY_PUBLIC_IP, "docs.python.org"),
                ("auditor", "https://social-media.local/feed", "GET", "HTTPS", "Blocked", "Medium", 0, "2026-04-10 10:03:00", "192.168.0.23", PROXY_PUBLIC_IP, "social-media.local"),
                ("operator", "http://updates.vendor.net", "GET", "HTTP", "Allowed", "Low", 220, "2026-04-10 10:16:00", "192.168.0.31", PROXY_PUBLIC_IP, "updates.vendor.net"),
                ("operator", "https://unknown-downloads.xyz/setup", "GET", "HTTPS", "Blocked", "High", 0, "2026-04-10 10:22:00", "192.168.0.31", PROXY_PUBLIC_IP, "unknown-downloads.xyz"),
                ("operator", "https://status.gateway.net", "GET", "HTTPS", "Allowed", "Low", 150, "2026-04-10 10:38:00", "192.168.0.31", PROXY_PUBLIC_IP, "status.gateway.net"),
                ("admin", "https://reports.internal", "GET", "HTTPS", "Allowed", "Low", 490, "2026-04-10 11:05:00", "192.168.0.11", PROXY_PUBLIC_IP, "reports.internal"),
                ("admin", "http://torrent-mirror.cc/file.iso", "GET", "HTTP", "Blocked", "High", 0, "2026-04-10 11:18:00", "192.168.0.11", PROXY_PUBLIC_IP, "torrent-mirror.cc"),
            ],
        )
    db.commit()


def get_overview_data():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    total_requests = db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"]
    blocked_requests = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
    ).fetchone()["count"]
    blocked_sites = db.execute("SELECT COUNT(*) AS count FROM blocked_sites").fetchone()["count"]
    latest_users_rows = db.execute(
        "SELECT username, created_at, last_active_at FROM users ORDER BY id DESC LIMIT 5"
    ).fetchall()

    latest_users = []
    now = datetime.now()
    for row in latest_users_rows:
        user = dict(row)
        is_online = False
        if user.get("last_active_at"):
            try:
                last_active = datetime.strptime(user["last_active_at"], "%Y-%m-%d %H:%M:%S")
                if now - last_active < timedelta(minutes=5):
                    is_online = True
            except:
                pass
        user["is_online"] = is_online
        latest_users.append(user)

    stats = {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "active_users": total_users,
        "blocked_sites": blocked_sites,
        "latest_users": latest_users
    }
    return stats, latest_users


def get_traffic_data():
    db = get_db()
    protocol_rows = db.execute(
        """
        SELECT protocol, COUNT(*) AS request_count, COALESCE(SUM(bandwidth_kb), 0) AS bandwidth_kb
        FROM logs
        GROUP BY protocol
        ORDER BY request_count DESC
        """
    ).fetchall()
    top_destinations = db.execute(
        """
        SELECT url, status, COUNT(*) AS hits, COALESCE(SUM(bandwidth_kb), 0) AS bandwidth_kb
        FROM logs
        GROUP BY url, status
        ORDER BY hits DESC, bandwidth_kb DESC
        LIMIT 6
        """
    ).fetchall()
    traffic_feed_rows = db.execute(
        """
        SELECT
            username,
            client_ip,
            proxy_ip,
            url,
            website_domain,
            target_ip,
            method,
            protocol,
            status,
            threat_level,
            bandwidth_kb,
            requested_at,
            strftime('%H:%M:%S', requested_at) AS request_time
        FROM logs
        ORDER BY requested_at DESC
        LIMIT 10
        """
    ).fetchall()
    recent_alerts = db.execute(
        """
        SELECT username, url, threat_level, requested_at
        FROM logs
        WHERE status = 'Blocked'
        ORDER BY requested_at DESC
        LIMIT 5
        """
    ).fetchall()

    total_bandwidth = sum(row["bandwidth_kb"] for row in protocol_rows)
    allowed_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Allowed'"
    ).fetchone()["count"]
    blocked_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
    ).fetchone()["count"]

    summary = {
        "requests_today": allowed_count + blocked_count,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "bandwidth_mb": round(total_bandwidth / 1024, 2),
    }
    traffic_feed = []
    for row in traffic_feed_rows:
        client_ip = row["client_ip"]
        if not client_ip or client_ip == "0.0.0.0":
            if row["username"].startswith("client@"):
                client_ip = row["username"].split("@", 1)[1]
            else:
                client_ip = "127.0.0.1"

        website_domain = row["website_domain"] or display_host(row["url"])
        traffic_feed.append(
            {
                "client_ip": str(client_ip or "Unknown"),
                "proxy_ip": str(row["proxy_ip"] or PROXY_PUBLIC_IP),
                "target_ip": str(row["target_ip"] or "Unknown"),
                "url": str(row["url"] or ""),
                "website_domain": str(website_domain or ""),
                "method": str(row["method"] or "GET"),
                "protocol": str(row["protocol"] or "HTTPS"),
                "status": str(row["status"] or "Allowed"),
                "threat_level": str(row["threat_level"] or "Low"),
                "bandwidth_kb": int(row["bandwidth_kb"] or 0),
                "requested_at": str(row["requested_at"] or ""),
                "request_time": str(row["request_time"] or ""),
            }
        )
    return summary, protocol_rows, top_destinations, traffic_feed, recent_alerts


def get_logs_data():
    db = get_db()
    system_logs = db.execute(
        """
        SELECT username, url, method, protocol, status, threat_level, bandwidth_kb, requested_at
        FROM logs
        ORDER BY requested_at DESC
        LIMIT 14
        """
    ).fetchall()
    blocked_activity = db.execute(
        """
        SELECT username, url, threat_level, requested_at
        FROM logs
        WHERE status = 'Blocked'
        ORDER BY requested_at DESC
        LIMIT 8
        """
    ).fetchall()
    blocked_sites = db.execute(
        """
        SELECT url, reason, created_at
        FROM blocked_sites
        ORDER BY created_at DESC, id DESC
        LIMIT 8
        """
    ).fetchall()
    activity_by_user = db.execute(
        """
        SELECT username, COUNT(*) AS total_events
        FROM logs
        GROUP BY username
        ORDER BY total_events DESC, username ASC
        LIMIT 6
        """
    ).fetchall()

    metrics = {
        "total_events": db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"],
        "security_alerts": db.execute(
            "SELECT COUNT(*) AS count FROM logs WHERE threat_level IN ('High', 'Critical')"
        ).fetchone()["count"],
        "blocked_events": db.execute(
            "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
        ).fetchone()["count"],
        "policy_rules": db.execute("SELECT COUNT(*) AS count FROM blocked_sites").fetchone()["count"],
    }
    return metrics, system_logs, blocked_activity, blocked_sites, activity_by_user


def display_host(url):
    parsed = urlparse(url)
    return parsed.netloc or url


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


@app.errorhandler(500)
def internal_error(error):
    tb = traceback.format_exc()
    print(f"CRITICAL ERROR:\n{tb}")
    return Response(
        json.dumps({
            "error": "Internal Server Error",
            "message": str(error),
            "traceback": tb
        }),
        status=500,
        mimetype='application/json'
    )


def hash_password(password):
    return generate_password_hash(password)


def verify_password(stored_password, provided_password):
    if not stored_password:
        return False
    if stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:"):
        return check_password_hash(stored_password, provided_password)
    return stored_password == provided_password


def get_current_user():
    username = session.get("user")
    return get_db().execute(
        "SELECT username, full_name, email, role, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            user = get_current_user()
            if not user or user["role"] != role:
                if role == "admin":
                    return render_template("access_denied.html"), 403
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def ensure_proxy_server():
    global proxy_thread
    with proxy_lock:
        if proxy_thread is None or not proxy_thread.is_alive():
            proxy_thread = start_proxy_server(str(DATABASE), host=PROXY_HOST, port=PROXY_PORT)
    return proxy_thread


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.before_request
def update_last_active():
    if "user" in session:
        db = get_db()
        db.execute(
            "UPDATE users SET last_active_at = ? WHERE username = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session["user"]),
        )
        db.commit()


@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    try:
        if "user" not in session:
            return Response(json.dumps({"error": "Unauthorized"}), status=401, mimetype='application/json')
        
        stats, _ = get_overview_data()
        # Bulletproof manual serialization
        json_data = json.dumps(stats, default=str)
        return Response(json_data, mimetype='application/json')
    except Exception as e:
        print(f"DEBUG ERROR [dashboard-stats]: {e}")
        return Response(json.dumps({"error": "Internal Server Error", "message": str(e)}), status=500, mimetype='application/json')


@app.route("/api/traffic-feed")
def api_traffic_feed():
    try:
        if "user" not in session:
            return Response(json.dumps({"error": "Unauthorized"}), status=401, mimetype='application/json')
        
        _, _, _, traffic_feed, _ = get_traffic_data()
        # Bulletproof manual serialization
        json_data = json.dumps(traffic_feed, default=str)
        return Response(json_data, mimetype='application/json')
    except Exception as e:
        print(f"DEBUG ERROR [traffic-feed]: {e}")
        return Response(json.dumps({"error": "Internal Server Error", "message": str(e)}), status=500, mimetype='application/json')


@app.route("/api/system-logs")
def api_system_logs():
    try:
        if "user" not in session:
            return Response(json.dumps({"error": "Unauthorized"}), status=401, mimetype='application/json')
        
        _, system_logs, _, _, _ = get_logs_data()
        # Bulletproof manual serialization
        json_data = json.dumps(rows_to_dicts(system_logs), default=str)
        return Response(json_data, mimetype='application/json')
    except Exception as e:
        print(f"DEBUG ERROR [system-logs]: {e}")
        return Response(json.dumps({"error": "Internal Server Error", "message": str(e)}), status=500, mimetype='application/json')


@app.route("/")
def home():
    return render_template("home.html", active_page="home")


@app.route("/about")
def about():
    return render_template("about.html", active_page="about")


@app.route("/login", methods=["GET", "POST"])
@app.route("/signin", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = get_db().execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and verify_password(user["password"], password):
            db_user = get_db().execute(
                "SELECT role FROM users WHERE username = ?",
                (user["username"],),
            ).fetchone()
            session["user"] = user["username"]
            session["role"] = db_user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html", active_page="login")


@app.route("/register", methods=["GET", "POST"])
@app.route("/signup", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        role = request.form.get("role", "user")
        admin_passcode = request.form.get("admin_passcode", "")

        if not username or not password or not confirm_password:
            flash("Username and password are required")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        if role == "admin" and admin_passcode != ADMIN_REGISTRATION_PASSCODE:
            flash("Invalid Admin Registration Passcode")
            return redirect(url_for("register"))

        db = get_db()
        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing_user:
            flash("User already exists")
        else:
            db.execute(
                "INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
                (username, hash_password(password), full_name, email, role),
            )
            db.commit()
            flash("Account created successfully. Please login.")
            return redirect(url_for("login"))

    return render_template("register.html", active_page="register")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        new_password = request.form["new_password"]

        if not username or not new_password:
            flash("Username and new password are required")
            return render_template("forgot_password.html", active_page="forgot_password")

        db = get_db()
        user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user:
            flash("User not found")
        else:
            db.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            db.commit()
            flash("Password updated successfully. Please log in.")
            return redirect(url_for("login"))

    return render_template("forgot_password.html", active_page="forgot_password")

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    current = request.form.get('current_password')
    new = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    db = get_db()

    user = db.execute(
        'SELECT * FROM users WHERE username = ?',
        (session['user'],)
    ).fetchone()

    if not user or not verify_password(user['password'], current):
        flash("Current password is incorrect")
        return redirect(url_for('settings'))

    if not new or new != confirm:
        flash("New passwords do not match")
        return redirect(url_for('settings'))

    db.execute(
        'UPDATE users SET password = ? WHERE username = ?',
        (hash_password(new), session['user'])
    )
    db.commit()

    flash("Password updated successfully")
    return redirect(url_for('settings'))




@app.route("/dashboard")
def dashboard():
    try:
        if "user" not in session:
            return redirect(url_for("login"))

        ensure_proxy_server()
        stats, latest_users = get_overview_data()

        return render_template(
            "dashboard.html",
            username=session["user"],
            stats=stats,
            latest_users=latest_users,
            proxy_host=PROXY_HOST,
            proxy_port=PROXY_PORT,
            active_page="dashboard",
        )
    except Exception as e:
        tb = traceback.format_exc()
        return f"<h1>Dashboard Error</h1><pre>{tb}</pre>", 500


@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))

    user = get_current_user()
    recent_activity = get_db().execute(
        """
        SELECT url, status, requested_at
        FROM logs
        WHERE username = ?
        ORDER BY requested_at DESC
        LIMIT 6
        """,
        (session["user"],),
    ).fetchall()
    return render_template(
        "profile.html",
        username=session["user"],
        user=user,
        recent_activity=recent_activity,
        display_host=display_host,
        active_page="profile",
    )


@app.route("/admin/users")
@role_required("admin")
def admin_users():
    db = get_db()
    users_rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    
    users = []
    now = datetime.now()
    for row in users_rows:
        user = dict(row)
        # Determine online status (active in last 5 minutes)
        is_online = False
        if user.get("last_active_at"):
            try:
                last_active = datetime.strptime(user["last_active_at"], "%Y-%m-%d %H:%M:%S")
                if now - last_active < timedelta(minutes=5):
                    is_online = True
            except:
                pass
        user["is_online"] = is_online
        users.append(user)
        
    return render_template("admin_users.html", users=users, active_page="admin_users")

@app.route("/admin/users/block/<username>")
@role_required("admin")
def block_user(username):
    db = get_db()
    db.execute("UPDATE users SET status = 'Blocked' WHERE username = ?", (username,))
    db.commit()
    flash(f"User {username} has been blocked.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/unblock/<username>")
@role_required("admin")
def unblock_user(username):
    db = get_db()
    db.execute("UPDATE users SET status = 'Active' WHERE username = ?", (username,))
    db.commit()
    flash(f"User {username} has been unblocked.")
    return redirect(url_for("admin_users"))

@app.route("/admin/blocked-sites", methods=["GET", "POST"])
@role_required("admin")
def admin_blocked_sites():
    db = get_db()
    if request.method == "POST":
        url = request.form.get("url").strip()
        reason = request.form.get("reason").strip()
        if url:
            db.execute("INSERT OR REPLACE INTO blocked_sites (url, reason) VALUES (?, ?)", (url, reason))
            db.commit()
            flash(f"Site {url} blocked successfully.")
        return redirect(url_for("admin_blocked_sites"))

    sites = db.execute("SELECT * FROM blocked_sites ORDER BY created_at DESC").fetchall()
    return render_template("admin_blocked_sites.html", sites=sites, active_page="admin_blocked_sites")

@app.route("/admin/blocked-sites/remove/<int:id>")
@role_required("admin")
def remove_blocked_site(id):
    db = get_db()
    db.execute("DELETE FROM blocked_sites WHERE id = ?", (id,))
    db.commit()
    flash("Site unblocked successfully.")
    return redirect(url_for("admin_blocked_sites"))

@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))

    preferences = {
        "session_security": "Enabled",
        "traffic_alerts": "Email alerts for blocked requests",
        "log_retention": "30 days",
        "role": "Administrator",
    }
    return render_template(
        "settings.html",
        username=session["user"],
        preferences=preferences,
        active_page="settings",
    )


@app.route("/traffic")
@role_required("admin")
def traffic():
    if "user" not in session:
        return redirect(url_for("login"))
    ensure_proxy_server()
    summary, protocol_rows, top_destinations, traffic_feed, recent_alerts = get_traffic_data()
    return render_template(
        "traffic.html",
        username=session["user"],
        summary=summary,
        protocol_rows=protocol_rows,
        top_destinations=top_destinations,
        traffic_feed=traffic_feed,
        recent_alerts=recent_alerts,
        display_host=display_host,
        proxy_host=PROXY_HOST,
        proxy_port=PROXY_PORT,
        active_page="traffic",
    )


@app.route("/logs")
@role_required("admin")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))
    ensure_proxy_server()
    metrics, system_logs, blocked_activity, blocked_sites, activity_by_user = get_logs_data()
    return render_template(
        "logs.html",
        username=session["user"],
        metrics=metrics,
        system_logs=system_logs,
        blocked_activity=blocked_activity,
        blocked_sites=blocked_sites,
        activity_by_user=activity_by_user,
        display_host=display_host,
        active_page="logs",
    )


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return redirect(url_for("home"))


init_db()


if __name__ == "__main__":
    ensure_proxy_server()
    app.run(debug=True, use_reloader=False)
