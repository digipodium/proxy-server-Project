import os
import sqlite3
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "secretkey"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", app.root_path)) / "CyberProxyDefender"
DATABASE = DATA_DIR / "users.db"


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_db():
    ensure_data_dir()
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    ensure_data_dir()
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    db.close()


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = get_db().execute(
            "SELECT username FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

        if user:
            session["user"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not username or not password or not confirm_password:
            flash("Username and password are required")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
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
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            db.commit()
            flash("Account created successfully. Please login.")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        new_password = request.form["new_password"]

        if not username or not new_password:
            flash("Username and new password are required")
            return render_template("forgot_password.html")

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
                (new_password, username),
            )
            db.commit()
            flash("Password updated successfully. Please log in.")
            return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    latest_users = db.execute(
        "SELECT username, created_at FROM users ORDER BY id DESC LIMIT 5"
    ).fetchall()

    stats = {
        "total_requests": 120,
        "blocked_requests": 25,
        "active_users": total_users,
    }

    return render_template(
        "dashboard.html",
        username=session["user"],
        stats=stats,
        latest_users=latest_users,
    )


@app.route("/traffic")
def traffic():
    if "user" not in session:
        return redirect(url_for("login"))
    flash("Traffic page coming soon.")
    return redirect(url_for("dashboard"))


@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))
    flash("Logs page coming soon.")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
