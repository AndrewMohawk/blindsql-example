import json
import logging
import os
import secrets
import sqlite3
import threading
import time

from flask import Flask, g, redirect, render_template_string, request, session, url_for


ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
FLAG = os.environ["CHALLENGE_FLAG"]

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")
timing_log = logging.getLogger("blindsql.timing")
app.secret_key = os.environ["SESSION_SECRET"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=4096,
)

PAGE = """<!doctype html>
<html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>BlindSQL Timing Lab</title>
<style>
body{margin:0;background:#09111c;color:#dbeafe;font:16px system-ui,sans-serif;display:grid;min-height:100vh;place-items:center}
main{width:min(92vw,34rem);background:#111c2d;border:1px solid #29405f;border-radius:16px;padding:2rem;box-shadow:0 20px 60px #0008}
h1{margin:.2rem 0;color:#67e8f9}p{line-height:1.5}.hint{color:#94a3b8;font-size:.9rem}
label{display:block;margin:1rem 0 .35rem}input{box-sizing:border-box;width:100%;padding:.8rem;background:#07101d;color:white;border:1px solid #3b5475;border-radius:8px}
button{margin-top:1.2rem;padding:.8rem 1.2rem;border:0;border-radius:8px;background:#22d3ee;color:#06202a;font-weight:700;cursor:pointer}
.error{background:#451a1a;color:#fecaca;padding:.7rem;border-radius:8px}.flag{background:#052e2b;color:#99f6e4;padding:1rem;border-radius:8px;overflow-wrap:anywhere}
code{color:#f0abfc}a{color:#67e8f9}
</style><main>
{% if flag %}<h1>Challenge complete</h1><p>You recovered the administrator credential.</p><div class=flag><code>{{ flag }}</code></div><p><a href="{{ url_for('logout') }}">Log out</a></p>
{% else %}<h1>BlindSQL Timing Lab</h1><p>The flag is available only to the <code>admin</code> account.</p>
<p class=hint>Training target: the username lookup uses SQLite and exposes a bounded <code>sleep_ms(n)</code> function. Infer the password with response timing, then log in normally.</p>
{% if error %}<p class=error>{{ error }}</p>{% endif %}
<form method=post><label for=username>Username</label><input id=username name=username maxlength=500 required autocomplete=off>
<label for=password>Password</label><input id=password name=password type=password maxlength=500 required autocomplete=off>
<button type=submit>Sign in</button></form>{% endif %}
</main></html>"""


def database():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
    db.execute("INSERT INTO users VALUES (?, ?)", ("admin", ADMIN_PASSWORD))

    def sleep_ms(value):
        try:
            milliseconds = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("sleep_ms requires an integer") from exc
        if milliseconds < 0:
            raise ValueError("sleep_ms rejects negative values")
        milliseconds = min(milliseconds, 250)
        time.sleep(milliseconds / 1000)
        return 0

    db.create_function("sleep_ms", 1, sleep_ms)
    return db


@app.before_request
def start_request_timing():
    g.request_id = secrets.token_hex(8)
    g.handler_start_ns = time.monotonic_ns()
    g.vulnerable_start_ns = None
    g.vulnerable_finish_ns = None


@app.after_request
def log_request_timing(response):
    timing_log.info(
        json.dumps(
            {
                "event": "request_timing",
                "request_id": g.get("request_id"),
                "handler_start_ns": g.get("handler_start_ns"),
                "vulnerable_query_start_ns": g.get("vulnerable_start_ns"),
                "vulnerable_query_finish_ns": g.get("vulnerable_finish_ns"),
                "worker_pid": os.getpid(),
                "thread_id": threading.get_ident(),
                "application_protocol": request.environ.get("SERVER_PROTOCOL", "unknown"),
                "status": response.status_code,
            },
            separators=(",", ":"),
        )
    )
    return response


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "blindsql"}


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("username") == "admin":
        return render_template_string(PAGE, flag=FLAG, error=None)

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")[:500]
        password = request.form.get("password", "")[:500]
        account = None
        try:
            with database() as db:
                # Deliberately vulnerable timing oracle. Its result is never
                # consulted for authentication or session creation.
                vulnerable_query = f"SELECT 1 FROM users WHERE username = '{username}' LIMIT 1"
                g.vulnerable_start_ns = time.monotonic_ns()
                try:
                    db.execute(vulnerable_query).fetchone()
                finally:
                    g.vulnerable_finish_ns = time.monotonic_ns()

                # This independent parameterized query is the only source of
                # authentication truth.
                account = db.execute(
                    "SELECT username FROM users WHERE username = ? AND password = ?",
                    (username, password),
                ).fetchone()
        except sqlite3.Error:
            account = None
        if account and account[0] == "admin":
            session.clear()
            session["username"] = "admin"
            return redirect(url_for("login"), code=303)
        error = "Invalid username or password."
    return render_template_string(PAGE, flag=None, error=error), (401 if error else 200)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
