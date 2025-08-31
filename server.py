import os
import sqlite3
import datetime
import random
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, flash, abort

APP_TITLE = "🎮 Private Game Server"
DB_PATH = "keys.db"
GAME_FOLDER = os.path.join(os.getcwd(), "Games")
LOG_LIMIT = 200

# Admin password (change via env var recommended)
ADMIN_PASSWORD = "Dark2502"
SECRET_KEY = "RandomSecret2502"

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("PGS_SECRET_KEY", "dev-secret-key")


# ---------- Database utilities ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS keys( key TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, last_used TEXT, usage_count INTEGER NOT NULL DEFAULT 0 )")
    cur.execute("CREATE TABLE IF NOT EXISTS logs( id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT NOT NULL, key TEXT, filename TEXT, ip TEXT )")
    conn.commit()
    conn.close()

def log(action, key=None, filename=None):
    conn = db()
    conn.execute("INSERT INTO logs(ts,action,key,filename,ip) VALUES(?,?,?,?,?)",
                 (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, key, filename, request.remote_addr if request else None))
    conn.commit()
    conn.close()


# ---------- Key utilities ----------
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def random_key():
    parts = []
    for _ in range(4):
        parts.append("".join(random.choice(ALPHABET) for __ in range(4)))
    return "-".join(parts)

def ensure_unique_keys(n):
    conn = db()
    cur = conn.cursor()
    created = 0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    while created < n:
        k = random_key()
        try:
            cur.execute("INSERT INTO keys(key,status,created_at) VALUES(?,?,?)", (k, "active", now))
            created += 1
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    conn.close()
    return created

def key_status(k):
    conn = db()
    row = conn.execute("SELECT status FROM keys WHERE key=?", (k,)).fetchone()
    conn.close()
    return row["status"] if row else None

def mark_usage(k):
    conn = db()
    conn.execute("UPDATE keys SET usage_count = usage_count + 1, last_used = ? WHERE key = ?",
                 (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), k))
    conn.commit()
    conn.close()


# ---------- Public routes ----------
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        k = request.form.get("key", "").strip().upper()
    else:
        # 👇 NEW: support ?key=... in the URL
        k = request.args.get("key", "").strip().upper()

    if k:
        status = key_status(k)
        if status == "active":
            log("LOGIN_SUCCESS", k)
            files = sorted([f for f in os.listdir(GAME_FOLDER) if os.path.isfile(os.path.join(GAME_FOLDER, f))])
            session["key"] = k
            return render_template("downloads.html", title=APP_TITLE, files=files, key=k)
        elif status == "revoked":
            log("LOGIN_REVOKED", k)
            return render_template("index.html", title=APP_TITLE, error="This key has been revoked. Please contact support.")
        else:
            log("LOGIN_FAIL", k)
            return render_template("index.html", title=APP_TITLE, error="Invalid key.")

    return render_template("index.html", title=APP_TITLE)

@app.route("/get/<path:filename>")
def get_file(filename):
    k = session.get("key")
    if not k or key_status(k) != "active":
        abort(403)
    # Log and serve file
    log("DOWNLOAD", k, filename)
    mark_usage(k)
    return send_from_directory(GAME_FOLDER, filename, as_attachment=True)


# ---------- Admin routes ----------
def require_admin():
    return session.get("admin") is True

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Wrong password")
    return render_template("admin_login.html", title=APP_TITLE)

@app.route("/admin/dashboard")
def admin_dashboard():
    if not require_admin(): return redirect(url_for("admin_login"))
    conn = db()
    stats = conn.execute(
        "SELECT (SELECT COUNT(*) FROM keys) as total, (SELECT COUNT(*) FROM keys WHERE status='active') as active, (SELECT COUNT(*) FROM keys WHERE status='revoked') as revoked, (SELECT IFNULL(SUM(usage_count),0) FROM keys) as downloads"
    ).fetchone()
    logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (LOG_LIMIT,)).fetchall()
    conn.close()
    return render_template("admin_dashboard.html", title=APP_TITLE, stats=stats, logs=logs)

@app.route("/admin/keys")
def admin_keys():
    if not require_admin(): return redirect(url_for("admin_login"))
    q = request.args.get("q", "").strip().upper()
    status = request.args.get("status", "")
    conn = db()
    sql = "SELECT * FROM keys"
    params = []
    where = []
    if q:
        where.append("key LIKE ?")
        params.append(f"%{q}%")
    if status in ("active", "revoked"):
        where.append("status = ?")
        params.append(status)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT 500"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("admin_keys.html", title=APP_TITLE, keys=rows, q=q, status=status)

@app.route("/admin/key/revoke/<k>", methods=["POST"])
def revoke_key(k):
    if not require_admin(): return redirect(url_for("admin_login"))
    conn = db()
    conn.execute("UPDATE keys SET status='revoked' WHERE key=?", (k,))
    conn.commit()
    conn.close()
    flash(f"Key {k} revoked")
    log("ADMIN_REVOKE", k)
    return redirect(url_for("admin_keys"))

@app.route("/admin/key/activate/<k>", methods=["POST"])
def activate_key(k):
    if not require_admin(): return redirect(url_for("admin_login"))
    conn = db()
    conn.execute("UPDATE keys SET status='active' WHERE key=?", (k,))
    conn.commit()
    conn.close()
    flash(f"Key {k} activated")
    log("ADMIN_ACTIVATE", k)
    return redirect(url_for("admin_keys"))

@app.route("/admin/key/add", methods=["POST"])
def add_key():
    if not require_admin(): return redirect(url_for("admin_login"))
    k = request.form.get("key", "").strip().upper()
    if not k:
        k = random_key()
    conn = db()
    try:
        conn.execute("INSERT INTO keys(key,status,created_at) VALUES(?,?,?)", (k, "active", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        flash(f"Key added: {k}")
        log("ADMIN_ADD_KEY", k)
    except sqlite3.IntegrityError:
        flash("Key already exists")
    conn.close()
    return redirect(url_for("admin_keys"))

@app.route("/admin/key/generate", methods=["POST"])
def generate_keys():
    if not require_admin(): return redirect(url_for("admin_login"))
    try:
        n = int(request.form.get("count", "1000"))
        n = max(1, min(n, 100000))
    except:
        n = 1000
    created = ensure_unique_keys(n)
    flash(f"Generated {created} keys")
    log("ADMIN_GENERATE", filename=str(created))
    return redirect(url_for("admin_keys"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    flash("Logged out")
    return redirect(url_for("admin_login"))


# ---------- Startup ----------
if __name__ == "__main__":
    os.makedirs(GAME_FOLDER, exist_ok=True)
    init_db()
    conn = db()
    total = conn.execute("SELECT COUNT(*) as c FROM keys").fetchone()["c"]
    conn.close()
    if total == 0:
        ensure_unique_keys(1000)  # seed 1,000 keys on first run
    app.run(host="0.0.0.0", port=8080)
