# Python taint multi-file scenario tests
# Simulates: request.args → service layer → database execution
# These test that Semgrep taint tracking follows data across functions and modules.

# --- File A: web handler (the entry point) ---

from flask import Flask, request
from services.user_service import search_users, update_user_profile

app = Flask(__name__)


@app.route("/api/users/search")
def search_handler():
    # Source: user input enters the application
    query = request.args.get("q")
    # ruleid: python.security.taint-sql-injection
    results = search_users(query)
    return {"results": results}


@app.route("/api/users/<int:user_id>/profile", methods=["POST"])
def profile_handler(user_id):
    name = request.form.get("name")
    bio = request.form.get("bio")
    # ruleid: python.security.taint-sql-injection
    update_user_profile(user_id, name, bio)
    return {"status": "ok"}


@app.route("/api/admin/run")
def admin_handler():
    cmd = request.args.get("cmd")
    import subprocess
    # ruleid: python.security.taint-command-injection
    subprocess.run(cmd, shell=True)
    return {"ran": cmd}


@app.route("/api/export")
def export_handler():
    filepath = request.args.get("path")
    # ruleid: python.security.taint-path-traversal
    with open(filepath) as f:
        data = f.read()
    return {"data": data}


@app.route("/api/webhook")
def webhook_handler():
    callback_url = request.args.get("callback")
    import requests
    # ruleid: python.security.taint-ssrf
    resp = requests.get(callback_url)
    return {"status": resp.status_code}


@app.route("/api/safe/search")
def safe_search_handler():
    query = request.args.get("q")
    # ok: python.security.taint-sql-injection
    results = safe_search(query)
    return {"results": results}


# --- Safe implementations ---

def safe_search(query: str):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{query}%",))
    return cursor.fetchall()
