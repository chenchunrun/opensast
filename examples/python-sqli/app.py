"""Minimal Flask app with SQL injection (for /sast-scan demos)."""

from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: string-built query
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchone())
