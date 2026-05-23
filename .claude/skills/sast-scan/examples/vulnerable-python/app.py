"""Vulnerable Python code for SAST testing."""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "")
    # Command injection vulnerability
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/eval")
def eval_expression():
    expr = request.args.get("expr", "")
    # Arbitrary code execution
    return str(eval(expr))


@app.route("/sql")
def sql_query():
    import sqlite3
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    # SQL injection
    cursor = conn.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return str(cursor.fetchall())


# Hardcoded secret
DATABASE_URL = "postgresql://admin:SuperSecret123@db.example.com:5432/prod"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
