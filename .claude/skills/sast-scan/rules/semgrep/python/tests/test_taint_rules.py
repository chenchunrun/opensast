import subprocess
import pickle
import pathlib
import requests
import urllib.request


def taint_sql(cursor, request):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python.security.taint-sql-injection
    cursor.execute(sql)

    # ok: python.security.taint-sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s", (1,))


def taint_command(request):
    cmd = request.form.get("cmd")
    # ruleid: python.security.taint-command-injection
    subprocess.run(cmd, shell=True)

    # ok: python.security.taint-command-injection
    subprocess.run(["ls", "-la"])


def taint_eval(request):
    expr = request.GET.get("expr")
    # ruleid: python.security.taint-eval
    eval(expr)

    # ok: python.security.taint-eval
    eval("1 + 1")


def taint_path(request):
    path = request.args.get("file")
    # ruleid: python.security.taint-path-traversal
    open(path, "r")

    # ok: python.security.taint-path-traversal
    open("/etc/app/config.json", "r")


def taint_ssrf(request):
    url = request.form.get("url")
    # ruleid: python.security.taint-ssrf
    requests.get(url)

    # ok: python.security.taint-ssrf
    requests.get("https://api.example.com/health")


def taint_pickle(request):
    data = request.args.get("blob")
    # ruleid: python.security.taint-pickle
    pickle.loads(data.encode())
