# Test corpus for Python rules
# Lines with # ruleid: should trigger
# Lines with # ok: should NOT trigger

import os
import subprocess
import pickle
import yaml
import hashlib
import tempfile
import random

# --- command-injection ---

# ruleid: python.security.command-injection-subprocess
subprocess.run(cmd, shell=True)

# ok: python.security.command-injection-subprocess
subprocess.run(["ls", "-la"])

# ok: python.security.command-injection-subprocess
subprocess.run("ls -la", shell=False)

# --- sql-injection ---

# ruleid: python.security.sql-injection-string-concat
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ruleid: python.security.sql-injection-string-concat
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# ok: python.security.sql-injection-string-concat
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# --- eval ---

# ruleid: python.security.eval-usage
eval(user_input)

# ok: python.security.eval-usage
eval("2 + 2")

# --- pickle ---

# ruleid: python.security.pickle-load
pickle.loads(data)

# ruleid: python.security.pickle-load
pickle.load(f)

# --- yaml ---

# ruleid: python.security.yaml-unsafe-load
yaml.load(data)

# ok: python.security.yaml-unsafe-load
yaml.safe_load(data)

# ok: python.security.yaml-unsafe-load
yaml.load(data, Loader=yaml.SafeLoader)

# --- hardcoded-secret ---

# ruleid: python.security.hardcoded-secret-string
db_password = "password123"

# ok: python.security.hardcoded-secret-string
db_password = os.environ.get("DB_PASSWORD")

# --- weak-hash ---

# ruleid: python.security.weak-hash-md5
hashlib.md5(data)

# ruleid: python.security.weak-hash-sha1
hashlib.sha1(data)

# ok: python.security.weak-hash-md5
hashlib.sha256(data)

# --- ssl-no-verify ---

# ruleid: python.security.insecure-ssl-no-verify
requests.get(url, verify=False)

# --- flask-debug ---

# ruleid: python.security.flask-debug
app.run(debug=True)

# --- tempfile ---

# ruleid: python.security.tempfile-insecure
tempfile.mktemp()

# ok: python.security.tempfile-insecure
tempfile.mkstemp()

# --- django-debug ---

# ruleid: python.security.django-debug
DEBUG = True
