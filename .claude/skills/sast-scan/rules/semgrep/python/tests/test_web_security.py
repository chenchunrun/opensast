import hashlib
import hmac
import os
import pathlib
import random
import requests
import tempfile
from flask import redirect
from django.http import HttpResponseRedirect


# ruleid: python.security.ssrf-requests
requests.get(user_url)

# ok: python.security.ssrf-requests
requests.get("https://api.example.com")

# ok: python.security.ssrf-requests
requests.get(settings.API_URL)

# ok: python.security.ssrf-requests
requests.post(INTERNAL_ENDPOINT, json=payload)

# ruleid: python.security.path-traversal
open(request.args.get("file"), "r")

# ruleid: python.security.path-traversal
open(os.path.join(base_dir, request.args.get("file")))

# ok: python.security.path-traversal
open("/etc/hosts", "r")

# ok: python.security.path-traversal
open(os.path.join("/safe", "base", "file.txt"), "r")

# ok: python.security.path-traversal
open(os.path.abspath("config.json"), "r")

# ok: python.security.path-traversal
pathlib.Path(__file__).parent / "template.html"

# ruleid: python.security.open-redirect
redirect(next_url)

# ok: python.security.open-redirect
redirect("/dashboard")

# ruleid: python.security.open-redirect
HttpResponseRedirect(next_url)

# ok: python.security.open-redirect
HttpResponseRedirect("/dashboard")

# ruleid: python.security.insecure-random
random.randint(1, 10)

# ok: python.security.insecure-random
random.shuffle(items)

# ruleid: python.security.timing-attack
if password == user_input:
    pass

# ok: python.security.timing-attack
hmac.compare_digest(api_token, user_input)

# ruleid: python.security.flask-debug
app.run(debug=True)

# ruleid: python.security.django-debug
DEBUG = True

# ruleid: python.security.csrf-disabled-django
@csrf_exempt
def webhook(request):
    return None

# ruleid: python.security.insecure-cookie-django
SESSION_COOKIE_SECURE = False

# ruleid: python.security.weak-hash-md5
hashlib.md5(data)

# ruleid: python.security.weak-hash-sha1
hashlib.sha1(data)

# ok: python.security.weak-hash-sha1
hashlib.sha256(data)

# ruleid: python.security.insecure-ssl-no-verify
requests.get(url, verify=False)

# ok: python.security.insecure-ssl-no-verify
requests.get(url, verify=True)

# ruleid: python.security.tempfile-insecure
tempfile.mktemp()

# ok: python.security.tempfile-insecure
tempfile.mkstemp()

# ruleid: python.security.assert-in-production
assert user.is_admin, "must be admin"

# ok: python.security.assert-in-production
if not user.is_admin:
    raise PermissionError("must be admin")

# ruleid: python.security.flask-secret-key-weak
app.secret_key = "dev"

# ok: python.security.flask-secret-key-weak
app.secret_key = os.environ.get("SECRET_KEY")

# ok: python.security.flask-secret-key-weak
app.secret_key = ""

# ok: python.security.flask-secret-key-weak
app.config["SECRET_KEY"] = "this-is-a-long-random-secret-key-that-is-not-weak"
