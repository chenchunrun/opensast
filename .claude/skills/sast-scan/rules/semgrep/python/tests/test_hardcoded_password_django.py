import os


# ruleid: python.security.hardcoded-password-django,python.security.hardcoded-secret-string
PASSWORD = "hardcoded-password"

# ok: python.security.hardcoded-password-django
PASSWORD = os.environ.get("DB_PASSWORD")

# ruleid: python.security.hardcoded-password-django
SECRET_KEY = "hardcoded-secret"

# ok: python.security.hardcoded-password-django
SECRET_KEY = os.environ.get("SECRET_KEY")

# ruleid: python.security.hardcoded-password-django
DATABASES = {"default": {"PASSWORD": "hardcoded-db-password"}}
