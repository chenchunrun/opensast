import os

# Positive: hardcoded password
# ruleid: python.security.hardcoded-secret-string
password = "hardcoded123"

# Positive: hardcoded secret
# ruleid: python.security.hardcoded-secret-string
db_secret = "super_secret_value"

# Positive: hardcoded api key
# ruleid: python.security.hardcoded-secret-string
api_key = "sk-1234567890abcdef"

# Positive: hardcoded token
# ruleid: python.security.hardcoded-secret-string
auth_token = "Bearer abc123def456"

# Negative: environment variable
# ok: python.security.hardcoded-secret-string
password = os.environ.get("DB_PASS")

# ok: python.security.hardcoded-secret-string
api_key = os.getenv("API_KEY")

# ok: python.security.hardcoded-secret-string
token = os.environ.get("AUTH_TOKEN")
