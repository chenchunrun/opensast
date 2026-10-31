# ruleid: nist800-53.cm6-debug-config
DEBUG = True
# ok: nist800-53.cm6-debug-config
DEBUG = False

# ruleid: nist800-53.ac7-no-rate-limiting-python
@app.post("/login")
def login():
    return authenticate()

# ruleid: nist800-53.au2-no-audit-log-python
def delete_user(user):
    db.delete(user)

# ok: nist800-53.au2-no-audit-log-python
def delete_user(user):
    logger.audit("delete user", user.id)
    db.delete(user)
