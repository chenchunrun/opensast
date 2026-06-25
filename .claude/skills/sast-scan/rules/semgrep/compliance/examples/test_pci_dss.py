# PCI-DSS compliance rule test fixtures

# --- pci-dss.logging-card-data ---

def process_payment_unsafe(card_number: str):
    import logging
    logger = logging.getLogger(__name__)
    # ruleid: pci-dss.logging-card-data
    logger.info("Processing payment", card_number=card_number)

def process_payment_safe(card_token: str):
    import logging
    logger = logging.getLogger(__name__)
    # ok: pci-dss.logging-card-data
    logger.info("Processing payment with token", token=card_token)

# --- pci-dss.default-credentials ---

# ruleid: pci-dss.default-credentials
password = "changeme"

# ruleid: pci-dss.default-credentials
admin_pass = "password"

# ok: pci-dss.default-credentials
username = "admin"

# --- pci-dss.sql-string-concatenation ---

def search_users(user_input: str):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # ruleid: pci-dss.sql-string-concatenation
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")

def safe_search(user_id: int):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # ok: pci-dss.sql-string-concatenation
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
