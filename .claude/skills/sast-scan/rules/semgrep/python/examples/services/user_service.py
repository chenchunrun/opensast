# services/user_service.py — simulated service layer called from web handler
# These functions receive tainted data from the handler and pass it to sinks.


def search_users(query: str):
    """Vulnerable: passes raw query string into SQL."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # This is reached by taint from search_handler()
    cursor.execute("SELECT * FROM users WHERE name LIKE '%" + query + "%'")
    return cursor.fetchall()


def update_user_profile(user_id: int, name: str, bio: str):
    """Vulnerable: string concatenation into SQL."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # name is tainted from profile_handler
    cursor.execute(
        "UPDATE users SET name='" + name + "', bio='" + bio + "' WHERE id=" + str(user_id)
    )
    conn.commit()


def search_users_safe(query: str):
    """Safe: uses parameterized query."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{query}%",))
    return cursor.fetchall()
