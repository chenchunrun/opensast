import sqlite3
import psycopg2

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()


def vulnerable_queries(uid, name, pid):
    # Positive: f-string in SQL query
    # ruleid: python.security.sql-injection-string-concat
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")

    # ruleid: python.security.sql-injection-string-concat
    cursor.execute(f"DELETE FROM users WHERE name = '{name}'")

    # Positive: string concatenation
    # ruleid: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM users WHERE id = " + uid)

    # Positive: percent formatting
    # ruleid: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)

    # Positive: .format()
    # ruleid: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))

    # Positive: conn.execute with f-string
    # ruleid: python.security.sql-injection-string-concat
    conn.execute(f"SELECT * FROM products WHERE id = '{pid}'")


def safe_queries(uid, pid):
    # Negative: parameterized query
    # ok: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))

    # ok: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))

    # ok: python.security.sql-injection-string-concat
    conn.execute("SELECT * FROM products WHERE id = %s", (pid,))

    # ok: python.security.sql-injection-string-concat
    cursor.execute(f"SELECT * FROM users")

    # ok: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM " + "users")

    # ok: python.security.sql-injection-string-concat
    conn.execute("SELECT * FROM %s" % "users")

    # ok: python.security.sql-injection-string-concat
    cursor.execute("SELECT * FROM {}".format("users"))
