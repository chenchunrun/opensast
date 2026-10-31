from flask import request

def load_user(cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id=%s", [user_id])
