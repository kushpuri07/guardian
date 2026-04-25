import sqlite3

def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'supersecret123', 'admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'password456', 'user')")
    conn.commit()
    return conn

def login(username: str, password: str) -> dict:
    """
    Authenticate a user by username and password.
    Returns user dict if successful, None otherwise.
    """
    conn = get_db()
    
    # ⚠️  VULNERABLE: direct string interpolation — SQL injection possible
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    cursor = conn.execute(query)
    user   = cursor.fetchone()
    conn.close()
    
    if user:
        return {"id": user[0], "username": user[1], "role": user[3]}
    return None


def get_user_profile(user_id: int) -> dict:
    conn = get_db()
    cursor = conn.execute(f"SELECT id, username, role FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "username": user[1], "role": user[2]}
    return None


if __name__ == "__main__":
    # Test normal login
    result = login("alice", "password456")
    print(f"Normal login: {result}")