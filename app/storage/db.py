"""MySQL users table + salted hashing (no chat storage).""" 

import pymysql
import hashlib
import os

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "rootpass")
MYSQL_DB = os.getenv("MYSQL_DATABASE", "securechat")

# Connect to MySQL
conn = pymysql.connect(
    host=MYSQL_HOST,
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DB
)

def create_user(username: str, password: str) -> bool:
    salt = os.urandom(16).hex()
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    with conn.cursor() as cur:
        try:
            cur.execute("INSERT INTO users (username, salt, password_hash) VALUES (%s, %s, %s)", (username, salt, pw_hash))
            conn.commit()
            return True
        except Exception:
            return False

def verify_user(username: str, password: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT salt, password_hash FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        if not row:
            return False
        salt, pw_hash = row
        check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return check_hash == pw_hash
