import sqlite3

DB_NAME = "vault.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash BLOB NOT NULL,
        kdf_salt BLOB NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_username TEXT NOT NULL,
        app_name TEXT NOT NULL,
        login_username TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        tag TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(owner_username) REFERENCES users(username)
    )
    """)

    conn.commit()
    conn.close()


def add_user(username, password_hash, kdf_salt):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (username, password_hash, kdf_salt) VALUES (?, ?, ?)",
        (username, password_hash, kdf_salt)
    )

    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash, kdf_salt FROM users WHERE username = ?",
        (username,)
    )

    row = cur.fetchone()
    conn.close()
    return row


def add_vault_item(owner_username, app_name, login_username, nonce, ciphertext, tag):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO vault (owner_username, app_name, login_username, nonce, ciphertext, tag)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (owner_username, app_name, login_username, nonce, ciphertext, tag))

    conn.commit()
    conn.close()


def list_vault_items(owner_username):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, app_name, login_username
        FROM vault
        WHERE owner_username = ?
        ORDER BY app_name COLLATE NOCASE
    """, (owner_username,))

    rows = cur.fetchall()
    conn.close()
    return rows


def get_vault_secret(owner_username, item_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT nonce, ciphertext, tag
        FROM vault
        WHERE owner_username = ? AND id = ?
    """, (owner_username, item_id))

    row = cur.fetchone()
    conn.close()
    return row


def update_vault_item(owner_username, item_id, app_name, login_username, nonce, ciphertext, tag):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE vault
        SET app_name = ?, login_username = ?, nonce = ?, ciphertext = ?, tag = ?
        WHERE owner_username = ? AND id = ?
    """, (app_name, login_username, nonce, ciphertext, tag, owner_username, item_id))

    conn.commit()
    conn.close()


def delete_vault_item(owner_username, item_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM vault
        WHERE owner_username = ? AND id = ?
    """, (owner_username, item_id))

    conn.commit()
    conn.close()
