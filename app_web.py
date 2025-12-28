import base64
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, make_response

from db import (
    init_db, add_user, get_user,
    add_vault_item, list_vault_items,
    get_vault_secret, delete_vault_item
)

from crypto_utils import (
    hash_password, verify_password,
    generate_kdf_salt, derive_key,
    encrypt_password, decrypt_password
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# In-memory session store: session_id -> {"username": str, "key": bytes}
SESSION_STORE = {}


def get_session():
    sid = request.cookies.get("sid")
    if not sid:
        return None, None
    s = SESSION_STORE.get(sid)
    if not s:
        return sid, None
    return sid, s


def require_login():
    sid, s = get_session()
    if not s:
        return None
    return s


@app.get("/")
def home():
    s = require_login()
    if s:
        return redirect(url_for("vault"))
    return redirect(url_for("login"))


@app.get("/register")
def register_page():
    return render_template("register.html")


@app.post("/register")
def register_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("register_page"))

    if get_user(username):
        flash("User already exists.", "error")
        return redirect(url_for("register_page"))

    pw_hash = hash_password(password)
    salt = generate_kdf_salt()
    add_user(username, pw_hash, salt)

    flash("Registration successful ✅ עכשיו אפשר להתחבר.", "success")
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = get_user(username)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("login"))

    pw_hash, salt = user
    if not verify_password(password, pw_hash):
        flash("Wrong password.", "error")
        return redirect(url_for("login"))

    # Derive AES key (session key) from master password + salt
    session_key = derive_key(password, salt)

    # Create session id + store in memory
    sid = secrets.token_urlsafe(32)
    SESSION_STORE[sid] = {"username": username, "key": session_key}

    resp = make_response(redirect(url_for("vault")))
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp


@app.get("/logout")
def logout():
    sid, _ = get_session()
    if sid and sid in SESSION_STORE:
        del SESSION_STORE[sid]
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("sid", "", expires=0)
    flash("Logged out.", "success")
    return resp


@app.get("/vault")
def vault():
    s = require_login()
    if not s:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = s["username"]
    rows = list_vault_items(username)  # [(id, app_name, login_username), ...]

    return render_template("vault.html", username=username, rows=rows)


@app.post("/vault/add")
def vault_add():
    s = require_login()
    if not s:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    app_name = request.form.get("app_name", "").strip()
    login_username = request.form.get("login_username", "").strip()
    password = request.form.get("password", "")

    if not app_name or not login_username or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("vault"))

    nonce, ct, tag = encrypt_password(s["key"], password)
    add_vault_item(s["username"], app_name, login_username, nonce, ct, tag)

    flash("Saved ✅", "success")
    return redirect(url_for("vault"))


@app.post("/vault/view")
def vault_view():
    s = require_login()
    if not s:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    item_id = request.form.get("item_id", "").strip()
    if not item_id.isdigit():
        flash("Select a valid entry.", "error")
        return redirect(url_for("vault"))

    secret = get_vault_secret(s["username"], int(item_id))
    if not secret:
        flash("Entry not found.", "error")
        return redirect(url_for("vault"))

    nonce, ct, tag = secret
    try:
        plain = decrypt_password(s["key"], nonce, ct, tag)
    except Exception:
        flash("Decryption failed.", "error")
        return redirect(url_for("vault"))

    # נחזיר לדף vault עם popup קטן
    flash(f"Password: {plain}", "reveal")
    return redirect(url_for("vault"))


@app.post("/vault/delete")
def vault_delete():
    s = require_login()
    if not s:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    item_id = request.form.get("item_id", "").strip()
    if not item_id.isdigit():
        flash("Select a valid entry.", "error")
        return redirect(url_for("vault"))

    delete_vault_item(s["username"], int(item_id))
    flash("Deleted ✅", "success")
    return redirect(url_for("vault"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
