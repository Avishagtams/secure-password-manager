import secrets
import re
import time
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify

from db import (
    init_db, add_user, get_user,
    add_vault_item, list_vault_items,
    get_vault_secret, delete_vault_item,
    update_vault_item
)

from crypto_utils import (
    hash_password, verify_password,
    generate_kdf_salt, derive_key,
    encrypt_password, decrypt_password
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# In-memory session store: session_id -> {"username": str, "key": bytes, "last_seen": float}
SESSION_STORE = {}

# ---- Login rate limiting / lockout ----
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60  # 5 minutes
LOGIN_GUARD = {}  # username -> {"count": int, "locked_until": float}

# ---- Session timeout ----
SESSION_TIMEOUT_SECONDS = 20 * 60  # 20 minutes


# -------- Password strength check --------
def is_strong_password(pw: str) -> tuple[bool, str]:
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", pw):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]", pw):
        return False, "Password must include at least one special character."
    if re.search(r"\s", pw):
        return False, "Password must not contain spaces."
    return True, ""


# -------- Login lockout helpers --------
def _is_locked(username: str) -> tuple[bool, int]:
    entry = LOGIN_GUARD.get(username)
    if not entry:
        return False, 0

    locked_until = entry.get("locked_until", 0)
    now = time.time()
    if locked_until and now < locked_until:
        return True, int(locked_until - now)
    return False, 0


def _register_failed_attempt(username: str) -> None:
    entry = LOGIN_GUARD.setdefault(username, {"count": 0, "locked_until": 0})
    entry["count"] += 1
    if entry["count"] >= MAX_LOGIN_ATTEMPTS:
        entry["locked_until"] = time.time() + LOCKOUT_SECONDS


def _clear_attempts(username: str) -> None:
    if username in LOGIN_GUARD:
        del LOGIN_GUARD[username]


# -------- Session helpers --------
def get_session():
    sid = request.cookies.get("sid")
    if not sid:
        return None, None

    s = SESSION_STORE.get(sid)
    if not s:
        return sid, None

    # Session timeout check
    now = time.time()
    last_seen = s.get("last_seen", now)
    if now - last_seen > SESSION_TIMEOUT_SECONDS:
        del SESSION_STORE[sid]
        return sid, None

    # Update last activity time
    s["last_seen"] = now
    return sid, s


def require_login():
    _, s = get_session()
    return s


# -------- Routes --------
@app.get("/")
def home():
    if require_login():
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

    ok, msg = is_strong_password(password)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("register_page"))

    if get_user(username):
        flash("User already exists.", "error")
        return redirect(url_for("register_page"))

    pw_hash = hash_password(password)
    salt = generate_kdf_salt()
    add_user(username, pw_hash, salt)

    flash("Registration successful ✅ You can now login.", "success")
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("login"))

    locked, remaining = _is_locked(username)
    if locked:
        flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
        return redirect(url_for("login"))

    user = get_user(username)
    if not user:
        _register_failed_attempt(username)
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))

    pw_hash, salt = user
    if not verify_password(password, pw_hash):
        _register_failed_attempt(username)
        left = max(0, MAX_LOGIN_ATTEMPTS - LOGIN_GUARD.get(username, {}).get("count", 0))
        if left > 0:
            flash(f"Invalid credentials. Attempts left: {left}.", "error")
        else:
            flash("Too many failed attempts. Locked for 5 minutes.", "error")
        return redirect(url_for("login"))

    # Success -> clear attempts
    _clear_attempts(username)

    # Derive AES session key from master password + per-user salt
    session_key = derive_key(password, salt)

    # Create session id + store in memory
    sid = secrets.token_urlsafe(32)
    SESSION_STORE[sid] = {"username": username, "key": session_key, "last_seen": time.time()}

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

    rows = list_vault_items(s["username"])  # [(id, app_name, login_username), ...]
    return render_template("vault.html", username=s["username"], rows=rows)


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

    nonce, ciphertext, tag = encrypt_password(s["key"], password)
    add_vault_item(s["username"], app_name, login_username, nonce, ciphertext, tag)

    flash("Saved ✅", "success")
    return redirect(url_for("vault"))


# ✅ CHANGED: Return JSON so the UI can show a modal instead of flashing "Password: ..."
@app.post("/vault/view")
def vault_view():
    s = require_login()
    if not s:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    item_id = request.form.get("item_id", "").strip()
    if not item_id.isdigit():
        return jsonify({"ok": False, "error": "Select a valid entry."}), 400

    secret = get_vault_secret(s["username"], int(item_id))
    if not secret:
        return jsonify({"ok": False, "error": "Entry not found."}), 404

    nonce, ciphertext, tag = secret
    try:
        plain = decrypt_password(s["key"], nonce, ciphertext, tag)
    except Exception:
        return jsonify({"ok": False, "error": "Decryption failed."}), 500

    return jsonify({"ok": True, "password": plain})


@app.post("/vault/update")
def vault_update():
    s = require_login()
    if not s:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    item_id = request.form.get("item_id", "").strip()
    app_name = request.form.get("app_name", "").strip()
    login_username = request.form.get("login_username", "").strip()
    new_password = request.form.get("password", "")

    if not item_id.isdigit():
        flash("Select a valid entry.", "error")
        return redirect(url_for("vault"))

    if not app_name or not login_username or not new_password:
        flash("All fields are required.", "error")
        return redirect(url_for("vault"))

    # Encrypt new password with a fresh nonce
    nonce, ciphertext, tag = encrypt_password(s["key"], new_password)

    update_vault_item(
        s["username"],
        int(item_id),
        app_name,
        login_username,
        nonce,
        ciphertext,
        tag
    )

    flash("Updated ✅", "success")
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
