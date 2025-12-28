import os
import hashlib
import bcrypt


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, password_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash)


def generate_kdf_salt() -> bytes:
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """
    Create a 32-byte encryption key using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )

from Crypto.Cipher import AES
import base64


def encrypt_password(key: bytes, plain_password: str) -> tuple[str, str, str]:
    """
    Encrypt a password using AES-GCM.
    Returns (nonce_b64, ciphertext_b64, tag_b64).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_password.encode("utf-8"))

    nonce_b64 = base64.b64encode(cipher.nonce).decode("utf-8")
    ct_b64 = base64.b64encode(ciphertext).decode("utf-8")
    tag_b64 = base64.b64encode(tag).decode("utf-8")
    return nonce_b64, ct_b64, tag_b64


def decrypt_password(key: bytes, nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
    """
    Decrypt AES-GCM encrypted password.
    """
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    return plain.decode("utf-8")
