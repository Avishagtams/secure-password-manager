import pytest
import re
import base64
from crypto_utils import (
    hash_password, verify_password,
    generate_kdf_salt, derive_key,
    encrypt_password, decrypt_password
)

def is_strong_password(pw: str) -> bool:
    if len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]", pw):
        return False
    if re.search(r"\s", pw):
        return False
    return True

def test_hash_and_verify_password():
    pw = "Strong1!Pass"
    h = hash_password(pw)
    assert verify_password(pw, h) is True
    assert verify_password("WrongPass1!", h) is False

def test_encrypt_decrypt_roundtrip():
    master = "Strong1!Pass"
    salt = generate_kdf_salt()
    key = derive_key(master, salt)

    nonce, ct, tag = encrypt_password(key, "MySecret123!")
    plain = decrypt_password(key, nonce, ct, tag)
    assert plain == "MySecret123!"

def test_decrypt_with_wrong_key_fails():
    salt1 = generate_kdf_salt()
    salt2 = generate_kdf_salt()
    key1 = derive_key("Strong1!Pass", salt1)
    key2 = derive_key("Strong1!Pass", salt2)

    nonce, ct, tag = encrypt_password(key1, "TopSecret!")
    with pytest.raises(Exception):
        decrypt_password(key2, nonce, ct, tag)

def test_password_strength_policy():
    assert is_strong_password("Aa1!aaaa") is True
    assert is_strong_password("short1!") is False
    assert is_strong_password("aaaaaaaa!") is False
    assert is_strong_password("AAAAAAA1!") is False
    assert is_strong_password("AaAAAAAA!") is False
    assert is_strong_password("Aa1AAAAA") is False


def test_aes_gcm_detects_tampering():
    master = "Strong1!Pass"
    salt = generate_kdf_salt()
    key = derive_key(master, salt)

    nonce, ct, tag = encrypt_password(key, "AttackAtDawn!")

    # tamper: flip one bit in ciphertext
    ct_bytes = bytearray(base64.b64decode(ct))
    ct_bytes[0] ^= 1
    tampered_ct = base64.b64encode(bytes(ct_bytes)).decode()

    with pytest.raises(Exception):
        decrypt_password(key, nonce, tampered_ct, tag)
