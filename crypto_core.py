# -*- coding: utf-8 -*-
"""
crypto_core.py
--------------
Cac ham mat ma dung cho de tai 20:
  - RSA 2048-bit: sinh khoa, ky/xac thuc chu ky (PSS + SHA-256),
    ma hoa/giai ma khoa phien (OAEP + SHA-256).
  - TripleDES (3DES) CBC mode: ma hoa/giai ma noi dung tin nhan.
  - SHA-256: bam kiem tra tinh toan ven.

Thu vien su dung: pycryptodome (cai bang `pip install pycryptodome`).
"""

import base64
import hmac

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# =========================== RSA ===========================

def generate_rsa_keypair(bits: int = 2048):
    """Sinh cap khoa RSA. Tra ve (private_key, public_key)."""
    key = RSA.generate(bits)
    return key, key.publickey()


def rsa_public_key_to_pem(pubkey) -> str:
    return pubkey.export_key().decode()


def rsa_public_key_from_pem(pem_str: str):
    return RSA.import_key(pem_str)


def rsa_sign(private_key, data: bytes) -> bytes:
    """Ky du lieu bang RSA-PSS + SHA-256 (chu ky so)."""
    h = SHA256.new(data)
    return pss.new(private_key).sign(h)


def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    """Xac thuc chu ky. Tra ve True/False, khong nem exception ra ngoai."""
    h = SHA256.new(data)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Ma hoa du lieu ngan (vd: khoa 3DES 24 byte) bang RSA-OAEP/SHA-256."""
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(data)


def rsa_decrypt(private_key, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(data)


# ======================== TripleDES =========================

def generate_3des_key() -> bytes:
    """Sinh khoa TripleDES 24-byte hop le (K1 != K2 != K3)."""
    while True:
        key = get_random_bytes(24)
        try:
            DES3.adjust_key_parity(key)
            return key
        except ValueError:
            continue  # khoa yeu, sinh lai


def des3_encrypt(key: bytes, plaintext: bytes):
    """Ma hoa CBC. Tra ve (iv, ciphertext). Block size DES = 8 byte."""
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    return iv, ciphertext


def des3_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


# ========================= SHA-256 ===========================

def sha256_hash(data: bytes) -> bytes:
    return SHA256.new(data).digest()


# ==================== HMAC (xac thuc danh tinh) ====================
# Dung de chung minh nguoi gui BIET mot "mat khau phong chat" (shared
# secret) da duoc thoa thuan truoc, ngoai viec chi giu dung private key
# RSA. Chu ky RSA don thuan chi chung minh "dung key vua trao doi", con
# HMAC nay moi thuc su rang buoc my_id voi mot bi mat chi nguoi duoc
# phep (giang vien/nhom) moi biet -> gan voi khai niem "xac thuc nguoi
# dung" thuc su, khong chi "xac thuc key".

def hmac_sha256(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, SHA256).digest()


def hmac_verify(secret: bytes, data: bytes, tag: bytes) -> bool:
    expected = hmac_sha256(secret, data)
    return hmac.compare_digest(expected, tag)


# ====================== Base64 helpers ========================
# Dung de nhung du lieu nhi phan (bytes) vao goi tin JSON dang van ban.

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode())
