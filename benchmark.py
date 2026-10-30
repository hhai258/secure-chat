# -*- coding: utf-8 -*-
"""
benchmark.py
------------
Do thoi gian ma hoa/giai ma TripleDES va cac thao tac RSA, ung voi cac
kich thuoc du lieu khac nhau -- dung so lieu nay cho phan "Thu nghiem"
va "Danh gia hieu qua" trong bao cao (yeu cau 2.1.1, muc 4-5).

Chay:
    python benchmark.py
    python benchmark.py --csv ket_qua.csv
"""

import argparse
import os
import time

from crypto_core import (
    generate_rsa_keypair, generate_3des_key, des3_encrypt, des3_decrypt,
    rsa_sign, rsa_verify, rsa_encrypt, rsa_decrypt, sha256_hash,
)


SIZES_BYTES = [
    1 * 1024,          # 1 KB   (tin nhan van ban ngan)
    10 * 1024,         # 10 KB
    100 * 1024,         # 100 KB
    1 * 1024 * 1024,    # 1 MB   (anh nho)
    5 * 1024 * 1024,    # 5 MB   (file am thanh ngan)
    20 * 1024 * 1024,   # 20 MB  (file lon hon)
]


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def benchmark_3des(sizes):
    key = generate_3des_key()
    rows = []
    for size in sizes:
        data = os.urandom(size)

        t0 = time.perf_counter()
        iv, ciphertext = des3_encrypt(key, data)
        enc_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        _ = des3_decrypt(key, iv, ciphertext)
        dec_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        _ = sha256_hash(iv + ciphertext)
        hash_ms = (time.perf_counter() - t0) * 1000

        rows.append((human_size(size), size, enc_ms, dec_ms, hash_ms))
    return rows


def benchmark_rsa():
    t0 = time.perf_counter()
    priv, pub = generate_rsa_keypair(2048)
    keygen_ms = (time.perf_counter() - t0) * 1000

    session_key = generate_3des_key()

    t0 = time.perf_counter()
    enc_key = rsa_encrypt(pub, session_key)
    rsa_enc_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    _ = rsa_decrypt(priv, enc_key)
    rsa_dec_ms = (time.perf_counter() - t0) * 1000

    info = b"Alice|1234567890"
    t0 = time.perf_counter()
    sig = rsa_sign(priv, info)
    sign_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    _ = rsa_verify(pub, info, sig)
    verify_ms = (time.perf_counter() - t0) * 1000

    return keygen_ms, rsa_enc_ms, rsa_dec_ms, sign_ms, verify_ms


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help="Duong dan file CSV de xuat ket qua (tuy chon)")
    args = parser.parse_args()

    print("=" * 78)
    print("BENCHMARK RSA (2048-bit) -- chay 1 lan cho cac thao tac trao khoa/ky")
    print("=" * 78)
    keygen_ms, rsa_enc_ms, rsa_dec_ms, sign_ms, verify_ms = benchmark_rsa()
    print(f"{'Sinh cap khoa RSA-2048':40s}: {keygen_ms:10.2f} ms")
    print(f"{'Ma hoa khoa 3DES (RSA-OAEP)':40s}: {rsa_enc_ms:10.2f} ms")
    print(f"{'Giai ma khoa 3DES (RSA-OAEP)':40s}: {rsa_dec_ms:10.2f} ms")
    print(f"{'Ky RSA/SHA-256 (PSS)':40s}: {sign_ms:10.2f} ms")
    print(f"{'Xac thuc chu ky RSA/SHA-256':40s}: {verify_ms:10.2f} ms")

    print()
    print("=" * 78)
    print("BENCHMARK TripleDES-CBC theo kich thuoc du lieu")
    print("=" * 78)
    rows = benchmark_3des(SIZES_BYTES)
    print(f"{'Kich thuoc':>12s} | {'Ma hoa (ms)':>12s} | {'Giai ma (ms)':>13s} | {'SHA-256 (ms)':>13s}")
    print("-" * 60)
    for label, size, enc_ms, dec_ms, hash_ms in rows:
        print(f"{label:>12s} | {enc_ms:12.2f} | {dec_ms:13.2f} | {hash_ms:13.2f}")

    if args.csv:
        import csv
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["kich_thuoc_nhan", "kich_thuoc_byte", "ma_hoa_ms", "giai_ma_ms", "sha256_ms"])
            for row in rows:
                writer.writerow(row)
        print(f"\nDa ghi ket qua ra {args.csv}")


if __name__ == "__main__":
    main()
