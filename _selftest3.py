# -*- coding: utf-8 -*-
"""
_selftest3.py -- KHONG phai file nop bai, chi dung de kiem thu noi bo.
Kiem tra 2 co che bao mat vua duoc bo sung them (so voi ban dau):

  Test 1: Gia mao "filename" trong goi tin file -> phia nhan phai phat
          hien duoc (truoc day filename KHONG nam trong du lieu duoc
          hash/ky, nen sua ten file khong bi phat hien).

  Test 2: Phat lai (replay) mot goi "keyexchange" cu (da qua han
          KEY_EXCHANGE_MAX_AGE_SECONDS giay) -> phia nhan phai tu choi,
          khong chap nhan vo dieu kien nhu truoc.
"""
import socket
import threading
import time

from peer_core import SecurePeer
from crypto_core import (
    rsa_sign, sha256_hash, rsa_encrypt, generate_3des_key, b64e,
)
from network_utils import send_json, recv_json


def test_filename_tamper_detection():
    print("=== TEST 1: gia mao ten file (filename) ===")
    port = 6101
    host_logs = []

    def host_log(m):
        host_logs.append(m)
        print(f"[HOST] {m}")

    host_peer = SecurePeer("Bob", on_log=host_log)
    ready = threading.Event()

    def run_h():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        host_peer.sock = conn
        host_peer.is_initiator = False
        host_peer._run_protocol()

    threading.Thread(target=run_h, daemon=True).start()
    ready.wait()

    client_peer = SecurePeer("Alice", on_log=lambda m: print(f"[CLIENT] {m}"))
    client_peer.connect("127.0.0.1", port)
    while not client_peer.running or not host_peer.running:
        time.sleep(0.05)

    # Gui file hop le nhu binh thuong, nhung SAU KHI da tinh hash/sig tren
    # ten file goc ("bao_cao_goc.pdf"), doi ten file thanh 1 ten khac
    # ("virus.exe") truoc khi dua vao goi tin -> mo phong ke tan cong
    # tren duong truyen sua doi truong filename.
    from crypto_core import des3_encrypt
    iv, ciphertext = des3_encrypt(client_peer.session_key, b"noi dung file")
    real_name = "bao_cao_goc.pdf"
    digest = sha256_hash(real_name.encode("utf-8") + iv + ciphertext)
    sig = rsa_sign(client_peer.priv_key, digest)

    send_json(client_peer.sock, {
        "type": "file",
        "filename": "virus.exe",  # <-- da bi doi ten so voi luc ky
        "size": len(ciphertext),
        "iv": b64e(iv),
        "cipher": b64e(ciphertext),
        "hash": b64e(digest),
        "sig": b64e(sig),
    })

    time.sleep(1)
    assert any("CANH BAO" in m and "Message Integrity Compromised" in m for m in host_logs), \
        "FAIL: he thong khong phat hien filename bi gia mao"
    print("PASS: he thong phat hien duoc filename bi doi tren duong truyen.\n")

    client_peer.close()
    host_peer.close()


def test_replay_key_exchange_rejected():
    print("=== TEST 2: phat lai (replay) goi key-exchange cu ===")
    port = 6102
    host_logs = []

    def host_log(m):
        host_logs.append(m)
        print(f"[HOST] {m}")

    host_peer = SecurePeer("Bob", on_log=host_log)
    ready = threading.Event()

    def run_h():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        host_peer.sock = conn
        host_peer.is_initiator = False
        # Chi chay handshake + exchange pubkey, ROI TU MO PHONG buoc
        # key-exchange thu cong o duoi, khong goi _run_protocol() day du.
        host_peer._handshake()
        host_peer._exchange_public_keys()

    th = threading.Thread(target=run_h, daemon=True)
    th.start()
    ready.wait()

    client_peer = SecurePeer("Alice", on_log=lambda m: print(f"[CLIENT] {m}"))
    client_peer.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_peer.sock.connect(("127.0.0.1", port))
    client_peer.is_initiator = True
    client_peer._handshake()
    client_peer._exchange_public_keys()
    th.join()

    # Ke tan cong ghi lai mot goi key-exchange "hop le" nhung da ky tu
    # RAT LAU ROI (timestamp bi lui 120 giay, vuot qua nguong 30 giay
    # cho phep) -> mo phong replay attack bang goi tin cu bi chan bat
    # duoc va gui lai sau.
    old_timestamp = str(int(time.time()) - 120)
    info = f"{client_peer.my_id}|{old_timestamp}".encode("utf-8")
    signed_info = rsa_sign(client_peer.priv_key, info)
    session_key = generate_3des_key()
    encrypted_key = rsa_encrypt(host_peer.pub_key, session_key)

    send_json(client_peer.sock, {
        "type": "keyexchange",
        "id": client_peer.my_id,
        "timestamp": old_timestamp,
        "signed_info": b64e(signed_info),
        "encrypted_3des_key": b64e(encrypted_key),
    })

    try:
        host_peer._receive_key_exchange()
        raised = False
    except RuntimeError as e:
        raised = True
        print(f"[HOST] Da tu choi goi key-exchange qua han: {e}")

    assert raised, "FAIL: he thong van chap nhan goi key-exchange da qua han (replay khong bi phat hien)"
    print("PASS: he thong tu choi goi key-exchange bi phat lai (qua han timestamp).\n")

    client_peer.close()
    host_peer.close()


def test_identity_auth_correct_password():
    print("=== TEST 3: dat mat khau phong chat GIONG NHAU -> ket noi thanh cong ===")
    port = 6103
    host_peer = SecurePeer("Bob", on_log=lambda m: print(f"[HOST] {m}"), shared_secret="matkhau123")
    client_peer = SecurePeer("Alice", on_log=lambda m: print(f"[CLIENT] {m}"), shared_secret="matkhau123")

    ready = threading.Event()

    def run_h():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        host_peer.sock = conn
        host_peer.is_initiator = False
        host_peer._run_protocol()

    threading.Thread(target=run_h, daemon=True).start()
    ready.wait()
    client_peer.connect("127.0.0.1", port)

    for _ in range(50):
        if client_peer.running and host_peer.running:
            break
        time.sleep(0.05)

    assert client_peer.running and host_peer.running, \
        "FAIL: hai ben cung mat khau nhung khong ket noi duoc"
    print("PASS: hai ben cung mat khau phong -> thiet lap phien bao mat thanh cong.\n")

    client_peer.close()
    host_peer.close()


def test_identity_auth_wrong_password_rejected():
    print("=== TEST 4: ke gia mao KHONG BIET mat khau phong -> bi TU CHOI ===")
    port = 6104
    host_peer = SecurePeer("Bob", on_log=lambda m: print(f"[HOST] {m}"), shared_secret="matkhau123")
    # "Ke gia mao" tu xung la Alice nhung dung SAI mat khau phong chat.
    fake_peer = SecurePeer("Alice", on_log=lambda m: print(f"[FAKE] {m}"), shared_secret="mat_khau_sai")

    ready = threading.Event()

    def run_h():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        host_peer.sock = conn
        host_peer.is_initiator = False
        host_peer._run_protocol()  # se bat exception ben trong, khong crash

    threading.Thread(target=run_h, daemon=True).start()
    ready.wait()

    try:
        fake_peer.connect("127.0.0.1", port)
    except Exception:
        pass

    time.sleep(0.5)
    assert not host_peer.running, \
        "FAIL: host van thiet lap phien bao mat voi ke khong biet mat khau (LO HONG!)"
    assert not fake_peer.running, \
        "FAIL: ke gia mao van thiet lap duoc phien bao mat (LO HONG!)"
    print("PASS: he thong tu choi ket noi tu nguoi khong biet dung mat khau phong (chong gia mao ID).\n")

    fake_peer.close()
    host_peer.close()


if __name__ == "__main__":
    test_filename_tamper_detection()
    time.sleep(0.5)
    test_replay_key_exchange_rejected()
    time.sleep(0.5)
    test_identity_auth_correct_password()
    time.sleep(0.5)
    test_identity_auth_wrong_password_rejected()
    print("=== TAT CA TEST (filename integrity + anti-replay + xac thuc danh tinh) DEU PASS ===")
