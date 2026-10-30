# -*- coding: utf-8 -*-
"""
_selftest.py -- KHONG phai file nop bai, chi dung de kiem thu noi bo.
Mo phong 2 peer tren localhost, gui tin nhan qua lai, va co tinh gia mao
1 goi tin de kiem tra co che phat hien "Message Integrity Compromised!".
"""
import socket
import threading
import time

from peer_core import SecurePeer
from network_utils import send_json, recv_json

received = {"host": [], "client": []}
errors = []


def log(prefix):
    def _log(msg):
        print(f"[{prefix}] {msg}")
    return _log


def make_msg_cb(name):
    def _cb(sender, text):
        received[name].append((sender, text))
    return _cb


def run_host(port, ready_evt, done_evt):
    peer = SecurePeer("Bob", on_log=log("HOST"), on_message=make_msg_cb("host"))
    t = threading.Thread(target=peer.host, args=(port,), daemon=True)
    t.start()
    while not peer.running:
        time.sleep(0.05)
    ready_evt.set()
    while not done_evt.is_set():
        time.sleep(0.05)
    peer.close()


def run_client(port, ready_evt, done_evt):
    ready_evt.wait(timeout=5)
    peer = SecurePeer("Alice", on_log=log("CLIENT"), on_message=make_msg_cb("client"))
    peer.connect("127.0.0.1", port)
    while not peer.running:
        time.sleep(0.05)

    peer.send_message("Xin chao Bob, day la tin nhan bi mat!")
    time.sleep(1)

    done_evt.set()
    time.sleep(0.5)
    peer.close()


def main():
    port = 6001
    ready_evt = threading.Event()
    done_evt = threading.Event()

    th = threading.Thread(target=run_host, args=(port, ready_evt, done_evt))
    tc = threading.Thread(target=run_client, args=(port, ready_evt, done_evt))
    th.start()
    tc.start()
    th.join()
    tc.join()

    print("\n=== KET QUA TEST 1: gui/nhan tin nhan hop le ===")
    print("Host nhan duoc:", received["host"])
    assert received["host"] == [("Alice", "Xin chao Bob, day la tin nhan bi mat!")], "FAIL: noi dung khong khop"
    print("PASS: tin nhan duoc ma hoa, truyen, giai ma dung noi dung goc.\n")


def test_tamper_detection():
    """Test 2: gia mao ciphertext -> phia nhan phai phat hien va gui NACK."""
    print("=== KET QUA TEST 2: phat hien gia mao du lieu ===")
    port = 6002
    host_logs = []
    client_logs = []

    def host_log(m):
        host_logs.append(m)
        print(f"[HOST] {m}")

    def client_log(m):
        client_logs.append(m)
        print(f"[CLIENT] {m}")

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

    th = threading.Thread(target=run_h, daemon=True)
    th.start()
    ready.wait()

    client_peer = SecurePeer("Alice", on_log=client_log)
    client_peer.connect("127.0.0.1", port)
    while not client_peer.running:
        time.sleep(0.05)
    while not host_peer.running:
        time.sleep(0.05)

    # Gia mao thu cong: tu tao mot goi "message" voi hash hop le nhung
    # ciphertext bi sua sau khi tinh hash, mo phong tan cong sua doi tren duong truyen.
    iv, ciphertext = (lambda k: __import__("crypto_core").des3_encrypt(k, b"noi dung goc"))(client_peer.session_key)
    from crypto_core import sha256_hash, rsa_sign, b64e
    digest = sha256_hash(iv + ciphertext)
    sig = rsa_sign(client_peer.priv_key, digest)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # doi 1 bit/byte dau tien -> hash se khong khop

    send_json(client_peer.sock, {
        "type": "message",
        "iv": b64e(iv),
        "cipher": b64e(bytes(tampered_ciphertext)),
        "hash": b64e(digest),
        "sig": b64e(sig),
    })

    time.sleep(1)
    assert any("CANH BAO" in m and "Message Integrity Compromised" in m for m in host_logs), \
        "FAIL: he thong khong phat hien du lieu bi gia mao"
    print("PASS: he thong phat hien du lieu bi gia mao va canh bao dung yeu cau.\n")

    client_peer.close()
    host_peer.close()


if __name__ == "__main__":
    main()
    time.sleep(0.5)
    test_tamper_detection()
    print("=== TAT CA TEST DEU PASS ===")
