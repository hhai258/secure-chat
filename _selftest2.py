# -*- coding: utf-8 -*-
"""_selftest2.py -- kiem thu SecureServer (nhieu client) va gui/nhan file."""
import os
import time
import threading

from secure_server import SecureServer
from peer_core import SecurePeer

received = {}


def make_msg_cb(name):
    def _cb(sender, text):
        received.setdefault(name, []).append((sender, text))
    return _cb


def test_multi_client():
    print("=== TEST: SecureServer voi nhieu client ===")
    port = 7001
    server = SecureServer("Host", on_log=lambda m: print(f"[HOST] {m}"))
    server.start(port)
    time.sleep(0.3)

    clients = []
    for name in ("Alice", "Bob", "Carol"):
        p = SecurePeer(name, on_log=lambda m, n=name: print(f"[{n}] {m}"),
                        on_message=make_msg_cb(name))
        t = threading.Thread(target=p.connect, args=("127.0.0.1", port), daemon=True)
        t.start()
        clients.append(p)

    for p in clients:
        for _ in range(100):
            if p.running:
                break
            time.sleep(0.05)
        assert p.running, f"Client {p.my_id} khong thiet lap duoc phien bao mat"

    time.sleep(0.5)
    who = server.list_clients()
    print("Danh sach client tren server:", who)
    assert set(who) == {"Alice", "Bob", "Carol"}, f"FAIL: danh sach client sai: {who}"

    server.broadcast("Chao tat ca moi nguoi!")
    time.sleep(0.5)
    for name in ("Alice", "Bob", "Carol"):
        assert received.get(name) == [("Host", "Chao tat ca moi nguoi!")], f"FAIL broadcast toi {name}: {received.get(name)}"
    print("PASS: broadcast toi 3 client dong thoi thanh cong.")

    server.send_to("Bob", "Tin nhan rieng cho Bob")
    time.sleep(0.5)
    assert received["Bob"][-1] == ("Host", "Tin nhan rieng cho Bob"), "FAIL: gui rieng that bai"
    assert len(received["Alice"]) == 1 and len(received["Carol"]) == 1, "FAIL: tin nhan rieng bi lo ra ngoai"
    print("PASS: gui tin nhan rieng (send_to) chi den dung 1 client.\n")

    for p in clients:
        p.close()
    server.stop()


def test_file_transfer():
    print("=== TEST: gui/nhan file ===")
    port = 7002
    server = SecureServer("Host", on_log=lambda m: print(f"[HOST] {m}"))
    server.start(port)
    time.sleep(0.3)

    received_files = []

    def on_file(sender, filename, path):
        received_files.append((sender, filename, path))

    client = SecurePeer("Alice", on_log=lambda m: print(f"[ALICE] {m}"), on_file=on_file)
    t = threading.Thread(target=client.connect, args=("127.0.0.1", port), daemon=True)
    t.start()
    for _ in range(100):
        if client.running:
            break
        time.sleep(0.05)
    assert client.running

    time.sleep(0.3)
    test_content = os.urandom(50_000)  # file nhi phan gia lap, 50KB
    tmp_path = "/tmp/test_upload.bin"
    with open(tmp_path, "wb") as f:
        f.write(test_content)

    server.send_file_to("Alice", tmp_path)
    time.sleep(1)

    assert len(received_files) == 1, f"FAIL: khong nhan duoc file, {received_files}"
    sender, filename, saved_path = received_files[0]
    with open(saved_path, "rb") as f:
        saved_content = f.read()
    assert saved_content == test_content, "FAIL: noi dung file sau khi giai ma khong khop file goc"
    print(f"PASS: file {filename} ({len(saved_content)} byte) giai ma dung noi dung goc, luu tai {saved_path}\n")

    client.close()
    server.stop()


if __name__ == "__main__":
    test_multi_client()
    time.sleep(0.5)
    test_file_transfer()
    print("=== TAT CA TEST (multi-client + file) DEU PASS ===")
