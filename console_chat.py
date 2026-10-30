# -*- coding: utf-8 -*-
"""
console_chat.py
----------------
Ban dong lenh (console) cua ung dung chat bao mat TripleDES + RSA + SHA-256.
Ho tro:
  - Vai tro "host": co the phuc vu NHIEU client cung mot luc (moi client
    co 1 phien bao mat rieng).
  - Vai tro "connect": mot client ket noi toi 1 host.
  - Gui van ban va gui FILE (van dung TripleDES + SHA-256 + chu ky RSA).

Cach chay (mo nhieu terminal):

  Terminal 1 (host - nguoi cho nhieu client vao chat):
      python console_chat.py host --port 5000 --id Bob

  Terminal 2, 3, ... (moi client mot terminal rieng):
      python console_chat.py connect --ip 127.0.0.1 --port 5000 --id Alice
      python console_chat.py connect --ip 127.0.0.1 --port 5000 --id Carol

Lenh trong luc chat:
  <van_ban>                gui tin nhan (host: gui toi TAT CA client; client: gui toi host)
  /who                     (chi host) liet ke cac client dang ket noi
  /to <id> <noi_dung>      (chi host) gui rieng toi 1 client
  /file <duong_dan>        gui 1 file (host: gui toi tat ca; client: gui toi host)
  /fileto <id> <duong_dan> (chi host) gui file rieng toi 1 client
  exit                     thoat
"""

import argparse
import threading
import time

from peer_core import SecurePeer
from secure_server import SecureServer


def run_host(args):
    def on_log(msg):
        print(msg)

    def on_message(sender, text):
        print(f"\n[{sender}]: {text}")

    def on_status(status):
        print(f"[TRANG THAI] {status}")

    def on_file(sender, filename, path):
        print(f"\n[{sender}] da gui file '{filename}' -> luu tai {path}")

    server = SecureServer(args.id, on_log=on_log, on_message=on_message,
                           on_status=on_status, on_file=on_file,
                           shared_secret=args.room_password)
    server.start(args.port)

    print("\nHost dang cho client ket noi. Cac lenh: /who, /to <id> <noi_dung>, "
          "/file <duong_dan>, /fileto <id> <duong_dan>, exit\n")
    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text.lower() == "exit":
                break
            elif text == "/who":
                clients = server.list_clients()
                print(f"Dang ket noi ({len(clients)}): {', '.join(clients) if clients else '(chua co client nao)'}")
            elif text.startswith("/to "):
                _, rest = text.split(" ", 1)
                cid, _, msg = rest.partition(" ")
                if msg:
                    server.send_to(cid, msg)
                else:
                    print("Cu phap: /to <id> <noi_dung>")
            elif text.startswith("/fileto "):
                _, rest = text.split(" ", 1)
                cid, _, path = rest.partition(" ")
                if path:
                    server.send_file_to(cid, path)
                else:
                    print("Cu phap: /fileto <id> <duong_dan>")
            elif text.startswith("/file "):
                _, path = text.split(" ", 1)
                server.broadcast_file(path.strip())
            else:
                server.broadcast(text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        server.stop()


def run_client(args):
    def on_log(msg):
        print(msg)

    def on_message(sender, text):
        print(f"\n[{sender}]: {text}")

    def on_status(status):
        print(f"[TRANG THAI] {status}")

    def on_file(sender, filename, path):
        print(f"\n[{sender}] da gui file '{filename}' -> luu tai {path}")

    peer = SecurePeer(args.id, on_log=on_log, on_message=on_message,
                       on_status=on_status, on_file=on_file,
                       shared_secret=args.room_password)
    t = threading.Thread(target=peer.connect, args=(args.ip, args.port), daemon=True)
    t.start()

    while not peer.running and t.is_alive():
        time.sleep(0.1)

    print("\nGo tin nhan va Enter de gui. '/file <duong_dan>' de gui file. 'exit' de thoat.\n")
    try:
        while True:
            text = input("> ").strip()
            if text.lower() == "exit":
                break
            if text.startswith("/file "):
                _, path = text.split(" ", 1)
                peer.send_file(path.strip())
            elif text:
                peer.send_message(text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        peer.close()


def main():
    parser = argparse.ArgumentParser(description="Secure chat console (TripleDES + RSA + SHA-256)")
    parser.add_argument("role", choices=["host", "connect"])
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--id", default="user")
    parser.add_argument("--room-password", default=None,
                         help="Mat khau phong chat dung chung (xac thuc danh tinh, khong chi xac thuc key). "
                              "Ca host va tat ca client PHAI dung cung 1 mat khau.")
    args = parser.parse_args()

    if args.role == "host":
        run_host(args)
    else:
        run_client(args)


if __name__ == "__main__":
    main()
