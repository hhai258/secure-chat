# -*- coding: utf-8 -*-
"""
peer_core.py
------------
Trai tim cua he thong: lop SecurePeer trien khai dung 4 buoc trong de bai:

  1) Handshake:              "Hello!" / "Ready!" + trao khoa cong khai RSA
  2) Xac thuc & Trao khoa:   ky (ID + timestamp) bang RSA/SHA-256,
                              ma hoa khoa TripleDES bang RSA-OAEP
  3) Ma hoa & kiem tra toan ven: TripleDES-CBC + SHA-256(iv||cipher) + chu ky
  4) Phia nguoi nhan:        giai ma khoa, kiem tra hash, xac thuc chu ky,
                              giai ma tin nhan hoac gui NACK neu khong hop le

Lop nay khong phu thuoc GUI: dung callback (on_log, on_message, on_status)
de bao cao ra ngoai, nen co the tai su dung cho ca ban console va ban GUI.

Ho tro them (so voi ban dau):
  - Gui/nhan FILE (van dung TripleDES-CBC + SHA-256 + chu ky RSA nhu tin nhan text).
  - Do thoi gian ma hoa/giai ma (phuc vu phan "Thu nghiem" trong bao cao).
  - Cho phep truyen san cap khoa RSA (priv_key/pub_key) tu ben ngoai, de
    SecureServer (secure_server.py) dung CHUNG 1 danh tinh RSA cho nhieu
    phien ket noi voi nhieu client khac nhau.
"""

import os
import socket
import threading
import time

from crypto_core import (
    generate_rsa_keypair, rsa_public_key_to_pem, rsa_public_key_from_pem,
    rsa_sign, rsa_verify, rsa_encrypt, rsa_decrypt,
    generate_3des_key, des3_encrypt, des3_decrypt,
    sha256_hash, hmac_sha256, hmac_verify, b64e, b64d,
)
from network_utils import send_json, recv_json


class SecurePeer:
    # So giay toi da cho phep giua thoi diem ky (timestamp trong goi
    # key-exchange) va thoi diem nhan, dung de chong replay attack (ke
    # tan cong ghi lai goi key-exchange cu, hop le va gui lai sau).
    KEY_EXCHANGE_MAX_AGE_SECONDS = 30

    def __init__(self, my_id, on_log=print, on_message=None, on_status=None,
                 on_file=None, priv_key=None, pub_key=None, save_dir="received_files",
                 shared_secret=None):
        self.my_id = my_id
        self.on_log = on_log
        self.on_message = on_message or (lambda sender, text: None)
        self.on_status = on_status or (lambda status: None)
        self.on_file = on_file or (lambda sender, filename, path: None)
        self.save_dir = save_dir

        # "Mat khau phong chat" (pre-shared secret) - CA HAI BEN phai
        # duoc cau hinh cung 1 gia tri nay truoc khi ket noi. Day la
        # yeu to "biet mat khau" bo sung ben canh yeu to "giu dung
        # private key RSA", giup rang buoc my_id voi mot bi mat that,
        # thay vi chap nhan vo dieu kien bat ky ai tu xung ten nao.
        # Neu de None: BO QUA kiem tra nay (tuong thich nguoc voi cac
        # ban selftest cu / khong yeu cau mat khau).
        self.shared_secret = shared_secret.encode("utf-8") if shared_secret else None

        self.sock = None
        self.server_sock = None

        # Cho phep dung chung 1 cap khoa RSA (vd: SecureServer dung 1 danh
        # tinh cho nhieu client), neu khong truyen vao thi tu sinh khoa moi.
        if priv_key is not None and pub_key is not None:
            self.priv_key, self.pub_key = priv_key, pub_key
        else:
            self.priv_key, self.pub_key = generate_rsa_keypair(2048)

        self.peer_pub_key = None
        self.peer_id = None

        self.session_key = None      # khoa TripleDES dung chung cho phien chat
        self.is_initiator = False    # True = ben "Client" (khoi tao trao khoa)
        self.running = False

        # Khoa rieng cho viec GHI len socket. Voi SecureServer, mot session
        # co the duoc ghi tu 2 thread khac nhau cung luc: (1) thread nhan
        # cua chinh no (vd: gui ACK/NACK sau khi nhan tin), va (2) thread
        # cua MOT session khac dang goi relay_from() -> p.send_message(...)
        # de chuyen tiep tin. Neu khong khoa, 2 lan sendall() co the xen ke
        # nhau tren cung 1 socket -> hong khung do dai (length-prefix) ->
        # ben nhan doc sai va rot ket noi (WinError 10054/10053...).
        self._send_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Thiet lap ket noi TCP
    # ------------------------------------------------------------------

    def host(self, port: int):
        """Vai tro nguoi nghe (tuong tu server): cho mot ket noi den."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", port))
        self.server_sock.listen(1)
        self.on_log(f"[*] Dang cho ket noi tren port {port} ...")
        conn, addr = self.server_sock.accept()
        self.sock = conn
        self.on_log(f"[+] Da ket noi voi {addr}")
        self.is_initiator = False
        self._run_protocol()

    def connect(self, ip: str, port: int):
        """Vai tro nguoi khoi tao (tuong tu client): chu dong ket noi."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))
        self.on_log(f"[+] Da ket noi den {ip}:{port}")
        self.is_initiator = True
        self._run_protocol()

    def _run_protocol(self):
        try:
            self._handshake()
            self._exchange_public_keys()
            if self.is_initiator:
                self._send_key_exchange()
            else:
                self._receive_key_exchange()
            self.on_status("SECURE")
            self.running = True
            threading.Thread(target=self._receive_loop, daemon=True).start()
        except Exception as e:
            self.on_log(f"[!] Loi thiet lap ket noi bao mat: {e}")
            self.on_status("ERROR")

    # ------------------------------------------------------------------
    # Buoc 1: Handshake don gian
    # ------------------------------------------------------------------

    def _handshake(self):
        if self.is_initiator:
            send_json(self.sock, {"type": "hello", "msg": "Hello!"})
            self.on_log("-> Gui: Hello!")
            resp = recv_json(self.sock)
            self.on_log(f"<- Nhan: {resp.get('msg')}")
        else:
            msg = recv_json(self.sock)
            self.on_log(f"<- Nhan: {msg.get('msg')}")
            send_json(self.sock, {"type": "ready", "msg": "Ready!"})
            self.on_log("-> Gui: Ready!")

    def _exchange_public_keys(self):
        send_json(self.sock, {
            "type": "pubkey",
            "id": self.my_id,
            "key": rsa_public_key_to_pem(self.pub_key),
        })
        pk_msg = recv_json(self.sock)
        self.peer_id = pk_msg["id"]
        self.peer_pub_key = rsa_public_key_from_pem(pk_msg["key"])
        self.on_log(f"<-> Da trao khoa cong khai RSA voi '{self.peer_id}'")

    # ------------------------------------------------------------------
    # Buoc 2: Xac thuc (ky so) & Trao khoa TripleDES
    # ------------------------------------------------------------------

    def _send_key_exchange(self):
        timestamp = str(int(time.time()))
        info = f"{self.my_id}|{timestamp}".encode("utf-8")
        signed_info = rsa_sign(self.priv_key, info)

        self.session_key = generate_3des_key()
        encrypted_key = rsa_encrypt(self.peer_pub_key, self.session_key)

        payload = {
            "type": "keyexchange",
            "id": self.my_id,
            "timestamp": timestamp,
            "signed_info": b64e(signed_info),
            "encrypted_3des_key": b64e(encrypted_key),
        }
        if self.shared_secret is not None:
            # auth_tag = HMAC(mat_khau_phong_chat, id|timestamp): chung
            # minh nguoi gui biet dung mat khau, khong chi giu dung key.
            payload["auth_tag"] = b64e(hmac_sha256(self.shared_secret, info))

        send_json(self.sock, payload)
        self.on_log("-> Da gui: signed_info (RSA/SHA-256) + encrypted_3des_key (RSA-OAEP)"
                     + (" + auth_tag (HMAC mat khau)" if self.shared_secret is not None else ""))

        ack = recv_json(self.sock)
        if ack.get("status") != "ok":
            raise RuntimeError(f"Doi tac tu choi goi trao khoa (ly do: {ack.get('reason', 'khong ro')})")
        self.on_log("<- Nhan ACK: trao khoa thanh cong")

    def _receive_key_exchange(self):
        msg = recv_json(self.sock)
        sender_id = msg["id"]
        timestamp = msg["timestamp"]
        info = f"{sender_id}|{timestamp}".encode("utf-8")
        signed_info = b64d(msg["signed_info"])

        if not rsa_verify(self.peer_pub_key, info, signed_info):
            send_json(self.sock, {"type": "key_ack", "status": "fail", "reason": "invalid_signature"})
            raise RuntimeError("Chu ky xac thuc (ID + timestamp) khong hop le")

        # Kiem tra "expiration": neu timestamp qua cu (hoac o tuong lai qua
        # xa) so voi thoi diem hien tai -> co the la goi tin bi ghi lai va
        # phat lai (replay attack), tu choi thay vi chap nhan vo dieu kien.
        age_seconds = abs(time.time() - int(timestamp))
        if age_seconds > self.KEY_EXCHANGE_MAX_AGE_SECONDS:
            send_json(self.sock, {"type": "key_ack", "status": "fail", "reason": "expired"})
            raise RuntimeError(
                f"Goi trao khoa da qua han ({age_seconds:.0f}s > "
                f"{self.KEY_EXCHANGE_MAX_AGE_SECONDS}s cho phep) - nghi ngo replay attack"
            )

        # Xac thuc DANH TINH nguoi dung bang mat khau phong chat (HMAC),
        # KHONG chi xac thuc "dung key RSA". Neu ta co dat shared_secret
        # nhung nguoi kia khong gui auth_tag hop le (khong biet mat
        # khau, hoac gia mao ID) -> tu choi, du chu ky RSA co hop le.
        if self.shared_secret is not None:
            auth_tag = msg.get("auth_tag")
            if auth_tag is None or not hmac_verify(self.shared_secret, info, b64d(auth_tag)):
                send_json(self.sock, {"type": "key_ack", "status": "fail", "reason": "auth_failed"})
                raise RuntimeError(
                    f"Xac thuc danh tinh '{sender_id}' khong hop le (sai/thieu mat khau phong chat) "
                    "- co the la mao danh"
                )

        self.session_key = rsa_decrypt(self.priv_key, b64d(msg["encrypted_3des_key"]))
        self.on_log(f"<- Da xac thuc chu ky + danh tinh cua '{sender_id}' va giai ma khoa TripleDES bang RSA"
                     if self.shared_secret is not None else
                     f"<- Da xac thuc chu ky cua '{sender_id}' va giai ma khoa TripleDES bang RSA")
        send_json(self.sock, {"type": "key_ack", "status": "ok"})
        self.on_log("-> Gui ACK trao khoa")

    # ------------------------------------------------------------------
    # Buoc 3: Ma hoa & gui tin nhan (kem kiem tra toan ven)
    # ------------------------------------------------------------------

    def send_message(self, plaintext: str, origin_id: str = None):
        """Gui 1 tin nhan van ban.

        origin_id: dung khi SecureServer RELAY tin nhan cua 1 client toi
        cac client khac -- cho biet ai la nguoi gui GOC (vd 'User3'), khac
        voi self.my_id la danh tinh cua Host (nguoi dang thuc su ky goi tin
        nay, vi Host la trung gian ma hoa lai voi session_key rieng cua tung
        client). Neu khong truyen, mac dinh la self.my_id (truong hop gui
        binh thuong, khong qua relay).
        """
        if not self.session_key:
            self.on_log("[!] Chua thiet lap phien bao mat, khong the gui")
            return
        origin = origin_id or self.my_id
        t0 = time.perf_counter()
        iv, ciphertext = des3_encrypt(self.session_key, plaintext.encode("utf-8"))
        # origin duoc dua vao du lieu duoc bam/ky, giong cach lam voi filename
        # trong send_file(), de chong sua doi "ai la nguoi gui" tren duong truyen.
        digest = sha256_hash(origin.encode("utf-8") + b"|" + iv + ciphertext)
        sig = rsa_sign(self.priv_key, digest)   # ky tren hash de xac thuc nguon goc + chong gia mao
        elapsed_ms = (time.perf_counter() - t0) * 1000

        payload = {
            "type": "message",
            "origin": origin,
            "iv": b64e(iv),
            "cipher": b64e(ciphertext),
            "hash": b64e(digest),
            "sig": b64e(sig),
        }
        with self._send_lock:
            send_json(self.sock, payload)
        self.on_log(f"-> Da gui tin nhan ma hoa TripleDES-CBC ({len(ciphertext)} byte, "
                     f"ma hoa+ky mat {elapsed_ms:.2f} ms)")

    # ------------------------------------------------------------------
    # Buoc 4: Nhan, kiem tra toan ven + xac thuc, giai ma
    # ------------------------------------------------------------------

    def _receive_loop(self):
        while self.running:
            try:
                msg = recv_json(self.sock)
            except Exception:
                self.on_log("[!] Mat ket noi")
                self.on_status("DISCONNECTED")
                break

            mtype = msg.get("type")
            if mtype == "message":
                self._handle_incoming_message(msg)
            elif mtype == "file":
                self._handle_incoming_file(msg)
            elif mtype == "ack":
                self.on_log("<- Nhan ACK: tin nhan hop le")
            elif mtype == "nack":
                self.on_log(f"<- Nhan NACK: {msg.get('reason')}")

    def _handle_incoming_message(self, msg):
        # "origin": ai la nguoi gui GOC. Neu goi tin khong co field nay (ban
        # cu / gui truc tiep khong qua relay), mac dinh la peer_id cua ket
        # noi truc tiep nay.
        origin = msg.get("origin") or self.peer_id
        iv = b64d(msg["iv"])
        ciphertext = b64d(msg["cipher"])
        received_hash = b64d(msg["hash"])
        sig = b64d(msg["sig"])

        recomputed_hash = sha256_hash(origin.encode("utf-8") + b"|" + iv + ciphertext)
        integrity_ok = recomputed_hash == received_hash
        sig_ok = rsa_verify(self.peer_pub_key, recomputed_hash, sig)

        if integrity_ok and sig_ok:
            t0 = time.perf_counter()
            plaintext = des3_decrypt(self.session_key, iv, ciphertext).decode("utf-8")
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self.on_log(f"<- Kiem tra toan ven: OK | Xac thuc chu ky: OK | giai ma mat {elapsed_ms:.2f} ms")
            self.on_message(origin, plaintext)
            with self._send_lock:
                send_json(self.sock, {"type": "ack"})
        else:
            reason = "Message Integrity Compromised!"
            self.on_log(f"<- CANH BAO: {reason} (toan_ven={integrity_ok}, chu_ky={sig_ok})")
            with self._send_lock:
                send_json(self.sock, {"type": "nack", "reason": reason})

    # ------------------------------------------------------------------
    # Gui / nhan FILE -- dung chung 1 co che voi tin nhan van ban:
    # TripleDES-CBC de ma hoa noi dung file, SHA-256(iv||cipher) de kiem
    # tra toan ven, chu ky RSA tren hash de xac thuc nguoi gui.
    # ------------------------------------------------------------------

    def send_file(self, filepath: str, origin_id: str = None):
        if not self.session_key:
            self.on_log("[!] Chua thiet lap phien bao mat, khong the gui file")
            return
        if not os.path.isfile(filepath):
            self.on_log(f"[!] Khong tim thay file: {filepath}")
            return

        origin = origin_id or self.my_id
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            raw = f.read()

        t0 = time.perf_counter()
        iv, ciphertext = des3_encrypt(self.session_key, raw)
        # Dua ca "filename" va "origin" vao du lieu duoc hash/ky, khong chi
        # iv+ciphertext. Neu khong lam vay, ke tan cong tren duong truyen co
        # the doi ten file / gia mao nguoi gui goc ma he thong khong phat
        # hien duoc (noi dung file van giai ma dung, nhung sai ten/nguon).
        digest = sha256_hash(origin.encode("utf-8") + b"|" + filename.encode("utf-8") + iv + ciphertext)
        sig = rsa_sign(self.priv_key, digest)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        payload = {
            "type": "file",
            "origin": origin,
            "filename": filename,
            "size": len(raw),
            "iv": b64e(iv),
            "cipher": b64e(ciphertext),
            "hash": b64e(digest),
            "sig": b64e(sig),
        }
        with self._send_lock:
            send_json(self.sock, payload)
        self.on_log(f"-> Da gui file '{filename}' ({len(raw)} byte goc -> {len(ciphertext)} "
                     f"byte ma hoa, mat {elapsed_ms:.2f} ms)")

    def _handle_incoming_file(self, msg):
        origin = msg.get("origin") or self.peer_id
        filename = msg.get("filename", "unnamed.bin")
        iv = b64d(msg["iv"])
        ciphertext = b64d(msg["cipher"])
        received_hash = b64d(msg["hash"])
        sig = b64d(msg["sig"])

        # Phai hash cung cach voi ben gui: origin + filename + iv + ciphertext,
        # de phat hien ca truong hop ten file / nguon goc bi sua doi tren
        # duong truyen.
        recomputed_hash = sha256_hash(origin.encode("utf-8") + b"|" + filename.encode("utf-8") + iv + ciphertext)
        integrity_ok = recomputed_hash == received_hash
        sig_ok = rsa_verify(self.peer_pub_key, recomputed_hash, sig)

        if integrity_ok and sig_ok:
            t0 = time.perf_counter()
            plaintext = des3_decrypt(self.session_key, iv, ciphertext)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            peer_dir = os.path.join(self.save_dir, origin or "unknown")
            os.makedirs(peer_dir, exist_ok=True)
            save_path = os.path.join(peer_dir, filename)
            with open(save_path, "wb") as f:
                f.write(plaintext)

            self.on_log(f"<- Nhan file '{filename}' ({len(plaintext)} byte) - Toan ven: OK | "
                         f"Chu ky: OK | giai ma mat {elapsed_ms:.2f} ms -> luu tai {save_path}")
            self.on_file(origin, filename, save_path)
            with self._send_lock:
                send_json(self.sock, {"type": "ack"})
        else:
            reason = "Message Integrity Compromised!"
            self.on_log(f"<- CANH BAO: {reason} (file '{filename}', toan_ven={integrity_ok}, chu_ky={sig_ok})")
            with self._send_lock:
                send_json(self.sock, {"type": "nack", "reason": reason})

    # ------------------------------------------------------------------

    def close(self):
        self.running = False
        for s in (self.sock, self.server_sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass
