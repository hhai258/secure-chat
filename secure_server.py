# -*- coding: utf-8 -*-
"""
secure_server.py
------------------
Mo rong SecurePeer de mot "host" co the phuc vu NHIEU client cung luc,
moi client co MOT phien bao mat rieng (Handshake / trao khoa / TripleDES
session key rieng cho tung ket noi) -- dung chung 1 danh tinh RSA cua host.

- Moi client ket noi vao van chay dung 4 buoc giao thuc nhu SecurePeer.
- SecureServer quan ly danh sach cac phien dang hoat dong (self.sessions),
  cho phep:
    * broadcast(text)          -> gui toi TAT CA client dang ket noi
    * send_to(client_id, text) -> gui rieng toi 1 client
    * send_file_to(client_id, path) / broadcast_file(path)
    * list_clients()           -> danh sach ID client dang ket noi
"""

import socket
import threading

from crypto_core import generate_rsa_keypair
from peer_core import SecurePeer


class SecureServer:
    def __init__(self, my_id, on_log=print, on_message=None, on_status=None, on_file=None,
                 shared_secret=None, on_client_join=None, on_client_leave=None,
                 relay_enabled=False):
        self.my_id = my_id
        self.on_log = on_log
        self.on_message = on_message or (lambda sender, text: None)
        self.on_status = on_status or (lambda status: None)
        self.on_file = on_file or (lambda sender, filename, path: None)
        # Goi khi mot client moi thiet lap phien bao mat thanh cong / khi
        # mot client ngat ket noi -- dung de GUI cap nhat danh sach client.
        self.on_client_join = on_client_join or (lambda client_id: None)
        self.on_client_leave = on_client_leave or (lambda client_id: None)
        # Neu True: tin nhan/ file nhan tu 1 client se duoc TU DONG chuyen
        # tiep (relay) toi TAT CA client con lai -> mo hinh "phong chat
        # nhom" (moi nguoi thay tin cua nhau). Neu False (mac dinh): giu
        # nguyen mo hinh "quan net" -- chi Host/Admin thay het, cac client
        # khong thay tin cua nhau.
        self.relay_enabled = relay_enabled
        # Mat khau phong chat dung chung cho TAT CA client ket noi vao
        # host nay - moi client phai duoc cau hinh cung gia tri nay.
        self.shared_secret = shared_secret

        # Mot cap khoa RSA DUY NHAT dai dien cho host, dung chung cho
        # tat ca cac phien voi cac client khac nhau.
        self.priv_key, self.pub_key = generate_rsa_keypair(2048)

        self.server_sock = None
        self.sessions = {}          # client_id -> SecurePeer
        self._lock = threading.Lock()
        self.running = False

    def start(self, port: int):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", port))
        self.server_sock.listen(5)
        self.running = True
        self.on_log(f"[*] SecureServer '{self.my_id}' dang lang nghe tren port {port} "
                     f"(ho tro nhieu client dong thoi) ...")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
            except OSError:
                break
            self.on_log(f"[+] Ket noi TCP moi tu {addr}, dang thiet lap phien bao mat ...")
            threading.Thread(target=self._handle_new_connection, args=(conn,), daemon=True).start()

    def _handle_new_connection(self, conn):
        # Wrapper rieng cho tung client: bat dung "ai gui" de co the tu
        # dong relay sang cac client con lai khi relay_enabled=True, va
        # phat hien mat ket noi (DISCONNECTED) de don session + bao GUI.
        def _on_message_wrapper(sender_id, text):
            self.on_message(sender_id, text)
            if self.relay_enabled:
                self.relay_from(sender_id, text)

        def _on_file_wrapper(sender_id, filename, path):
            self.on_file(sender_id, filename, path)
            if self.relay_enabled:
                self.relay_file_from(sender_id, path)

        def _on_status_wrapper(status):
            self.on_status(status)
            if status == "DISCONNECTED":
                self._remove_session_by_conn(conn)

        peer = SecurePeer(
            self.my_id,
            on_log=self.on_log,
            on_message=_on_message_wrapper,
            on_status=_on_status_wrapper,
            on_file=_on_file_wrapper,
            priv_key=self.priv_key,
            pub_key=self.pub_key,
            shared_secret=self.shared_secret,
        )
        peer.sock = conn
        peer.is_initiator = False
        peer._run_protocol()   # chay dong bo phan handshake+trao khoa, roi tu tach thread nhan tin

        if peer.running and peer.peer_id:
            with self._lock:
                self.sessions[peer.peer_id] = peer
            self.on_log(f"[+] Client '{peer.peer_id}' da vao phien bao mat "
                         f"(hien co {len(self.sessions)} client)")
            self.on_client_join(peer.peer_id)

    def _remove_session_by_conn(self, conn):
        removed_id = None
        with self._lock:
            for cid, p in list(self.sessions.items()):
                if p.sock is conn:
                    removed_id = cid
                    del self.sessions[cid]
                    break
        if removed_id:
            self.on_log(f"[-] Client '{removed_id}' da ngat ket noi "
                         f"(hien con {len(self.sessions)} client)")
            self.on_client_leave(removed_id)

    # ------------------------------------------------------------------

    def list_clients(self):
        with self._lock:
            return list(self.sessions.keys())

    def send_to(self, client_id: str, text: str):
        with self._lock:
            peer = self.sessions.get(client_id)
        if peer:
            peer.send_message(text)
        else:
            self.on_log(f"[!] Khong tim thay client '{client_id}' dang ket noi")

    def broadcast(self, text: str):
        with self._lock:
            peers = list(self.sessions.values())
        for p in peers:
            p.send_message(text)

    def send_file_to(self, client_id: str, filepath: str):
        with self._lock:
            peer = self.sessions.get(client_id)
        if peer:
            peer.send_file(filepath)
        else:
            self.on_log(f"[!] Khong tim thay client '{client_id}' dang ket noi")

    def broadcast_file(self, filepath: str):
        with self._lock:
            peers = list(self.sessions.values())
        for p in peers:
            p.send_file(filepath)

    def relay_from(self, sender_id: str, text: str):
        """Chuyen tiep tin nhan cua 1 client toi TAT CA client con lai
        (khong gui nguoc lai chinh nguoi gui). Dung field 'origin' trong
        giao thuc (xem peer_core.send_message) de bao cho ben nhan biet
        dung ai la nguoi gui GOC, thay vi nhet ten vao noi dung tin nhan."""
        with self._lock:
            peers = [(cid, p) for cid, p in self.sessions.items() if cid != sender_id]
        for cid, p in peers:
            p.send_message(text, origin_id=sender_id)

    def relay_file_from(self, sender_id: str, filepath: str):
        """Chuyen tiep 1 file da nhan tu 1 client toi tat ca client con lai."""
        with self._lock:
            peers = [(cid, p) for cid, p in self.sessions.items() if cid != sender_id]
        for cid, p in peers:
            p.send_file(filepath, origin_id=sender_id)

    def stop(self):
        self.running = False
        with self._lock:
            for p in self.sessions.values():
                p.close()
            self.sessions.clear()
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
