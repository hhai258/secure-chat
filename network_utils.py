# -*- coding: utf-8 -*-
"""
network_utils.py
-----------------
Gui/nhan cac goi tin JSON qua ket noi TCP (socket).
Dung tien to do dai 4 byte (length-prefix framing) truoc moi goi tin
de dam bao ben nhan doc du va dung du lieu, khong bi tron lan giua
cac goi tin lien tiep (van de pho bien khi dung TCP stream).
"""

import socket
import json
import struct


def send_json(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Ket noi bi dong dot ngot")
        buf += chunk
    return buf


def recv_json(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))
