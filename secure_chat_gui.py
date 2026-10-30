# -*- coding: utf-8 -*-
"""
secure_chat_gui.py
-------------------
Giao dien do hoa (Tkinter) cho ung dung chat bao mat TripleDES + RSA + SHA-256.

Ho tro 2 mo hinh:
  1) "Host (cho)"  -> dung SecureServer, CHAP NHAN NHIEU client cung luc.
     Moi client co 1 phien bao mat (Handshake/RSA/TripleDES) rieng voi Host.
     - Mac dinh (bo trong o "Cho phep client thay tin cua nhau"): mo hinh
       "quan net" -- chi Host/Admin doc duoc tin cua tung nguoi, cac client
       KHONG thay tin nhan cua nhau.
     - Neu tick chon "Cho phep client thay tin cua nhau (relay)": Host se
       TU DONG chuyen tiep tin nhan/ file nhan duoc tu 1 client toi TAT CA
       client con lai -> thanh phong chat nhom (nhung Host van la trung
       gian doc duoc noi dung, khong phai ma hoa dau-cuoi that giua cac
       client voi nhau).
  2) "Connect (ket noi)" -> dung SecurePeer, ket noi toi 1 Host (co the la
     may Host o tren, hoac 1 SecurePeer khac dang o che do host-1-nguoi).

Chay:
    python secure_chat_gui.py

QUAN TRONG: moi cua so GUI CHI duoc bam DUY NHAT 1 trong 2 nut "Host (cho)"
hoac "Connect (ket noi)" DUNG 1 LAN. Sau khi bam, ca 2 nut se tu khoa lai
de tranh loi giam port / giam ket noi (WinError 10054/10061).
"""

import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk

from peer_core import SecurePeer
from secure_server import SecureServer

BROADCAST_LABEL = "[Tat ca / Broadcast]"


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat - TripleDES + RSA + SHA-256")
        self.root.geometry("880x620")

        self.peer = None       # dung khi la Client (Connect)
        self.server = None     # dung khi la Host (co the nhieu client)
        self.mode = None       # "host" | "client"

        self._build_connect_frame()
        self._build_chat_frame()

    # ------------------------------------------------------------ UI ---

    def _build_connect_frame(self):
        frame = tk.Frame(self.root, padx=10, pady=10)
        frame.pack(fill="x")

        tk.Label(frame, text="ID cua ban:").grid(row=0, column=0, sticky="w")
        self.id_entry = tk.Entry(frame, width=12)
        self.id_entry.insert(0, "User")
        self.id_entry.grid(row=0, column=1, padx=5)

        tk.Label(frame, text="IP:").grid(row=0, column=2, sticky="w")
        self.ip_entry = tk.Entry(frame, width=14)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=3, padx=5)

        tk.Label(frame, text="Port:").grid(row=0, column=4, sticky="w")
        self.port_entry = tk.Entry(frame, width=8)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=5, padx=5)

        tk.Label(frame, text="Mat khau phong:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.password_entry = tk.Entry(frame, width=16, show="*")
        self.password_entry.grid(row=1, column=1, columnspan=2, sticky="w", padx=5, pady=(6, 0))
        tk.Label(frame, text="(moi nguoi phai go giong nhau - xac thuc danh tinh, de trong = khong bat)",
                 fg="gray").grid(row=1, column=3, columnspan=3, sticky="w", pady=(6, 0))

        self.relay_var = tk.BooleanVar(value=False)
        self.relay_check = tk.Checkbutton(
            frame, text="Cho phep cac client thay tin cua nhau (relay - chi ap dung khi Host)",
            variable=self.relay_var)
        self.relay_check.grid(row=2, column=0, columnspan=6, sticky="w", pady=(4, 0))

        self.host_btn = tk.Button(frame, text="Host (cho)", command=self.on_host)
        self.host_btn.grid(row=0, column=6, padx=5)
        self.connect_btn = tk.Button(frame, text="Connect (ket noi)", command=self.on_connect)
        self.connect_btn.grid(row=0, column=7, padx=5)

        self.status_label = tk.Label(frame, text="Trang thai: Chua ket noi", fg="gray")
        self.status_label.grid(row=3, column=0, columnspan=8, sticky="w", pady=(8, 0))

    def _build_chat_frame(self):
        main = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(main)
        tk.Label(left, text="Nhat ky giao thuc (Handshake / Xac thuc / Toan ven)").pack(anchor="w")
        self.log_area = scrolledtext.ScrolledText(left, width=42, state="disabled", bg="#111111", fg="#33ff33")
        self.log_area.pack(fill="both", expand=True)
        main.add(left)

        mid = tk.Frame(main)
        tk.Label(mid, text="Danh sach dang ket noi (chi khi Host)").pack(anchor="w")
        self.client_listbox = tk.Listbox(mid, width=16)
        self.client_listbox.pack(fill="both", expand=True)
        self.client_listbox.insert("end", BROADCAST_LABEL)
        self.client_listbox.selection_set(0)
        main.add(mid)

        right = tk.Frame(main)
        tk.Label(right, text="Tin nhan").pack(anchor="w")
        self.chat_area = scrolledtext.ScrolledText(right, width=48, state="disabled")
        self.chat_area.pack(fill="both", expand=True)

        bottom = tk.Frame(right)
        bottom.pack(fill="x", pady=(5, 0))
        self.msg_entry = tk.Entry(bottom)
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.on_send())
        tk.Button(bottom, text="Gui file", command=self.on_send_file).pack(side="right", padx=(0, 5))
        tk.Button(bottom, text="Gui", command=self.on_send).pack(side="right")

        main.add(right)

    # ----------------------------------------------- callback tu Peer ---

    def log(self, msg):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", msg + "\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def show_message(self, sender, text):
        self.chat_area.configure(state="normal")
        self.chat_area.insert("end", f"{sender}: {text}\n")
        self.chat_area.see("end")
        self.chat_area.configure(state="disabled")

    def set_status(self, status):
        colors = {"SECURE": "green", "ERROR": "red", "DISCONNECTED": "red"}
        texts = {
            "SECURE": "Da thiet lap phien bao mat (SECURE)",
            "ERROR": "Loi thiet lap ket noi",
            "DISCONNECTED": "Mat ket noi",
        }
        self.status_label.config(
            text=f"Trang thai: {texts.get(status, status)}",
            fg=colors.get(status, "black"),
        )

    def _add_client_to_list(self, client_id):
        names = self.client_listbox.get(0, "end")
        if client_id not in names:
            self.client_listbox.insert("end", client_id)

    def _remove_client_from_list(self, client_id):
        for i, name in enumerate(self.client_listbox.get(0, "end")):
            if name == client_id:
                self.client_listbox.delete(i)
                break

    def _selected_target(self):
        sel = self.client_listbox.curselection()
        if not sel:
            return BROADCAST_LABEL
        return self.client_listbox.get(sel[0])

    # -------------------------------------------- hanh dong nguoi dung ---

    def _lock_mode_buttons(self):
        # Sau khi da chon Host hoac Connect, khoa ca 2 nut lai de tranh
        # bam nham lan 2 gay giam port / giam ket noi (WinError 10054/10061).
        self.host_btn.config(state="disabled")
        self.connect_btn.config(state="disabled")

    def on_host(self):
        my_id = self.id_entry.get().strip() or "Host"
        port = int(self.port_entry.get().strip())
        room_password = self.password_entry.get().strip() or None
        relay_on = self.relay_var.get()

        self.mode = "host"
        self._lock_mode_buttons()
        self.log(f"[*] Bat dau lam Host (id={my_id}, port={port}, "
                 f"relay={'BAT' if relay_on else 'TAT'}) ...")

        self.server = SecureServer(
            my_id,
            on_log=self._safe_log,
            on_message=self._safe_message,
            on_status=self._safe_status,
            on_file=self._on_file_received,
            shared_secret=room_password,
            relay_enabled=relay_on,
            on_client_join=self._safe_client_join,
            on_client_leave=self._safe_client_leave,
        )
        threading.Thread(target=self.server.start, args=(port,), daemon=True).start()
        self.set_status("SECURE")  # Host luon san sang; tung client se co log rieng khi vao

    def on_connect(self):
        my_id = self.id_entry.get().strip() or "Client"
        ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
        room_password = self.password_entry.get().strip() or None

        self.mode = "client"
        self._lock_mode_buttons()

        self.peer = SecurePeer(my_id, on_log=self._safe_log,
                                on_message=self._safe_message, on_status=self._safe_status,
                                on_file=self._on_file_received, shared_secret=room_password)
        threading.Thread(target=self.peer.connect, args=(ip, port), daemon=True).start()

    def on_send(self):
        text = self.msg_entry.get().strip()
        if not text:
            return

        if self.mode == "host" and self.server:
            target = self._selected_target()
            if target == BROADCAST_LABEL:
                self.server.broadcast(text)
                self.show_message("Toi -> Tat ca", text)
            else:
                self.server.send_to(target, text)
                self.show_message(f"Toi -> {target}", text)
        elif self.mode == "client" and self.peer:
            self.peer.send_message(text)
            self.show_message("Toi", text)
        else:
            return

        self.msg_entry.delete(0, "end")

    def on_send_file(self):
        path = filedialog.askopenfilename(title="Chon file de gui")
        if not path:
            return
        filename = path.replace("\\", "/").split("/")[-1]

        if self.mode == "host" and self.server:
            target = self._selected_target()
            if target == BROADCAST_LABEL:
                self.server.broadcast_file(path)
                self.show_message("Toi -> Tat ca", f"[da gui file: {filename}]")
            else:
                self.server.send_file_to(target, path)
                self.show_message(f"Toi -> {target}", f"[da gui file: {filename}]")
        elif self.mode == "client" and self.peer:
            self.peer.send_file(path)
            self.show_message("Toi", f"[da gui file: {filename}]")

    def _on_file_received(self, sender, filename, saved_path):
        self.root.after(0, self.show_message, sender, f"[da gui file: {filename}] -> {saved_path}")

    # Tkinter khong thread-safe: cac callback chay tu thread mang phai
    # dua viec cap nhat GUI ve main thread bang root.after(0, ...)
    def _safe_log(self, msg):
        self.root.after(0, self.log, msg)

    def _safe_message(self, sender, text):
        self.root.after(0, self.show_message, sender, text)

    def _safe_status(self, status):
        self.root.after(0, self.set_status, status)

    def _safe_client_join(self, client_id):
        self.root.after(0, self._add_client_to_list, client_id)

    def _safe_client_leave(self, client_id):
        self.root.after(0, self._remove_client_from_list, client_id)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
