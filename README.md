# Đề tài 20: Ứng dụng bảo mật tin nhắn văn bản (TripleDES + RSA + SHA-256)

## 1. Cấu trúc project

```
secure_chat/
├── crypto_core.py       # Các hàm mã hoá: RSA (ký/xác thực, OAEP), TripleDES-CBC, SHA-256
├── network_utils.py     # Gửi/nhận gói tin JSON qua socket (length-prefix framing)
├── peer_core.py         # Lõi giao thức: Handshake -> Xác thực & trao khoá -> Gửi/nhận tin nhắn & FILE
├── secure_server.py     # Server hỗ trợ NHIỀU client cùng lúc (mỗi client 1 phiên bảo mật riêng)
├── console_chat.py      # Bản dòng lệnh: host (đa client) hoặc connect (1 client), có lệnh /file, /to, /who
├── secure_chat_gui.py   # Bản giao diện đồ hoạ Tkinter (điểm thưởng), có nút "Gửi file"
├── benchmark.py         # Đo thời gian mã hoá/giải mã theo kích thước dữ liệu (phục vụ báo cáo)
├── _selftest.py         # Test: gửi/nhận tin nhắn hợp lệ + giả mạo dữ liệu (kiểm tra NACK)
└── _selftest2.py         # Test: nhiều client cùng lúc (broadcast/gửi riêng) + gửi/nhận file
```

## 2. Cài đặt

```bash
pip install pycryptodome
```

Không cần thư viện nào khác — `socket`, `threading`, `tkinter`, `json` đều có sẵn trong Python.

## 3. Cách chạy thử (bản console)

Mở nhiều terminal (host + nhiều client, giống một phòng chat P2P nhiều người), có thể trên cùng máy (localhost) hoặc nhiều máy trong cùng mạng LAN.

**Terminal 1 — host (Bob), có thể phục vụ nhiều client cùng lúc:**
```bash
python console_chat.py host --port 5000 --id Bob
```

**Terminal 2, 3, ... — mỗi client một terminal riêng:**
```bash
python console_chat.py connect --ip 127.0.0.1 --port 5000 --id Alice
python console_chat.py connect --ip 127.0.0.1 --port 5000 --id Carol
```

Sau khi thấy dòng `[TRANG THAI] SECURE`, gõ tin nhắn và Enter để gửi. Các lệnh có sẵn:

| Lệnh | Vai trò | Ý nghĩa |
|---|---|---|
| `<văn bản>` | cả hai | host: gửi (broadcast) tới **tất cả** client; client: gửi tới host |
| `/who` | chỉ host | liệt kê các client đang kết nối |
| `/to <id> <nội dung>` | chỉ host | gửi tin nhắn riêng tới đúng 1 client |
| `/file <đường_dẫn>` | cả hai | gửi 1 file (mã hoá TripleDES như tin nhắn) |
| `/fileto <id> <đường_dẫn>` | chỉ host | gửi file riêng tới đúng 1 client |
| `exit` | cả hai | thoát |

File nhận được sẽ tự lưu vào thư mục `received_files/<tên_người_gửi>/`.

## 4. Cách chạy bản GUI (điểm thưởng)

```bash
python secure_chat_gui.py
```

Mở chương trình 2 lần (2 cửa sổ, chế độ 1-1). Một bên nhập ID, bấm **Host (chờ)**; bên còn lại nhập cùng IP/Port, bấm **Connect (kết nối)**. Cửa sổ bên trái hiển thị nhật ký giao thức (handshake, ký số, kiểm tra toàn vẹn, thời gian mã hoá/giải mã...), bên phải là khung chat có nút **Gửi file**.

> Lưu ý: bản GUI hiện chỉ hỗ trợ 1-1 (giống P2P thuần tuý). Tính năng nhiều-client-cùng-lúc hiện có ở bản console (`console_chat.py` + `secure_server.py`).

## 5. Đo thời gian mã hoá/giải mã (phục vụ báo cáo)

```bash
python benchmark.py --csv ket_qua.csv
```

In ra bảng thời gian RSA (sinh khoá, ký, mã hoá/giải mã khoá phiên) và TripleDES-CBC (mã hoá/giải mã/SHA-256) với nhiều kích thước dữ liệu (1KB → 20MB), đồng thời xuất file CSV để vẽ biểu đồ trong báo cáo.

## 6. Chạy test tự động

```bash
python _selftest.py     # Test 1: gửi/nhận hợp lệ | Test 2: giả mạo dữ liệu -> NACK
python _selftest2.py    # Test 3: nhiều client cùng lúc | Test 4: gửi/nhận file
```

## 6. Giải thích luồng xử lý (khớp với 4 bước trong đề bài)

### Bước 1 — Handshake
- Client gửi `{"type":"hello","msg":"Hello!"}`
- Server phản hồi `{"type":"ready","msg":"Ready!"}`
- Hai bên trao khoá công khai RSA (`{"type":"pubkey","id":...,"key":<PEM>}`) để chuẩn bị cho bước xác thực/trao khoá.

### Bước 2 — Xác thực & Trao khoá
- Client (bên khởi tạo) tạo `signed_info = RSA_Sign(priv_key, ID + "|" + timestamp)` (RSA-PSS/SHA-256).
- Client sinh khoá phiên TripleDES 24-byte ngẫu nhiên, mã hoá bằng khoá công khai RSA của Server: `encrypted_3des_key = RSA-OAEP_Encrypt(pub_key_server, session_key)`.
- Gửi gói: `{"signed_info": "...", "encrypted_3des_key": "..."}`.
- Server xác thực chữ ký bằng khoá công khai của Client, nếu hợp lệ thì giải mã lấy `session_key` bằng khoá riêng RSA của mình, rồi gửi `key_ack: ok`.

### Bước 3 — Mã hoá & kiểm tra toàn vẹn (khi gửi tin nhắn)
- Sinh `iv` ngẫu nhiên 8 byte (kích thước block của DES).
- `ciphertext = TripleDES-CBC_Encrypt(session_key, iv, plaintext)`
- `hash = SHA-256(iv || ciphertext)`
- `sig = RSA_Sign(priv_key, hash)` — ký trên hash để người nhận xác thực đúng người gửi và dữ liệu không bị đổi.
- Gửi gói: `{"iv":..., "cipher":..., "hash":..., "sig":...}`.

### Bước 4 — Phía người nhận
- Tính lại `hash' = SHA-256(iv || ciphertext)`, so sánh với `hash` nhận được (kiểm tra toàn vẹn).
- Xác thực `sig` bằng khoá công khai RSA của người gửi (xác thực danh tính + chống giả mạo).
- Nếu **cả hai** hợp lệ: giải mã bằng TripleDES, hiển thị nội dung, gửi `ACK`.
- Nếu **một trong hai** sai: gửi `NACK` kèm cảnh báo `"Message Integrity Compromised!"`.

## 7. Vì sao chọn các thuật toán/tham số này

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Mã hoá nội dung | TripleDES-CBC, khoá 24 byte (3-key) | Theo đúng yêu cầu đề bài; CBC + IV ngẫu nhiên tránh lộ mẫu dữ liệu giống nhau (khác ECB) |
| Trao khoá phiên | RSA-2048 + OAEP/SHA-256 | OAEP là chuẩn an toàn hiện đại cho mã hoá RSA, chống tấn công padding oracle so với PKCS#1 v1.5 cũ |
| Chữ ký số | RSA-PSS + SHA-256 | PSS là chuẩn chữ ký RSA khuyến nghị hiện nay (an toàn hơn PKCS#1 v1.5 signature cũ) |
| Kiểm tra toàn vẹn | SHA-256(iv‖ciphertext) | Phát hiện dữ liệu bị sửa trên đường truyền; kết hợp thêm chữ ký để chống kẻ tấn công tự tính lại hash sau khi sửa dữ liệu |

> Lưu ý khi viết báo cáo: bạn có thể đổi PSS/OAEP thành PKCS1_v1_5 (`Crypto.Signature.pkcs1_15`) nếu muốn bám sát "RSA/SHA-256" theo nghĩa hẹp mà đề cập — cả hai đều hợp lệ, chỉ cần nêu rõ lựa chọn và lý do trong báo cáo.

## 8. Gợi ý nội dung cho báo cáo (theo mục 2.1.1 của tài liệu hướng dẫn)

1. **Đặt vấn đề:** nêu 3 yêu cầu — bảo mật nội dung (TripleDES), xác thực người gửi/nhận (RSA), toàn vẹn dữ liệu (SHA-256).
2. **Mô tả thuật toán + 3 bước** (Handshake / Xác thực & trao khoá / Truyền + kiểm tra toàn vẹn): dùng đúng nội dung mục 6 ở trên, có thể vẽ lại sơ đồ tuần tự (sequence diagram).
3. **Phân tích mã nguồn:** dẫn các hàm trong `crypto_core.py` và `peer_core.py`, giải thích từng bước.
4. **Thử nghiệm:** chạy `console_chat.py` hoặc `secure_chat_gui.py`, gửi tin nhắn với độ dài khác nhau, đo thời gian bằng `time.perf_counter()` quanh lệnh `des3_encrypt`/`des3_decrypt`; chạy `_selftest.py` để minh hoạ trường hợp phát hiện giả mạo — chụp log làm bằng chứng.
5. **Đánh giá hiệu quả:** so sánh nội dung gốc và nội dung sau giải mã (phải giống hệt); xác nhận NACK xuất hiện khi dữ liệu bị sửa.
6. **Nhận xét thuật toán:** TripleDES chậm hơn AES nhưng vẫn đáp ứng yêu cầu đề bài; RSA-2048 tốn chi phí tính toán hơn ECC nhưng đơn giản, phổ biến, đủ an toàn cho phạm vi bài tập.
7. **Đề xuất cải tiến:** thay TripleDES bằng AES-256-GCM (vừa mã hoá vừa xác thực, nhanh hơn); dùng chứng chỉ số (X.509) thay vì trao khoá công khai trực tiếp để chống tấn công man-in-the-middle ở bước handshake; thêm cơ chế forward secrecy bằng Diffie-Hellman ephemeral cho mỗi phiên.

## 9. Giới hạn cần nêu rõ trong báo cáo (để hoàn thiện/trung thực)

- Bước trao khoá công khai RSA ở Handshake **chưa được xác thực bằng CA/chứng chỉ**, nên về lý thuyết vẫn có thể bị tấn công man-in-the-middle nếu kẻ tấn công chen vào ngay từ đầu kết nối TCP. Đây là điểm có thể nêu trong phần "đề xuất cải tiến".
- Khoá TripleDES chỉ được trao đổi **một lần cho cả phiên chat** (không đổi khoá theo từng tin nhắn) — có thể cải tiến bằng cách tạo `iv` mới mỗi tin nhắn (đã làm) và định kỳ đổi khoá phiên (rotate key).
