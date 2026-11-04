# EVOLUTIONZ V2 — Key Server

Server key + panel admin cho mod EVOLUTIONZ V2 (Liên Quân Mobile).

- Đăng nhập key có **chữ ký RSA-2048/SHA-256**: client chỉ giữ khoá công khai,
  không thể tự tạo phản hồi hợp lệ → không thể crack key bằng server giả.
- Khoá key theo **HWID**, giới hạn số thiết bị, chống chia sẻ key.
- **Hot-update lib**: admin tải `libMyLibName.so` mới lên panel, client tự động
  tải và thay thế khi vào game — không cần phát hành lại APK.
- Hỗ trợ cập nhật **bắt buộc** kèm nội dung thay đổi.
- Lưu trữ: Redis (Render Key Value) hoặc SQLite (chạy local).

## Chạy local

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt cryptography
SIGNING_KEY_PATH=private.pem \
ADMIN_USER=admin ADMIN_PASSWORD=admin123 \
SQLITE_PATH=./evz.db COOKIE_SECURE=0 \
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8099
```

Mở http://127.0.0.1:8099/admin

## Biến môi trường

| Biến | Ý nghĩa |
|---|---|
| `APP_NAME` | Tên hiển thị (mặc định `EVOLUTIONZ V2`) |
| `GAME_ID` | Mã game (mặc định `PUBG`) |
| `TOKEN_PREFIX` | Tiền tố token md5 (mặc định `PUBG`, khớp client cũ) |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Tài khoản admin khởi tạo (mặc định `admin` / `admin123`) |
| `SIGNING_KEY_PEM` | Khoá riêng RSA (PEM). Có thể dùng `\n` thay xuống dòng |
| `SIGNING_KEY_PATH` | Hoặc đường dẫn file khoá riêng |
| `TICKET_SECRET` | Bí mật ký ticket tải lib |
| `REDIS_URL` | Redis dùng để lưu dữ liệu (khuyến nghị) |
| `SQLITE_PATH` | Đường dẫn SQLite khi không có Redis |
| `SESSION_HOURS` | Thời hạn phiên admin (giờ) |
| `COOKIE_SECURE` | `1` khi chạy HTTPS (mặc định) |
| `ADMIN_IP_ALLOW` | Danh sách IP được vào admin, cách nhau dấu phẩy |
| `FREE_KEYS_ENABLED` | `1` để bật phát key free |

## API client

### `POST /connect`

`application/x-www-form-urlencoded`:

```
game=PUBG&user_key=EVZ-XXXX-XXXX-XXXX-XXXX&serial=<hwid>&ver=<version>
```

Thành công:

```json
{
  "status": true,
  "data": {
    "token": "md5(PUBG-key-serial-secret)",
    "rng": 1793798904,
    "EXP": "04/12/2026 20:28",
    "payload": "<base64 json>",
    "sig": "<base64 RSA signature>",
    "ticket": "<ticket tải lib>",
    "lib": {"version": "...", "md5": "...", "size": 4751544}
  }
}
```

`payload` (JSON, ký bằng RSA PKCS#1 v1.5 + SHA-256):

```json
{"k":"<key>","s":"<serial>","g":"PUBG","e":<exp_epoch>,"r":<now>,"v":1,
 "lv":"<lib version>","lm":"<lib md5>","ls":<lib size>,"ln":"<notes>","lmust":1}
```

Thất bại: `{"status": false, "reason": "..."}`

### `GET /api/lib/file?ticket=...`

Tải `libMyLibName.so`. Ticket chỉ dùng được 10 phút, phát ra sau khi đăng nhập hợp lệ.

### `GET /api/lib/info?ticket=...`

Thông tin bản mod hiện tại.

### `POST /api/free`

`serial=<hwid>` — nhận 1 key free (nếu admin bật). Mỗi thiết bị 1 lần / 7 ngày.

## Bảo mật

- Không có bí mật ký trong client: chỉ khoá công khai.
- Key gắn HWID, giới hạn thiết bị, reset trong panel.
- Giới hạn tần suất theo IP và theo key.
- Panel admin: phiên HMAC, cookie HttpOnly/SameSite=Strict, chống brute-force.
- Nên đổi mật khẩu admin mặc định ngay sau khi triển khai.
