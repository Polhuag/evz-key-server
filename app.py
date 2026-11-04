import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Form, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from store import open_store

APP_NAME = os.environ.get("APP_NAME", "EVOLUTIONZ V2")
GAME_ID = os.environ.get("GAME_ID", "PUBG")
TOKEN_PREFIX = os.environ.get("TOKEN_PREFIX", "PUBG")
MIN_CLIENT_VERSION = os.environ.get("MIN_CLIENT_VERSION", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ADMIN_IP_ALLOW = [x.strip() for x in os.environ.get("ADMIN_IP_ALLOW", "").split(",") if x.strip()]
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
FREE_ENABLED = os.environ.get("FREE_KEYS_ENABLED", "0") == "1"
TZ = timezone(timedelta(hours=7))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
kv = open_store()


def _load_private_key():
    pem = os.environ.get("SIGNING_KEY_PEM", "")
    path = os.environ.get("SIGNING_KEY_PATH", "")
    if pem:
        data = pem.replace("\\n", "\n").encode()
    elif path and os.path.exists(path):
        data = open(path, "rb").read()
    else:
        return None
    return serialization.load_pem_private_key(data, password=None)


PRIVATE_KEY = _load_private_key()


def now_ts():
    return int(time.time())


def fmt_ts(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, TZ).strftime("%d/%m/%Y %H:%M")


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s)


def canonical(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


def sign_payload(obj):
    if PRIVATE_KEY is None:
        raise RuntimeError("signing key not configured")
    raw = canonical(obj)
    sig = PRIVATE_KEY.sign(raw, padding.PKCS1v15(), hashes.SHA256())
    return b64e(raw), b64e(sig)


def get_key(k):
    raw = kv.get("key:" + k)
    if not raw:
        return None
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


def put_key(rec):
    kv.set("key:" + rec["k"], json.dumps(rec, ensure_ascii=False).encode())


def all_keys():
    out = []
    for name in kv.keys("key:"):
        raw = kv.get(name)
        if not raw:
            continue
        try:
            out.append(json.loads(raw.decode()))
        except Exception:
            pass
    return out


def log_event(entry):
    entry["t"] = now_ts()
    kv.lpush("log:connect", json.dumps(entry, ensure_ascii=False).encode())
    kv.ltrim("log:connect", 0, 999)


def recent_logs(limit=200):
    out = []
    for raw in kv.lrange("log:connect", 0, limit - 1):
        try:
            out.append(json.loads(raw.decode()))
        except Exception:
            pass
    return out


def mask(s, keep=3):
    if not s:
        return ""
    s = str(s)
    if len(s) <= keep * 2:
        return s[:1] + "*" * max(1, len(s) - 2) + s[-1:]
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


class RateLimiter:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def hit(self, key, limit, window):
        t = time.time()
        with self.lock:
            arr = self.data.get(key, [])
            arr = [x for x in arr if t - x < window]
            if len(arr) >= limit:
                self.data[key] = arr
                return False
            arr.append(t)
            self.data[key] = arr
            if len(self.data) > 20000:
                for k in list(self.data.keys())[:5000]:
                    self.data.pop(k, None)
            return True


rl = RateLimiter()


KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def gen_key(prefix="EVZ"):
    groups = []
    for _ in range(4):
        groups.append("".join(secrets.choice(KEY_ALPHABET) for _ in range(4)))
    return prefix + "-" + "-".join(groups)


def valid_key_format(k):
    return bool(re.fullmatch(r"[A-Z0-9]{2,8}(-[A-Z0-9]{4}){3,5}", k or ""))


def ticket_make(game, serial, key, ttl=600):
    body = canonical({"g": game, "s": serial, "k": key, "x": now_ts() + ttl})
    mac = hmac.new(os.environ.get("TICKET_SECRET", "evz").encode(), body, hashlib.sha256).digest()
    return b64e(body) + "." + b64e(mac)


def ticket_check(ticket, game):
    try:
        body_b64, mac_b64 = ticket.split(".", 1)
        body = b64d(body_b64)
        mac = b64d(mac_b64)
        want = hmac.new(os.environ.get("TICKET_SECRET", "evz").encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want):
            return None
        obj = json.loads(body.decode())
        if obj.get("g") != game:
            return None
        if obj.get("x", 0) < now_ts():
            return None
        return obj
    except Exception:
        return None


def lib_meta(game):
    raw = kv.get("lib:%s:meta" % game)
    if not raw:
        return None
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# client API
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    return {"ok": True, "app": APP_NAME, "signed": PRIVATE_KEY is not None,
            "storage": type(kv).__name__, "lib": (lib_meta(GAME_ID) or {}).get("version", "")}


@app.post("/connect")
async def connect(request: Request):
    ip = client_ip(request)
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    game = str(body.get("game") or GAME_ID)
    key = str(body.get("user_key") or "").strip().upper()
    serial = str(body.get("serial") or "").strip()
    ver = str(body.get("ver") or "").strip()

    if not rl.hit("c:" + ip, 40, 60):
        return JSONResponse({"status": False, "reason": "Quá nhiều yêu cầu, thử lại sau"}, status_code=429)
    if not key or not serial:
        return JSONResponse({"status": False, "reason": "Thiếu key hoặc mã thiết bị"})
    if not rl.hit("k:" + key, 30, 60):
        return JSONResponse({"status": False, "reason": "Quá nhiều yêu cầu cho key này"})
    if MIN_CLIENT_VERSION and ver and ver < MIN_CLIENT_VERSION:
        return JSONResponse({"status": False, "reason": "Phiên bản đã cũ, cập nhật mod"})

    rec = get_key(key)
    reason = ""
    if rec is None:
        reason = "Key không hợp lệ"
    elif rec.get("game") and rec["game"] != game:
        reason = "Key không đúng game"
    elif rec.get("banned"):
        reason = "Key đã bị khoá"
    elif rec.get("expires") and rec["expires"] < now_ts():
        reason = "Key đã hết hạn"

    if not reason:
        serials = rec.get("serials") or []
        if serial not in serials:
            limit = int(rec.get("device_limit") or 1)
            if len(serials) >= limit:
                reason = "Key đang dùng trên thiết bị khác"
            else:
                serials.append(serial)
                rec["serials"] = serials
        if not reason:
            rec["used"] = rec.get("used") or now_ts()
            rec["last_seen"] = now_ts()
            rec["last_ip"] = ip
            rec["activations"] = int(rec.get("activations") or 0) + 1
            put_key(rec)

    if reason:
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0, "r": reason, "ver": ver})
        return JSONResponse({"status": False, "reason": reason})

    exp_ts = rec.get("expires") or 0
    meta = lib_meta(game) or {}
    payload = {
        "k": key,
        "s": serial,
        "g": game,
        "e": exp_ts,
        "r": now_ts(),
        "v": 1,
        "lv": str(meta.get("version") or ""),
        "lm": str(meta.get("md5") or ""),
        "ls": int(meta.get("size") or 0),
        "ln": str(meta.get("notes") or ""),
        "lmust": 1 if meta.get("mandatory", True) else 0,
    }
    payload_b64, sig_b64 = sign_payload(payload)
    lib = None
    if meta:
        lib = {"version": meta.get("version"), "md5": meta.get("md5"), "size": meta.get("size")}

    log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 1, "r": "", "ver": ver})

    return JSONResponse({
        "status": True,
        "data": {
            "token": hashlib.md5(("%s-%s-%s-%s" % (TOKEN_PREFIX, key, serial,
                                                   os.environ.get("TOKEN_SECRET", "evz"))).encode()).hexdigest(),
            "rng": now_ts(),
            "EXP": fmt_ts(exp_ts) if exp_ts else "Vĩnh viễn",
            "payload": payload_b64,
            "sig": sig_b64,
            "ticket": ticket_make(game, serial, key),
            "lib": lib,
        },
    })


@app.get("/api/lib/info")
def api_lib_info(ticket: str = "", game: str = ""):
    game = game or GAME_ID
    t = ticket_check(ticket, game)
    if not t:
        raise HTTPException(status_code=403, detail="invalid ticket")
    meta = lib_meta(game)
    if not meta:
        return {"status": False, "reason": "Chưa có bản mod"}
    return {"status": True, "data": {"version": meta.get("version"), "md5": meta.get("md5"), "size": meta.get("size")}}


@app.get("/api/lib/file")
def api_lib_file(ticket: str = "", game: str = ""):
    game = game or GAME_ID
    if not ticket_check(ticket, game):
        raise HTTPException(status_code=403, detail="invalid ticket")
    blob = kv.get("lib:%s:blob" % game)
    if not blob:
        raise HTTPException(status_code=404, detail="no lib")
    meta = lib_meta(game) or {}
    headers = {"X-Lib-Version": str(meta.get("version", "")), "X-Lib-Md5": str(meta.get("md5", ""))}
    return Response(content=blob, media_type="application/octet-stream", headers=headers)


@app.post("/api/free")
async def api_free(request: Request):
    if not FREE_ENABLED and kv.get("cfg:free") != b"1":
        return JSONResponse({"status": False, "reason": "Tính năng nhận key free đang tắt"})
    form = await request.form()
    serial = str(form.get("serial") or "").strip()
    ip = client_ip(request)
    if not serial:
        return JSONResponse({"status": False, "reason": "Thiếu mã thiết bị"})
    if not rl.hit("f:" + serial, 1, 7 * 86400):
        return JSONResponse({"status": False, "reason": "Thiết bị này đã nhận key free"})
    raw = kv.lpop("pool:free")
    if not raw:
        return JSONResponse({"status": False, "reason": "Đã hết key free"})
    key = raw.decode()
    rec = get_key(key)
    if not rec:
        return JSONResponse({"status": False, "reason": "Đã hết key free"})
    rec["serials"] = [serial]
    rec["used"] = now_ts()
    rec["last_ip"] = ip
    put_key(rec)
    log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 1, "r": "free", "ver": ""})
    return JSONResponse({"status": True, "data": {"key": key, "EXP": fmt_ts(rec.get("expires")) if rec.get("expires") else "Vĩnh viễn"}})


# ---------------------------------------------------------------------------
# admin
# ---------------------------------------------------------------------------

def _boot_auth():
    if not kv.get("auth:user"):
        kv.set("auth:user", ADMIN_USER.encode())
        kv.set("auth:secret", secrets.token_hex(32).encode())
        salt = secrets.token_bytes(16)
        kv.set("auth:salt", salt)
        kv.set("auth:hash", hashlib.pbkdf2_hmac("sha256", ADMIN_PASSWORD.encode(), salt, 120000))
    if not kv.get("auth:secret"):
        kv.set("auth:secret", secrets.token_hex(32).encode())


_boot_auth()


def auth_user():
    raw = kv.get("auth:user")
    return raw.decode() if raw else ADMIN_USER


def auth_ok(user, password):
    if not hmac.compare_digest(user.strip().lower(), auth_user().lower()):
        return False
    salt = kv.get("auth:salt")
    want = kv.get("auth:hash")
    if not salt or not want:
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return hmac.compare_digest(got, want)


def auth_secret():
    raw = kv.get("auth:secret")
    return raw if raw else b"evz"


def make_session():
    body = canonical({"x": now_ts() + SESSION_HOURS * 3600, "n": secrets.token_hex(8)})
    mac = hmac.new(auth_secret(), body, hashlib.sha256).digest()
    return b64e(body) + "." + b64e(mac)


def check_session(request: Request):
    tok = request.cookies.get("evz_admin", "")
    if not tok:
        return False
    try:
        body_b64, mac_b64 = tok.split(".", 1)
        body = b64d(body_b64)
        mac = b64d(mac_b64)
        want = hmac.new(auth_secret(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want):
            return False
        return json.loads(body.decode()).get("x", 0) > now_ts()
    except Exception:
        return False


def admin_guard(request: Request):
    ip = client_ip(request)
    if ADMIN_IP_ALLOW and ip not in ADMIN_IP_ALLOW:
        raise HTTPException(status_code=403, detail="forbidden")
    if not check_session(request):
        raise HTTPException(status_code=307, headers={"Location": "/admin/login"})


def stats():
    keys = all_keys()
    t = now_ts()
    active = sum(1 for k in keys if not k.get("banned") and (not k.get("expires") or k["expires"] > t))
    expired = sum(1 for k in keys if k.get("expires") and k["expires"] <= t)
    banned = sum(1 for k in keys if k.get("banned"))
    used = sum(1 for k in keys if k.get("used"))
    logs = recent_logs(1000)
    online = len({l.get("serial") for l in logs if l.get("ok") and l.get("t", 0) > t - 600})
    return {"total": len(keys), "active": active, "expired": expired, "banned": banned,
            "used": used, "online": online, "free_pool": len(kv.lrange("pool:free", 0, 9999))}


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if check_session(request):
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME})


@app.post("/admin/login")
def admin_login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = client_ip(request)
    if not rl.hit("a:" + ip, 8, 600):
        return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME,
                                                         "error": "Sai quá nhiều lần, thử lại sau 10 phút"}, status_code=429)
    if not auth_ok(username, password):
        return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME,
                                                         "error": "Tài khoản hoặc mật khẩu không đúng",
                                                         "username": username}, status_code=401)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie("evz_admin", make_session(), max_age=SESSION_HOURS * 3600,
                    httponly=True, samesite="strict", secure=COOKIE_SECURE)
    return resp


@app.post("/admin/logout")
def admin_logout():
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("evz_admin")
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    meta = lib_meta(GAME_ID)
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "app": APP_NAME, "stats": stats(), "lib": meta,
        "logs": recent_logs(20), "fmt": fmt_ts, "mask": mask,
    })


@app.get("/admin/keys", response_class=HTMLResponse)
def admin_keys(request: Request, q: str = "", status: str = ""):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    t = now_ts()
    keys = all_keys()
    if q:
        ql = q.strip().lower()
        keys = [k for k in keys if ql in k["k"].lower() or ql in (k.get("note") or "").lower()
                or any(ql in s.lower() for s in (k.get("serials") or []))]
    if status == "active":
        keys = [k for k in keys if not k.get("banned") and (not k.get("expires") or k["expires"] > t)]
    elif status == "expired":
        keys = [k for k in keys if k.get("expires") and k["expires"] <= t]
    elif status == "banned":
        keys = [k for k in keys if k.get("banned")]
    elif status == "unused":
        keys = [k for k in keys if not k.get("used")]
    keys.sort(key=lambda x: x.get("created", 0), reverse=True)
    return templates.TemplateResponse("keys.html", {
        "request": request, "app": APP_NAME, "keys": keys[:500], "q": q, "status": status,
        "fmt": fmt_ts, "mask": mask, "now": t, "stats": stats(),
    })


@app.post("/admin/keys/create")
def admin_keys_create(count: int = Form(1), days: int = Form(30), note: str = Form(""),
                      device_limit: int = Form(1), free: str = Form("")):
    count = max(1, min(200, int(count)))
    days = max(0, min(3650, int(days)))
    device_limit = max(1, min(5, int(device_limit)))
    created = now_ts()
    expires = created + days * 86400 if days > 0 else 0
    out = []
    for _ in range(count):
        k = gen_key()
        while get_key(k):
            k = gen_key()
        rec = {"k": k, "game": GAME_ID, "created": created, "days": days, "expires": expires,
               "note": note[:120], "serials": [], "device_limit": device_limit, "banned": False,
               "free": bool(free), "used": None, "last_seen": None, "last_ip": "", "activations": 0}
        put_key(rec)
        if free:
            kv.lpush("pool:free", k.encode())
        out.append(k)
    resp = RedirectResponse("/admin/keys?created=" + ",".join(out[:50]), status_code=303)
    return resp


@app.post("/admin/keys/action")
def admin_keys_action(action: str = Form(...), key: str = Form(...), value: str = Form("")):
    rec = get_key(key.strip().upper())
    if not rec:
        return RedirectResponse("/admin/keys", status_code=303)
    a = action
    if a == "delete":
        kv.delete("key:" + rec["k"])
    elif a == "ban":
        rec["banned"] = True
        put_key(rec)
    elif a == "unban":
        rec["banned"] = False
        put_key(rec)
    elif a == "reset":
        rec["serials"] = []
        put_key(rec)
    elif a == "extend":
        d = max(1, min(3650, int(value or 1)))
        base = rec["expires"] if rec.get("expires") and rec["expires"] > now_ts() else now_ts()
        rec["expires"] = base + d * 86400
        rec["days"] = int(rec.get("days") or 0) + d
        put_key(rec)
    elif a == "limit":
        rec["device_limit"] = max(1, min(5, int(value or 1)))
        put_key(rec)
    return RedirectResponse("/admin/keys", status_code=303)


@app.get("/admin/lib", response_class=HTMLResponse)
def admin_lib(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("lib.html", {
        "request": request, "app": APP_NAME, "lib": lib_meta(GAME_ID), "fmt": fmt_ts,
    })


@app.post("/admin/lib/upload")
async def admin_lib_upload(file: UploadFile = File(...), version: str = Form(""),
                           notes: str = Form(""), mandatory: str = Form("")):
    blob = await file.read()
    if not blob:
        return RedirectResponse("/admin/lib?err=empty", status_code=303)
    if len(blob) > 64 * 1024 * 1024:
        return RedirectResponse("/admin/lib?err=size", status_code=303)
    if blob[:4] != b"\x7fELF":
        return RedirectResponse("/admin/lib?err=notelf", status_code=303)
    md5 = hashlib.md5(blob).hexdigest()
    ver = version.strip() or datetime.now(TZ).strftime("%Y%m%d-%H%M")
    meta = {"version": ver, "md5": md5, "size": len(blob), "uploaded": now_ts(),
            "filename": file.filename or "libMyLibName.so",
            "notes": notes.strip()[:600], "mandatory": bool(mandatory)}
    kv.set("lib:%s:blob" % GAME_ID, blob)
    kv.set("lib:%s:meta" % GAME_ID, json.dumps(meta, ensure_ascii=False).encode())
    return RedirectResponse("/admin/lib?ok=1", status_code=303)


@app.post("/admin/lib/delete")
def admin_lib_delete():
    kv.delete("lib:%s:blob" % GAME_ID)
    kv.delete("lib:%s:meta" % GAME_ID)
    return RedirectResponse("/admin/lib?ok=2", status_code=303)


@app.get("/admin/logs", response_class=HTMLResponse)
def admin_logs(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("logs.html", {
        "request": request, "app": APP_NAME, "logs": recent_logs(400), "fmt": fmt_ts, "mask": mask,
    })


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("settings.html", {
        "request": request, "app": APP_NAME, "user": auth_user(),
        "free_on": kv.get("cfg:free") == b"1", "ok": request.query_params.get("ok", ""),
        "err": request.query_params.get("err", ""),
    })


@app.post("/admin/settings/password")
def admin_settings_password(username: str = Form(""), password: str = Form(""),
                            password2: str = Form("")):
    if not username.strip() or len(password) < 6:
        return RedirectResponse("/admin/settings?err=short", status_code=303)
    if password != password2:
        return RedirectResponse("/admin/settings?err=match", status_code=303)
    salt = secrets.token_bytes(16)
    kv.set("auth:user", username.strip().encode())
    kv.set("auth:salt", salt)
    kv.set("auth:hash", hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000))
    kv.set("auth:secret", secrets.token_hex(32).encode())
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("evz_admin")
    return resp


@app.post("/admin/settings/free")
def admin_settings_free(enabled: str = Form("")):
    kv.set("cfg:free", b"1" if enabled else b"0")
    return RedirectResponse("/admin/settings?ok=1", status_code=303)


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    meta = lib_meta(GAME_ID)
    return templates.TemplateResponse("landing.html", {
        "request": request, "app": APP_NAME, "lib": meta, "fmt": fmt_ts,
    })


@app.get("/admin/backup")
def admin_backup(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    data = {"app": APP_NAME, "time": now_ts(), "keys": all_keys(), "lib": lib_meta(GAME_ID)}
    body = json.dumps(data, ensure_ascii=False, indent=1).encode()
    return Response(content=body, media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="evz-backup.json"'})


@app.post("/admin/restore")
async def admin_restore(request: Request, file: UploadFile = File(...)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    try:
        data = json.loads((await file.read()).decode())
        for rec in data.get("keys", []):
            if rec.get("k"):
                put_key(rec)
    except Exception:
        return RedirectResponse("/admin/settings?err=backup", status_code=303)
    return RedirectResponse("/admin/settings?ok=1", status_code=303)
