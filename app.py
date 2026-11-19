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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from store import open_store
import struct
import random
import gate

APP_NAME = os.environ.get("APP_NAME", "EVOLUTIONZ V2")
GAME_ID = os.environ.get("GAME_ID", "com.garena.game.kgvn")
TOKEN_PREFIX = os.environ.get("TOKEN_PREFIX", "EVOLUTIONZ-V2")
MIN_CLIENT_VERSION = os.environ.get("MIN_CLIENT_VERSION", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ADMIN_IP_ALLOW = [x.strip() for x in os.environ.get("ADMIN_IP_ALLOW", "").split(",") if x.strip()]
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))
LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
LOCAL_LIB = os.path.join(LIB_DIR, "current.so")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
FREE_ENABLED = os.environ.get("FREE_KEYS_ENABLED", "0") == "1"
TZ = timezone(timedelta(hours=7))

LOG_MAX_BYTES = 200_000
LOG_MAX_RAW = 300_000
LOG_MAX_LINE = 4096
LOG_KEEP = 40
LOG_TTL = 14 * 86400
LOG_TOKEN_TTL = 7 * 86400
LOG_BAD_MAX = 5
LOG_DEV_RE = re.compile(r"^[0-9a-f]{16}$")
LOG_VER_RE = re.compile(r"^1\.64\.1\.7-v\d+$")
LOG_TOK_RE = re.compile(r"^[0-9a-f]{32}$")

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


def log_dev_id(serial):
    return hashlib.sha256(str(serial or "").encode()).hexdigest()[:16]


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


def migrate_legacy_game():
    legacy = "PUBG"
    if not GAME_ID or GAME_ID == legacy:
        return
    old_prefix = "lib:%s:" % legacy
    new_prefix = "lib:%s:" % GAME_ID
    for name in list(kv.keys(old_prefix)):
        target = new_prefix + name[len(old_prefix):]
        if name == old_prefix + "releases":
            if not kv.lrange(target, 0, 0):
                for item in reversed(kv.lrange(name, 0, 1000)):
                    kv.lpush(target, item)
        else:
            raw = kv.get(name)
            if raw is not None and kv.get(target) is None:
                kv.set(target, raw)
        kv.delete(name)
    for rec in all_keys():
        if rec.get("game") == legacy:
            rec["game"] = GAME_ID
            put_key(rec)


migrate_legacy_game()


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


def mask_ip(s):
    if not s:
        return "—"
    parts = str(s).split(".")
    if len(parts) == 4:
        return "%s.%s.*.*" % (parts[0], parts[1])
    return mask(s, 3)


templates.env.filters["mask_ip"] = mask_ip


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
    return base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + base64.urlsafe_b64encode(mac).decode().rstrip("=")


def ticket_check(ticket, game):
    try:
        body_b64, mac_b64 = ticket.split(".", 1)
        body = base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
        mac = base64.urlsafe_b64decode(mac_b64 + "=" * (-len(mac_b64) % 4))
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


def device_info(body, ip):
    ver = str(body.get("ver") or "").strip()
    return {
        "did": str(body.get("did") or "")[:80],
        "brand": str(body.get("brand") or "")[:48],
        "model": str(body.get("model") or "")[:64],
        "device": str(body.get("device") or "")[:64],
        "android": str(body.get("android") or "")[:32],
        "sdk": str(body.get("sdk") or "")[:8],
        "abi": str(body.get("abi") or "")[:32],
        "app": str(body.get("app") or ver)[:48],
        "res": str(body.get("res") or "")[:32],
        "lang": str(body.get("lang") or "")[:24],
        "ram": str(body.get("ram") or "")[:24],
        "carrier": str(body.get("carrier") or "")[:48],
        "root": str(body.get("root") or "")[:4],
        "emu": str(body.get("emu") or "")[:4],
        "ip": ip,
        "first": now_ts(),
        "last": now_ts(),
    }


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
    dev = device_info(body, ip)

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
            devices = rec.get("devices") or {}
            olddev = devices.get(serial) or {}
            if olddev.get("first"):
                dev["first"] = olddev.get("first")
            devices[serial] = dev
            rec["devices"] = devices
            rec["last_device"] = dev
            put_key(rec)

    if reason:
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0, "r": reason, "ver": ver})
        return JSONResponse({"status": False, "reason": reason})

    exp_ts = rec.get("expires") or 0
    meta = lib_meta(game) or {}
    log_dev = log_dev_id(serial)
    log_lt = secrets.token_hex(16)
    log_lk = secrets.token_hex(32)
    try:
        kv.set_ex("evzlog:tok:" + log_dev, log_lt.encode(), LOG_TOKEN_TTL)
        kv.set_ex("evzlog:key:" + log_dev, log_lk.encode(), LOG_TOKEN_TTL)
    except Exception:
        pass
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
        "fr": 1 if rec.get("free") else 0,
        "v2": 1 if GATE_ON else 0,
        "strict": 1 if GATE_STRICT else 0,
        "lt": log_lt,
        "lk": log_lk,
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


@app.post("/heartbeat")
async def heartbeat(request: Request):
    ip = client_ip(request)
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        body = await request.json()
    else:
        body = dict(await request.form())

    game = str(body.get("game") or GAME_ID)
    key = str(body.get("user_key") or "").strip().upper()
    serial = str(body.get("serial") or "").strip()
    ver = str(body.get("ver") or "").strip()

    if not rl.hit("h:" + ip, 80, 60):
        return JSONResponse({"status": False, "reason": "Quá nhiều yêu cầu"}, status_code=429)
    if not key or not serial:
        return JSONResponse({"status": False, "reason": "Thiếu key hoặc mã thiết bị"})

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
    elif serial not in (rec.get("serials") or []):
        reason = "Thiết bị không khớp key"

    if reason:
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0, "r": reason, "ver": ver})
        return JSONResponse({"status": False, "reason": reason})

    dev = device_info(body, ip)
    devices = rec.get("devices") or {}
    olddev = devices.get(serial) or {}
    if olddev.get("first"):
        dev["first"] = olddev["first"]
    devices[serial] = dev
    rec["devices"] = devices
    rec["last_device"] = dev
    rec["last_seen"] = now_ts()
    rec["last_ip"] = ip
    put_key(rec)

    payload = {
        "k": key,
        "s": serial,
        "g": game,
        "r": now_ts(),
        "hb": 1,
        "e": rec.get("expires") or 0,
        "fr": 1 if rec.get("free") else 0,
    }
    payload_b64, sig_b64 = sign_payload(payload)
    return JSONResponse({
        "status": True,
        "data": {
            "payload": payload_b64,
            "sig": sig_b64,
            "EXP": fmt_ts(rec.get("expires") or 0),
            "ticket": ticket_make(game, serial, key),
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
def api_lib_file(ticket: str = "", game: str = "", apk: str = ""):
    game = game or GAME_ID
    if GATE_STRICT:
        log_event({"ip": "-", "key": "-", "serial": "-", "ok": 0, "r": "strict", "ver": ""})
        raise HTTPException(status_code=403, detail="strict")
    if not ticket_check(ticket, game):
        raise HTTPException(status_code=403, detail="invalid ticket")
    _m = lib_meta(game) or {}
    if not apk_ok(_m, apk):
        log_event({"ip": "-", "key": "-", "serial": "-", "ok": 0, "r": "apk-legacy:" + apk.strip().lower()[:12], "ver": str(_m.get("version", ""))})
        raise HTTPException(status_code=403, detail="apk mismatch")
    meta = lib_meta(game) or {}
    rid = meta.get("id")
    blob = kv.get("lib:%s:blob:%s" % (game, rid)) if rid else None
    if not blob:
        blob = kv.get("lib:%s:blob" % game)
    if not blob:
        try:
            with open(LOCAL_LIB, "rb") as f:
                blob = f.read()
        except Exception:
            blob = None
    if not blob:
        raise HTTPException(status_code=404, detail="no lib")
    headers = {"X-Lib-Version": str(meta.get("version", "")), "X-Lib-Md5": str(meta.get("md5", ""))}
    return Response(content=blob, media_type="application/octet-stream", headers=headers)


GATE_ON = os.environ.get("EVZ_GATE", "1") == "1"
GATE_STRICT = os.environ.get("EVZ_STRICT", "1") == "1"
GATE_MODE = int(os.environ.get("EVZ_MODULE_MODE", "1"))
GATE_ENFORCE = os.environ.get("EVZ_ENFORCE", "1") == "1"
GATE_CERTS = [x.strip().lower().replace(":", "") for x in os.environ.get(
    "EVZ_CERT_SHA256",
    "06a76d3b576fa5e0fd532e82b41030ab8776df04704b25047d70ad8d8dbf1d82").split(",") if x.strip()]

_plan_cache = {}


def apk_ok(meta, got):
    want = str((meta or {}).get("apk") or "").lower().replace(",", " ").split()
    got = str(got or "").strip().lower()
    if not want:
        return True
    if not got:
        return False
    for w in want:
        if hmac.compare_digest(w, got):
            return True
    return False


def lib_blob(game):
    meta = lib_meta(game) or {}
    rid = meta.get("id")
    blob = kv.get("lib:%s:blob:%s" % (game, rid)) if rid else None
    if not blob:
        blob = kv.get("lib:%s:blob" % game)
    if not blob:
        try:
            with open(LOCAL_LIB, "rb") as f:
                blob = f.read()
        except Exception:
            blob = None
    return meta, blob


def module_plan(game):
    meta, blob = lib_blob(game)
    if not blob:
        return None
    key = (meta.get("md5") or "") + ":" + hashlib.md5(blob).hexdigest() + ":" + str(gate.CHUNK_SIZE)
    plan = _plan_cache.get(key)
    if plan is None:
        chunks, leaves, root = gate.build_module(blob, gate.CHUNK_SIZE)
        plan = {"chunks": chunks, "leaves": leaves, "root": root,
                "ldig": gate.leaves_digest(leaves), "md5": hashlib.md5(blob).hexdigest(),
                "ver": str(meta.get("version") or "")}
        if len(_plan_cache) > 4:
            _plan_cache.clear()
        _plan_cache[key] = plan
    return plan


def gate_sess_key(sid):
    return "v2s:" + sid


def gate_load(sid):
    raw = kv.get(gate_sess_key(sid))
    if not raw:
        return None
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


def gate_store(sess):
    kv.set(gate_sess_key(sess["sid"]), json.dumps(sess).encode())


def gate_blocked(serial):
    return kv.get("v2b:" + gate.blake(serial.encode(), size=16).hex()) is not None


@app.post("/v2/open")
async def v2_open(request: Request):
    ip = client_ip(request)
    if not GATE_ON:
        return JSONResponse({"ok": 0, "r": "off"})
    ctype = request.headers.get("content-type", "")
    body = await request.json() if "application/json" in ctype else dict(await request.form())
    try:
        key = str(body.get("key") or "").strip().upper()
        serial = str(body.get("serial") or "").strip()
        cert = str(body.get("cert") or "").strip().lower().replace(":", "")
        build = str(body.get("build") or "").strip()
        cpub = base64.b64decode(str(body.get("cpub") or "").replace(" ", "+"))
        cn = base64.b64decode(str(body.get("cn") or "").replace(" ", "+"))
        proof = base64.b64decode(str(body.get("proof") or "").replace(" ", "+"))
    except Exception:
        return JSONResponse({"ok": 0, "r": "bad"})
    if len(cpub) != 32 or len(cn) != 16 or len(proof) != 32:
        return JSONResponse({"ok": 0, "r": "bad"})
    if not rl.hit("v2o:" + ip, 20, 60):
        return JSONResponse({"ok": 0, "r": "rate"})
    if GATE_CERTS and cert not in GATE_CERTS:
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0, "r": "cert", "ver": build})
        return JSONResponse({"ok": 0, "r": "cert"})
    meta_now = lib_meta(GAME_ID) or {}
    if not apk_ok(meta_now, body.get("apk")):
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0,
                   "r": "apk:" + str(body.get("apk") or "").strip().lower()[:12], "ver": build})
        return JSONResponse({"ok": 0, "r": "apk"})
    if gate_blocked(serial):
        return JSONResponse({"ok": 0, "r": "locked"})

    rec = get_key(key)
    if rec is None or (rec.get("game") and rec["game"] != GAME_ID) or rec.get("banned") or \
            (rec.get("expires") and rec["expires"] < now_ts()):
        return JSONResponse({"ok": 0, "r": "denied"})
    serials = rec.get("serials") or []
    if serial not in serials:
        if len(serials) >= int(rec.get("device_limit") or 1):
            return JSONResponse({"ok": 0, "r": "denied"})
        serials.append(serial)
        rec["serials"] = serials
        put_key(rec)

    want = gate.proof(key, serial, cert, build, cpub, cn)
    if not hmac.compare_digest(want, proof):
        alts = {
            "c0": gate.proof(key, serial, "", build, cpub, cn),
            "s0": gate.proof(key, "", cert, build, cpub, cn),
            "kL": gate.proof(key.lower(), serial, cert, build, cpub, cn),
            "kU": gate.proof(key.upper(), serial, cert, build, cpub, cn),
            "b0": gate.proof(key, serial, cert, "", cpub, cn),
            "sw": gate.proof(key, serial, cert, build, cn, cpub),
        }
        hit = [k for k, v in alts.items() if hmac.compare_digest(v, proof)]
        log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0,
                   "r": "proof:" + (",".join(hit) or "none"), "ver": build,
                   "cert": cert[:10], "ser": repr(serial)[:24]})
        return JSONResponse({"ok": 0, "r": "denied"})

    plan = module_plan(GAME_ID)
    if not plan:
        return JSONResponse({"ok": 0, "r": "norelease"})

    sid = os.urandom(16)
    sn = os.urandom(16)
    sk, spub = gate.x25519_pair()
    exp = now_ts() + gate.SESSION_TTL
    perm = list(range(len(plan["chunks"])))
    random.SystemRandom().shuffle(perm)
    sess = {"sid": sid.hex(), "sk": base64.b64encode(sk).decode(),
            "cpub": base64.b64encode(cpub).decode(), "cn": base64.b64encode(cn).decode(),
            "sn": base64.b64encode(sn).decode(), "spub": base64.b64encode(spub).decode(),
            "key": key, "serial": serial, "cert": cert, "build": build,
            "md5": plan["md5"], "ver": plan["ver"], "n": len(plan["chunks"]),
            "csz": gate.CHUNK_SIZE, "mode": GATE_MODE, "exp": exp,
            "perm": perm, "used": {}, "cnt": 0}
    gate_store(sess)

    tr = gate.manifest(sid, sn, spub, cpub, cn, sess["n"], sess["csz"], GATE_MODE,
                       sess["ver"], plan["root"], plan["ldig"], exp)
    sig = PRIVATE_KEY.sign(tr, padding.PKCS1v15(), hashes.SHA256()) if PRIVATE_KEY else b""
    lt = secrets.token_hex(16)
    lk = secrets.token_hex(32)
    try:
        kv.set_ex("evzlog:key:" + log_dev_id(serial), lk.encode(), LOG_TOKEN_TTL)
        kv.set_ex("evzlog:tok:" + log_dev_id(serial), lt.encode(), LOG_TOKEN_TTL)
    except Exception:
        pass
    log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 1, "r": "v2", "ver": build})
    return JSONResponse({
        "ok": 1, "sid": sid.hex(), "sn": base64.b64encode(sn).decode(),
        "spub": base64.b64encode(spub).decode(), "n": sess["n"], "csz": sess["csz"],
        "mode": GATE_MODE, "x": exp, "ver": sess["ver"], "md5": plan["md5"],
        "root": base64.b64encode(plan["root"]).decode(),
        "leaves": [base64.b64encode(x).decode() for x in plan["leaves"]],
        "sig": base64.b64encode(sig).decode(),
        "strict": 1 if GATE_STRICT else 0,
        "lt": lt,
        "lk": lk,
    })


@app.post("/v2/sh")
async def v2_sh(request: Request):
    ip = client_ip(request)
    if not GATE_ON:
        return JSONResponse({"ok": 0, "r": "off"})
    try:
        body = await request.json()
        sid = str(body.get("sid") or "")
        want = [int(x) for x in (body.get("i") or [])]
    except Exception:
        return JSONResponse({"ok": 0, "r": "bad"})
    if not sid or not want or len(want) > gate.BATCH_MAX:
        return JSONResponse({"ok": 0, "r": "bad"})
    if not rl.hit("v2s:" + ip, 600, 60):
        return JSONResponse({"ok": 0, "r": "rate"})
    sess = gate_load(sid)
    if not sess or sess["exp"] < now_ts():
        return JSONResponse({"ok": 0, "r": "expired"})
    plan = module_plan(GAME_ID)
    if not plan or plan["md5"] != sess["md5"]:
        return JSONResponse({"ok": 0, "r": "norelease"})
    sidb = bytes.fromhex(sid)
    sk = base64.b64decode(sess["sk"])
    cpub = base64.b64decode(sess["cpub"])
    spub = base64.b64decode(sess["spub"])
    sn = base64.b64decode(sess["sn"])
    cn = base64.b64decode(sess["cn"])
    shared = gate.x25519_shared(sk, cpub)
    skey = gate.session_key(shared, sidb, sn, cpub, spub, cn)
    out = []
    for slot in want:
        if slot < 0 or slot >= sess["n"]:
            continue
        n_used = int(sess["used"].get(str(slot), 0))
        if n_used >= 3:
            continue
        sess["used"][str(slot)] = n_used + 1
        sess["cnt"] = int(sess.get("cnt") or 0) + 1
        if sess["cnt"] > sess["n"] * 4 + 40:
            break
        idx = sess["perm"][slot]
        nonce = os.urandom(24)
        aad = gate.chunk_aad(sidb, slot)
        sealed = gate.seal(skey, nonce, aad, plan["chunks"][idx])
        out.append({"i": slot, "d": base64.b64encode(nonce + sealed).decode(),
                    "t": base64.b64encode(gate.index_tag(skey, sidb, slot)).decode()})
    gate_store(sess)
    return JSONResponse({"ok": 1, "c": out})


@app.post("/v2/flag")
async def v2_flag(request: Request):
    ctype = request.headers.get("content-type", "")
    body = await request.json() if "application/json" in ctype else dict(await request.form())
    key = str(body.get("key") or "").strip().upper()
    serial = str(body.get("serial") or "").strip()
    reason = str(body.get("reason") or "")[:40]
    ip = client_ip(request)
    rec = get_key(key)
    if rec is not None:
        rec["flag_last"] = {"r": reason, "t": now_ts(), "s": mask(serial)}
        put_key(rec)
    log_event({"ip": ip, "key": mask(key), "serial": mask(serial), "ok": 0, "r": "flag:" + reason, "ver": ""})
    if GATE_ENFORCE and reason in ("tamper", "sig", "md5", "size"):
        kv.set("v2b:" + gate.blake(serial.encode(), size=16).hex(), str(now_ts() + 3600).encode())
    return JSONResponse({"ok": 1})


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
# client log ingest
# ---------------------------------------------------------------------------

def _log_bad_ratio(body):
    if not body:
        return 0.0
    bad = 0
    for b in body:
        if b in (9, 10, 13):
            continue
        if b < 32 or b == 127:
            bad += 1
    return bad / float(len(body))


@app.post("/log")
async def client_log(request: Request):
    dev = request.query_params.get("dev", "")
    ver = request.query_params.get("ver", "")[:32]
    tok = request.query_params.get("t", "")

    if not LOG_DEV_RE.fullmatch(dev):
        return JSONResponse({"ok": False, "e": "dev"}, status_code=400)
    if not LOG_VER_RE.fullmatch(ver):
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)

    ip = client_ip(request)
    minute = now_ts() // 60

    # per-IP budget first: cheap protection for Redis and token probing
    try:
        ipk = "evzlog:ipl:%s:%d" % (ip, minute)
        ipn = kv.incr(ipk)
        if ipn == 1:
            kv.expire(ipk, 70)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)
    if ipn > 20:
        return JSONResponse({"ok": False, "e": "busy"}, status_code=429)

    try:
        want = kv.get("evzlog:tok:" + dev)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)

    ok = bool(want) and bool(LOG_TOK_RE.fullmatch(tok)) and hmac.compare_digest(want, tok.encode())
    if not ok:
        try:
            bk = "evzlog:bad:" + dev
            bad = kv.incr(bk)
            if bad == 1:
                kv.expire(bk, 3600)
            if bad > LOG_BAD_MAX:
                kv.delete("evzlog:tok:" + dev)
        except Exception:
            pass
        return JSONResponse({"ok": False, "e": "auth"}, status_code=403)

    # per-device: at most one accepted log per 20 seconds
    try:
        got = kv.set_nx("evzlog:rl:" + dev, b"1", 20)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)
    if not got:
        return JSONResponse({"ok": False, "e": "slow"}, status_code=429)

    # global cap: 600 accepted-ish requests per minute
    try:
        gk = "evzlog:grl:%d" % minute
        gn = kv.incr(gk)
        if gn == 1:
            kv.expire(gk, 70)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)
    if gn > 600:
        return JSONResponse({"ok": False, "e": "busy"}, status_code=429)

    try:
        kraw = kv.get("evzlog:key:" + dev)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)
    if not kraw:
        return JSONResponse({"ok": False, "e": "auth"}, status_code=403)
    try:
        klog = bytes.fromhex(kraw.decode())
    except Exception:
        return JSONResponse({"ok": False, "e": "auth"}, status_code=403)
    if len(klog) != 32:
        return JSONResponse({"ok": False, "e": "auth"}, status_code=403)

    clen = request.headers.get("content-length", "")
    if clen.isdigit() and int(clen) > LOG_MAX_RAW:
        return JSONResponse({"ok": False, "e": "big"}, status_code=413)
    total = 0
    parts = []
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > LOG_MAX_RAW:
                return JSONResponse({"ok": False, "e": "big"}, status_code=413)
            parts.append(chunk)
    except Exception:
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)
    body = b"".join(parts)

    b64 = b"".join(body.split())
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)
    if len(blob) < 28:
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)
    try:
        plain = AESGCM(klog).decrypt(blob[:12], blob[12:], dev.encode())
    except Exception:
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)

    if len(plain) > LOG_MAX_BYTES:
        return JSONResponse({"ok": False, "e": "big"}, status_code=413)
    lines = plain.splitlines() or ([plain] if plain else [])
    if lines and all(len(x) > LOG_MAX_LINE for x in lines):
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)
    if plain and (b"\x00" in plain or _log_bad_ratio(plain) > 0.10):
        return JSONResponse({"ok": False, "e": "bad"}, status_code=400)

    ts = now_ts()
    stamp = datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%dT%H:%M:%S%z")
    header = ("----- %s ver=%s %d bytes -----\n" % (stamp, ver, len(plain))).encode()
    try:
        ck = "evzlog:chunks:" + dev
        kv.rpush(ck, header + b64)
        kv.ltrim(ck, -LOG_KEEP, -1)
        kv.expire(ck, LOG_TTL)
        mk = "evzlog:meta:" + dev
        kv.hset(mk, {"dev": dev, "ver": ver, "last": str(ts), "bytes": str(len(plain))})
        kv.expire(mk, LOG_TTL)
        kv.zadd("evzlog:index", ts, dev)
    except Exception:
        return JSONResponse({"ok": False, "e": "store"}, status_code=500)
    return JSONResponse({"ok": True})


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


def _boot_lib():
    meta = lib_meta(GAME_ID)
    if not meta:
        return
    if not meta.get("id"):
        meta["id"] = "%d-%s" % (int(meta.get("uploaded") or now_ts()), secrets.token_hex(3))
        blob = kv.get("lib:%s:blob" % GAME_ID)
        if blob:
            kv.set("lib:%s:blob:%s" % (GAME_ID, meta["id"]), blob)
        kv.set("lib:%s:meta" % GAME_ID, json.dumps(meta, ensure_ascii=False).encode())
    if not kv.lrange("lib:%s:releases" % GAME_ID, 0, 0):
        kv.lpush("lib:%s:releases" % GAME_ID, json.dumps(meta, ensure_ascii=False).encode())


_boot_lib()


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


def key_status(rec, t=None):
    t = t or now_ts()
    if rec.get("banned"):
        return "banned"
    if rec.get("expires") and rec["expires"] <= t:
        return "expired"
    if not rec.get("used"):
        return "unused"
    return "active"


STATUS_LABEL = {"active": "Hoạt động", "unused": "Chưa dùng", "expired": "Hết hạn", "banned": "Bị khoá"}


def is_blocked(serial):
    return kv.get("devblk:" + serial) is not None


def all_devices():
    t = now_ts()
    out = {}
    for rec in all_keys():
        for s in rec.get("serials") or []:
            d = out.get(s)
            if not d:
                d = {"serial": s, "keys": [], "last_seen": 0, "last_ip": "", "blocked": is_blocked(s)}
                out[s] = d
            d["keys"].append(rec)
            if (rec.get("last_seen") or 0) > d["last_seen"]:
                d["last_seen"] = rec["last_seen"]
                d["last_ip"] = rec.get("last_ip") or ""
    devs = list(out.values())
    for d in devs:
        d["online"] = d["last_seen"] > t - 900
        d["primary"] = max(d["keys"], key=lambda k: k.get("last_seen") or 0)
        d["info"] = (d["primary"].get("devices") or {}).get(d["serial"]) or d["primary"].get("last_device") or {}
    devs.sort(key=lambda d: (-(d["last_seen"] or 0), d["serial"]))
    return devs


def stats():
    keys = all_keys()
    t = now_ts()
    active = sum(1 for k in keys if key_status(k, t) == "active")
    expired = sum(1 for k in keys if key_status(k, t) == "expired")
    banned = sum(1 for k in keys if key_status(k, t) == "banned")
    used = sum(1 for k in keys if k.get("used"))
    free_pool = len([k for k in keys if k.get("free") and not k.get("used")])
    devs = all_devices()
    online = sum(1 for d in devs if d["online"])
    unused = sum(1 for k in keys if not k.get("used") and not k.get("banned"))
    return {"total": len(keys), "active": active, "expired": expired, "banned": banned,
            "used": used, "online": online, "free_pool": free_pool, "devices": len(devs),
            "unused": unused}


def _key_rows(q, status, sort, direction):
    t = now_ts()
    keys = all_keys()
    if q:
        ql = q.strip().lower()
        keys = [k for k in keys if ql in k["k"].lower() or ql in (k.get("note") or "").lower()
                or any(ql in s.lower() for s in (k.get("serials") or []))]
    if status in STATUS_LABEL:
        keys = [k for k in keys if key_status(k, t) == status]
    reverse = direction != "asc"
    if sort == "key":
        keys.sort(key=lambda k: k["k"], reverse=reverse)
    elif sort == "status":
        keys.sort(key=lambda k: key_status(k, t), reverse=reverse)
    elif sort == "expires":
        keys.sort(key=lambda k: k.get("expires") or 0, reverse=reverse)
    elif sort == "last_seen":
        keys.sort(key=lambda k: k.get("last_seen") or 0, reverse=reverse)
    else:
        keys.sort(key=lambda k: k.get("created") or 0, reverse=reverse)
    return keys, t


@app.get("/admin/keys", response_class=HTMLResponse)
def admin_keys(request: Request, q: str = "", status: str = "", sort: str = "created",
               dir: str = "desc", page: int = 1):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    keys, t = _key_rows(q, status, sort, dir)
    per = 25
    pages = max(1, (len(keys) + per - 1) // per)
    page = max(1, min(page, pages))
    rows = keys[(page - 1) * per: page * per]
    return templates.TemplateResponse("keys.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "keys", "keys": rows,
        "total": len(keys), "page": page, "pages": pages, "q": q, "status": status,
        "sort": sort, "dir": dir, "fmt": fmt_ts, "mask": mask, "now": t,
        "stats": stats(), "status_of": key_status, "labels": STATUS_LABEL,
        "created": request.query_params.get("created", ""),
    })


@app.get("/admin/keys/new", response_class=HTMLResponse)
def admin_keys_new(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("keys_new.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "keys", "stats": stats(),
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
        out.append(k)
    return RedirectResponse("/admin/keys?created=" + ",".join(out[:50]), status_code=303)


@app.post("/admin/keys/action")
def admin_keys_action(request: Request, action: str = Form(...), key: str = Form(...), value: str = Form("")):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    rec = get_key(key.strip().upper())
    if rec:
        if action == "delete":
            kv.delete("key:" + rec["k"])
        elif action == "ban":
            rec["banned"] = True
            put_key(rec)
        elif action == "unban":
            rec["banned"] = False
            put_key(rec)
        elif action == "reset":
            rec["serials"] = []
            put_key(rec)
        elif action == "extend":
            d = max(1, min(3650, int(value or 30)))
            base = rec["expires"] if rec.get("expires") and rec["expires"] > now_ts() else now_ts()
            rec["expires"] = base + d * 86400
            rec["days"] = int(rec.get("days") or 0) + d
            put_key(rec)
        elif action == "limit":
            rec["device_limit"] = max(1, min(5, int(value or 1)))
            put_key(rec)
        elif action == "free_on":
            rec["free"] = True
            put_key(rec)
        elif action == "free_off":
            rec["free"] = False
            put_key(rec)
    back = request_referer_key()
    return RedirectResponse(back, status_code=303)


def request_referer_key():
    return "/admin/keys"


@app.post("/admin/keys/bulk")
def admin_keys_bulk(request: Request, action: str = Form(...), keys: list[str] = Form([])):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    done = 0
    for k in keys:
        rec = get_key(k.strip().upper())
        if not rec:
            continue
        done += 1
        if action == "delete":
            kv.delete("key:" + rec["k"])
        elif action == "ban":
            rec["banned"] = True
            put_key(rec)
        elif action == "unban":
            rec["banned"] = False
            put_key(rec)
        elif action == "reset":
            rec["serials"] = []
            put_key(rec)
        elif action == "extend":
            base = rec["expires"] if rec.get("expires") and rec["expires"] > now_ts() else now_ts()
            rec["expires"] = base + 30 * 86400
            rec["days"] = int(rec.get("days") or 0) + 30
            put_key(rec)
        elif action == "free_on":
            rec["free"] = True
            put_key(rec)
        elif action == "free_off":
            rec["free"] = False
            put_key(rec)
    return RedirectResponse("/admin/keys?bulk=%d" % done, status_code=303)


@app.get("/admin/devices", response_class=HTMLResponse)
def admin_devices(request: Request, q: str = "", state: str = ""):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    devs = all_devices()
    if q:
        ql = q.strip().lower()
        devs = [d for d in devs if ql in d["serial"].lower()
                or any(ql in k["k"].lower() for k in d["keys"])
                or ql in (d.get("info", {}).get("model") or "").lower()
                or ql in (d.get("info", {}).get("brand") or "").lower()
                or ql in (d.get("info", {}).get("did") or "").lower()]
    if state == "online":
        devs = [d for d in devs if d["online"]]
    elif state == "offline":
        devs = [d for d in devs if not d["online"]]
    elif state == "blocked":
        devs = [d for d in devs if d["blocked"]]
    return templates.TemplateResponse("devices.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "devices", "devices": devs,
        "q": q, "state": state, "fmt": fmt_ts, "mask": mask, "stats": stats(),
    })


@app.post("/admin/devices/action")
def admin_devices_action(request: Request, serial: str = Form(...), action: str = Form(...)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    serial = serial.strip()
    if action == "unbind":
        for rec in all_keys():
            if serial in (rec.get("serials") or []):
                rec["serials"] = [s for s in rec["serials"] if s != serial]
                put_key(rec)
    elif action == "block":
        kv.set("devblk:" + serial, b"1")
    elif action == "unblock":
        kv.delete("devblk:" + serial)
    return RedirectResponse("/admin/devices", status_code=303)


def _log_meta(dev):
    try:
        raw = kv.hgetall("evzlog:meta:" + dev) or {}
    except Exception:
        raw = {}
    out = {}
    for k, v in raw.items():
        k = k.decode() if isinstance(k, bytes) else str(k)
        out[k] = v.decode() if isinstance(v, bytes) else str(v)
    return out


def _log_key(dev):
    try:
        raw = kv.get("evzlog:key:" + dev)
        if not raw:
            return None
        return bytes.fromhex(raw.decode())
    except Exception:
        return None


def _log_chunks(dev):
    try:
        return kv.rrange("evzlog:chunks:" + dev, -LOG_KEEP, -1) or []
    except Exception:
        return []


def _log_plain(dev):
    key = _log_key(dev)
    if key is None:
        return None
    out = []
    for ch in _log_chunks(dev):
        _h, _sep, b64 = ch.partition(b"\n")
        try:
            blob = base64.b64decode(b"".join(b64.split()), validate=True)
            if len(blob) < 28:
                continue
            out.append(AESGCM(key).decrypt(blob[:12], blob[12:], dev.encode()))
        except Exception:
            out.append(b"[chunk khong giai ma duoc]\n")
    return b"".join(out)


@app.get("/admin/logs", response_class=HTMLResponse)
def admin_logs(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    items = []
    try:
        rows = kv.zrevrange("evzlog:index", 0, 199, withscores=True) or []
    except Exception:
        rows = []
    for row in rows:
        if isinstance(row, (tuple, list)):
            dev, score = row[0], row[1]
        else:
            dev, score = row, 0
        dev = dev.decode() if isinstance(dev, bytes) else str(dev)
        meta = _log_meta(dev)
        try:
            nchunks = kv.llen("evzlog:chunks:" + dev)
        except Exception:
            nchunks = 0
        items.append({"dev": dev, "ver": meta.get("ver", ""), "chunks": nchunks,
                      "last": int(float(score) or 0), "bytes": meta.get("bytes", "")})
    return templates.TemplateResponse("logs.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "logs",
        "items": items, "fmt": fmt_ts, "stats": stats(),
    })


@app.get("/admin/logs/{dev}", response_class=HTMLResponse)
def admin_log_detail(request: Request, dev: str, raw: int = 0):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    if not LOG_DEV_RE.fullmatch(dev):
        raise HTTPException(status_code=404, detail="not found")
    meta = _log_meta(dev)
    plain = _log_plain(dev)
    if plain is None:
        if raw:
            raise HTTPException(status_code=409, detail="log key expired")
        return templates.TemplateResponse("log_detail.html", {
            "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "logs",
            "dev": dev, "text": "", "missing_key": True, "raw": 0,
            "ver": meta.get("ver", ""), "last": int(meta.get("last") or 0),
            "bytes": 0, "shown": 0, "fmt": fmt_ts, "stats": stats(),
        })
    if raw:
        return Response(content=plain, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="%s.log"' % dev})
    text = plain.decode("utf-8", "replace")
    return templates.TemplateResponse("log_detail.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "logs",
        "dev": dev, "text": text, "missing_key": False, "raw": 0,
        "ver": meta.get("ver", ""), "last": int(meta.get("last") or 0),
        "bytes": len(plain), "shown": len(text), "fmt": fmt_ts, "stats": stats(),
    })


def releases_list():
    out = []
    seen = set()
    for raw in kv.lrange("lib:%s:releases" % GAME_ID, 0, 49):
        try:
            it = json.loads(raw.decode())
        except Exception:
            continue
        if it.get("id") in seen:
            continue
        seen.add(it.get("id"))
        out.append(it)
    return out[:30]


def releases_rewrite(items):
    kv.delete("lib:%s:releases" % GAME_ID)
    for it in reversed(items):
        kv.lpush("lib:%s:releases" % GAME_ID, json.dumps(it, ensure_ascii=False).encode())


@app.get("/admin/releases", response_class=HTMLResponse)
def admin_releases(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("releases.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "releases",
        "lib": lib_meta(GAME_ID), "releases": releases_list(), "fmt": fmt_ts,
        "stats": stats(), "ok": request.query_params.get("ok", ""),
        "err": request.query_params.get("err", ""),
    })


@app.post("/admin/releases/upload")
async def admin_releases_upload(request: Request, file: UploadFile = File(...), version: str = Form(""),
                                notes: str = Form(""), mandatory: str = Form(""),
                                apk_sha: str = Form("")):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    blob = await file.read()
    if not blob:
        return RedirectResponse("/admin/releases?err=empty", status_code=303)
    if len(blob) > 64 * 1024 * 1024:
        return RedirectResponse("/admin/releases?err=size", status_code=303)
    if blob[:4] != b"\x7fELF":
        return RedirectResponse("/admin/releases?err=notelf", status_code=303)
    prev_apk = str((lib_meta(GAME_ID) or {}).get("apk") or "").lower().replace(",", " ").split()
    for extra in apk_sha.strip().lower().replace(",", " ").split():
        if extra == "clear":
            prev_apk = []
            continue
        if len(extra) == 64 and extra not in prev_apk:
            prev_apk.append(extra)
    md5 = hashlib.md5(blob).hexdigest()
    sha256 = hashlib.sha256(blob).hexdigest()
    ver = version.strip() or datetime.now(TZ).strftime("%Y%m%d-%H%M")
    rid = "%d-%s" % (now_ts(), secrets.token_hex(3))
    meta = {"id": rid, "version": ver, "md5": md5, "sha256": sha256, "size": len(blob),
            "uploaded": now_ts(), "filename": file.filename or "libMyLibName.so",
            "notes": notes.strip()[:600], "mandatory": bool(mandatory),
            "apk": " ".join(prev_apk)[:2048]}
    kv.set("lib:%s:blob:%s" % (GAME_ID, rid), blob)
    try:
        os.makedirs(LIB_DIR, exist_ok=True)
        with open(LOCAL_LIB, "wb") as f:
            f.write(blob)
    except Exception:
        pass
    kv.set("lib:%s:meta" % GAME_ID, json.dumps(meta, ensure_ascii=False).encode())
    kv.lpush("lib:%s:releases" % GAME_ID, json.dumps(meta, ensure_ascii=False).encode())
    keep = releases_list()[1:]
    for old in keep:
        kv.delete("lib:%s:blob:%s" % (GAME_ID, old.get("id", "")))
    return RedirectResponse("/admin/releases?ok=1", status_code=303)


@app.post("/admin/releases/activate")
def admin_releases_activate(request: Request, rid: str = Form(...)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    for it in releases_list():
        if it.get("id") == rid:
            if kv.get("lib:%s:blob:%s" % (GAME_ID, rid)) is None:
                return RedirectResponse("/admin/releases?err=gone", status_code=303)
            kv.set("lib:%s:meta" % GAME_ID, json.dumps(it, ensure_ascii=False).encode())
            break
    return RedirectResponse("/admin/releases?ok=2", status_code=303)


@app.post("/admin/releases/delete")
def admin_releases_delete(request: Request, rid: str = Form(...)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    meta = lib_meta(GAME_ID) or {}
    if meta.get("id") == rid:
        return RedirectResponse("/admin/releases?err=active", status_code=303)
    kv.delete("lib:%s:blob:%s" % (GAME_ID, rid))
    releases_rewrite([r for r in releases_list() if r.get("id") != rid])
    return RedirectResponse("/admin/releases?ok=3", status_code=303)


@app.get("/admin/free-stock", response_class=HTMLResponse)
def admin_free_stock(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    t = now_ts()
    pool = [k for k in all_keys() if k.get("free") and not k.get("used") and not k.get("banned")
            and (not k.get("expires") or k["expires"] > t)]
    pool.sort(key=lambda k: k.get("created") or 0)
    claimed = [k for k in all_keys() if k.get("free") and k.get("used")]
    claimed.sort(key=lambda k: k.get("used") or 0, reverse=True)
    return templates.TemplateResponse("free_stock.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "free",
        "pool": pool, "claimed": claimed[:30], "fmt": fmt_ts, "mask": mask, "stats": stats(),
        "enabled": kv.get("cfg:free") == b"1", "ok": request.query_params.get("ok", ""),
    })


@app.post("/admin/free-stock/add")
def admin_free_stock_add(request: Request, count: int = Form(10), days: int = Form(3)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    count = max(1, min(100, int(count)))
    days = max(1, min(365, int(days)))
    created = now_ts()
    expires = created + days * 86400
    for _ in range(count):
        k = gen_key()
        while get_key(k):
            k = gen_key()
        put_key({"k": k, "game": GAME_ID, "created": created, "days": days, "expires": expires,
                 "note": "free", "serials": [], "device_limit": 1, "banned": False, "free": True,
                 "used": None, "last_seen": None, "last_ip": "", "activations": 0})
    return RedirectResponse("/admin/free-stock?ok=1", status_code=303)


@app.post("/admin/free-stock/remove")
def admin_free_stock_remove(request: Request, key: str = Form(...)):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    rec = get_key(key.strip().upper())
    if rec and rec.get("free") and not rec.get("used"):
        kv.delete("key:" + rec["k"])
    return RedirectResponse("/admin/free-stock", status_code=303)


@app.get("/admin/lib")
def admin_lib_redirect():
    return RedirectResponse("/admin/releases", status_code=307)


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if check_session(request):
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME})


@app.post("/admin/login")
def admin_login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = client_ip(request)
    if not rl.hit("a:" + ip, 8, 600):
        return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME, "user_name": auth_user(),
                                                         "error": "Sai quá nhiều lần, thử lại sau 10 phút"}, status_code=429)
    if not auth_ok(username, password):
        return templates.TemplateResponse("login.html", {"request": request, "app": APP_NAME, "user_name": auth_user(),
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
    t = now_ts()
    keys = all_keys()
    soon = [k for k in keys if k.get("expires") and t < k["expires"] <= t + 3 * 86400 and not k.get("banned")]
    soon.sort(key=lambda k: k["expires"])
    devs = all_devices()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "page_name": "home", "stats": stats(),
        "lib": lib_meta(GAME_ID), "logs": recent_logs(24), "fmt": fmt_ts, "mask": mask,
        "soon": soon[:5], "online": [d for d in devs if d["online"]][:5], "now": t,
        "status_of": key_status, "labels": STATUS_LABEL,
    })


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse("settings.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "user": auth_user(),
        "free_on": kv.get("cfg:free") == b"1", "ok": request.query_params.get("ok", ""),
        "err": request.query_params.get("err", ""), "game": GAME_ID, "stats": stats(),
    })


@app.post("/admin/settings/password")
def admin_settings_password(request: Request, username: str = Form(""), password: str = Form(""),
                            password2: str = Form("")):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
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
def admin_settings_free(request: Request, enabled: str = Form("")):
    if not check_session(request):
        return RedirectResponse("/admin/login", status_code=303)
    kv.set("cfg:free", b"1" if enabled else b"0")
    return RedirectResponse("/admin/settings?ok=1", status_code=303)


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    meta = lib_meta(GAME_ID)
    return templates.TemplateResponse("landing.html", {
        "request": request, "app": APP_NAME, "user_name": auth_user(), "lib": meta, "fmt": fmt_ts,
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
