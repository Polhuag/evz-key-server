import base64
import hashlib
import json
import os
import sys
import time

DB = "/tmp/opencode/log_test.db"
os.environ["SQLITE_PATH"] = DB
os.environ.pop("REDIS_URL", None)
os.environ.pop("KEY_VALUE_URL", None)
os.environ.setdefault("EVZ_GATE", "1")
os.environ.setdefault("EVZ_MODULE_MODE", "0")
os.environ.setdefault("EVZ_CERT_SHA256", "aa" * 32)
os.environ.setdefault("APP_NAME", "EVOLUTIONZ V2")

if os.path.exists(DB):
    os.remove(DB)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if "SIGNING_KEY_PEM" not in os.environ:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.environ["SIGNING_KEY_PEM"] = k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as srv
import gate
from fastapi.testclient import TestClient

KEY = "EVZ-LOGT-LOGT-LOGT-LOGT"
CERT = "aa" * 32
BUILD = "1.64.1.7-v162"
VER = "1.64.1.7-v162"

srv.kv.set("key:" + KEY, json.dumps({
    "k": KEY, "game": srv.GAME_ID, "created": srv.now_ts(),
    "expires": srv.now_ts() + 86400, "serials": [], "device_limit": 50,
}).encode())
blob = b"EVZFAKELIB" * 500
srv.kv.set("lib:%s:meta" % srv.GAME_ID, json.dumps({
    "id": "ridlog", "version": BUILD, "md5": hashlib.md5(blob).hexdigest(),
    "size": len(blob), "notes": "test", "mandatory": False,
}).encode())
srv.kv.set("lib:%s:blob:ridlog" % srv.GAME_ID, blob)

c = TestClient(srv.app)


def open_gate(serial):
    """Simulate a mod client doing /v2/open and read the issued log token/key."""
    sk, cpub = gate.x25519_pair()
    cn = os.urandom(16)
    proof = gate.proof(KEY, serial, CERT, BUILD, cpub, cn)
    r = c.post("/v2/open", json={
        "key": KEY, "serial": serial, "cert": CERT, "build": BUILD,
        "cpub": base64.b64encode(cpub).decode(),
        "cn": base64.b64encode(cn).decode(),
        "proof": base64.b64encode(proof).decode(),
    })
    assert r.status_code == 200, r.text
    o = r.json()
    assert o.get("ok") == 1, o
    assert len(o.get("lt", "")) == 32, o
    assert len(o.get("lk", "")) == 64, o
    klog = bytes.fromhex(o["lk"])
    assert klog == bytes.fromhex(srv.kv.get("evzlog:key:" + srv.log_dev_id(serial)).decode())
    return o["lt"], srv.log_dev_id(serial), klog


def encrypt(klog, dev, plain):
    nonce = os.urandom(12)
    ct = AESGCM(klog).encrypt(nonce, plain, dev.encode())
    return base64.b64encode(nonce + ct)


def post_log(dev, tok, body, ver=VER, ip="10.1.0.1"):
    return c.post("/log", params={"dev": dev, "ver": ver, "t": tok},
                  content=body, headers={"x-forwarded-for": ip,
                                         "content-type": "text/plain"})


# 0) /connect issues lt + lk in the signed payload; use them for /log
serial_c = "serial-connect-1"
r = c.post("/connect", json={"user_key": KEY, "serial": serial_c, "ver": VER})
assert r.status_code == 200, r.text
o = r.json()
assert o.get("status") is True, o
payload = json.loads(base64.b64decode(o["data"]["payload"]).decode())
assert len(payload.get("lt", "")) == 32 and len(payload.get("lk", "")) == 64, payload
devc = srv.log_dev_id(serial_c)
assert srv.kv.get("evzlog:tok:" + devc).decode() == payload["lt"]
assert srv.kv.get("evzlog:key:" + devc).decode() == payload["lk"]
r = post_log(devc, payload["lt"], encrypt(bytes.fromhex(payload["lk"]), devc, b"from connect\n"), ip="10.2.0.1")
assert r.status_code == 200 and r.json() == {"ok": True}, (r.status_code, r.text)
print("ok /connect payload lt+lk drive encrypted /log")

# 1) encrypted body + valid token -> accepted, stored, then per-dev 20s limit
lt, dev1, klog1 = open_gate("serial-log-1")
plain1 = b"hello\n<script>alert(1)</script>\n"
r = post_log(dev1, lt, encrypt(klog1, dev1, plain1), ip="10.1.0.1")
assert r.status_code == 200 and r.json() == {"ok": True}, (r.status_code, r.text)
chunks = srv.kv.rrange("evzlog:chunks:" + dev1, -40, -1)
assert len(chunks) == 1, chunks
assert chunks[0].startswith(b"----- ") and b"ver=" + VER.encode() in chunks[0].split(b"\n")[0]
assert plain1 not in chunks[0], "chunk must not contain plaintext"
r = post_log(dev1, lt, encrypt(klog1, dev1, b"second\n"), ip="10.1.0.1")
assert r.status_code == 429 and r.json().get("e") == "slow", (r.status_code, r.text)
assert len(srv.kv.rrange("evzlog:chunks:" + dev1, -40, -1)) == 1, "429 must not write"
print("ok encrypted log accepted + per-dev 20s limit")

# 2) wrong token -> 403 auth
lt2, dev2, klog2 = open_gate("serial-log-2")
r = post_log(dev2, "0" * 32, encrypt(klog2, dev2, b"nope\n"), ip="10.1.0.2")
assert r.status_code == 403 and r.json().get("e") == "auth", (r.status_code, r.text)
print("ok wrong token -> 403 auth")

# 3) bad dev format -> 400
r = post_log("ZZZZ", "0" * 32, b"x\n", ip="10.1.0.3")
assert r.status_code == 400, (r.status_code, r.text)
print("ok bad dev -> 400")

# 4) bad ver -> 400
lt3, dev3, klog3 = open_gate("serial-log-3")
r = post_log(dev3, lt3, encrypt(klog3, dev3, b"x\n"), ver="2.0", ip="10.1.0.4")
assert r.status_code == 400, (r.status_code, r.text)
print("ok bad ver -> 400")

# 5) raw body > 300KB -> 413
lt4, dev4, klog4 = open_gate("serial-log-4")
r = post_log(dev4, lt4, b"a" * 300001, ip="10.1.0.5")
assert r.status_code == 413, (r.status_code, r.text)
print("ok oversized raw body -> 413")

# 6) decrypted body > 200KB -> 413
lt5, dev5, klog5 = open_gate("serial-log-5")
r = post_log(dev5, lt5, encrypt(klog5, dev5, b"a" * 200001), ip="10.1.0.6")
assert r.status_code == 413, (r.status_code, r.text)
print("ok oversized decrypted body -> 413")

# 7) plaintext body with valid token -> 400 bad (no plaintext accepted)
lt6, dev6, klog6 = open_gate("serial-log-6")
r = post_log(dev6, lt6, b"plain text log\n", ip="10.1.0.7")
assert r.status_code == 400 and r.json().get("e") == "bad", (r.status_code, r.text)
print("ok plaintext body rejected -> 400 bad")

# 8) broken base64 / bad tag -> 400 bad
lt12, dev12, klog12 = open_gate("serial-log-12")
r = post_log(dev12, lt12, b"!!!not-base64!!!", ip="10.1.0.7")
assert r.status_code == 400, (r.status_code, r.text)
lt13, dev13, klog13 = open_gate("serial-log-13")
bad_tag = bytearray(encrypt(klog13, dev13, b"tamper\n"))
bad_tag[-2] = ord("A") if bad_tag[-2] != ord("A") else ord("B")
r = post_log(dev13, lt13, bytes(bad_tag), ip="10.1.0.7")
assert r.status_code == 400 and r.json().get("e") == "bad", (r.status_code, r.text)
print("ok invalid base64 / bad GCM tag -> 400 bad")

# 9) non-printable decrypted body -> 400 bad
lt7, dev7, klog7 = open_gate("serial-log-7")
r = post_log(dev7, lt7, encrypt(klog7, dev7, b"\x00" * 64), ip="10.1.0.8")
assert r.status_code == 400 and r.json().get("e") == "bad", (r.status_code, r.text)
print("ok non-printable decrypted body -> 400 bad")

# 10) bad-token counter > 5 revokes the token
lt8, dev8, klog8 = open_gate("serial-log-8")
for i in range(6):
    r = post_log(dev8, "f" * 32, encrypt(klog8, dev8, b"x\n"), ip="10.1.0.9")
    assert r.status_code == 403, (i, r.status_code, r.text)
assert srv.kv.get("evzlog:tok:" + dev8) is None, "token should be revoked"
r = post_log(dev8, lt8, encrypt(klog8, dev8, b"x\n"), ip="10.1.0.9")
assert r.status_code == 403, (r.status_code, r.text)
print("ok bad-token counter revokes token after >5")

# 11) expired token -> 403
lt9, dev9, klog9 = open_gate("serial-log-9")
srv.kv.set_ex("evzlog:tok:" + dev9, lt9.encode(), 1)
time.sleep(1.2)
r = post_log(dev9, lt9, encrypt(klog9, dev9, b"x\n"), ip="10.1.0.10")
assert r.status_code == 403 and r.json().get("e") == "auth", (r.status_code, r.text)
print("ok expired token -> 403")

# 12) missing / expired klog -> 403 auth
lt10, dev10, klog10 = open_gate("serial-log-10")
srv.kv.delete("evzlog:key:" + dev10)
r = post_log(dev10, lt10, encrypt(klog10, dev10, b"x\n"), ip="10.1.0.11")
assert r.status_code == 403 and r.json().get("e") == "auth", (r.status_code, r.text)
lt11, dev11, klog11 = open_gate("serial-log-11")
srv.kv.set_ex("evzlog:key:" + dev11, klog11.hex().encode(), 1)
time.sleep(1.2)
r = post_log(dev11, lt11, encrypt(klog11, dev11, b"x\n"), ip="10.1.0.12")
assert r.status_code == 403 and r.json().get("e") == "auth", (r.status_code, r.text)
print("ok missing/expired klog -> 403 auth")

# 13) per-IP limit 20/min -> 429 busy
ip = "10.9.9.9"
hit429 = None
for i in range(25):
    r = post_log("0123456789abcdef", "0" * 32, b"x\n", ip=ip)
    if r.status_code == 429:
        hit429 = (i, r.json())
        break
    assert r.status_code == 403, (i, r.status_code, r.text)
assert hit429 and hit429[1].get("e") == "busy", hit429
print("ok per-IP limit -> 429 busy at request", hit429[0] + 1)

# 14) admin list / detail / raw download / missing key notice
r = c.get("/admin/logs", follow_redirects=False)
assert r.status_code == 303 and r.headers.get("location") == "/admin/login", (r.status_code, r.text)
sess = srv.make_session()
r = c.get("/admin/logs", cookies={"evz_admin": sess})
assert r.status_code == 200 and dev1 in r.text and "Tải" in r.text, (r.status_code, r.text[:300])
r = c.get("/admin/logs/" + dev1, cookies={"evz_admin": sess})
assert r.status_code == 200, (r.status_code, r.text[:200])
assert "hello" in r.text and "&lt;script&gt;" in r.text, "log must be escaped"
assert "?raw=1" in r.text, "download link missing"
r = c.get("/admin/logs/" + dev1 + "?raw=1", cookies={"evz_admin": sess})
assert r.status_code == 200 and r.content == plain1, (r.status_code, r.content[:80])
assert ".log" in r.headers.get("content-disposition", "")
r = c.get("/admin/logs/" + dev10, cookies={"evz_admin": sess})
assert r.status_code == 200 and "Không tìm thấy khoá giải mã" in r.text, (r.status_code, r.text[:200])
r = c.get("/admin/logs/nothex", cookies={"evz_admin": sess})
assert r.status_code == 404, r.status_code
print("ok admin list/detail/raw/missing-key/404")

print("ALL LOG TESTS OK")
