import os
import struct

from nacl import bindings
from nacl import hash as nhash
from nacl.encoding import RawEncoder

MAGIC = b"EVZ2\x00"
CHUNK_SIZE = int(os.environ.get("EVZ_CHUNK_SIZE", "65536"))
BATCH_MAX = int(os.environ.get("EVZ_BATCH_MAX", "16"))
SESSION_TTL = int(os.environ.get("EVZ_SESSION_TTL", "120"))


def blake(data, key=b"", size=32):
    return nhash.blake2b(bytes(data), key=bytes(key), digest_size=size, encoder=RawEncoder)


def x25519_pair(seed=None):
    sk = bytes(seed) if seed else os.urandom(32)
    return sk, bindings.crypto_scalarmult_base(sk)


def x25519_shared(sk, pk):
    return bindings.crypto_scalarmult(bytes(sk), bytes(pk))


def sha256(data):
    import hashlib
    return hashlib.sha256(bytes(data)).digest()


def manifest(sid, sn, spub, cpub, cn, n, csz, mode, ver, root, leaves_digest, exp):
    v = ver.encode()
    return (MAGIC + sid + sn + spub + cpub + cn +
            struct.pack(">IIBHQ", n, csz, mode, len(v), exp) + v + root + leaves_digest)


def session_key(shared, sid, sn, cpub, spub, cn):
    return blake(b"EVZ2K" + sid + sn + cn + cpub + spub, key=shared, size=32)


def proof(key, serial, cert, build, cpub, cn):
    k = sha256(("%s|%s|%s|%s" % (key, serial, cert, build)).encode())
    return blake(b"EVZ2P" + cpub + cn + build.encode(), key=k, size=32)


def index_tag(session_key_bytes, sid, slot):
    return blake(b"EVZ2I" + sid + struct.pack(">H", slot), key=session_key_bytes, size=16)


def chunk_aad(sid, slot):
    return b"EVZ2C" + sid + struct.pack(">H", slot)


def seal(key, nonce, aad, plain):
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(plain), bytes(aad), bytes(nonce), bytes(key))


def open_sealed(key, nonce, aad, sealed):
    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(bytes(sealed), bytes(aad), bytes(nonce), bytes(key))


def build_module(blob, csz=CHUNK_SIZE):
    data_size = csz - 8
    n = (len(blob) + data_size - 1) // data_size
    chunks = []
    leaves = []
    for i in range(n):
        data = blob[i * data_size:(i + 1) * data_size]
        body = struct.pack(">II", i, len(data)) + data
        pt = body + os.urandom(csz - len(body))
        chunks.append(pt)
        leaves.append(blake(pt))
    root = blake(b"EVZ2R" + b"".join(leaves))
    return chunks, leaves, root


def leaves_digest(leaves):
    return blake(b"EVZ2L" + b"".join(leaves))
