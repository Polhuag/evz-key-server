import json
import os
import sqlite3
import threading
import time


class KV:
    def get(self, k):
        raise NotImplementedError

    def set(self, k, v):
        raise NotImplementedError

    def set_ex(self, k, v, ex):
        raise NotImplementedError

    def set_nx(self, k, v, ex=None):
        raise NotImplementedError

    def incr(self, k):
        raise NotImplementedError

    def expire(self, k, ex):
        raise NotImplementedError

    def delete(self, k):
        raise NotImplementedError

    def keys(self, prefix=""):
        raise NotImplementedError

    def lpush(self, k, v):
        raise NotImplementedError

    def rpush(self, k, v):
        raise NotImplementedError

    def lpop(self, k):
        raise NotImplementedError

    def lrange(self, k, start, stop):
        raise NotImplementedError

    def rrange(self, k, start, stop):
        raise NotImplementedError

    def llen(self, k):
        raise NotImplementedError

    def ltrim(self, k, start, stop):
        raise NotImplementedError

    def hset(self, k, mapping):
        raise NotImplementedError

    def hgetall(self, k):
        raise NotImplementedError

    def zadd(self, k, score, member):
        raise NotImplementedError

    def zrevrange(self, k, start, stop, withscores=True):
        raise NotImplementedError


class RedisKV(KV):
    def __init__(self, url):
        import redis
        self.r = redis.from_url(url, decode_responses=False)
        self.r.ping()

    def get(self, k):
        return self.r.get(k)

    def set(self, k, v):
        self.r.set(k, v)

    def set_ex(self, k, v, ex):
        self.r.set(k, v, ex=ex)

    def set_nx(self, k, v, ex=None):
        return bool(self.r.set(k, v, nx=True, ex=ex))

    def incr(self, k):
        return int(self.r.incr(k))

    def expire(self, k, ex):
        self.r.expire(k, ex)

    def delete(self, k):
        self.r.delete(k)

    def keys(self, prefix=""):
        out = []
        for k in self.r.scan_iter(match=prefix + "*", count=500):
            out.append(k.decode() if isinstance(k, bytes) else k)
        return out

    def lpush(self, k, v):
        self.r.lpush(k, v)

    def rpush(self, k, v):
        self.r.rpush(k, v)

    def lpop(self, k):
        return self.r.lpop(k)

    def lrange(self, k, start, stop):
        return self.r.lrange(k, start, stop)

    def rrange(self, k, start, stop):
        return self.r.lrange(k, start, stop)

    def llen(self, k):
        return int(self.r.llen(k))

    def ltrim(self, k, start, stop):
        self.r.ltrim(k, start, stop)

    def hset(self, k, mapping):
        self.r.hset(k, mapping=mapping)

    def hgetall(self, k):
        return self.r.hgetall(k)

    def zadd(self, k, score, member):
        self.r.zadd(k, {member: score})

    def zrevrange(self, k, start, stop, withscores=True):
        return self.r.zrevrange(k, start, stop, withscores=withscores)


class SqliteKV(KV):
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB)")
        self.c.execute("CREATE TABLE IF NOT EXISTS exp (k TEXT PRIMARY KEY, x REAL)")
        self.c.execute("CREATE TABLE IF NOT EXISTS lists (k TEXT, seq INTEGER PRIMARY KEY AUTOINCREMENT, v BLOB)")
        self.c.execute("CREATE INDEX IF NOT EXISTS lists_k ON lists (k, seq)")
        self.c.commit()

    def _get_raw(self, k):
        row = self.c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        if not row:
            return None
        ex = self.c.execute("SELECT x FROM exp WHERE k=?", (k,)).fetchone()
        if ex and ex[0] <= time.time():
            self.c.execute("DELETE FROM kv WHERE k=?", (k,))
            self.c.execute("DELETE FROM exp WHERE k=?", (k,))
            self.c.commit()
            return None
        return bytes(row[0]) if row[0] is not None else None

    def _put_raw(self, k, v):
        self.c.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                       (k, sqlite3.Binary(v)))

    def _put_exp(self, k, ex):
        self.c.execute("INSERT INTO exp (k, x) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET x=excluded.x",
                       (k, time.time() + ex))

    def get(self, k):
        with self.lock:
            return self._get_raw(k)

    def set(self, k, v):
        with self.lock:
            self._put_raw(k, v)
            self.c.execute("DELETE FROM exp WHERE k=?", (k,))
            self.c.commit()

    def set_ex(self, k, v, ex):
        with self.lock:
            self._put_raw(k, v)
            self._put_exp(k, ex)
            self.c.commit()

    def set_nx(self, k, v, ex=None):
        with self.lock:
            if self._get_raw(k) is not None:
                return False
            self._put_raw(k, v)
            if ex:
                self._put_exp(k, ex)
            else:
                self.c.execute("DELETE FROM exp WHERE k=?", (k,))
            self.c.commit()
            return True

    def incr(self, k):
        with self.lock:
            raw = self._get_raw(k)
            try:
                n = int(raw) if raw else 0
            except Exception:
                n = 0
            n += 1
            self._put_raw(k, str(n).encode())
            self.c.commit()
            return n

    def expire(self, k, ex):
        with self.lock:
            self._put_exp(k, ex)
            self.c.commit()

    def delete(self, k):
        with self.lock:
            self.c.execute("DELETE FROM kv WHERE k=?", (k,))
            self.c.execute("DELETE FROM exp WHERE k=?", (k,))
            self.c.execute("DELETE FROM lists WHERE k=?", (k,))
            self.c.commit()

    def keys(self, prefix=""):
        with self.lock:
            rows = self.c.execute("SELECT k FROM kv WHERE k LIKE ?", (prefix + "%",)).fetchall()
        return [r[0] for r in rows]

    def lpush(self, k, v):
        with self.lock:
            self.c.execute("INSERT INTO lists (k, v) VALUES (?, ?)", (k, sqlite3.Binary(v)))
            self.c.commit()

    def rpush(self, k, v):
        with self.lock:
            self.c.execute("INSERT INTO lists (k, v) VALUES (?, ?)", (k, sqlite3.Binary(v)))
            self.c.commit()

    def lpop(self, k):
        with self.lock:
            row = self.c.execute("SELECT seq, v FROM lists WHERE k=? ORDER BY seq DESC LIMIT 1", (k,)).fetchone()
            if not row:
                return None
            self.c.execute("DELETE FROM lists WHERE seq=?", (row[0],))
            self.c.commit()
        return bytes(row[1])

    def lrange(self, k, start, stop):
        with self.lock:
            rows = self.c.execute("SELECT v FROM lists WHERE k=? ORDER BY seq DESC LIMIT ? OFFSET ?",
                                  (k, stop - start + 1, start)).fetchall()
        return [bytes(r[0]) for r in rows]

    def rrange(self, k, start, stop):
        with self.lock:
            rows = [bytes(r[0]) for r in self.c.execute(
                "SELECT v FROM lists WHERE k=? ORDER BY seq DESC", (k,)).fetchall()]
        rows.reverse()
        n = len(rows)
        s = start if start >= 0 else max(0, n + start)
        e = stop if stop >= 0 else n + stop
        if e < s:
            return []
        return rows[s:e + 1]

    def llen(self, k):
        with self.lock:
            row = self.c.execute("SELECT COUNT(*) FROM lists WHERE k=?", (k,)).fetchone()
        return int(row[0]) if row else 0

    def ltrim(self, k, start, stop):
        with self.lock:
            rows = [r[0] for r in self.c.execute(
                "SELECT seq FROM lists WHERE k=? ORDER BY seq DESC", (k,)).fetchall()]
            n = len(rows)
            s = start if start >= 0 else max(0, n + start)
            e = stop if stop >= 0 else n + stop
            keep = set(rows[s:e + 1]) if e >= s else set()
            for seq in rows:
                if seq not in keep:
                    self.c.execute("DELETE FROM lists WHERE seq=?", (seq,))
            self.c.commit()

    def hset(self, k, mapping):
        with self.lock:
            raw = self._get_raw(k)
            d = json.loads(raw.decode()) if raw else {}
            for a, b in mapping.items():
                d[str(a)] = b.decode() if isinstance(b, bytes) else str(b)
            self._put_raw(k, json.dumps(d, ensure_ascii=False).encode())
            self.c.commit()

    def hgetall(self, k):
        with self.lock:
            raw = self._get_raw(k)
            d = json.loads(raw.decode()) if raw else {}
        return {str(a): str(b) for a, b in d.items()}

    def zadd(self, k, score, member):
        with self.lock:
            raw = self._get_raw(k)
            d = json.loads(raw.decode()) if raw else {}
            d[str(member)] = float(score)
            self._put_raw(k, json.dumps(d).encode())
            self.c.commit()

    def zrevrange(self, k, start, stop, withscores=True):
        with self.lock:
            raw = self._get_raw(k)
            d = json.loads(raw.decode()) if raw else {}
        items = sorted(d.items(), key=lambda x: x[1], reverse=True)
        n = len(items)
        s = start if start >= 0 else max(0, n + start)
        e = stop if stop >= 0 else n + stop
        items = items[s:e + 1] if e >= s else []
        if withscores:
            return [(m, float(sc)) for m, sc in items]
        return [m for m, _ in items]


def open_store():
    url = os.environ.get("REDIS_URL") or os.environ.get("KEY_VALUE_URL")
    if url:
        try:
            return RedisKV(url)
        except Exception as e:
            print("redis connect failed, fallback sqlite:", e, flush=True)
    path = os.environ.get("SQLITE_PATH", "/tmp/evz.db")
    return SqliteKV(path)
