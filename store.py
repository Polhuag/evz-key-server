import os
import sqlite3
import threading


class KV:
    def get(self, k):
        raise NotImplementedError

    def set(self, k, v):
        raise NotImplementedError

    def delete(self, k):
        raise NotImplementedError

    def keys(self, prefix=""):
        raise NotImplementedError

    def lpush(self, k, v):
        raise NotImplementedError

    def lpop(self, k):
        raise NotImplementedError

    def lrange(self, k, start, stop):
        raise NotImplementedError

    def ltrim(self, k, start, stop):
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

    def delete(self, k):
        self.r.delete(k)

    def keys(self, prefix=""):
        out = []
        for k in self.r.scan_iter(match=prefix + "*", count=500):
            out.append(k.decode() if isinstance(k, bytes) else k)
        return out

    def lpush(self, k, v):
        self.r.lpush(k, v)

    def lpop(self, k):
        return self.r.lpop(k)

    def lrange(self, k, start, stop):
        return self.r.lrange(k, start, stop)

    def ltrim(self, k, start, stop):
        self.r.ltrim(k, start, stop)


class SqliteKV(KV):
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB)")
        self.c.execute("CREATE TABLE IF NOT EXISTS lists (k TEXT, seq INTEGER PRIMARY KEY AUTOINCREMENT, v BLOB)")
        self.c.execute("CREATE INDEX IF NOT EXISTS lists_k ON lists (k, seq)")
        self.c.commit()

    def get(self, k):
        with self.lock:
            row = self.c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return bytes(row[0]) if row and row[0] is not None else None

    def set(self, k, v):
        with self.lock:
            self.c.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                           (k, sqlite3.Binary(v)))
            self.c.commit()

    def delete(self, k):
        with self.lock:
            self.c.execute("DELETE FROM kv WHERE k=?", (k,))
            self.c.commit()

    def keys(self, prefix=""):
        with self.lock:
            rows = self.c.execute("SELECT k FROM kv WHERE k LIKE ?", (prefix + "%",)).fetchall()
        return [r[0] for r in rows]

    def lpush(self, k, v):
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

    def ltrim(self, k, start, stop):
        with self.lock:
            rows = self.c.execute("SELECT seq FROM lists WHERE k=? ORDER BY seq DESC LIMIT -1 OFFSET ?",
                                  (k, stop + 1)).fetchall()
            for r in rows:
                self.c.execute("DELETE FROM lists WHERE seq=?", (r[0],))
            self.c.commit()


def open_store():
    url = os.environ.get("REDIS_URL") or os.environ.get("KEY_VALUE_URL")
    if url:
        try:
            return RedisKV(url)
        except Exception as e:
            print("redis connect failed, fallback sqlite:", e, flush=True)
    path = os.environ.get("SQLITE_PATH", "/tmp/evz.db")
    return SqliteKV(path)
