"""Paper Desk live relay: receives pushes from the trading box, serves the dashboard.
Stdlib only. PAPER data display only - no trading functionality."""
import hashlib, hmac, json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

PUSH_TOKEN = os.environ.get("PUSH_TOKEN", "")
VIEW_KEY = os.environ.get("VIEW_KEY", "")
MAX_BODY = 1_000_000
LOCK = threading.Lock()
STATE = {"raw": None, "t": None, "pushes": 0}
INDEX = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), "rb").read()

# View key: either VIEW_KEY (plain) or VIEW_KEY_HASH = "pbkdf2$<iters>$<salt_hex>$<hash_hex>"
VIEW_HASH = os.environ.get("VIEW_KEY_HASH", "")
def _hash_parts():
    try:
        _, it, salt, h = VIEW_HASH.split("$"); return int(it), bytes.fromhex(salt), h
    except Exception: return None
HP = _hash_parts()
COOKIE_VAL = hmac.new(HP[1], b"cookie|" + HP[2].encode(), "sha256").hexdigest() if HP else VIEW_KEY

def view_ok(candidate):
    """candidate = key presented via ?k= or X-View-Key"""
    if not candidate: return False
    if HP:
        it, salt, h = HP
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, it).hex(), h)
    return eq(candidate, VIEW_KEY)

def eq(a, b):
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())

class H(BaseHTTPRequestHandler):
    server_version = "PaperDesk"
    def log_message(self, *a): pass
    def _send(self, code, body=b"", ctype="application/json", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in extra: self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def _authed(self, q):
        if not (VIEW_KEY or HP): return False
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "pdk" in ck and eq(ck["pdk"].value, COOKIE_VAL): return True
        if view_ok(self.headers.get("X-View-Key", "")): return True
        if view_ok((q.get("k") or [""])[0]): return True
        return False
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if u.path not in ("/", "/index.html", "/api/state"):
            return self._send(404, b'{"error":"not found"}')
        if not self._authed(q):
            return self._send(401, b'{"error":"view key required"}')
        if u.path == "/api/state":
            with LOCK:
                raw, t, n = STATE["raw"], STATE["t"], STATE["pushes"]
            age = None if t is None else round(time.time() - t, 1)
            d = json.loads(raw) if raw else {}
            d["_relay"] = {"has_data": raw is not None, "push_age_s": age, "pushes": n}
            return self._send(200, json.dumps(d).encode())
        extra = []
        if view_ok((q.get("k") or [""])[0]):
            extra.append(("Set-Cookie", f"pdk={COOKIE_VAL}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Strict"))
            # drop ?k= from the URL bar
            return self._send(302, b"", "text/plain", extra + [("Location", "/")])
        return self._send(200, INDEX, "text/html; charset=utf-8")
    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/push": return self._send(404, b'{"error":"not found"}')
        if not eq(self.headers.get("X-Push-Token", ""), PUSH_TOKEN):
            return self._send(401, b'{"error":"bad token"}')
        try: n = int(self.headers.get("Content-Length", "0"))
        except ValueError: n = 0
        if n <= 0 or n > MAX_BODY: return self._send(413, b'{"error":"bad size"}')
        body = self.rfile.read(n)
        try:
            d = json.loads(body)
            if not isinstance(d, dict): raise ValueError
        except Exception:
            return self._send(400, b'{"error":"bad json"}')
        with LOCK:
            STATE["raw"] = body; STATE["t"] = time.time(); STATE["pushes"] += 1
        self._send(200, b'{"ok":true}')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
