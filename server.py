"""Paper Desk live relay: receives pushes from the trading box, serves the dashboard.
Stdlib only. PAPER data display only - no trading functionality."""
import hashlib, hmac, json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
import collections

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

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<meta name="theme-color" content="#0b0f14"><title>Paper Desk</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0f14;color:#e6edf3;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
form{width:min(92vw,360px);background:#131a22;border:1px solid #243040;border-radius:14px;padding:24px}
h1{font-size:18px;margin:0 0 4px}p.s{margin:0 0 18px;color:#8b98a8;font-size:13px}
input{width:100%;font-size:18px;padding:13px;border-radius:10px;border:1px solid #2d3b4e;background:#0b0f14;color:#e6edf3}
button{width:100%;margin-top:14px;font-size:17px;padding:13px;border:0;border-radius:10px;background:#2f81f7;color:#fff;font-weight:600}
.e{color:#ff7b72;font-size:14px;margin:0 0 12px}</style></head><body>
<form method="POST" action="/login"><h1>Paper Desk</h1><p class="s">Live paper-trading view. Enter passcode.</p>
__MSG__<input type="password" name="k" autocomplete="current-password" autofocus required placeholder="Passcode">
<button type="submit">Unlock</button></form></body></html>"""

def login_page(msg=""):
    m = f'<p class="e">{msg}</p>' if msg else ""
    return LOGIN_HTML.replace("__MSG__", m).encode()

FAILS = collections.defaultdict(list)   # ip -> [timestamps]
GFAILS = []
FLOCK = threading.Lock()
def rate_limited(ip):
    now = time.time()
    with FLOCK:
        FAILS[ip] = [t for t in FAILS[ip] if now - t < 60]
        GFAILS[:] = [t for t in GFAILS if now - t < 60]
        if len(FAILS) > 5000: FAILS.clear()
        return len(FAILS[ip]) >= 5 or len(GFAILS) >= 30
def note_fail(ip):
    now = time.time()
    with FLOCK:
        FAILS[ip].append(now); GFAILS.append(now)

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
    def _ip(self):
        xf = self.headers.get("X-Forwarded-For", "")
        return (xf.split(",")[-1].strip() if xf else self.client_address[0]) or "?"
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if u.path not in ("/", "/index.html", "/api/state"):
            return self._send(404, b'{"error":"not found"}')
        if not self._authed(q):
            if u.path == "/api/state":
                return self._send(401, b'{"error":"view key required"}')
            return self._send(200, login_page(), "text/html; charset=utf-8")
        if u.path == "/api/state":
            with LOCK:
                raw, t, n = STATE["raw"], STATE["t"], STATE["pushes"]
            age = None if t is None else round(time.time() - t, 1)
            d = json.loads(raw) if raw else {}
            d["_relay"] = {"has_data": raw is not None, "push_age_s": age, "pushes": n}
            return self._send(200, json.dumps(d).encode())
        extra = []
        if view_ok((q.get("k") or [""])[0]):
            extra.append(("Set-Cookie", f"pdk={COOKIE_VAL}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax"))
            # drop ?k= from the URL bar
            return self._send(302, b"", "text/plain", extra + [("Location", "/")])
        return self._send(200, INDEX, "text/html; charset=utf-8")
    def _login(self):
        ip = self._ip()
        try: n = int(self.headers.get("Content-Length", "0"))
        except ValueError: n = 0
        if n <= 0 or n > 2048: return self._send(413, login_page("Bad request"), "text/html; charset=utf-8")
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        if rate_limited(ip):
            time.sleep(1)
            return self._send(429, login_page("Too many attempts. Wait a minute."), "text/html; charset=utf-8", [("Retry-After", "60")])
        if view_ok((form.get("k") or [""])[0]):
            ck = f"pdk={COOKIE_VAL}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax"
            return self._send(302, b"", "text/plain", [("Set-Cookie", ck), ("Location", "/")])
        note_fail(ip); time.sleep(1)
        return self._send(401, login_page("Wrong passcode"), "text/html; charset=utf-8")
    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login": return self._login()
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
