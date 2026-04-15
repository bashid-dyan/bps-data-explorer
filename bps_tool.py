"""
BPS Data Explorer - local & cloud web tool
Hanya memakai Python standard library (tidak perlu pip install).

Cara pakai lokal:
    1. Copy .env.example jadi .env, isi BPS_API_KEY
    2. python bps_tool.py
    3. Buka http://localhost:8080

Deploy ke Railway:
    Set environment variables:
        BPS_API_KEY   = api key dari webapi.bps.go.id
        APP_PASSWORD  = password untuk akses UI (opsional tapi SANGAT disarankan)
        PORT          = diatur otomatis oleh Railway
"""
import http.server
import socketserver
import urllib.request
import urllib.parse
import urllib.error
import json
import os
import sys
import hmac
from pathlib import Path

ROOT = Path(__file__).parent
os.chdir(ROOT)


def load_env():
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k.strip(), v)


load_env()
API_KEY = os.environ.get("BPS_API_KEY", "").strip()
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()  # kosong = tanpa auth
BASE = "https://webapi.bps.go.id/v1/api"
PORT = int(os.environ.get("PORT", "8080"))


def check_auth(handler) -> bool:
    """Return True kalau boleh lanjut. Kalau APP_PASSWORD kosong, selalu True."""
    if not APP_PASSWORD:
        return True
    token = handler.headers.get("X-App-Password", "")
    # constant-time compare
    return hmac.compare_digest(token, APP_PASSWORD)


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/"):
            self.proxy()
            return
        if self.path in ("/", ""):
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        # /auth/check — validasi password dari UI
        if self.path == "/auth/check":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(body or b"{}")
            except Exception:
                payload = {}
            pwd = (payload.get("password") or "").strip()
            if not APP_PASSWORD:
                self.send_json(200, {"ok": True, "auth_required": False})
                return
            ok = hmac.compare_digest(pwd, APP_PASSWORD)
            self.send_json(200 if ok else 401, {"ok": ok, "auth_required": True})
            return
        self.send_json(404, {"error": "not found"})

    def proxy(self):
        if not check_auth(self):
            self.send_json(401, {"error": "unauthorized"})
            return
        parsed = urllib.parse.urlparse(self.path)
        endpoint = parsed.path[len("/api/"):].strip("/")
        if endpoint not in {"list", "view", "domain"}:
            self.send_json(400, {"error": f"endpoint '{endpoint}' tidak dikenal"})
            return
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        params = {k: v[0] for k, v in qs.items() if v and v[0] != ""}
        params["key"] = API_KEY
        url = f"{BASE}/{endpoint}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bps-tool/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.HTTPError as e:
            self.send_json(e.code, {"error": f"BPS API HTTP {e.code}", "detail": e.reason})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write(f"  · {fmt % args}\n")
        except Exception:
            pass


def main():
    if not API_KEY:
        print("=" * 60)
        print("❌ BPS_API_KEY belum diset.")
        print("   Lokal : buat file .env berisi BPS_API_KEY=xxx")
        print("   Railway : set env var BPS_API_KEY di dashboard")
        print("=" * 60)
        sys.exit(1)

    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.allow_reuse_address = True
        print("=" * 60)
        print(" 📊  BPS Data Explorer")
        print(f"     Listening on 0.0.0.0:{PORT}")
        if APP_PASSWORD:
            print(f"     🔒 Password protection: ON")
        else:
            print(f"     ⚠️  Password protection: OFF (set APP_PASSWORD env var)")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Stopped.")


if __name__ == "__main__":
    main()
