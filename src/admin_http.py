# admin_http.py
import json
import urllib.parse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

from records import RecordStore
from auth import check_basic_auth  # فقط چک می‌کند، پاسخ نمی‌فرستد

# این store از dns_udp_server به این فایل inject می‌شود
store: RecordStore | None = None


class AdminHandler(BaseHTTPRequestHandler):
    # ---------- helpers ----------
    def _send_json(self, status_code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status_code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, rel_path: str, content_type: str):
        """
        فایل‌های UI را از مسیر پروژه سرو می‌کند.
        rel_path مثل: ui/index.html
        """
        project_root = Path(__file__).resolve().parent.parent  # ریشه پروژه (کنار src)
        file_path = project_root / rel_path

        if not file_path.exists():
            return self._send_text(404, "Not Found")

        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _unauthorized(self):
        """
        نکته:
        اگر هدر WWW-Authenticate را بفرستیم، مرورگر پنجره Sign in باز می‌کند.
        برای UI بهتر است 401 بدهیم ولی این هدر را نفرستیم تا خود UI پیام بدهد.
        """
        body = b"Unauthorized"
        self.send_response(401)
        # ❌ حذف شد تا popup مرورگر نیاد
        # self.send_header("WWW-Authenticate", 'Basic realm="Admin Area"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _require_admin(self) -> bool:
        if not check_basic_auth(self.headers):
            self._unauthorized()
            return False
        return True

    def _require_store(self) -> bool:
        global store
        if store is None:
            self._send_json(500, {"error": "Record store not initialized"})
            return False
        return True

    # ---------- routes ----------
    def do_GET(self):
        # 1) UI routes (public, no auth)
        if self.path in ("/", "/ui", "/ui/", "/ui/index.html"):
            return self._send_file("ui/index.html", "text/html; charset=utf-8")

        if self.path == "/ui/app.js":
            return self._send_file("ui/app.js", "application/javascript; charset=utf-8")

        # 2) Admin API routes (protected)
        if self.path not in ("/admin/health", "/admin/records"):
            return self._send_json(404, {"error": "Not Found"})

        if not self._require_admin():
            return

        if not self._require_store():
            return

        if self.path == "/admin/health":
            return self._send_json(200, {"status": "ok"})

        if self.path == "/admin/records":
            items = store.list_all()
            return self._send_json(200, {"items": items})

    def do_POST(self):
        if self.path != "/admin/record":
            return self._send_json(404, {"error": "Not Found"})

        if not self._require_admin():
            return

        if not self._require_store():
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return self._send_json(400, {"error": "Invalid JSON"})

        try:
            domain = data["domain"]
            rtype = data["type"]
            value = data["value"]
        except KeyError:
            return self._send_json(400, {"error": "Missing required fields"})

        ttl = data.get("ttl", 60)
        priority = data.get("priority", 10)

        try:
            store.add(domain, rtype, value, ttl, priority)
        except Exception as e:
            return self._send_json(400, {"error": str(e)})

        return self._send_json(200, {"status": "record added"})

    def do_DELETE(self):
        if not self.path.startswith("/admin/record/"):
            return self._send_json(404, {"error": "Not Found"})

        if not self._require_admin():
            return

        if not self._require_store():
            return

        raw = self.path[len("/admin/record/"):]
        domain = urllib.parse.unquote(raw).strip()
        if not domain:
            return self._send_json(400, {"error": "Missing domain in path"})

        removed = store.delete(domain)
        return self._send_json(200, {"status": "record deleted", "removed": removed})


def start_admin_server(record_store: RecordStore, port: int = 8080):
    global store
    store = record_store

    server = HTTPServer(("127.0.0.1", port), AdminHandler)
    print(f"✅ Admin API + UI listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()
