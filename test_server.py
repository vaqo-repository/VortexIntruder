"""Realistic test server for VortexIntruder testing.

Simulates a web application with varied responses:
  - Valid login:  admin / secret123  → 302 redirect + session cookie
  - Locked users: user contains 'locked' → 403
  - Rate limit:   password contains 'ratelimit' → 429
  - Server error: password contains 'error' or 'crash' → 500
  - SQL-like:     password contains ' or ' or '--' → 200 + "Welcome" (SQLi test)
  - Short pwd:    len < 4 → 200 + "Password too short"
  - Default:      wrong credentials → 401 Unauthorized
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import html
import hashlib
import time

VALID_USER = "admin"
VALID_PASS = "secret123"

request_counter = 0


class TestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global request_counter
        request_counter += 1

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = dict(urllib.parse.parse_qsl(body))

        user = params.get("username", "")
        pwd = params.get("password", "")
        safe_user = html.escape(user)

        # 1) Rate limiting simulation (every 100th request or keyword)
        if "ratelimit" in pwd.lower() or request_counter % 100 == 0:
            self._respond(429, "Too Many Requests",
                          f"<h1>429 - Rate Limited</h1>"
                          f"<p>Try again in 60 seconds. Request #{request_counter}</p>")
            return

        # 2) Server error simulation
        if any(kw in pwd.lower() for kw in ("error", "crash", "servererr")):
            self._respond(500, "Internal Server Error",
                          "<h1>500 - Internal Server Error</h1>"
                          "<p>An unexpected error occurred.</p>")
            return

        # 3) Account lockout simulation
        if "locked" in user.lower() or "blocked" in pwd.lower():
            self._respond(403, "Forbidden",
                          f"<h1>403 - Account Locked</h1>"
                          f"<p>Account '{safe_user}' has been locked due to too many failed attempts.</p>")
            return

        # 4) SQL injection test — simulate vulnerable app
        if any(s in pwd for s in ("' or '", "' OR '", "--", "1=1", "admin'--")):
            token = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
            self._respond(200, "OK",
                          f"<h1>Welcome {safe_user}!</h1>"
                          f"<p>Dashboard loaded (SQLi bypass)</p>"
                          f'<input name="csrf" value="{token}">',
                          extra_headers={"Set-Cookie": f"session=sqli_{token}; Path=/"})
            return

        # 5) Password too short
        if len(pwd) < 4:
            self._respond(200, "OK",
                          f"<h1>Validation Error</h1>"
                          f"<p>Password too short (min 4 chars)</p>")
            return

        # 6) Valid credentials
        if user == VALID_USER and pwd == VALID_PASS:
            token = hashlib.md5(f"{user}{time.time()}".encode()).hexdigest()[:16]
            self._respond(302, "Found",
                          f"<h1>Welcome {safe_user}!</h1>"
                          f"<p>Login successful — redirecting to dashboard</p>"
                          f'<input name="csrf" value="{token}">',
                          extra_headers={
                              "Set-Cookie": f"session={token}; Path=/; HttpOnly",
                              "Location": "/dashboard",
                          })
            return

        # 7) Default — invalid credentials → 401
        self._respond(401, "Unauthorized",
                      f"<h1>Login failed</h1>"
                      f"<p>Invalid password for user: {safe_user}</p>")

    def do_GET(self):
        if self.path == "/dashboard":
            self._respond(200, "OK",
                          "<h1>Dashboard</h1><p>You are logged in.</p>")
        else:
            self._respond(200, "OK",
                          "<h1>Test Server Running</h1>"
                          f"<p>Requests handled: {request_counter}</p>")

    def _respond(self, code, reason, body_html, extra_headers=None):
        full_body = f"<html><body>{body_html}</body></html>"
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(full_body.encode())))
        self.send_header("X-Request-Id", str(request_counter))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(full_body.encode())

    def log_message(self, format, *args):
        print(f"[#{request_counter:>5}] {args[0]}")


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 9999), TestHandler)
    print("="*50)
    print("  VortexIntruder Test Server")
    print("="*50)
    print(f"  URL:        http://127.0.0.1:9999")
    print(f"  Valid cred: {VALID_USER} / {VALID_PASS}")
    print()
    print("  Response codes:")
    print("    302 — valid login (admin/secret123)")
    print("    401 — wrong credentials")
    print("    403 — locked account / blocked")
    print("    429 — rate limited")
    print("    500 — server error (pwd contains 'error')")
    print("    200 — SQLi bypass / short password")
    print("="*50)
    server.serve_forever()
