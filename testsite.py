"""Deliberately vulnerable local target for demonstrating webpent.

DO NOT DEPLOY. Bind to loopback only.
Run: python testsite.py  ->  http://127.0.0.1:8000
"""
import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PAGE = """<!doctype html><html><head><title>testsite</title></head>
<body><h1>Vulnerable demo app</h1>
<p>Try: <a href="/search?q=hello">/search?q=hello</a>,
<a href="/go?next=https://example.com">/go?next=</a>,
<a href="/fetch?url=http://example.com">/fetch?url=</a>,
<a href="/item?id=1">/item?id=1</a></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="text/html", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path

        if path == "/search":
            q = qs.get("q", [""])[0]
            # XSS: reflection without encoding
            body = f"<html><body>Results for: {q}</body></html>"
            self._send(200, body)
        elif path == "/go":
            next_url = qs.get("next", ["/"])[0]
            # Open redirect
            self._send(302, "redirecting", headers={"Location": next_url})
        elif path == "/fetch":
            url = qs.get("url", [""])[0]
            # SSRF: server-side fetch of user URL (faked — returns canary markers if matched)
            if "webpent-canary" in url or "ssrf-canary" in url:
                self._send(200, "<pre>fetched content: webpent-canary marker from remote host</pre>")
            elif "169.254.169.254" in url:
                self._send(200, "ami-id: ami-0123456789abcdef0\ninstance-id: i-0abc\n")
            else:
                self._send(200, f"<pre>fetched: {html.escape(url)}</pre>")
        elif path == "/item":
            item = qs.get("id", ["0"])[0]
            # SQLi: naive string concat with error leak
            try:
                if any(c in item for c in "'\""):
                    raise ValueError("you have an error in your sql syntax; check the manual that corresponds to your MySQL server version")
                row = {"id": item, "name": f"item-{item}"}
                self._send(200, json.dumps(row), ctype="application/json")
            except ValueError as e:
                self._send(500, json.dumps({"error": str(e)}), ctype="application/json")
        elif path == "/":
            self._send(200, PAGE)
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    print("Vulnerable demo on http://127.0.0.1:8000 (loopback only)")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
