"""HVMC lab-results API (demo container workload). Read-only health and version endpoints; no ePHI in this image."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

VERSION = os.environ.get("APP_VERSION", "1.0.0")


class Handler(BaseHTTPRequestHandler):
    server_version = "hvmc-lab-api"                    # hide the Python version banner
    sys_version = ""

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        elif self.path == "/version":
            self._send(200, {"service": "hvmc-lab-api", "version": VERSION})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):                  # structured access log to stdout
        print(json.dumps({"client": self.client_address[0], "request": fmt % args}), flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
