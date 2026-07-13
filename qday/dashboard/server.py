"""Tiny stdlib HTTP server for the dashboard. Re-reads the store on every
request, so a fresh `qday scan` shows up on reload — that's the whole
"continuous" loop for the MVP: cron the scan, keep the page open."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..store import Store
from .html import render_dashboard


def serve(db_path: str, port: int = 8080) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server API)
            store = Store(db_path)
            try:
                page = render_dashboard(store).encode()
            finally:
                store.close()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, fmt, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"dashboard: http://127.0.0.1:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
