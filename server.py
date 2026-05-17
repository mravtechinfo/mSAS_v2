#!/usr/bin/env python3
"""
Custom HTTP server for Mobile Security Auditor.
Serves static files and returns a custom 404.html for missing pages.
"""

import os
import sys
import mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler


class CustomHandler(SimpleHTTPRequestHandler):
    """HTTP request handler with custom 404 page."""

    def send_error(self, code, message=None):
        """Override to serve a custom 404.html for 404 errors."""
        if code == 404:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()

            # Try subdirectory-specific 404.html first, then fall back to root
            paths_to_try = []
            path_parts = self.path.strip('/').split('/')
            if len(path_parts) > 1:
                paths_to_try.append(os.path.join(path_parts[0], '404.html'))
            paths_to_try.append('404.html')

            content = None
            for p in paths_to_try:
                if os.path.exists(p) and os.path.isfile(p):
                    with open(p, 'rb') as f:
                        content = f.read()
                    break

            if content is None:
                content = (
                    '<!DOCTYPE html>\n'
                    '<html><head><meta charset="utf-8"><title>404</title>\n'
                    '<meta http-equiv="refresh" content="0;url=/">\n'
                    '<style>body{background:#0a0e17;color:#e0e4ec;display:flex;align-items:center;'
                    'justify-content:center;min-height:100vh;font-family:sans-serif;text-align:center;}'
                    'a{color:#38bdf8;}</style></head>\n'
                    '<body><div><h1>404 &mdash; Not Found</h1>\n'
                    '<p><a href="/">&larr; Back to Mobile Security Auditor</a></p></div></body></html>'
                ).encode('utf-8')

            self.wfile.write(content)
        else:
            super().send_error(code, message)

    def log_message(self, format, *args):
        """Quiet logging with status codes."""
        status = args[1] if len(args) > 1 else '?'
        if status != '200':
            super().log_message(format, *args)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('0.0.0.0', port), CustomHandler)
    print(f'🌐 Mobile Security Auditor — http://localhost:{port}/')
    print(f'📁 Serving: {os.getcwd()}')
    print(f'⚡ Custom 404 handler active')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down…')
        server.server_close()


if __name__ == '__main__':
    main()
