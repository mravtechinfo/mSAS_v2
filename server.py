#!/usr/bin/env python3
"""
Custom HTTP server for mSAS — Mobile Security Analysis Suite.
Serves static files, provides API endpoints, handles file uploads, CORS, and compression.
"""

import os
import sys
import json
import gzip
import uuid
import shutil
import hashlib
import mimetypes
from io import BytesIO
from urllib.parse import urlparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_uploads')
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500 MB
ALLOWED_EXTENSIONS = {'.apk', '.ipa', '.zip'}
CORS_ORIGINS = ['*']

# API routes for quick matching
API_ROUTES = {'/api/status', '/api/health', '/api/tools', '/api/uploads', '/api/clear-uploads'}


# ── Helpers ────────────────────────────────────────────────────────────────────

def json_response(handler, data, status=200):
    """Send a JSON response."""
    body = json.dumps(data, indent=2, default=str).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler._send_cors()
    handler.end_headers()
    handler.wfile.write(body)


def error_response(handler, message, status=400):
    """Send a JSON error response."""
    json_response(handler, {'error': message, 'status': status}, status)


def get_mime(path):
    """Get MIME type for a file path."""
    mime, _ = mimetypes.guess_type(path)
    return mime or 'application/octet-stream'


def get_upload_path():
    """Ensure upload directory exists and return its path."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    return UPLOAD_DIR


def human_size(num):
    """Format bytes as human-readable string."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if num < 1024:
            return f'{num:.1f} {unit}' if unit != 'B' else f'{num} {unit}'
        num /= 1024
    return f'{num:.1f} TB'


# ── Request Handler ────────────────────────────────────────────────────────────

class MobileSecurityHandler(SimpleHTTPRequestHandler):
    """HTTP handler with API endpoints, CORS, file uploads, and compression."""

    # ── CORS ────────────────────────────────────────────────────────────────

    def _send_cors(self):
        """Add CORS headers to the response."""
        origin = self.headers.get('Origin', '*')
        if '*' in CORS_ORIGINS or origin in CORS_ORIGINS:
            self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')

    # ── HTTP Method Dispatchers ─────────────────────────────────────────────

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        """Route GET requests: API -> static files."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        # API endpoints
        if path == '/api/status':
            self._handle_status()
        elif path == '/api/uploads':
            self._handle_list_uploads()
        elif path.startswith('/api/uploads/'):
            filename = path[len('/api/uploads/'):]
            self._handle_get_upload(filename)
        elif path == '/api/tools':
            self._handle_list_tools()
        elif path == '/api/health':
            self._handle_health()
        elif path.startswith('/api/'):
            error_response(self, 'Endpoint not found', 404)
        else:
            # Serve static files
            super().do_GET()

    def do_POST(self):
        """Route POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        if path == '/api/upload':
            self._handle_file_upload()
        elif path.startswith('/api/analyze/'):
            tool = path[len('/api/analyze/'):]
            self._handle_analyze(tool)
        elif path == '/api/clear-uploads':
            self._handle_clear_uploads()
        elif path.startswith('/api/'):
            error_response(self, 'Endpoint not found', 404)
        else:
            error_response(self, 'Method not allowed', 405)

    def do_DELETE(self):
        """Route DELETE requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        if path.startswith('/api/uploads/'):
            filename = path[len('/api/uploads/'):]
            self._handle_delete_upload(filename)
        elif path.startswith('/api/'):
            error_response(self, 'Endpoint not found', 404)
        else:
            error_response(self, 'Method not allowed', 405)

    # ── API Handlers ────────────────────────────────────────────────────────

    def _handle_status(self):
        """GET /api/status — Return server and suite status."""
        upload_dir = get_upload_path()
        uploads = []
        if os.path.isdir(upload_dir):
            for f in os.listdir(upload_dir):
                fpath = os.path.join(upload_dir, f)
                if os.path.isfile(fpath):
                    uploads.append({
                        'name': f,
                        'size': os.path.getsize(fpath),
                        'sizeHuman': human_size(os.path.getsize(fpath)),
                        'modified': datetime.fromtimestamp(
                            os.path.getmtime(fpath), tz=timezone.utc
                        ).isoformat()
                    })

        json_response(self, {
            'server': 'mSAS — Mobile Security Analysis Suite',
            'version': '2.0.0',
            'status': 'running',
            'uploadCount': len(uploads),
            'uploads': uploads,
            'tools': {
                'apk-auditor': os.path.isdir('apk-auditor'),
                'ipa-auditor': os.path.isdir('ipa-auditor'),
                'adb-auditor': os.path.isdir('adb-auditor')
            },
            'maxUploadSize': MAX_UPLOAD_SIZE,
            'maxUploadSizeHuman': human_size(MAX_UPLOAD_SIZE)
        })

    def _handle_health(self):
        """GET /api/health — Simple health check."""
        json_response(self, {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    def _handle_list_tools(self):
        """GET /api/tools — List available analysis tools."""
        tools = []
        if os.path.isdir('apk-auditor'):
            tools.append({
                'id': 'apk-auditor',
                'name': 'APK Auditor',
                'description': 'Android APK static analysis',
                'path': '/apk-auditor/index.html',
                'icon': '📱',
                'rules': '150+'
            })
        if os.path.isdir('ipa-auditor'):
            tools.append({
                'id': 'ipa-auditor',
                'name': 'IPA Auditor',
                'description': 'iOS IPA static analysis',
                'path': '/ipa-auditor/index.html',
                'icon': '🍎',
                'rules': '80+'
            })
        if os.path.isdir('adb-auditor'):
            tools.append({
                'id': 'adb-auditor',
                'name': 'ADB Auditor',
                'description': 'Android device auditing via WebUSB',
                'path': '/adb-auditor/index.html',
                'icon': '🤖'
            })
        json_response(self, {'tools': tools, 'count': len(tools)})

    def _handle_file_upload(self):
        """POST /api/upload — Upload APK/IPA files for analysis."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_UPLOAD_SIZE:
            error_response(self, f'File too large. Maximum: {human_size(MAX_UPLOAD_SIZE)}', 413)
            return

        content_type = self.headers.get('Content-Type', '')
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[1].split(';')[0].strip()
            if boundary.startswith('"') and boundary.endswith('"'):
                boundary = boundary[1:-1]

        if not boundary:
            error_response(self, 'Invalid multipart form data', 400)
            return

        raw_body = self.rfile.read(content_length)
        upload_dir = get_upload_path()

        saved_files = []
        # Parse multipart data manually
        boundary_bytes = b'--' + boundary.encode('utf-8')
        parts = raw_body.split(boundary_bytes)
        for part in parts:
            if not part.strip() or part.strip() == b'--':
                continue

            # Split headers from body
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                continue
            headers_raw = part[:header_end].decode('utf-8', errors='replace')
            body = part[header_end + 4:]
            if body.endswith(b'\r\n'):
                body = body[:-2]

            # Extract filename from Content-Disposition
            filename = None
            for line in headers_raw.split('\r\n'):
                if line.lower().startswith('content-disposition'):
                    if 'filename="' in line:
                        filename = line.split('filename="')[1].split('"')[0]
                    elif "filename='" in line:
                        filename = line.split("filename='")[1].split("'")[0]

            if not filename:
                continue

            # Validate extension
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                error_response(self, f'Invalid file type: {ext}. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', 400)
                return

            # Save file with unique name to avoid collisions
            unique_name = f"{uuid.uuid4().hex}{ext}"
            save_path = os.path.join(upload_dir, unique_name)

            with open(save_path, 'wb') as f:
                f.write(body)

            file_hash = hashlib.sha256(body).hexdigest()
            saved_files.append({
                'originalName': filename,
                'storedName': unique_name,
                'size': len(body),
                'sizeHuman': human_size(len(body)),
                'sha256': file_hash,
                'path': f'/api/uploads/{unique_name}'
            })

        if not saved_files:
            error_response(self, 'No valid files found in upload', 400)
            return

        json_response(self, {
            'message': f'{len(saved_files)} file(s) uploaded successfully',
            'files': saved_files
        }, 201)

    def _handle_list_uploads(self):
        """GET /api/uploads — List all uploaded files."""
        upload_dir = get_upload_path()
        if not os.path.isdir(upload_dir):
            json_response(self, {'uploads': [], 'count': 0})
            return

        files = []
        for f in sorted(os.listdir(upload_dir), key=lambda x: os.path.getmtime(os.path.join(upload_dir, x)), reverse=True):
            fpath = os.path.join(upload_dir, f)
            if os.path.isfile(fpath):
                files.append({
                    'name': f,
                    'size': os.path.getsize(fpath),
                    'sizeHuman': human_size(os.path.getsize(fpath)),
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(fpath), tz=timezone.utc
                    ).isoformat()
                })

        json_response(self, {'uploads': files, 'count': len(files)})

    def _handle_get_upload(self, filename):
        """GET /api/uploads/<filename> — Download an uploaded file."""
        safe_name = os.path.basename(filename)
        fpath = os.path.join(UPLOAD_DIR, safe_name)
        if not os.path.isfile(fpath):
            error_response(self, 'File not found', 404)
            return

        file_size = os.path.getsize(fpath)
        self.send_response(200)
        self.send_header('Content-Type', get_mime(safe_name))
        self.send_header('Content-Disposition', f'attachment; filename="{safe_name}"')
        self.send_header('Content-Length', str(file_size))
        self._send_cors()
        self.end_headers()

        with open(fpath, 'rb') as f:
            shutil.copyfileobj(f, self.wfile)

    def _handle_delete_upload(self, filename):
        """DELETE /api/uploads/<filename> — Delete an uploaded file."""
        safe_name = os.path.basename(filename)
        fpath = os.path.join(UPLOAD_DIR, safe_name)
        if not os.path.isfile(fpath):
            error_response(self, 'File not found', 404)
            return

        os.remove(fpath)
        json_response(self, {'message': f'Deleted: {safe_name}'})

    def _handle_clear_uploads(self):
        """POST /api/clear-uploads — Delete all uploaded files."""
        upload_dir = get_upload_path()
        removed = 0
        if os.path.isdir(upload_dir):
            for f in os.listdir(upload_dir):
                fpath = os.path.join(upload_dir, f)
                if os.path.isfile(fpath):
                    os.remove(fpath)
                    removed += 1
        json_response(self, {'message': f'Cleared {removed} upload(s)', 'removed': removed})

    def _handle_analyze(self, tool):
        """POST /api/analyze/<tool> — Placeholder for server-side analysis."""
        json_response(self, {
            'message': f'Server-side analysis for {tool} is not yet implemented. All analysis currently runs client-side via Web Workers.',
            'tool': tool,
            'clientSide': True
        })

    # ── Static File Serving Overrides ────────────────────────────────────────

    def send_head(self):
        """Override to add CORS and compression support to static files."""
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            parts = self.path.rstrip('/').split('/')
            if not self.path.endswith('/'):
                # Redirect to add trailing slash for directories
                self.send_response(301)
                self.send_header('Location', self.path + '/')
                self._send_cors()
                self.end_headers()
                return None
            for index in 'index.html', 'index.htm':
                index_path = os.path.join(path, index)
                if os.path.exists(index_path):
                    path = index_path
                    break
            else:
                return self.list_directory(path)

        ctype = get_mime(path)
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(404, 'File not found')
            return None

        fs = os.fstat(f.fileno())
        file_size = fs.st_size
        accept_encoding = self.headers.get('Accept-Encoding', '')

        # Check if client accepts gzip and file is compressible
        use_gzip = (
            'gzip' in accept_encoding
            and file_size > 1024  # Only compress files > 1KB
            and ctype.startswith(('text/', 'application/json', 'application/javascript'))
        )

        if use_gzip:
            # Read and compress
            content = f.read()
            f.close()
            compressed = gzip.compress(content, compresslevel=6)

            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(compressed)))
            self.send_header('Vary', 'Accept-Encoding')
            self.send_header('Cache-Control', 'no-cache')
            self._send_cors()
            self.end_headers()
            return BytesIO(compressed)
        else:
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(file_size))
            self.send_header('Cache-Control', 'no-cache')
            self._send_cors()
            self.end_headers()
            return f

    def send_error(self, code, message=None):
        """Override to serve custom 404 pages and JSON error responses for API routes."""
        # JSON errors for API routes
        if self.path.startswith('/api/'):
            err_msg = message or {
                400: 'Bad request',
                403: 'Forbidden',
                404: 'Endpoint not found',
                405: 'Method not allowed',
                413: 'Payload too large',
                500: 'Internal server error',
            }.get(code, 'Unknown error')

            body = json.dumps({
                'error': err_msg,
                'status': code,
                'path': self.path
            }).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self._send_cors()
            self.end_headers()
            self.wfile.write(body)
            return

        # HTML error pages for non-API routes
        if code == 404:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self._send_cors()
            self.end_headers()

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
                    '<p><a href="/">&larr; Back to mSAS</a></p></div></body></html>'
                ).encode('utf-8')

            self.wfile.write(content)
        else:
            super().send_error(code, message)

    def log_message(self, format, *args):
        """Enhanced logging with method, path, status, and size."""
        method = self.command
        path = self.path
        status = args[1] if len(args) > 1 else '?'
        size = args[2] if len(args) > 2 else '-'
        if status != '200' or self.path.startswith('/api/'):
            super().log_message(f'{method} {path} -> {status} ({size} bytes)')


# ── Server Entry Point ─────────────────────────────────────────────────────────

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    bind = sys.argv[2] if len(sys.argv) > 2 else '0.0.0.0'

    server = HTTPServer((bind, port), MobileSecurityHandler)

    print(f'╔══════════════════════════════════════════════╗')
    print(f'║     🛡️  mSAS — Security Analysis Suite       ║')
    print(f'╠══════════════════════════════════════════════╣')
    print(f'║  🌐  http://localhost:{port}/{" " * (13 - len(str(port)))}║')
    print(f'║  📁  Serving: {os.path.basename(os.getcwd())}{" " * 20}║')
    print(f'║  🔌  CORS: {"enabled" if "*" in CORS_ORIGINS else "configured"}{" " * 18}║')
    print(f'║  📤  Uploads: {UPLOAD_DIR}{" " * 20}║')
    print(f'║  📦  Max upload: {human_size(MAX_UPLOAD_SIZE)}{" " * 16}║')
    print(f'║  ⚡  API: /api/status /api/health /api/tools║')
    print(f'║  📋  API: /api/upload /api/uploads║')
    print(f'╚══════════════════════════════════════════════╝')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down…')
        server.server_close()


if __name__ == '__main__':
    main()
