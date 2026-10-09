"""Test-only manifest metadata variants; all bytes/chunks use the real Rust fixture."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import urllib.request


def serve(source, directory_mode=None, file_mode=None):
    with urllib.request.urlopen(source + '/manifest', timeout=5) as response:
        manifest = json.load(response)
    def digest():
        return hashlib.sha256(json.dumps(['magus-fs-manifest-v1', manifest['chunk_size'], manifest['entries']], separators=(',', ':')).encode()).hexdigest()
    assert manifest['digest'] == digest(), 'canonical test fixture encoding differs'
    for entry in manifest['entries']:
        if entry['directory'] and directory_mode is not None:
            entry.update(mode=directory_mode, uid=1001, gid=1001)
        elif not entry['directory'] and file_mode is not None:
            entry['mode'] = file_mode
    manifest['digest'] = digest()
    body = json.dumps(manifest, separators=(',', ':')).encode()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            if self.path == '/manifest':
                data = body
            elif self.path == '/stats' or self.path.startswith('/chunks/'):
                with urllib.request.urlopen(source + self.path, timeout=5) as response:
                    data = response.read()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    print('http://127.0.0.1:' + str(server.server_address[1]), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--directory-mode', type=lambda x: int(x, 8))
    parser.add_argument('--file-mode', type=lambda x: int(x, 8))
    args = parser.parse_args()
    serve(args.source, args.directory_mode, args.file_mode)
