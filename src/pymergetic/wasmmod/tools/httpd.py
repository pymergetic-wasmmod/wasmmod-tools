# Tiny static HTTP server for wasmmod pack smoke tests.
# Serves a directory tree as-is (VFS mirror). No JSON / resolve API.
#
#   python3 tools/wasmmod.py httpd --dir packs --port 0 --write-port .http-port
#   # or: tools/wasmmod_httpd.py …
#
# Then: wasm.verify(False); wasm.install_hook("http://127.0.0.1:<port>/")

from __future__ import annotations

import argparse
import http.server
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="Static pack HTTP server (VFS mirror)")
    ap.add_argument("--dir", required=True, help="Directory to serve (e.g. examples/packs)")
    ap.add_argument("--port", type=int, default=0, help="Listen port (0 = ephemeral)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--write-port", help="Write chosen port to this file")
    ap.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress per-request logs (default: log every GET/HEAD)",
    )
    args = ap.parse_args()

    root = os.path.abspath(args.dir)
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 1

    os.chdir(root)
    quiet = args.quiet

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt: str, *log_args) -> None:
            # Silence default '"GET /x HTTP/1.0" 200 -' — we log in log_request.
            pass

        def log_request(self, code: object = "-", size: object = "-") -> None:
            if quiet:
                return
            # HEAD probes + GET of .wasm / .sig / .crt show up here.
            print(f"  [httpd] {self.command} {self.path} → {code}", flush=True)

    httpd = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    host, port = httpd.server_address[:2]
    if args.write_port:
        with open(args.write_port, "w", encoding="utf-8") as f:
            f.write(str(port))
    print(f"[httpd] serving {root} on http://{host}:{port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
