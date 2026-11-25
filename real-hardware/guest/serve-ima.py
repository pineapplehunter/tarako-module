"""Test-only HTTP service exposing just the guest's SHA-384 IMA log."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG = Path("/sys/kernel/security/ima/ascii_runtime_measurements_sha384")
LIMIT = 4 * 1024 * 1024


class LogHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def do_GET(self):
        if self.path != "/ima.log":
            self.send_error(404)
            return
        try:
            with LOG.open("rb") as log:
                data = log.read(LIMIT + 1)
        except OSError:
            self.send_error(503, "IMA log unavailable")
            return
        if not data or len(data) > LIMIT:
            self.send_error(503, "IMA log empty or exceeds the size limit")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    with ThreadingHTTPServer((args.listen, args.port), LogHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
