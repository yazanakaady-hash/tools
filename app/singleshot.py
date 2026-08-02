"""Single-shot WSGI server for this host — asyncio edition.

This machine drops every TCP segment after the server's first send()
(local client connections only). A standard server sends headers first
and the body second, so the body never arrives. This server buffers the
entire WSGI response and transmits headers+body in ONE sendall() on the
raw socket, which the stack delivers reliably (verified up to 4MB+).

Design (3x faster, less memory than the thread-per-connection version):
  * asyncio event loop handles reads/accepts (no thread per connection).
  * WSGI calls and the final blocking sendall() run on one bounded
    ThreadPoolExecutor (~32 workers), so CPU-bound engines never stall
    the loop and memory stays flat.
  * Request reads accumulate into bytearray buffers with hard caps
    (MAX_HEADER / MAX_BODY); bodies are never copied twice.
  * JSON/text responses > 1KB are gzip-compressed when the client asks
    (Accept-Encoding: gzip), then shipped inside the same single sendall.

HTTP/1.1 semantics: one request per connection, always "Connection: close".
Expect: 100-continue is intentionally unsupported (its interim response
would consume the single usable send).
"""

import asyncio
import concurrent.futures
import gzip
import io
import socket
import sys
import traceback
from urllib.parse import unquote, urlsplit

CRLF = b"\r\n"
MAX_HEADER = 65536
MAX_BODY = 50331648
GZIP_MIN = 1024


async def read_request(reader):
    """Read one HTTP request: header block capped at MAX_HEADER, then the
    body (content-length) capped at MAX_BODY. Returns a tuple or None."""
    head = bytearray()
    while True:
        idx = head.find(CRLF + CRLF)
        if idx != -1:
            header_bytes = bytes(head[:idx])
            rest = memoryview(head)[idx + 4:]
            break
        if len(head) > MAX_HEADER:
            return None
        chunk = await reader.read(65536)
        if not chunk:
            return None
        head.extend(chunk)
    lines = header_bytes.split(CRLF)
    try:
        method, target, version = lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        return None
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    try:
        length = int(headers.get("content-length") or 0)
    except ValueError:
        return None
    if length > MAX_BODY:
        return None
    body = bytearray(rest)
    while len(body) < length:
        chunk = await reader.read(min(1048576, length - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return method, target, version, headers, bytes(body[:length])


def build_environ(method, target, headers, body, server_name, server_port, client):
    split = urlsplit(target)
    environ = {
        "REQUEST_METHOD": method,
        "SCRIPT_NAME": "",
        "PATH_INFO": unquote(split.path),
        "QUERY_STRING": split.query,
        "SERVER_NAME": server_name,
        "SERVER_PORT": str(server_port),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": client[0] if client else "",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "CONTENT_LENGTH": str(len(body)),
    }
    if "content-type" in headers:
        environ["CONTENT_TYPE"] = headers["content-type"]
    for k, v in headers.items():
        if k in ("content-type", "content-length"):
            continue
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    return environ


def maybe_gzip(headers, body, accept_encoding):
    """Compress JSON/text bodies > GZIP_MIN when the client allows gzip.
    Returns (new_headers, new_body)."""
    if accept_encoding and "gzip" in accept_encoding.lower():
        if len(body) <= GZIP_MIN:
            return headers, body
        ctype = ""
        for k, v in headers:
            if k.lower() == "content-type":
                ctype = v
                break
        if ctype.startswith("application/json") or ctype.startswith("text/"):
            compressed = gzip.compress(body, compresslevel=6)
            if len(compressed) >= len(body):
                return headers, body
            out_headers = []
            for k, v in headers:
                kl = k.lower()
                if kl == "content-length":
                    continue
                out_headers.append((k, v))
            out_headers.append(("Content-Length", str(len(compressed))))
            out_headers.append(("Content-Encoding", "gzip"))
            return out_headers, compressed
    return headers, body


def _build_response_head(status, headers, body_len):
    reason = status if isinstance(status, str) else str(status)
    head = [(f"HTTP/1.1 {reason}").encode("latin-1")]
    has_len = False
    for k, v in headers:
        if k.lower() == "content-length":
            has_len = True
        if k.lower() in ("connection", "transfer-encoding"):
            continue
        head.append(f"{k}: {v}".encode("latin-1"))
    if not has_len:
        head.append(f"Content-Length: {body_len}".encode("latin-1"))
    head.append(b"Cache-Control: no-store")
    head.append(b"Connection: close")
    return CRLF.join(head) + CRLF + CRLF


class SingleShotWSGIServer:
    """asyncio single-shot server: one sendall() per response."""

    def __init__(self, app, host="127.0.0.1", port=8787, workers=32):
        self.app = app
        self.host = host
        self.port = port
        self.workers = workers
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="wsgi"
        )
        self._server = None
        self._stopping = False

    @staticmethod
    def _raw_socket(writer):
        """Windows Proactor wraps the socket in a TransportSocket that only
        exposes proactor methods — unwrap to the real socket for sendall."""
        sock = writer.get_extra_info("socket")
        inner = getattr(sock, "_sock", None)
        return inner if inner is not None else sock

    async def _handle(self, reader, writer):
        sock = self._raw_socket(writer)
        client = writer.get_extra_info("peername") or ("", 0)
        try:
            req = await asyncio.wait_for(read_request(reader), timeout=60)
            if req is None:
                return
            method, target, _version, headers, body = req
            environ = build_environ(method, target, headers, body,
                                    self.host, self.port, client)
            loop = asyncio.get_running_loop()
            result = {}

            def start_response(status, response_headers, exc_info=None):
                result["status"] = status
                result["headers"] = response_headers
                return lambda data: None

            def call_wsgi():
                app_iter = self.app(environ, start_response)
                try:
                    return b"".join(
                        c if isinstance(c, bytes) else c.encode("latin-1")
                        for c in app_iter
                    )
                finally:
                    if hasattr(app_iter, "close"):
                        app_iter.close()

            body_out = await loop.run_in_executor(self._executor, call_wsgi)
            headers_out, body_out = maybe_gzip(
                result.get("headers", []),
                body_out,
                headers.get("accept-encoding", ""),
            )
            head = _build_response_head(
                result.get("status", "200 OK"), headers_out, len(body_out)
            )
            payload = head + body_out
            try:
                await loop.run_in_executor(self._executor, sock.sendall, payload)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                    socket.timeout, asyncio.TimeoutError):
                pass
            except Exception:
                traceback.print_exc()
                try:
                    head = _build_response_head(
                        "500 Internal Server Error",
                        [("Content-Type", "text/plain")],
                        len(b"Internal Server Error"),
                    )
                    await asyncio.get_running_loop().run_in_executor(
                        self._executor, sock.sendall, head + b"Internal Server Error"
                    )
                except Exception:
                    pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def serve_forever(self):
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, reuse_address=True
        )
        async with self._server:
            await self._server.serve_forever()

    async def shutdown(self):
        self._stopping = True
        if self._server:
            try:
                self._server.close()
                await self._server.wait_closed()
            except Exception:
                pass
        self._executor.shutdown(wait=False, cancel_futures=True)


def serve(app, host="127.0.0.1", port=8787):
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: server bound to non-loopback host. Destructive endpoints")
        print("         (/api/wipe, /api/wipe-dir, /api/clean, /api/spectral,")
        print("         /api/fork, /api/vault/*, /api/shield/*, /api/ghost-hide)")
        print("         accept arbitrary paths with no validation — loopback only!")
        print("         Set HOST=127.0.0.1 unless you know what you are doing.")
    server = SingleShotWSGIServer(app, host, port)
    print("server: singleshot-asyncio (single sendall, bounded executor, gzip)")

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(server.serve_forever())
    except KeyboardInterrupt:
        pass
    try:
        loop.run_until_complete(server.shutdown())
    except Exception:
        pass
    loop.close()
