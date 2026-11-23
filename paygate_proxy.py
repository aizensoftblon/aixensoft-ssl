#!/usr/bin/env python3
"""Proxy local PayGate (wallet + checkout) cuando el DNS bloquea paygate.to."""
from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
PORT = 8766
MERCHANT_WALLET = "0x80bD7c5b58344d869c01D9d9c0AD62e632DCE839"
PAYGATE_API_HOST = "api.paygate.to"
PAYGATE_CHECKOUT_HOST = "checkout.paygate.to"
PAYGATE_EDGE_IP = "104.26.4.61"
LOCAL_BASE = f"http://{HOST}:{PORT}"
ALLOWED_CALLBACK_HOSTS = frozenset({"ssl.aixensoft.com", "localhost", "127.0.0.1"})

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)


def parse_address_in(body: str) -> str | None:
    body = body.strip()
    try:
        data = json.loads(body)
        addr = data.get("address_in")
        if addr:
            return str(addr)
    except json.JSONDecodeError:
        pass
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", body):
        return body
    return None


def paygate_raw_request(
    server_host: str,
    path_and_query: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, list[tuple[str, str]], bytes]:
    headers = {
        "Host": server_host,
        "User-Agent": "Aixensoft-SSL-PaygateProxy/1.1",
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)
    if body:
        headers["Content-Length"] = str(len(body))
    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    request = f"{method} {path_and_query} HTTP/1.1\r\n{header_block}\r\n".encode("ascii") + body

    ctx = ssl.create_default_context()
    with socket.create_connection((PAYGATE_EDGE_IP, 443), timeout=60) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_host) as tls:
            tls.sendall(request)
            buf = bytearray()
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)

    raw_resp = bytes(buf)
    if b"\r\n\r\n" not in raw_resp:
        raise urllib.error.URLError("respuesta HTTP inválida")

    head, payload = raw_resp.split(b"\r\n\r\n", 1)
    head_text = head.decode("iso-8859-1", errors="replace")
    lines = head_text.split("\r\n")
    status_line = lines[0]
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError) as exc:
        raise urllib.error.URLError(status_line) from exc

    resp_headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        resp_headers.append((name.strip(), value.strip()))

    if "chunked" in head_text.lower():
        payload = _decode_chunked(payload)

    return status, resp_headers, payload


def _decode_chunked(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            break
        size_line = data[pos:line_end].split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            break
        out.extend(data[pos : pos + size])
        pos += size + 2
    return bytes(out)


def paygate_wallet_fetch(callback: str) -> str:
    path_q = urllib.parse.urlencode(
        {"address": MERCHANT_WALLET, "callback": callback},
        quote_via=urllib.parse.quote,
    )
    _status, _headers, payload = paygate_raw_request(
        PAYGATE_API_HOST, f"/control/wallet.php?{path_q}"
    )
    text = payload.decode("utf-8", errors="replace")
    if parse_address_in(text) is None:
        raise urllib.error.URLError(f"wallet.php sin address_in ({_status})")
    return text


def allowed_callback(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.path != "/checkout.html":
        return False
    host = parsed.hostname or ""
    if host not in ALLOWED_CALLBACK_HOSTS:
        return False
    if host == "ssl.aixensoft.com":
        return parsed.scheme == "https"
    return parsed.scheme in ("http", "https")


def to_local_checkout_url(remote_url: str) -> str:
    parsed = urllib.parse.urlparse(remote_url)
    if parsed.netloc == PAYGATE_CHECKOUT_HOST:
        return f"{LOCAL_BASE}/p{parsed.path}?{parsed.query}" if parsed.query else f"{LOCAL_BASE}/p{parsed.path}"
    if parsed.netloc == PAYGATE_API_HOST:
        return f"{LOCAL_BASE}/a{parsed.path}?{parsed.query}" if parsed.query else f"{LOCAL_BASE}/a{parsed.path}"
    return remote_url


def rewrite_location(value: str) -> str:
    if value.startswith("/"):
        return f"{LOCAL_BASE}/p{value}"
    for host, prefix in (
        (PAYGATE_CHECKOUT_HOST, "/p"),
        (PAYGATE_API_HOST, "/a"),
    ):
        needle = f"https://{host}"
        if value.startswith(needle):
            rest = value[len(needle) :]
            return f"{LOCAL_BASE}{prefix}{rest}"
    return value


def rewrite_body(content: bytes, content_type: str) -> bytes:
    if "text/html" not in content_type and "javascript" not in content_type:
        return content
    text = content.decode("utf-8", errors="replace")
    text = text.replace(f"https://{PAYGATE_CHECKOUT_HOST}", f"{LOCAL_BASE}/p")
    text = text.replace(f"https://{PAYGATE_API_HOST}", f"{LOCAL_BASE}/a")
    return text.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _proxy_upstream(self, prefix: str, upstream_host: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith(prefix + "/") and parsed.path != prefix:
            self.send_error(404)
            return
        remote_path = parsed.path[len(prefix) :] or "/"
        if parsed.query:
            remote_path += "?" + parsed.query

        extra: dict[str, str] = {}
        ctype = self.headers.get("Content-Type")
        if ctype:
            extra["Content-Type"] = ctype
        accept = self.headers.get("Accept")
        if accept:
            extra["Accept"] = accept
        cookie = self.headers.get("Cookie")
        if cookie:
            extra["Cookie"] = cookie
        referer = self.headers.get("Referer")
        if referer:
            extra["Referer"] = rewrite_location(referer.replace(LOCAL_BASE + "/p", f"https://{PAYGATE_CHECKOUT_HOST}"))
            extra["Referer"] = extra["Referer"].replace(
                LOCAL_BASE + "/a", f"https://{PAYGATE_API_HOST}"
            )

        body = b""
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 0:
            body = self.rfile.read(length)

        try:
            status, resp_headers, payload = paygate_raw_request(
                upstream_host, remote_path, self.command, extra, body
            )
        except urllib.error.URLError as exc:
            self.send_error(502, f"Upstream PayGate: {exc}")
            return

        content_type = "application/octet-stream"
        out_headers: list[tuple[str, str]] = []
        for name, value in resp_headers:
            lower = name.lower()
            if lower in _HOP_BY_HOP:
                continue
            if lower == "location":
                value = rewrite_location(value)
            if lower == "content-type":
                content_type = value
            out_headers.append((name, value))

        payload = rewrite_body(payload, content_type)

        self.send_response(status)
        for name, value in out_headers:
            if name.lower() == "content-length":
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path.startswith("/p/"):
            self._proxy_upstream("/p", PAYGATE_CHECKOUT_HOST)
            return
        if self.path.startswith("/a/"):
            self._proxy_upstream("/a", PAYGATE_API_HOST)
            return
        if not self.path.startswith("/public/ssl/paygate-link"):
            self.send_error(404)
            return

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        amount = (qs.get("amount") or [""])[0].strip()
        email = (qs.get("email") or [""])[0].strip()
        callback = (qs.get("callback") or [""])[0].strip()

        try:
            amount_f = float(amount)
        except ValueError:
            self.send_error(400, "amount inválido")
            return
        if not (1.0 <= amount_f <= 50_000.0) or "@" not in email or not allowed_callback(callback):
            self.send_error(400, "parámetros inválidos")
            return

        try:
            text = paygate_wallet_fetch(callback)
        except urllib.error.URLError as e:
            self.send_error(502, f"PayGate no alcanzable: {e}")
            return

        address_in = parse_address_in(text)
        if not address_in:
            self.send_error(502, "respuesta PayGate inválida")
            return

        remote_checkout = (
            f"https://{PAYGATE_CHECKOUT_HOST}/process-payment.php"
            f"?address={address_in}"
            f"&amount={amount_f}"
            f"&provider=hosted"
            f"&email={urllib.parse.quote(email)}"
            f"&currency=USD"
        )
        checkout_url = to_local_checkout_url(remote_checkout)
        payload = json.dumps({"checkout_url": checkout_url}).encode("utf-8")
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        if self.path.startswith("/p/"):
            self._proxy_upstream("/p", PAYGATE_CHECKOUT_HOST)
            return
        if self.path.startswith("/a/"):
            self._proxy_upstream("/a", PAYGATE_API_HOST)
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[paygate-proxy] {fmt % args}")


def main() -> None:
    server = HTTPServer((HOST, PORT), Handler)
    print(f"PayGate proxy: {LOCAL_BASE}/public/ssl/paygate-link")
    print(f"Túnel checkout: {LOCAL_BASE}/p/...")
    server.serve_forever()


if __name__ == "__main__":
    main()