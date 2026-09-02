"""Minimal HTTP client primitives for the lifecycle test harness."""

from __future__ import annotations

import http.client
import socket
import time


def wait_port(port: int, timeout: float = 10.0) -> None:
    """Wait until a local TCP listener accepts connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"NGINX did not listen on port {port}")


def request(
    port: int, path: str, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes]:
    """Issue a GET and return status, normalized headers, and body."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    connection.request("GET", path, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    result = (
        response.status,
        {key.lower(): value for key, value in response.getheaders()},
        body,
    )
    connection.close()
    return result


def raw_exchange(
    port: int,
    payload: bytes,
    *,
    half_close: bool = False,
    slow: bool = False,
) -> bytes:
    """Exercise low-level client shutdown and slow-reader behavior."""
    with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
        client.settimeout(8)
        client.sendall(payload)
        if half_close:
            client.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                chunk = client.recv(1024)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if slow:
                time.sleep(0.001)
        return b"".join(chunks)


def decoded_raw_body(response: bytes) -> bytes:
    """Decode the body of a close-delimited or chunked HTTP/1 response."""
    try:
        header_block, body = response.split(b"\r\n\r\n", 1)
    except ValueError as exc:
        raise AssertionError("raw response has no HTTP header terminator") from exc
    headers = header_block.lower()
    if b"transfer-encoding: chunked" not in headers:
        return body

    decoded = bytearray()
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            raise AssertionError("chunked response has no size terminator")
        size_text = body[cursor:line_end].split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise AssertionError(f"invalid chunk size: {size_text!r}") from exc
        cursor = line_end + 2
        if size == 0:
            return bytes(decoded)
        end = cursor + size
        if end + 2 > len(body) or body[end : end + 2] != b"\r\n":
            raise AssertionError("truncated chunked response")
        decoded.extend(body[cursor:end])
        cursor = end + 2
