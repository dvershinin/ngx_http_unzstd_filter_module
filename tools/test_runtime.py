#!/usr/bin/env python3
"""End-to-end lifecycle tests for ngx_http_unzstd_filter_module."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time

from runtime_http import decoded_raw_body, raw_exchange, request, wait_port
from torture_lab import (
    fd_delta_report,
    new_evidence,
    parser_directive_inventory,
    run_configuration_tests,
    settled_worker_fds,
    terminate_and_verify_worker,
    validate_public_evidence,
)


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx-binary", required=True, type=pathlib.Path)
    parser.add_argument("--module", required=True, type=pathlib.Path)
    parser.add_argument("--port", type=int, default=18880)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--directives-json", required=True, type=pathlib.Path)
    parser.add_argument("--evidence-path", required=True, type=pathlib.Path)
    return parser.parse_args()


def nginx_configuration(
    root: pathlib.Path, module: pathlib.Path, port: int
) -> str:
    user = "user root;\n" if os.geteuid() == 0 else ""
    return f"""load_module {module};
{user}worker_processes 2;
pid {root}/nginx.pid;
error_log {root}/error.log notice;

events {{ worker_connections 256; }}

http {{
    access_log off;
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    server {{
        listen 127.0.0.1:{port + 1};

        location = /payload.zst {{
            root {root}/origin;
            default_type text/plain;
            add_header Content-Encoding zstd always;
        }}

        location = /large.zst {{
            root {root}/origin;
            default_type application/octet-stream;
            add_header Content-Encoding zstd always;
        }}
    }}

    server {{
        listen 127.0.0.1:{port};

        location = /plain {{
            unzstd on;
            proxy_pass http://127.0.0.1:{port + 1}/payload.zst;
        }}

        location = /accepted {{
            unzstd on;
            proxy_pass http://127.0.0.1:{port + 1}/payload.zst;
        }}

        location = /large {{
            unzstd on;
            unzstd_buffers 2 1k;
            proxy_buffering off;
            proxy_pass http://127.0.0.1:{port + 1}/large.zst;
        }}
    }}
}}
"""


class Nginx:
    def __init__(self, binary: pathlib.Path, root: pathlib.Path) -> None:
        self.binary = binary
        self.root = root
        self.conf = root / "nginx.conf"

    def command(self, *args: str) -> list[str]:
        return [
            str(self.binary),
            "-p",
            str(self.root),
            "-c",
            str(self.conf),
            *args,
        ]

    def check(self, *args: str) -> str:
        result = subprocess.run(
            self.command(*args),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"NGINX {' '.join(args)} failed: {result.stdout}")
        return result.stdout

    def start(self, port: int) -> int:
        self.check()
        wait_port(port)
        return int((self.root / "nginx.pid").read_text().strip())

    def reload(self, port: int) -> None:
        self.check("-s", "reload")
        wait_port(port)

    def stop(self) -> None:
        if (self.root / "nginx.pid").exists():
            self.check("-s", "quit")
            deadline = time.time() + 8
            while (self.root / "nginx.pid").exists() and time.time() < deadline:
                time.sleep(0.05)
            if (self.root / "nginx.pid").exists():
                raise RuntimeError("NGINX did not stop cleanly")


def prepare_zstd(source: pathlib.Path, destination: pathlib.Path) -> None:
    result = subprocess.run(
        ["zstd", "-q", "-f", "--no-progress", str(source), "-o", str(destination)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"zstd fixture creation failed: {result.stdout}")


def generated_at(value: str) -> str:
    if value:
        return value
    result = subprocess.run(
        ["git", "show", "-s", "--format=%cI", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.strip() or "unspecified"


def main() -> None:
    args = parse_args()
    args.nginx_binary = args.nginx_binary.resolve()
    args.module = args.module.resolve()
    if not args.nginx_binary.is_file() or not args.module.is_file():
        raise SystemExit("NGINX binary and dynamic module are required")

    with tempfile.TemporaryDirectory(prefix="unzstd-torture-") as directory:
        root = pathlib.Path(directory)
        origin = root / "origin"
        origin.mkdir()
        plain = b"GetPageSpeed unzstd runtime proof\n" * 128
        large = bytes(range(256)) * 4096
        (origin / "payload").write_bytes(plain)
        (origin / "large").write_bytes(large)
        prepare_zstd(origin / "payload", origin / "payload.zst")
        prepare_zstd(origin / "large", origin / "large.zst")
        encoded = (origin / "payload.zst").read_bytes()

        renamed = root / "ngx_http_unzstd_quality_gate.so"
        shutil.copy2(args.module, renamed)
        configurations = run_configuration_tests(
            args.nginx_binary, renamed, root, args.port + 20
        )

        nginx = Nginx(args.nginx_binary, root)
        nginx.conf.write_text(nginx_configuration(root, renamed, args.port))
        nginx.check("-t")
        full_config = nginx.check("-T")
        if f"load_module {renamed};" not in full_config or "unzstd on;" not in full_config:
            raise AssertionError("nginx -T did not preserve the renamed module and directives")

        master_pid = nginx.start(args.port)
        try:
            status, headers, body = request(args.port, "/plain")
            if status != 200 or body != plain or "content-encoding" in headers:
                raise AssertionError("runtime decompression response was incorrect")

            status, headers, body = request(
                args.port, "/accepted", {"Accept-Encoding": "zstd"}
            )
            if status != 200 or body != encoded or headers.get("content-encoding") != "zstd":
                raise AssertionError("accepted zstd response was not preserved")

            status, _, body = request(args.port, "/large")
            if status != 200 or body != large:
                raise AssertionError("large fragmented response was not decompressed")

            baseline = settled_worker_fds(master_pid, 2)

            aborting = socket.create_connection(("127.0.0.1", args.port), timeout=4)
            aborting.sendall(
                b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            aborting.close()

            half_closed = raw_exchange(
                args.port,
                b"GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                half_close=True,
            )
            if half_closed and decoded_raw_body(half_closed) != plain:
                raise AssertionError("half-closed client did not receive the decoded body")

            slow = raw_exchange(
                args.port,
                b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                slow=True,
            )
            if decoded_raw_body(slow) != large:
                raise AssertionError("slow reader did not receive the decoded body")

            raw_exchange(args.port, b"BROKEN REQUEST\r\n\r\n")
            if request(args.port, "/plain")[2] != plain:
                raise AssertionError("normal traffic failed after hostile clients")

            nginx.reload(args.port)
            if request(args.port, "/plain")[2] != plain:
                raise AssertionError("normal traffic failed after reload")

            settled = terminate_and_verify_worker(master_pid, baseline)
            fd_report = fd_delta_report(baseline, settled, 2)
            if not fd_report["within_allowance"]:
                raise AssertionError(f"worker descriptor growth: {fd_report}")
        finally:
            nginx.stop()

        error_log = (root / "error.log").read_text(errors="replace")
        found = [marker for marker in SANITIZER_MARKERS if marker in error_log]
        if found:
            raise AssertionError(f"sanitizer marker in NGINX log: {found}")

        inventory = parser_directive_inventory(args.directives_json.resolve())
        evidence = new_evidence(
            generated_at=generated_at(args.generated_at),
            nginx_binary=args.nginx_binary,
            configurations=configurations,
            directive_inventory=inventory,
            gates={
                "nginx_t": "passed",
                "nginx_T": "passed",
                "renamed_dynamic_module": "passed",
                "client_abort": "passed",
                "half_close": "passed",
                "slow_reader": "passed",
                "malformed_request": "passed",
                "reload": "passed",
                "worker_replacement": "passed",
                "settled_fd": fd_report,
            },
        )
        validate_public_evidence(evidence)
        args.evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print("Torture Lab: all runtime and lifecycle gates passed")


if __name__ == "__main__":
    main()
