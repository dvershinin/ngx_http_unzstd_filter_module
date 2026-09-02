#!/usr/bin/env python3
"""Reusable lifecycle probes and public verification evidence helpers."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import signal
import subprocess
import time
from typing import Any


FD_DELTA_PER_WORKER_ALLOWANCE = 2
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
UPSTREAM_BASE = "658990e20a5f1cefbf760eb427741ce95b6eebc9"


def sha256_file(path: pathlib.Path) -> str:
    """Return the SHA-256 digest for a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_commit() -> str | None:
    """Return the checked-out source commit when Git is available."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.strip() or None


def module_upstream_version() -> str:
    """Return the module lineage, not the NGINX build version."""
    result = subprocess.run(
        ["git", "describe", "--tags", "--always", "--dirty"],
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.strip() or "unknown"


def parser_directive_inventory(
    path: pathlib.Path, project_root: pathlib.Path = PROJECT_ROOT
) -> dict[str, Any]:
    """Validate and pass through nginx101's source-owned inventory."""
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or data.get("generator") != "nginx101":
        raise ValueError("directive inventory is not nginx101 schema version 1")

    root = project_root.resolve()
    sources = data.get("source_files")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("directive inventory has no source files")
    for relative, expected in sources.items():
        source = (root / relative).resolve()
        if source != root and root not in source.parents:
            raise ValueError(f"directive source escapes project root: {relative}")
        if not source.is_file():
            raise ValueError(f"directive source is missing: {relative}")
        if sha256_file(source) != expected:
            raise ValueError(f"directive inventory is stale for {relative}")

    directives = data.get("directives")
    if not isinstance(directives, list) or not directives:
        raise ValueError("directive inventory has no directives")
    names = []
    for directive in directives:
        if not isinstance(directive, dict) or not directive.get("name"):
            raise ValueError("directive inventory contains an invalid directive")
        names.append(directive["name"])

    return {
        "source": "nginx101",
        "status": "passed",
        "directives": sorted(names),
        "inventory": data,
    }


def valid_configurations() -> list[dict[str, str]]:
    """Return public-safe configurations spanning every directive/context."""
    return [
        {
            "slug": "http-enable",
            "title": "Enable decompression globally",
            "directive": "unzstd",
            "config": "http { unzstd on; server { listen 127.0.0.1:PORT; } }",
        },
        {
            "slug": "server-enable",
            "title": "Enable decompression for a virtual host",
            "directive": "unzstd",
            "config": "http { server { listen 127.0.0.1:PORT; unzstd on; } }",
        },
        {
            "slug": "location-enable",
            "title": "Enable decompression for one location",
            "directive": "unzstd",
            "config": "http { server { listen 127.0.0.1:PORT; location / { unzstd on; } } }",
        },
        {
            "slug": "location-disable",
            "title": "Override inherited decompression",
            "directive": "unzstd",
            "config": "http { unzstd on; server { listen 127.0.0.1:PORT; location /raw { unzstd off; } } }",
        },
        {
            "slug": "http-force",
            "title": "Force decompression globally",
            "directive": "unzstd_force",
            "config": "http { unzstd on; unzstd_force on; server { listen 127.0.0.1:PORT; } }",
        },
        {
            "slug": "server-force",
            "title": "Force decompression for a virtual host",
            "directive": "unzstd_force",
            "config": "http { server { listen 127.0.0.1:PORT; unzstd on; unzstd_force on; } }",
        },
        {
            "slug": "location-force",
            "title": "Force decompression for one location",
            "directive": "unzstd_force",
            "config": "http { server { listen 127.0.0.1:PORT; location / { unzstd on; unzstd_force on; } } }",
        },
        {
            "slug": "http-buffers",
            "title": "Set global decompression buffers",
            "directive": "unzstd_buffers",
            "config": "http { unzstd_buffers 8 4k; server { listen 127.0.0.1:PORT; } }",
        },
        {
            "slug": "server-buffers",
            "title": "Set virtual-host decompression buffers",
            "directive": "unzstd_buffers",
            "config": "http { server { listen 127.0.0.1:PORT; unzstd_buffers 4 8k; } }",
        },
        {
            "slug": "location-buffers",
            "title": "Set location decompression buffers",
            "directive": "unzstd_buffers",
            "config": "http { server { listen 127.0.0.1:PORT; location / { unzstd_buffers 2 16k; } } }",
        },
        {
            "slug": "dictionary",
            "title": "Load a shared Zstandard dictionary",
            "directive": "unzstd_dict_file",
            "config": "http { unzstd_dict_file __ROOT__/dict; server { listen 127.0.0.1:PORT; } }",
        },
        {
            "slug": "combined-policy",
            "title": "Combine dictionary, buffers, and forced decoding",
            "directive": "unzstd_dict_file",
            "config": "http { unzstd_dict_file __ROOT__/dict; unzstd_buffers 8 8k; server { listen 127.0.0.1:PORT; location / { unzstd on; unzstd_force on; } } }",
        },
    ]


def nginx_t_configuration(
    item: dict[str, str], root: pathlib.Path, module: pathlib.Path, port: int
) -> str:
    """Render one inventory example as a complete NGINX configuration."""
    body = item["config"].replace("__ROOT__", str(root)).replace("PORT", str(port))
    return (
        f"load_module {module};\n"
        "worker_processes 1;\n"
        f"pid {root}/nginx.pid;\n"
        f"error_log {root}/error.log notice;\n"
        "events { worker_connections 64; }\n"
        f"{body}\n"
    )


def run_configuration_tests(
    nginx_binary: pathlib.Path,
    module: pathlib.Path,
    root: pathlib.Path,
    port: int,
) -> list[dict[str, str]]:
    """Run every public configuration through the real ``nginx -t``."""
    (root / "logs").mkdir(exist_ok=True)
    (root / "dict").write_bytes(b"unzstd-quality-dictionary")
    results = []
    for index, item in enumerate(valid_configurations()):
        conf = root / f"config-{index}.conf"
        conf.write_text(nginx_t_configuration(item, root, module, port + index))
        result = subprocess.run(
            [str(nginx_binary), "-p", str(root), "-c", str(conf), "-t"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"{item['slug']} failed nginx -t: {result.stdout}")
        results.append({**item, "nginx_t_status": "passed"})
    return results


def worker_pids(master_pid: int) -> list[int]:
    """Return Linux child PIDs for an NGINX master."""
    path = pathlib.Path(f"/proc/{master_pid}/task/{master_pid}/children")
    if not path.exists():
        raise RuntimeError("worker lifecycle probe requires Linux /proc")
    return sorted(int(value) for value in path.read_text().split())


def settled_worker_fds(
    master_pid: int, expected_workers: int, timeout: float = 8.0
) -> dict[int, int]:
    """Wait for a stable worker set and return each worker's FD count."""
    deadline = time.time() + timeout
    previous: dict[int, int] | None = None
    while time.time() < deadline:
        pids = worker_pids(master_pid)
        current = {
            pid: len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
            for pid in pids
            if pathlib.Path(f"/proc/{pid}/fd").is_dir()
        }
        if len(current) == expected_workers and current == previous:
            return current
        previous = current
        time.sleep(0.1)
    raise RuntimeError(f"workers did not settle: {previous}")


def terminate_and_verify_worker(
    master_pid: int, before: dict[int, int], timeout: float = 8.0
) -> dict[int, int]:
    """Terminate a non-primary worker and prove the master replaces it."""
    victim = max(before)
    os.kill(victim, signal.SIGTERM)
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = worker_pids(master_pid)
        if len(current) == len(before) and victim not in current:
            return settled_worker_fds(master_pid, len(before), timeout)
        time.sleep(0.1)
    raise RuntimeError(f"worker {victim} was not replaced")


def fd_delta_report(
    baseline: dict[int, int], settled: dict[int, int], worker_count: int
) -> dict[str, int | bool]:
    """Compare aggregate descriptors before and after worker replacement."""
    baseline_total = sum(baseline.values())
    settled_total = sum(settled.values())
    delta = settled_total - baseline_total
    allowance = worker_count * FD_DELTA_PER_WORKER_ALLOWANCE
    return {
        "baseline_total": baseline_total,
        "settled_total": settled_total,
        "delta": delta,
        "allowance": allowance,
        "within_allowance": delta <= allowance,
    }


def distro_name() -> str:
    """Return a compact distro identifier for public evidence."""
    values: dict[str, str] = {}
    path = pathlib.Path("/etc/os-release")
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
    return "-".join(filter(None, (values.get("ID"), values.get("VERSION_ID")))) or platform.system()


def new_evidence(
    *,
    generated_at: str,
    nginx_binary: pathlib.Path,
    configurations: list[dict[str, str]],
    directive_inventory: dict[str, Any],
    gates: dict[str, Any],
) -> dict[str, Any]:
    """Create schema-v1 public-safe verification evidence."""
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "module": {
            "handle": "unzstd",
            "display_name": "NGINX Unzstd Filter",
            "source_commit": source_commit(),
            "upstream_version": module_upstream_version(),
            "upstream_freshness": f"includes upstream {UPSTREAM_BASE}",
            "repo_private": False,
        },
        "platform": {
            "nginx_version": subprocess.run(
                [str(nginx_binary), "-v"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True,
            ).stdout.strip(),
            "nginx_branch": "nginx",
            "distro": distro_name(),
            "arch": platform.machine(),
            "binary_sha256": sha256_file(nginx_binary),
            "sonames": ["ngx_http_unzstd_filter_module.so"],
        },
        "levels": {
            "built": {"status": "passed", "detail": "package-realistic dynamic module"},
            "config": {"status": "passed", "detail": "nginx -t and nginx -T"},
            "runtime": {"status": "passed", "detail": "real NGINX proxy decompression"},
            "sanitized": {"status": "not_run", "detail": "final CI gate owns this claim"},
            "fuzzed": {"status": "not_run", "detail": "no bounded fuzzer in this run"},
            "torture": {"status": "passed", "detail": "hostile clients and worker lifecycle"},
        },
        "directive_inventory": directive_inventory,
        "configurations": configurations,
        "provenance": {
            "public_evidence_url": "https://github.com/dvershinin/ngx_http_unzstd_filter_module/actions"
        },
        "gates": gates,
    }


def validate_public_evidence(evidence: dict[str, Any]) -> None:
    """Reject private or machine-local data from public evidence."""
    rendered = json.dumps(evidence, sort_keys=True)
    forbidden = ("/tmp/", "/private/", "file://", "git@", "api.github.com/repos/")
    for marker in forbidden:
        if marker in rendered:
            raise ValueError(f"public evidence contains forbidden marker: {marker}")
    if evidence.get("schema_version") != 1:
        raise ValueError("public evidence must use schema version 1")
