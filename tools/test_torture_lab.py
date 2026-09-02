#!/usr/bin/env python3
"""Hermetic tests for Torture Lab policy and evidence."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from torture_lab import (
    FD_DELTA_PER_WORKER_ALLOWANCE,
    fd_delta_report,
    parser_directive_inventory,
    sha256_file,
    valid_configurations,
    validate_public_evidence,
)
from runtime_http import decoded_raw_body


class TortureLabTests(unittest.TestCase):
    def test_decodes_chunked_runtime_response(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
        )
        self.assertEqual(decoded_raw_body(response), b"abcde")

    def test_preserves_close_delimited_runtime_response(self) -> None:
        response = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc"
        self.assertEqual(decoded_raw_body(response), b"abc")

    def test_allows_settled_worker_replacement_noise(self) -> None:
        report = fd_delta_report({100: 8, 101: 8}, {200: 10, 201: 10}, 2)
        self.assertEqual(report["allowance"], 2 * FD_DELTA_PER_WORKER_ALLOWANCE)
        self.assertTrue(report["within_allowance"])

    def test_rejects_unexplained_descriptor_growth(self) -> None:
        report = fd_delta_report({100: 8, 101: 8}, {200: 14, 201: 14}, 2)
        self.assertFalse(report["within_allowance"])

    def test_parser_inventory_is_source_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "module.c"
            source.write_text("module source")
            inventory = root / "directives.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generator": "nginx101",
                        "source_files": {"module.c": sha256_file(source)},
                        "directives": [{"name": "unzstd"}],
                    }
                )
            )
            parsed = parser_directive_inventory(inventory, root)
        self.assertEqual(parsed["directives"], ["unzstd"])

    def test_stale_parser_inventory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "module.c").write_text("new source")
            inventory = root / "directives.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generator": "nginx101",
                        "source_files": {"module.c": "stale"},
                        "directives": [{"name": "unzstd"}],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "stale"):
                parser_directive_inventory(inventory, root)

    def test_configuration_inventory_is_complete_and_public(self) -> None:
        configurations = valid_configurations()
        self.assertGreaterEqual(len(configurations), 10)
        self.assertEqual(
            {item["directive"] for item in configurations},
            {"unzstd", "unzstd_buffers", "unzstd_dict_file", "unzstd_force"},
        )
        self.assertFalse(any("/tmp/" in item["config"] for item in configurations))

    def test_private_evidence_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "forbidden"):
            validate_public_evidence({"schema_version": 1, "path": "/tmp/private"})


if __name__ == "__main__":
    unittest.main()
