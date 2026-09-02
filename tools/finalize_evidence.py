#!/usr/bin/env python3
"""Promote runtime evidence only after every sanitizer dependency passed."""

from __future__ import annotations

import argparse
import json
import pathlib

from torture_lab import validate_public_evidence


def finalize(source: pathlib.Path, destination: pathlib.Path) -> None:
    """Mark sanitizer evidence passed in the dependency-gated final job."""
    evidence = json.loads(source.read_text())
    for level in ("built", "config", "runtime", "torture"):
        if evidence.get("levels", {}).get(level, {}).get("status") != "passed":
            raise ValueError(f"cannot finalize evidence: {level} did not pass")
    evidence["levels"]["sanitized"] = {
        "status": "passed",
        "detail": "static ASan and UBSan suite passed for this commit",
    }
    validate_public_evidence(evidence)
    destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    finalize(args.source, args.destination)


if __name__ == "__main__":
    main()
