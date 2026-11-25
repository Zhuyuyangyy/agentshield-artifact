"""Verify the SHA-256 manifest of an anonymous artifact snapshot.

The snapshot's ``MANIFEST.json`` lists every shipped file except itself. This
command recomputes each digest, checks each byte count, and reports files that
are listed but missing or present but unlisted.

Usage
-----
    python scripts/verify_artifact_manifest.py [--root DIR] [--strict]

Exit status is the contract:

    0  every listed file matches and no unlisted file is present
    1  a digest, size, listing, or count mismatch
    2  the manifest is missing or not readable JSON

Runtime caches (``__pycache__``, ``*.pyc``, ``.pytest_cache``, ``.ruff_cache``)
are ignored by default because running the shipped tests creates them. Pass
``--strict`` to treat them as unlisted files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import List, Sequence, Tuple

CACHE_PARTS = frozenset({
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".git",
})


def _is_cache(relative: Path, strict: bool) -> bool:
    if strict:
        return False
    return (relative.suffix == ".pyc"
            or any(part in CACHE_PARTS for part in relative.parts))


def verify(root: Path, strict: bool = False) -> Tuple[int, List[str], List[str]]:
    manifest_path = root / "MANIFEST.json"
    if not manifest_path.is_file():
        return 2, [], [f"missing {manifest_path}"]
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return 2, [], [f"{manifest_path} is not valid JSON: {exc}"]
    files = document.get("files")
    if not isinstance(files, dict):
        return 2, [], [f"{manifest_path} has no files object"]

    log: List[str] = []
    problems: List[str] = []
    for relative, entry in sorted(files.items()):
        target = root / relative
        if not target.is_file():
            problems.append(f"listed file is missing: {relative}")
            continue
        data = target.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry.get("sha256"):
            problems.append(
                f"hash mismatch: {relative} hashes to {digest}, manifest "
                f"records {entry.get('sha256')}")
        elif len(data) != entry.get("bytes"):
            problems.append(
                f"size mismatch: {relative} is {len(data)} bytes, manifest "
                f"records {entry.get('bytes')}")
        else:
            log.append(f"ok    {relative}")

    actual = {
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
        and not _is_cache(path.relative_to(root), strict)
    }
    listed = {Path(relative) for relative in files}
    for relative in sorted(actual - listed, key=lambda path: path.as_posix()):
        problems.append(
            f"shipped file is not listed in the manifest: {relative.as_posix()}")
    if document.get("file_count") != len(files):
        problems.append(
            f"file_count is {document.get('file_count')}, manifest lists "
            f"{len(files)}")
    total = sum(entry.get("bytes", 0) for entry in files.values()
                if isinstance(entry, dict))
    if document.get("total_bytes") != total:
        problems.append(
            f"total_bytes is {document.get('total_bytes')}, listed files sum "
            f"to {total}")
    return (1 if problems else 0), log, problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify-artifact-manifest")
    parser.add_argument("--root", default=".",
                        help="snapshot root containing MANIFEST.json")
    parser.add_argument("--strict", action="store_true",
                        help="treat runtime caches as unlisted files")
    args = parser.parse_args(argv)
    code, log, problems = verify(Path(args.root).resolve(), args.strict)
    if problems:
        print(f"FAIL: {len(problems)} manifest problem(s)")
        for problem in problems:
            print(f"   {problem}")
        return code
    print(f"OK: MANIFEST.json matches {len(log)} shipped file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
