"""Local, fail-closed package artifact integrity gate (not signature verification)."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import stat
import sys

MAX_ARTIFACTS = 10_000
MAX_BYTES_PER_ARTIFACT = 100 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class GateError(ValueError):
    """A package integrity check did not meet its acceptance contract."""


def verify(root: Path, manifest: Path) -> int:
    if manifest.is_symlink():
        raise GateError("manifest symlinks are not accepted")
    try:
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise GateError("artifact root is not a directory")
        spec = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError("root or manifest cannot be read") from exc
    if not isinstance(spec, dict) or spec.get("schema_version") != 1:
        raise GateError("unsupported manifest schema")
    entries = spec.get("artifacts")
    if not isinstance(entries, list) or not (1 <= len(entries) <= MAX_ARTIFACTS):
        raise GateError("manifest must contain 1..10000 artifacts")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise GateError("invalid artifact entry")
        rel, expected = entry["path"], entry["sha256"]
        if not isinstance(rel, str) or not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise GateError("invalid artifact path or SHA-256")
        parts = rel.split("/")
        if ("\\" in rel or ":" in rel or "\x00" in rel or
                any(p in ("", ".", "..") for p in parts)):
            raise GateError("unsafe artifact path")
        if rel in seen:
            raise GateError("duplicate artifact path")
        seen.add(rel)
        candidate = root
        for part in parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise GateError("artifact symlinks are not accepted")
        try:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise GateError("artifact escapes root")
            info = candidate.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES_PER_ARTIFACT:
                raise GateError("artifact must be a regular file <= 100 MiB")
            digest = hashlib.sha256()
            with candidate.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise GateError("artifact is missing or unreadable") from exc
        if not hmac.compare_digest(digest.hexdigest(), expected):
            raise GateError("artifact SHA-256 mismatch")
    return len(seen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        count = verify(args.root, args.manifest)
    except GateError as exc:
        print(f"INTEGRITY_GATE_FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"LOCAL_ARTIFACT_SHA256_VERIFIED: {count} file(s); no provenance or signature claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
