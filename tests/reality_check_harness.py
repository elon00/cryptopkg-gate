"""Compatibility entrypoint: requires a real manifest and artifact root."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from package_integrity_gate import main

if __name__ == "__main__":
    raise SystemExit(main())
