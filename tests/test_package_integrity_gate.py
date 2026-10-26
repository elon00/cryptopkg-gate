"""Real filesystem and subprocess regressions for the local integrity checker."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).resolve().parents[1] / "package_integrity_gate.py"


class PackageIntegrityGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "artifacts"
        self.root.mkdir()
        self.manifest = Path(self.tmp.name) / "manifest.json"
        self.data = self.root / "release.bin"
        self.data.write_bytes(b"signed-by-no-one: test fixture only")
        self.entries = [{"path": "release.bin", "sha256": hashlib.sha256(self.data.read_bytes()).hexdigest()}]

    def run_gate(self, expected_ok):
        self.manifest.write_text(json.dumps({"schema_version": 1, "artifacts": self.entries}), encoding="utf-8")
        result = subprocess.run([sys.executable, str(CLI), "--root", str(self.root),
                                 "--manifest", str(self.manifest)], text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode == 0, expected_ok, result.stdout + result.stderr)
        return result

    def test_valid_file(self):
        self.assertIn("LOCAL_ARTIFACT_SHA256_VERIFIED", self.run_gate(True).stdout)

    def test_tamper_fails(self):
        self.data.write_bytes(b"changed")
        self.run_gate(False)

    def test_missing_fails(self):
        self.data.unlink()
        self.run_gate(False)

    def test_duplicate_fails(self):
        self.entries.append(self.entries[0].copy())
        self.run_gate(False)

    def test_parent_traversal_fails(self):
        self.entries[0]["path"] = "../release.bin"
        self.run_gate(False)

    def test_absolute_path_fails(self):
        self.entries[0]["path"] = str(self.data)
        self.run_gate(False)

    def test_backslash_fails(self):
        self.entries[0]["path"] = r"folder\release.bin"
        self.run_gate(False)

    def test_invalid_digest_fails(self):
        self.entries[0]["sha256"] = "f" * 63
        self.run_gate(False)

    def test_empty_manifest_fails(self):
        self.entries = []
        self.run_gate(False)

    def test_symlink_fails(self):
        link = self.root / "linked.bin"
        try:
            link.symlink_to(self.data)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        self.entries[0]["path"] = "linked.bin"
        self.run_gate(False)

    def test_nested_valid(self):
        nested = self.root / "nested"
        nested.mkdir()
        new = nested / "pkg.tar"
        new.write_bytes(b"archive fixture")
        self.entries = [{"path": "nested/pkg.tar", "sha256": hashlib.sha256(new.read_bytes()).hexdigest()}]
        self.run_gate(True)

    def test_manifest_not_json_fails(self):
        self.manifest.write_text("not json", encoding="utf-8")
        result = subprocess.run([sys.executable, str(CLI), "--root", str(self.root),
                                 "--manifest", str(self.manifest)], capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
