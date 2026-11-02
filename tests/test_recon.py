"""Small synthetic fixtures; no third-party APKs or network access needed."""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extract_flutter_artifacts import extract  # noqa: E402
from flutter_attack_surface import analyze  # noqa: E402


def make_apk(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


class ExtractTests(unittest.TestCase):
    def test_direct_apk_collects_flutter_files_and_rejects_unsafe_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "app.apk"
            make_apk(apk, {
                "AndroidManifest.xml": b"binary manifest",
                "classes.dex": b"dex",
                "lib/arm64-v8a/libapp.so": b"AOT",
                "lib/arm64-v8a/libflutter.so": b"engine",
                "assets/flutter_assets/FontManifest.json": b"[]",
                "assets/flutter_assets/../../escape.txt": b"unsafe",
                "res/icon.png": b"ignored",
            })
            out = root / "out"
            report = extract(apk, out, all_native=False)
            self.assertTrue(report["flutter_detected"])
            self.assertEqual(report["split_count"], 1)
            self.assertEqual(len(report["artifacts"]), 5)
            self.assertEqual(report["skipped"][0]["reason"], "unsafe path")
            self.assertFalse((root / "escape.txt").exists())
            self.assertTrue((out / "inventory.json").exists())

    def test_nested_apks_are_kept_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base.apk"
            native = root / "config.arm64.apk"
            make_apk(base, {"assets/flutter_assets/FontManifest.json": b"[]"})
            make_apk(native, {
                "lib/arm64-v8a/libapp.so": b"AOT",
                "lib/arm64-v8a/libflutter.so": b"engine",
            })
            bundle = root / "bundle.apks"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.write(base, "base.apk")
                archive.write(native, "config.arm64.apk")
            report = extract(bundle, root / "out", all_native=False)
            self.assertEqual(report["split_count"], 2)
            self.assertTrue(report["flutter_detected"])
            outputs = {row["output"] for row in report["artifacts"]}
            self.assertEqual(len(outputs), 3)


class TriageTests(unittest.TestCase):
    def test_urls_are_redacted_and_bare_hosts_are_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libapp.so"
            binary.write_bytes(
                b"https://search.example.com/v1/users?token=secret123&userId=42\x00"
                b"https://api.example.com/token/shortsecret\x00"
                b"edge.example.net\x00/api/private\x00"
                b"AKIAABCDEFGHIJKLMNOP"
            )
            report = analyze(str(binary))
            encoded = json.dumps(report)
            self.assertIn("search.example.com", {row["value"] for row in report["hosts"]})
            self.assertIn("edge.example.net", {row["value"] for row in report["hosts"]})
            self.assertIn("https://search.example.com/v1/users", {row["value"] for row in report["urls"]})
            self.assertIn("https://api.example.com/token/{value}", {row["value"] for row in report["urls"]})
            self.assertIn("/api/private", {row["value"] for row in report["paths"]})
            self.assertNotIn("/search", {row["value"] for row in report["paths"]})
            self.assertIn("token", {row["value"] for row in report["query_keys"]})
            self.assertIn("AWS access key ID", {row["value"] for row in report["secret_patterns"]})
            self.assertNotIn("secret123", encoded)
            self.assertNotIn("shortsecret", encoded)
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", encoded)

    def test_utf16_strings_have_byte_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libapp.so"
            binary.write_bytes(b"\x00\x00" + "api.example.org".encode("utf-16le"))
            report = analyze(str(binary))
            row = next(row for row in report["hosts"] if row["value"] == "api.example.org")
            self.assertEqual(row["evidence"][0]["byte_offset"], 2)


if __name__ == "__main__":
    unittest.main()
