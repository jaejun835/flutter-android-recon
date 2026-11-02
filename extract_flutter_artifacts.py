#!/usr/bin/env python3
"""Collect Flutter Android artifacts from an APK, XAPK/APKS, or split-APK directory.

This tool reads local files only. It does not run an app or contact a server.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath


MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_NESTED_APK_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEX_RE = re.compile(r"classes\d*\.dex$")
NATIVE_RE = re.compile(r"lib/[^/]+/[^/]+\.so$")


def clean_member(name: str) -> PurePosixPath | None:
    """Reject archive paths that could escape the output directory."""
    if "\\" in name or name.startswith("/") or "\x00" in name:
        return None
    parts = PurePosixPath(name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return PurePosixPath(*parts)


def selected(name: str, all_native: bool) -> bool:
    if name == "AndroidManifest.xml" or DEX_RE.fullmatch(name):
        return True
    if name.startswith("assets/flutter_assets/"):
        return True
    if NATIVE_RE.fullmatch(name):
        return all_native or name.endswith("/libapp.so") or name.endswith("/libflutter.so")
    return False


def split_tag(name: str) -> str:
    stem = Path(name).stem
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-") or "apk"
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    return f"{safe[:60]}-{digest}"


def iter_apk_sources(source: Path):
    """Yield (split label, ZipFile). Caller owns each yielded ZipFile context."""
    suffix = source.suffix.lower()
    if source.is_file() and suffix == ".apk":
        yield source.name, zipfile.ZipFile(source)
        return
    if source.is_file() and suffix in {".xapk", ".apks"}:
        with zipfile.ZipFile(source) as outer:
            found = False
            for entry in outer.infolist():
                if entry.is_dir() or not entry.filename.lower().endswith(".apk"):
                    continue
                found = True
                if entry.file_size > MAX_NESTED_APK_BYTES:
                    raise ValueError(f"nested APK too large: {entry.filename}")
                data = outer.read(entry)
                yield entry.filename, zipfile.ZipFile(io.BytesIO(data))
            if not found:
                raise ValueError("archive contains no APK files")
        return
    if source.is_dir():
        apks = sorted(p for p in source.rglob("*.apk") if p.is_file())
        if apks:
            for apk in apks:
                yield apk.relative_to(source).as_posix(), zipfile.ZipFile(apk)
            return
    raise ValueError("input must be an APK, XAPK, APKS, or directory containing APKs")


def extract(source: Path, output: Path, all_native: bool) -> dict:
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    skipped: list[dict] = []
    total_bytes = 0
    found_app = False
    found_engine = False
    found_assets = False
    split_count = 0

    for split_name, apk in iter_apk_sources(source):
        split_count += 1
        tag = split_tag(split_name)
        with apk:
            for entry in apk.infolist():
                if entry.is_dir() or not selected(entry.filename, all_native):
                    continue
                clean = clean_member(entry.filename)
                if clean is None:
                    skipped.append({"split": split_name, "entry": entry.filename, "reason": "unsafe path"})
                    continue
                if entry.file_size > MAX_MEMBER_BYTES or total_bytes + entry.file_size > MAX_TOTAL_BYTES:
                    skipped.append({"split": split_name, "entry": entry.filename, "reason": "size limit"})
                    continue
                data = apk.read(entry)
                relative = Path("artifacts", tag, *clean.parts)
                destination = output / relative
                if destination.exists():
                    skipped.append({"split": split_name, "entry": entry.filename, "reason": "duplicate output path"})
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                total_bytes += len(data)
                records.append({
                    "split": split_name,
                    "archive_entry": entry.filename,
                    "output": relative.as_posix(),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
                found_app |= clean.name == "libapp.so"
                found_engine |= clean.name == "libflutter.so"
                found_assets |= str(clean).startswith("assets/flutter_assets/")

    if not records:
        raise ValueError("no Flutter or Android artifacts were selected")
    report = {
        "input": str(source.resolve()),
        "flutter_detected": bool(found_app and (found_engine or found_assets)),
        "split_count": split_count,
        "total_extracted_bytes": total_bytes,
        "artifacts": records,
        "skipped": skipped,
        "note": "Local file collection only. AndroidManifest.xml may be binary XML; Dart source is not recovered.",
    }
    (output / "inventory.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="APK, XAPK, APKS, or directory containing APKs")
    parser.add_argument("output", type=Path, help="new or empty output directory")
    parser.add_argument("--all-native", action="store_true", help="also collect other native libraries")
    args = parser.parse_args()
    try:
        report = extract(args.input, args.output, args.all_native)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Splits: {report['split_count']}")
    print(f"Flutter detected: {'yes' if report['flutter_detected'] else 'uncertain'}")
    print(f"Artifacts: {len(report['artifacts'])}; skipped: {len(report['skipped'])}")
    print(f"Inventory: {args.output / 'inventory.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
