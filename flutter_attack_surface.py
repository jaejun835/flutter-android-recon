#!/usr/bin/env python3
"""Triage literal attack-surface clues in extracted Flutter Android artifacts.

Offline and target-neutral: no app is executed, no server is contacted, and no
host is labelled in scope. Dart AOT code is not decompiled by this script.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


MAX_FILE_BYTES = 256 * 1024 * 1024
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
URL_RE = re.compile(r"https?://[^\s\"'<>\\\x00]+", re.I)
HOST_RE = re.compile(r"(?<![a-z0-9_.@-])(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.I)
API_PATH_RE = re.compile(
    r"/(?:v\d+|api|oauth|auth|graphql|users?|accounts?|profiles?|"
    r"sessions?|collections?|favorites?|routes?|search|subscriptions?)"
    r"(?:/[a-z0-9_{}:.-]+){0,6}", re.I
)
AUTH_RE = re.compile(
    r"\b(?:oauth|oidc|bearer|jwt|pkce|refresh_?token|access_?token|id_?token|"
    r"client_?id|client_?secret|redirect_?uri|session|authorization|api_?key)\b", re.I
)
QUERY_KEY_RE = re.compile(r"[?&]([a-z][a-z0-9_-]{0,63})=", re.I)
SECRET_PATTERNS = {
    "AWS access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    "private key header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Bearer literal": re.compile(r"\bBearer\s+[A-Za-z0-9_\-.=]{12,}"),
}
TEXT_EXTENSIONS = {".json", ".txt", ".xml", ".yaml", ".yml", ".js", ".html", ".arb", ".bin", ".dat"}
FILE_SUFFIXES = {"apk", "aab", "bin", "css", "dart", "dex", "dll", "gif", "html", "jpeg", "jpg", "json", "js", "png", "so", "svg", "ttf", "webp", "xml"}
STATIC_PATH_EXTENSIONS = {".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".png", ".svg", ".ttf", ".webp", ".woff", ".woff2"}


class Hits:
    def __init__(self):
        self.rows: dict[str, dict] = {}

    def add(self, value: str, source: str, byte_offset: int):
        row = self.rows.setdefault(value, {"value": value, "count": 0, "evidence": []})
        row["count"] += 1
        evidence = {"file": source, "byte_offset": byte_offset}
        if evidence not in row["evidence"] and len(row["evidence"]) < 3:
            row["evidence"].append(evidence)

    def sorted(self):
        return sorted(self.rows.values(), key=lambda row: (-row["count"], row["value"]))


def safe_path(path: str) -> str:
    """Keep route shape without printing long identifiers in URL paths."""
    path = re.sub(
        r"(?i)(/(?:token|secret|password|api[_-]?key|session))/[^/]+",
        r"\1/{value}", path,
    )
    return re.sub(r"(?<=/)[A-Za-z0-9_-]{24,}(?=/|$)", "{value}", path)[:200]


def valid_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    if "." not in host or host.rsplit(".", 1)[-1] in FILE_SUFFIXES:
        return False
    return bool(HOST_RE.fullmatch(host))


def wanted(path: Path, include_dex: bool, include_native: bool) -> bool:
    if path.name == "libapp.so":
        return True
    if include_native and path.suffix == ".so":
        return True
    if include_dex and re.fullmatch(r"classes\d*\.dex", path.name):
        return True
    parts = path.parts
    return "flutter_assets" in parts and path.suffix.lower() in TEXT_EXTENSIONS


def iter_inputs(source: str, include_dex: bool, include_native: bool):
    if source == "-":
        yield "<stdin>", sys.stdin.buffer.read()
        return
    path = Path(source)
    if path.is_file():
        yield path.name, path.read_bytes()
        return
    if not path.is_dir():
        raise FileNotFoundError(source)
    for file in sorted(path.rglob("*")):
        if file.is_file() and wanted(file, include_dex, include_native):
            if file.stat().st_size <= MAX_FILE_BYTES:
                yield file.relative_to(path).as_posix(), file.read_bytes()


def scan_text(text: str, source: str, base: int, width: int, buckets: dict[str, Hits]):
    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:)]}")
        try:
            parsed = urlsplit(raw)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not valid_host(host):
            continue
        offset = base + match.start() * width
        buckets["hosts"].add(host, source, offset)
        path = safe_path(parsed.path)
        buckets["urls"].add(f"{parsed.scheme.lower()}://{host}{path}", source, offset)
        if path and Path(path).suffix.lower() not in STATIC_PATH_EXTENSIONS:
            buckets["paths"].add(path, source, offset)
        for key in QUERY_KEY_RE.findall("?" + parsed.query):
            buckets["query_keys"].add(key.lower(), source, offset)

    # Bare domains are common in compiled constants. Remove URLs first so
    # occurrences in URLs are not counted twice; preserve offsets with spaces.
    without_urls = URL_RE.sub(lambda match: " " * len(match.group(0)), text)
    for match in HOST_RE.finditer(without_urls):
        host = match.group(0).lower()
        if valid_host(host):
            buckets["hosts"].add(host, source, base + match.start() * width)

    # Exclude URLs here: otherwise a hostname such as search.example.com can
    # produce a false "/search" route candidate.
    for match in API_PATH_RE.finditer(without_urls):
        buckets["paths"].add(safe_path(match.group(0)), source, base + match.start() * width)

    for match in AUTH_RE.finditer(text):
        buckets["auth_markers"].add(match.group(0).lower(), source, base + match.start() * width)

    # Report types and locations only; never print matched secret values.
    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            buckets["secret_patterns"].add(label, source, base + match.start() * width)


def analyze(source: str, include_dex: bool = False, include_native: bool = False) -> dict:
    buckets = {key: Hits() for key in ("hosts", "urls", "paths", "query_keys", "auth_markers", "secret_patterns")}
    scanned = []
    for name, data in iter_inputs(source, include_dex, include_native):
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(f"file exceeds {MAX_FILE_BYTES} bytes: {name}")
        scanned.append({"file": name, "bytes": len(data)})
        for pattern, encoding, width in ((ASCII_RE, "ascii", 1), (UTF16_RE, "utf-16le", 2)):
            for match in pattern.finditer(data):
                text = match.group(0).decode(encoding, errors="replace")
                scan_text(text, name, match.start(), width, buckets)
    if not scanned:
        raise ValueError("no supported files found")
    return {
        "input": source,
        "scanned_files": scanned,
        **{key: bucket.sorted() for key, bucket in buckets.items()},
        "note": "Literal strings only. No Dart AOT decompilation, scope judgement, or network verification.",
    }


def display(report: dict, limit: int):
    print(f"Files scanned: {len(report['scanned_files'])}")
    for key, title in (
        ("hosts", "Host candidates"), ("urls", "URLs (query values omitted)"),
        ("paths", "Path candidates"), ("query_keys", "Query parameter names"),
        ("auth_markers", "Auth markers"), ("secret_patterns", "Secret shapes (values hidden)"),
    ):
        rows = report[key]
        print(f"\n== {title}: {len(rows)} ==")
        for row in rows[:limit]:
            first = row["evidence"][0]
            print(f"{row['value']}  [{row['count']}]  {first['file']} @ 0x{first['byte_offset']:x}")
        if len(rows) > limit:
            print(f"... {len(rows) - limit} more; use --json-output for complete evidence")
    print("\nCandidates only. Review raw artifacts and current authorization before testing.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="artifact directory, file, or '-' for stdin")
    parser.add_argument("--include-dex", action="store_true", help="also scan classes*.dex")
    parser.add_argument("--include-native", action="store_true", help="also scan other .so files")
    parser.add_argument("--json-output", type=Path, help="write full candidate report as JSON")
    parser.add_argument("--max", type=int, default=50, help="maximum rows per text section")
    args = parser.parse_args()
    if args.max < 1:
        parser.error("--max must be at least 1")
    try:
        report = analyze(args.input, args.include_dex, args.include_native)
        if args.json_output:
            args.json_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    display(report, args.max)
    if args.json_output:
        print(f"JSON report: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
