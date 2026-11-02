# flutter-android-recon

Small, dependency-free, **offline** reconnaissance helpers for Flutter Android
apps. They follow the same two-stage idea as
[dotnet-android-recon](https://github.com/jaejun835/dotnet-android-recon):
collect framework artifacts, then triage attack-surface clues. No domain or bug
bounty program is hardcoded.

1. `extract_flutter_artifacts.py` collects the useful Flutter and Android files
   from an APK, XAPK, APKS archive, or a directory containing split APKs.
2. `flutter_attack_surface.py` scans literal ASCII and UTF-16LE strings for host,
   URL, path, query-key, authentication, and secret-shape candidates.

Neither script runs the app or makes network requests. A candidate is not a
vulnerability or permission to test a host.

## Requirements

- Python 3.10 or newer; only the standard library is used.
- `apksigner` is recommended separately when validating the downloaded APK's
  signature. A valid signature alone does not establish that a third-party
  download matches the official distribution.

## Quick start

```bash
python3 extract_flutter_artifacts.py app.apk extracted
python3 flutter_attack_surface.py extracted --json-output candidates.json
```

For an APKPure XAPK or a bundle of split APKs, pass the `.xapk` or `.apks` file
to the extractor. A directory containing `.apk` split files also works.

```bash
python3 extract_flutter_artifacts.py bundle.xapk extracted
```

The extractor keeps split names separate, records each file's SHA-256 digest and
original archive entry in `extracted/inventory.json`, and collects:

- `libapp.so` and `libflutter.so` for every available ABI;
- `assets/flutter_assets/` files;
- root `AndroidManifest.xml` and `classes*.dex` files.

Other native libraries can be collected with `--all-native`. By default, the
triage script scans `libapp.so` and text-like Flutter assets. Add `--include-dex`
or `--include-native` when those files matter. The extractor limits each selected
member to 256 MiB and the combined output to 512 MiB.

```bash
python3 extract_flutter_artifacts.py --all-native app.apk extracted
python3 flutter_attack_surface.py extracted --include-dex --include-native \
  --json-output candidates.json --max 30
```

`flutter_attack_surface.py` also accepts a single file or `-` for standard
input. Text output is capped by `--max` per section; `--json-output` retains all
candidates and up to three source offsets for each one.

## Reading the results

- **Hosts** are literal host candidates, not an in-scope list.
- **URLs** omit user information, query values, and fragments. Long path
  segments are replaced with `{value}`.
- **Paths** and **query parameter names** are leads for manual review. A path
  may come from documentation, a dependency, or dead code.
- **Secret shapes** show type, count, and source offsets, never the matched
  value. Raw extracted files can still contain sensitive material; handle them
  accordingly.

Review the original strings and the current program scope before making any
live request. This tool does not verify server behavior.

## Limits

Flutter release builds usually compile Dart code ahead of time into
`libapp.so`. These scripts **do not decompile Dart AOT code** or reconstruct
functions. They can miss strings assembled at runtime, encoded or encrypted
constants, and values absent from the APK. `AndroidManifest.xml` is collected
as-is and may be binary XML. Static output is a starting point for manual
analysis, not a complete map of the app.

## Tests

The tests create synthetic APKs locally; no real app or network access is used.

```bash
python3 -m unittest discover -s tests -v
```
