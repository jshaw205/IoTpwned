# Packaging IoTpwned as a standalone executable

IoTpwned can be frozen into a single, self-contained executable with
[PyInstaller](https://pyinstaller.org) so non-technical users can run it without
installing Python.

## Build

```bash
pip install -e ".[build]"
python packaging/build.py --clean
```

Output:

| OS | Binary |
|----|--------|
| Windows | `dist/iotpwned.exe` |
| macOS   | `dist/iotpwned` |
| Linux   | `dist/iotpwned` |

Then run it:

```bash
./dist/iotpwned                 # no args -> opens the local web UI (double-click default)
./dist/iotpwned --cidr 192.168.1.0/24   # any flag -> normal CLI scan
./dist/iotpwned --version
```

The frozen binary defaults to the **web UI** when launched with no arguments (so
a double-click gives non-technical users the "click Scan" experience). This
default lives in `iotpwned_launcher.py`; the `iotpwned` pip console script is
unaffected and stays CLI-first.

## Files

- [`../iotpwned.spec`](../iotpwned.spec) — the PyInstaller build config (a single
  onefile console app). This is the source of truth for the build.
- [`iotpwned_launcher.py`](iotpwned_launcher.py) — the entry script PyInstaller
  freezes. Calls `iotpwned.cli:main`, defaulting to the web UI when run with no
  arguments.
- [`build.py`](build.py) — a small cross-platform wrapper that runs PyInstaller
  on the spec and prints where the binary landed.

## Important: no cross-compilation

PyInstaller **cannot** build a macOS or Linux binary from Windows (or any other
cross combination). To ship all three, run `python packaging/build.py` on each
target OS — e.g. a CI matrix with `windows-latest`, `macos-latest`, and
`ubuntu-latest` runners, each uploading its `dist/iotpwned*` artifact.

## Notes

- The optional `mac-vendor-lookup` package is deliberately excluded from the
  frozen build (the binary falls back to the built-in OUI table), keeping it
  small and dependency-free.
- The Wi-Fi check shells out to the OS tool (`netsh` / `airport` / `nmcli`),
  which is present on the target machine — it is not bundled.
- `build/` and `dist/` are git-ignored; only the spec and these scripts are
  tracked.
- macOS Gatekeeper and Windows SmartScreen will warn on an unsigned binary.
  Code-signing/notarisation is out of scope here; document it for a real release.
