"""Cross-platform build helper: freeze IoTpwned into a single executable.

Usage:
    python packaging/build.py            # build using iotpwned.spec
    python packaging/build.py --clean    # remove build/ and dist/ first

Run this on each OS you want a binary for — PyInstaller cannot cross-compile.
The result lands in ``dist/iotpwned`` (``dist/iotpwned.exe`` on Windows).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "iotpwned.spec"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the IoTpwned executable.")
    parser.add_argument("--clean", action="store_true",
                        help="Remove build/ and dist/ before building.")
    args = parser.parse_args()

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Install it with:\n"
              "    pip install -e \".[build]\"    (or: pip install pyinstaller)")
        return 1

    if args.clean:
        for d in ("build", "dist"):
            path = ROOT / d
            if path.exists():
                shutil.rmtree(path)
                print(f"removed {path}")

    print(f"Building from {SPEC.name} ...")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm"],
        cwd=ROOT,
    )
    if result.returncode != 0:
        return result.returncode

    exe = ROOT / "dist" / ("iotpwned.exe" if sys.platform.startswith("win")
                           else "iotpwned")
    if exe.exists():
        size_mb = exe.stat().st_size / (1024 * 1024)
        print(f"\nBuilt: {exe}  ({size_mb:.1f} MB)")
        print(f"  Try it:  {exe} --version")
    else:
        print("Build finished but the expected binary was not found.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
