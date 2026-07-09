# PyInstaller spec for IoTpwned — builds a single-file console executable.
#
#   pyinstaller iotpwned.spec        (or: python packaging/build.py)
#
# Produces dist/iotpwned  (dist/iotpwned.exe on Windows). PyInstaller cannot
# cross-compile, so run this on each target OS to get that OS's binary.

# The optional `mac-vendor-lookup` package is intentionally NOT bundled — the
# frozen build falls back to IoTpwned's built-in OUI table, keeping the binary
# small and self-contained. It's listed as an exclude so a dev machine that
# happens to have it installed doesn't accidentally pull it in.

a = Analysis(
    ['packaging/iotpwned_launcher.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['mac_vendor_lookup', 'tkinter', 'pyinstaller'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='iotpwned',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
