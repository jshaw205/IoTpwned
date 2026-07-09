"""Light checks for the packaging setup (no actual PyInstaller build)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_packaging_files_exist():
    assert (ROOT / "iotpwned.spec").is_file()
    assert (ROOT / "packaging" / "build.py").is_file()
    assert (ROOT / "packaging" / "iotpwned_launcher.py").is_file()


def test_launcher_exposes_cli_main():
    # Load the launcher by path and confirm its `main` is the CLI entry point.
    path = ROOT / "packaging" / "iotpwned_launcher.py"
    spec = importlib.util.spec_from_file_location("iotpwned_launcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from iotpwned.cli import main as cli_main
    assert module.main is cli_main
    assert callable(module.main)


def test_spec_targets_the_launcher():
    spec_text = (ROOT / "iotpwned.spec").read_text(encoding="utf-8")
    assert "packaging/iotpwned_launcher.py" in spec_text
    assert "name='iotpwned'" in spec_text
