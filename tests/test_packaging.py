"""Light checks for the packaging setup (no actual PyInstaller build)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_launcher():
    path = ROOT / "packaging" / "iotpwned_launcher.py"
    spec = importlib.util.spec_from_file_location("iotpwned_launcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_packaging_files_exist():
    assert (ROOT / "iotpwned.spec").is_file()
    assert (ROOT / "packaging" / "build.py").is_file()
    assert (ROOT / "packaging" / "iotpwned_launcher.py").is_file()


def test_launcher_exposes_cli_main():
    module = _load_launcher()
    from iotpwned.cli import main as cli_main
    assert module.main is cli_main
    assert callable(module.main)


def _capturing_launcher():
    module = _load_launcher()
    captured = {}

    def fake_main(argv):
        captured["argv"] = argv
        return 0

    module.main = fake_main
    return module, captured


def test_frozen_binary_defaults_to_web_ui():
    # No args -> the frozen binary should launch the web UI (--web).
    module, captured = _capturing_launcher()
    rc = module.run([])
    assert rc == 0
    assert captured["argv"] == ["--web"]


def test_frozen_binary_passes_cli_args_through():
    # Any args -> normal CLI (no web default injected).
    module, captured = _capturing_launcher()
    module.run(["--version"])
    assert captured["argv"] == ["--version"]
    module.run(["--cidr", "192.168.1.0/24", "--no-wifi"])
    assert captured["argv"] == ["--cidr", "192.168.1.0/24", "--no-wifi"]


def test_spec_targets_the_launcher():
    spec_text = (ROOT / "iotpwned.spec").read_text(encoding="utf-8")
    assert "packaging/iotpwned_launcher.py" in spec_text
    assert "name='iotpwned'" in spec_text
