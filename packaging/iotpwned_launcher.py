"""Entry point for the PyInstaller-built executable.

A standalone script (absolute import, run as ``__main__``) that PyInstaller can
analyse and freeze. We avoid pointing PyInstaller at ``iotpwned/__main__.py``
because that module uses a package-relative import, which doesn't resolve when
run as a top-level script.

Default behaviour differs from the ``iotpwned`` pip console script on purpose:
when the frozen binary is launched with **no arguments** (e.g. a non-technical
user double-clicks it), it opens the local web UI rather than the terminal CLI.
Passing any CLI flag (``--cidr``, ``--version``, ``--help``, …) runs the normal
command-line interface.
"""

import sys

from iotpwned.cli import main


def run(argv=None):
    """Dispatch: no args -> web UI; any args -> the normal CLI."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["--web"]
    return main(argv)


if __name__ == "__main__":
    sys.exit(run())
