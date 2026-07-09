"""Entry point for the PyInstaller-built executable.

A standalone script (absolute import, run as ``__main__``) that PyInstaller can
analyse and freeze. We avoid pointing PyInstaller at ``iotpwned/__main__.py``
because that module uses a package-relative import, which doesn't resolve when
run as a top-level script.
"""

import sys

from iotpwned.cli import main

if __name__ == "__main__":
    sys.exit(main())
