"""Enable ``python -m webscan``."""

import sys

from webscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
