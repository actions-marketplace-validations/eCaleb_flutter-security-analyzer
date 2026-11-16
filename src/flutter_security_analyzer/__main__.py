"""Allow the scanner to be run with ``python -m flutter_security_analyzer``."""

import sys

from flutter_security_analyzer.main import main

if __name__ == '__main__':
    sys.exit(main())
