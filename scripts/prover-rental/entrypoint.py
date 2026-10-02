#!/usr/bin/env python3
"""Select the immutable image adapter without accepting executable names."""

import os
from pathlib import Path
import sys


def main():
    args = sys.argv[1:]
    warm = bool(args and args[0] == "--warm-session")
    adapter = Path(__file__).resolve().parent / ("warm_worker.py" if warm else "worker.py")
    os.execv(sys.executable, [sys.executable, str(adapter), *(args[1:] if warm else args)])


if __name__ == "__main__":
    main()
