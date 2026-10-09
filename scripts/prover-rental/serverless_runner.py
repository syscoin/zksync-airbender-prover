#!/usr/bin/env python3
"""Start the pinned provider SDK around the isolated persistent FRI adapter."""

import importlib
from importlib.metadata import version
import os
from pathlib import Path
import sys


SDK_VERSION = "1.12.0"
ADAPTER_DIRECTORY = Path("/opt/zksys-rental")


def single_concurrency(_current):
    return 1


def main():
    os.umask(0o077)
    # Resolve the SDK before adding the adapter path. Image staging also renames
    # the local provider utility, so later SDK imports cannot resolve to it.
    sdk = importlib.import_module("runpod")
    if version("runpod") != SDK_VERSION:
        raise RuntimeError("serverless_sdk_version_mismatch")
    sys.path.insert(0, str(ADAPTER_DIRECTORY))
    module = importlib.import_module("serverless_worker")
    worker = module.ServerlessFriWorker()
    try:
        worker.initialize()
        sdk.serverless.start({"handler": worker.handler, "concurrency_modifier": single_concurrency,
                              "refresh_worker": False})
    finally:
        worker.close()


if __name__ == "__main__":
    main()
