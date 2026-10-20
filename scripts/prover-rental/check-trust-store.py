#!/usr/bin/env python3
"""Reject the distrusted emSign root in each Serverless TLS trust source."""

import argparse
import hashlib
from importlib.metadata import version
import os
from pathlib import Path
import re
import ssl
import subprocess


# Certifi GHSA-6q48-6c7w-9gw2; 2026.10.19 retains the unaffected emSign roots.
DISTRUSTED_ROOTS = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
}


def fingerprints(pem):
    certificates = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not certificates:
        raise ValueError("CA bundle contains no certificates")
    return {hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() for cert in certificates}


def check_fingerprints(name, values):
    if not values or DISTRUSTED_ROOTS.intersection(values):
        raise ValueError(f"{name}: empty trust store or distrusted emSign root")


def refresh_debian_store(config=Path("/etc/ca-certificates.conf"), roots=Path("/usr/share/ca-certificates")):
    lines = config.read_text().splitlines(keepends=True)
    for index, line in enumerate(lines):
        entry = line.strip()
        if not entry or entry.startswith(("#", "!")):
            continue
        path = roots / entry
        if path.is_file() and DISTRUSTED_ROOTS.intersection(fingerprints(path.read_text())):
            lines[index] = "!" + line
    config.write_text("".join(lines))
    subprocess.run(["update-ca-certificates", "--fresh"], check=True)


def system_fingerprints():
    paths = ssl.get_default_verify_paths()
    files = {Path(paths.cafile)} if paths.cafile else set()
    # OpenSSL loads hashed-directory certificates lazily, so get_ca_certs alone
    # cannot prove that a custom SSL_CERT_DIR excludes a distrusted root.
    directories = os.environ.get(paths.openssl_capath_env, paths.openssl_capath or "")
    for directory in directories.split(os.pathsep):
        path = Path(directory)
        if directory and path.is_dir():
            files.update(item.resolve() for item in path.iterdir() if item.is_file())
    values = {hashlib.sha256(cert).hexdigest()
              for cert in ssl.create_default_context().get_ca_certs(binary_form=True)}
    for path in files:
        raw = path.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" in raw:
            values.update(fingerprints(raw.decode("ascii")))
    return values


def check_stores():
    import botocore
    import certifi

    if tuple(map(int, version("certifi").split("."))) < (2026, 10, 19):
        raise ValueError("certifi 2026.10.19 or newer is required")
    for name, path in (("certifi", Path(certifi.where())),
                       ("botocore", Path(botocore.__file__).with_name("cacert.pem"))):
        check_fingerprints(name, fingerprints(path.read_text()))
    check_fingerprints("default SSL", system_fingerprints())
    print("certifi, botocore and default SSL trust stores exclude the distrusted emSign root")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-system", action="store_true",
                        help="disable only the distrusted root in the Debian image CA configuration")
    args = parser.parse_args()
    if args.refresh_system:
        refresh_debian_store()
    check_stores()


if __name__ == "__main__":
    main()
