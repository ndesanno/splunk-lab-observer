"""Provision a private LAN certificate and one high-entropy owner password."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
from pathlib import Path


DEFAULT_CONFIG_DIR = Path.home() / ".config" / "splunk-lab-observer"


def private_lan_address(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or address.is_unspecified or address.is_multicast or not (address.is_private or address.is_loopback):
        raise ValueError("Use one private IPv4 address on the mini PC")
    return str(address)


def write_private_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)


def provision_lan_credentials(config_dir, address):
    address = private_lan_address(address)
    config_dir = Path(config_dir).expanduser()
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if config_dir.stat().st_mode & 0o077:
        raise ValueError("The credential directory must be private to its owner")

    paths = {
        "certfile": config_dir / "cert.pem",
        "keyfile": config_dir / "key.pem",
        "auth_file": config_dir / "auth.json",
        "password_file": config_dir / "initial-password.txt",
    }
    if any(path.exists() for path in paths.values()):
        raise FileExistsError("LAN credentials already exist; use the existing files or move them before provisioning again")

    previous_umask = os.umask(0o077)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                "-keyout", str(paths["keyfile"]), "-out", str(paths["certfile"]),
                "-days", "365", "-subj", "/CN=Splunk Lab Observer",
                "-addext", f"subjectAltName=IP:{address}",
            ],
            check=True,
            capture_output=True,
        )
    finally:
        os.umask(previous_umask)
    os.chmod(paths["keyfile"], 0o600)

    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    write_private_file(paths["auth_file"], json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "digest": base64.b64encode(digest).decode(),
    }) + "\n")
    write_private_file(paths["password_file"], password + "\n")
    return paths


def certificate_fingerprint(certfile):
    pem = Path(certfile).read_text(encoding="ascii")
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def main():
    parser = argparse.ArgumentParser(description="Set up HTTPS and owner login for one LAN address")
    parser.add_argument("--address", required=True, help="Private IPv4 address of the mini PC")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    args = parser.parse_args()
    paths = provision_lan_credentials(args.config_dir, args.address)
    print(f"Credential directory: {args.config_dir}")
    print(f"One-time password file: {paths['password_file']}")
    print(f"Certificate: {paths['certfile']}")
    print(f"Certificate SHA-256 fingerprint: {certificate_fingerprint(paths['certfile'])}")
    print("Read the password locally and remove the one-time file after saving it on your Mac.")


if __name__ == "__main__":
    main()
