"""Signed rule bundles: key generation, bundle creation, and signature verification.

A bundle is a zip with ``manifest.json`` (``{"format": 1, "version": N, ...}``) and rule files.
Its detached signature (``<bundle>.sig``) is a base64 Ed25519 signature over
``b"venom-bundle-v1:" + sha256_hex(bundle)``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from venom.engines.hashes import HashListError, parse_hash_list
from venom.engines.yara import RuleSource, compile_sources, count_rules
from venom.rulesets import HASH_SUFFIX, rule_files

BUNDLE_FORMAT = 1
MANIFEST_NAME = "manifest.json"
PASSPHRASE_ENV = "VENOM_KEY_PASSPHRASE"


class BundleError(Exception):
    pass


def bundle_message(sha256_hex: str) -> bytes:
    return b"venom-bundle-v1:" + sha256_hex.lower().encode("ascii")


def load_public_key(text: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleError("public key is not valid base64") from exc
    if len(raw) != 32:
        raise BundleError("public key must be a 32-byte Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_bundle(public_key: str, sha256_hex: str, signature: bytes) -> None:
    """Verify a raw 64-byte signature, or the base64 text form written by ``create_bundle``."""
    if len(signature) == 64:
        sig = signature
    else:
        try:
            sig = base64.b64decode(signature.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BundleError("signature is not valid base64") from exc
    try:
        load_public_key(public_key).verify(sig, bundle_message(sha256_hex))
    except InvalidSignature as exc:
        raise BundleError("signature verification failed") from exc


def _passphrase() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode() if value else None


def generate_keypair(out_dir: Path, name: str = "venom-signing") -> tuple[Path, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / f"{name}.key"
    pub_path = out_dir / f"{name}.pub"
    if key_path.exists() or pub_path.exists():
        raise BundleError(f"refusing to overwrite existing key files in {out_dir}")
    private_key = Ed25519PrivateKey.generate()
    passphrase = _passphrase()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub_path.write_text(public_b64 + "\n", encoding="ascii")
    return key_path, public_b64


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
    except (OSError, ValueError, TypeError) as exc:
        raise BundleError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleError("signing key must be an Ed25519 private key")
    return key


def validate_rule_files(files: list[Path], namespace: str = "validate") -> tuple[int, int]:
    """Strictly validate rule files. Returns ``(yara_rule_count, hash_count)``."""
    sources: list[RuleSource] = []
    hash_count = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == HASH_SUFFIX:
            try:
                hash_count += len(parse_hash_list(text, path.name))
            except HashListError as exc:
                raise BundleError(str(exc)) from exc
        else:
            sources.append(RuleSource(namespace, path.name, text))
    if sources:
        try:
            compile_sources(sources, strict=True)
        except Exception as exc:  # yara_x.CompileError
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else repr(exc)
            raise BundleError(f"rules failed to compile: {first}") from exc
    return sum(count_rules(s.text) for s in sources), hash_count


def create_bundle(rules_dir: Path, output: Path, version: int, key_path: Path) -> Path:
    if version < 1:
        raise BundleError("bundle version must be a positive integer")
    files = rule_files(rules_dir)
    if not files:
        raise BundleError(f"no .yar, .yara or .hashes files found in {rules_dir}")
    rule_count, hash_count = validate_rule_files(files)
    key = _load_private_key(key_path)
    names = [p.relative_to(rules_dir).as_posix() for p in files]
    manifest = {
        "format": BUNDLE_FORMAT,
        "version": version,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "rule_count": rule_count,
        "hash_count": hash_count,
        "files": names,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
        for path, name in zip(files, names, strict=True):
            archive.write(path, f"rules/{name}")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    signature = base64.b64encode(key.sign(bundle_message(digest)))
    sig_path = output.with_name(output.name + ".sig")
    sig_path.write_bytes(signature + b"\n")
    return sig_path
