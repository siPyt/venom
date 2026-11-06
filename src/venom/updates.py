"""Rule feed updates and ClamAV signature updates.

Every feed update is: download (HTTPS only, size-capped) -> authenticate (pinned SHA-256
and/or Ed25519 signature, with rollback protection) -> extract rule files only -> compile
-> atomically activate, keeping the previous version for ``venom update --rollback``.
A failure at any step leaves the active rules untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from venom import __version__
from venom.archives import read_bounded
from venom.bundles import MANIFEST_NAME, BundleError, validate_rule_files, verify_bundle
from venom.config import FeedConfig, MiB, Settings
from venom.engines.clamav import find_executable
from venom.rulesets import FEED_STATE_FILE, HASH_SUFFIX, YARA_SUFFIXES, read_feed_state

USER_AGENT = f"venom/{__version__} (+https://github.com/siPyt/venom)"
MAX_SIGNATURE_SIZE = 4096
MAX_RULE_FILES = 10_000
MAX_EXTRACTED_TOTAL = 512 * MiB
_TIMEOUT = 60


class UpdateError(Exception):
    pass


@dataclass
class UpdateResult:
    name: str
    status: str
    """``updated``, ``unchanged``, ``rolled-back``, ``skipped`` or ``failed``."""
    message: str

    @property
    def ok(self) -> bool:
        return self.status != "failed"


class _HTTPSOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise UpdateError(f"refusing redirect to non-HTTPS URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str) -> BinaryIO:
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme == "https":
        opener = urllib.request.build_opener(_HTTPSOnlyRedirects)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        return opener.open(request, timeout=_TIMEOUT)
    if scheme == "file":
        return open(urllib.request.url2pathname(urllib.parse.urlsplit(url).path), "rb")
    if scheme == "" or (len(scheme) == 1 and os.name == "nt"):
        return open(os.path.expanduser(url), "rb")
    raise UpdateError(f"refusing insecure or unsupported URL {url!r}; use https:// or a local path")


def _describe(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return str(exc.reason)
    if isinstance(exc, OSError):
        return exc.strerror or str(exc)
    return str(exc)


def download(url: str, dest: Path, max_size: int) -> str:
    """Download ``url`` to ``dest`` with a hard size cap. Returns the SHA-256 hex digest."""
    digest = hashlib.sha256()
    total = 0
    try:
        with _open(url) as response, open(dest, "xb") as out:
            length = getattr(response, "headers", {}).get("Content-Length")
            if length and length.isdigit() and int(length) > max_size:
                raise UpdateError(f"{url} is {int(length)} bytes; the limit is {max_size}")
            while chunk := response.read(MiB):
                total += len(chunk)
                if total > max_size:
                    raise UpdateError(f"{url} exceeds the {max_size}-byte download limit")
                digest.update(chunk)
                out.write(chunk)
    except UpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise UpdateError(f"download failed for {url}: {_describe(exc)}") from exc
    return digest.hexdigest()


def _download_small(url: str, limit: int) -> bytes:
    try:
        with _open(url) as response:
            data = read_bounded(response, limit)
    except UpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise UpdateError(f"download failed for {url}: {_describe(exc)}") from exc
    if data is None:
        raise UpdateError(f"{url} is larger than {limit} bytes")
    return data


def _authenticate(feed: FeedConfig, sha256: str) -> str:
    if feed.sha256 and sha256 != feed.sha256.lower():
        raise UpdateError(f"SHA-256 mismatch: expected {feed.sha256.lower()}, got {sha256}")
    if feed.public_key:
        signature_url = feed.signature_url or feed.url + ".sig"
        signature = _download_small(signature_url, MAX_SIGNATURE_SIZE)
        try:
            verify_bundle(feed.public_key, sha256, signature)
        except BundleError as exc:
            raise UpdateError(f"{exc}; the bundle was rejected") from exc
        return "signature verified"
    if feed.sha256:
        return "SHA-256 pinned"
    scheme = urllib.parse.urlsplit(feed.url).scheme.lower()
    return "HTTPS" if scheme == "https" else "local file"


def _safe_name(index: int, name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", posixpath.basename(name))[:100] or "rules"
    return f"{index:05d}-{base}"


def _extract(archive_path: Path, dest: Path) -> tuple[list[Path], dict[str, Any] | None]:
    """Copy only rule files out of the bundle, under names we generate ourselves."""
    files: list[Path] = []
    manifest: dict[str, Any] | None = None
    remaining = MAX_EXTRACTED_TOTAL
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/")
                suffix = posixpath.splitext(name)[1].lower()
                is_manifest = name == MANIFEST_NAME
                if not is_manifest and suffix not in (*YARA_SUFFIXES, HASH_SUFFIX):
                    continue
                if info.flag_bits & 0x1:
                    raise UpdateError(f"bundle member {name} is encrypted")
                with archive.open(info) as member:
                    data = read_bounded(
                        member, min(remaining, 64 * 1024 if is_manifest else remaining)
                    )
                if data is None:
                    raise UpdateError("bundle contents exceed the extraction size limit")
                remaining -= len(data)
                if is_manifest:
                    try:
                        loaded = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise UpdateError(f"invalid {MANIFEST_NAME}: {exc}") from exc
                    if not isinstance(loaded, dict):
                        raise UpdateError(f"invalid {MANIFEST_NAME}: expected an object")
                    manifest = loaded
                    continue
                if len(files) >= MAX_RULE_FILES:
                    raise UpdateError(f"bundle has more than {MAX_RULE_FILES} rule files")
                target = dest / _safe_name(len(files), name)
                target.write_bytes(data)
                files.append(target)
    except (
        zipfile.BadZipFile,
        zlib.error,
        OSError,
        EOFError,
        NotImplementedError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise UpdateError(f"cannot read bundle: {exc}") from exc
    return files, manifest


def _check_version(
    feed: FeedConfig,
    manifest: dict[str, Any] | None,
    state: dict[str, Any] | None,
    allow_downgrade: bool,
) -> int | None:
    version = manifest.get("version") if manifest else None
    if version is not None and (not isinstance(version, int) or isinstance(version, bool)):
        raise UpdateError("manifest version must be an integer")
    if not feed.public_key:
        return version
    if version is None or version < 1:
        raise UpdateError("signed bundles must carry a positive manifest version")
    installed = state.get("version") if state else None
    if isinstance(installed, int) and version <= installed and not allow_downgrade:
        raise UpdateError(
            f"rollback protection: bundle version {version} is not newer than installed "
            f"version {installed} (use --allow-downgrade to override)"
        )
    return version


def _activate(feed_root: Path, new_rules: Path) -> None:
    current = feed_root / "current"
    previous = feed_root / "previous"
    if previous.exists():
        shutil.rmtree(previous)
    moved = False
    if current.exists():
        os.replace(current, previous)
        moved = True
    try:
        os.replace(new_rules, current)
    except OSError as exc:
        if moved and not current.exists():
            os.replace(previous, current)
        raise UpdateError(f"cannot activate new rules: {exc.strerror or exc}") from exc


def update_feed(
    settings: Settings, feed: FeedConfig, *, allow_downgrade: bool = False
) -> UpdateResult:
    feed_root = settings.feeds_dir / feed.name
    try:
        feed_root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=feed_root))
    except OSError as exc:
        return UpdateResult(feed.name, "failed", f"cannot prepare {feed_root}: {exc}")
    try:
        bundle = staging / "bundle.zip"
        sha256 = download(feed.url, bundle, feed.max_size)
        trust = _authenticate(feed, sha256)
        state = read_feed_state(feed_root / "current")
        if state and state.get("sha256") == sha256:
            return UpdateResult(
                feed.name,
                "unchanged",
                f"already up to date ({state.get('rule_count', 0)} rules, {trust})",
            )
        rules_dir = staging / "rules"
        rules_dir.mkdir()
        files, manifest = _extract(bundle, rules_dir)
        version = _check_version(feed, manifest, state, allow_downgrade)
        try:
            rule_count, hash_count = validate_rule_files(files)
        except BundleError as exc:
            raise UpdateError(str(exc)) from exc
        if rule_count + hash_count == 0:
            raise UpdateError("bundle contains no rules; keeping the current rules")
        new_state = {
            "name": feed.name,
            "url": feed.url,
            "sha256": sha256,
            "trust": trust,
            "version": version,
            "rule_count": rule_count,
            "hash_count": hash_count,
            "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        (rules_dir / FEED_STATE_FILE).write_text(json.dumps(new_state, indent=2), encoding="utf-8")
        _activate(feed_root, rules_dir)
        detail = f"{rule_count} rules" + (f", {hash_count} hashes" if hash_count else "")
        return UpdateResult(feed.name, "updated", f"{detail} ({trust})")
    except UpdateError as exc:
        return UpdateResult(feed.name, "failed", str(exc))
    except OSError as exc:
        return UpdateResult(feed.name, "failed", exc.strerror or str(exc))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def rollback_feed(settings: Settings, name: str) -> UpdateResult:
    feed_root = settings.feeds_dir / name
    current, previous, swap = feed_root / "current", feed_root / "previous", feed_root / ".swap"
    if not previous.is_dir():
        return UpdateResult(name, "failed", "no previous version to roll back to")
    try:
        if swap.exists():
            shutil.rmtree(swap)
        if current.exists():
            os.replace(current, swap)
        os.replace(previous, current)
        if swap.exists():
            os.replace(swap, previous)
    except OSError as exc:
        return UpdateResult(name, "failed", f"rollback failed: {exc.strerror or exc}")
    state = read_feed_state(current) or {}
    return UpdateResult(
        name, "rolled-back", f"restored rules fetched at {state.get('fetched_at', 'unknown time')}"
    )


def run_freshclam(settings: Settings) -> UpdateResult:
    if settings.clamav.mode == "off":
        return UpdateResult("clamav", "skipped", "ClamAV is disabled in configuration")
    executable = find_executable("freshclam", settings.clamav.freshclam)
    if not executable:
        return UpdateResult("clamav", "skipped", "freshclam not found (ClamAV is not installed)")
    try:
        proc = subprocess.run(
            [executable],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return UpdateResult("clamav", "failed", f"cannot run freshclam: {exc}")
    if proc.returncode == 0:
        return UpdateResult("clamav", "updated", "ClamAV signature databases are up to date")
    output = (proc.stderr.strip() or proc.stdout.strip()).splitlines()[-3:]
    hint = (
        " If the freshclam service is already running it keeps signatures updated on its own; "
        "otherwise run this with administrator/root privileges."
    )
    return UpdateResult(
        "clamav", "failed", f"freshclam exited with {proc.returncode}: {' | '.join(output)}.{hint}"
    )
