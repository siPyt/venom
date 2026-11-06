from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from helpers import ScanFn, detected, zip_bytes
from venom import updates
from venom.bundles import (
    BundleError,
    bundle_message,
    create_bundle,
    generate_keypair,
    verify_bundle,
)
from venom.config import FeedConfig, Settings
from venom.rulesets import FEED_STATE_FILE, read_feed_state
from venom.updates import UpdateError, rollback_feed, update_feed


def rule(name: str, token: str) -> bytes:
    return f'rule {name} {{ meta: score = 90 strings: $a = "{token}" condition: $a }}\n'.encode()


def feed_zip(path: Path, members: dict[str, bytes]) -> FeedConfig:
    path.write_bytes(zip_bytes(members))
    return FeedConfig(name="local", url=str(path))


def current(settings: Settings, name: str = "local") -> Path:
    return settings.feeds_dir / name / "current"


def test_unsigned_local_feed(settings: Settings, tmp_path: Path, scan: ScanFn) -> None:
    feed = feed_zip(
        tmp_path / "rules.zip",
        {
            "rules/a.yar": rule("Feed_Rule_A", "feed-token-a"),
            "rules/hashes/b.hashes": f"{'c' * 64} Win.Test.Hash\n".encode(),
            "README.md": b"ignored",
            "tools/evil.exe": b"MZ ignored",
        },
    )
    settings.feeds = [feed]
    result = update_feed(settings, feed)
    assert (result.status, result.ok) == ("updated", True), result.message
    assert "local file" in result.message

    files = sorted(p.name for p in current(settings).iterdir())
    assert files == [FEED_STATE_FILE, "00000-a.yar", "00001-b.hashes"]
    state = read_feed_state(current(settings))
    assert state is not None
    assert (state["rule_count"], state["hash_count"]) == (1, 1)

    sample = tmp_path / "scan-me" / "x.txt"
    sample.parent.mkdir()
    sample.write_bytes(b"... feed-token-a ...")
    assert detected(scan(sample.parent)) == {str(sample): {"Feed_Rule_A"}}

    assert update_feed(settings, feed).status == "unchanged"


def test_path_traversal_names_are_neutralized(settings: Settings, tmp_path: Path) -> None:
    feed = feed_zip(tmp_path / "evil.zip", {"../../escape.yar": rule("Esc", "esc-token")})
    assert update_feed(settings, feed).status == "updated"
    assert (current(settings) / "00000-escape.yar").is_file()
    assert not (settings.feeds_dir / "escape.yar").exists()
    assert not (tmp_path / "escape.yar").exists()


def test_invalid_rules_keep_current_version(settings: Settings, tmp_path: Path) -> None:
    feed = feed_zip(tmp_path / "rules.zip", {"a.yar": rule("Good", "good-token")})
    assert update_feed(settings, feed).status == "updated"
    before = read_feed_state(current(settings))

    feed_zip(tmp_path / "rules.zip", {"a.yar": b"rule Broken { condition: nope }"})
    result = update_feed(settings, feed)
    assert result.status == "failed"
    assert "compile" in result.message
    assert read_feed_state(current(settings)) == before
    assert not list((settings.feeds_dir / "local").glob(".staging-*"))


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ({"README.md": b"no rules here"}, "no rules"),
        ({"a.yar": b"// only a comment\n"}, "no rules"),
        ({"bad.hashes": b"zzzz Name\n"}, "SHA-256"),
    ],
)
def test_bundles_without_valid_rules_fail(
    settings: Settings, tmp_path: Path, members: dict[str, bytes], message: str
) -> None:
    feed = feed_zip(tmp_path / "rules.zip", members)
    result = update_feed(settings, feed)
    assert result.status == "failed"
    assert message in result.message
    assert not current(settings).exists()


def test_corrupt_bundle_fails_cleanly(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "rules.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    result = update_feed(settings, FeedConfig(name="local", url=str(path)))
    assert result.status == "failed"


def test_sha256_pinning(settings: Settings, tmp_path: Path) -> None:
    feed = feed_zip(tmp_path / "rules.zip", {"a.yar": rule("Pinned", "pin")})
    digest = hashlib.sha256((tmp_path / "rules.zip").read_bytes()).hexdigest()

    feed.sha256 = "0" * 64
    result = update_feed(settings, feed)
    assert result.status == "failed" and "mismatch" in result.message

    feed.sha256 = digest.upper()
    result = update_feed(settings, feed)
    assert result.status == "updated" and "SHA-256 pinned" in result.message


def test_download_size_limit(settings: Settings, tmp_path: Path) -> None:
    feed = feed_zip(tmp_path / "rules.zip", {"a.yar": rule("Big", "big")})
    feed.max_size = 10
    result = update_feed(settings, feed)
    assert result.status == "failed" and "limit" in result.message


@pytest.mark.parametrize(
    "url", ["http://example.org/rules.zip", "ftp://example.org/rules.zip", "data:,x"]
)
def test_insecure_urls_are_refused(settings: Settings, url: str) -> None:
    result = update_feed(settings, FeedConfig(name="remote", url=url))
    assert result.status == "failed"
    assert "refusing" in result.message


def test_redirects_to_http_are_refused() -> None:
    handler = updates._HTTPSOnlyRedirects()
    request = updates.urllib.request.Request("https://example.org/rules.zip")
    with pytest.raises(UpdateError, match="non-HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://evil.example/x.zip")


# ----------------------------------------------------------- signed bundles


@pytest.fixture
def signing(tmp_path: Path) -> tuple[Path, str]:
    return generate_keypair(tmp_path / "keys")


def make_signed(
    tmp_path: Path, key: Path, version: int, token: str, name: str = "bundle.zip"
) -> Path:
    rules_dir = tmp_path / f"src-{version}-{token}"
    rules_dir.mkdir()
    (rules_dir / "signed.yar").write_bytes(rule("Signed_Rule", token))
    out = tmp_path / "publish" / name
    create_bundle(rules_dir, out, version, key)
    return out


def test_signed_bundle_lifecycle(
    settings: Settings, tmp_path: Path, signing: tuple[Path, str]
) -> None:
    key, public = signing
    bundle = make_signed(tmp_path, key, 1, "v1")
    feed = FeedConfig(name="signed", url=str(bundle), public_key=public)

    result = update_feed(settings, feed)
    assert result.status == "updated", result.message
    assert "signature verified" in result.message
    assert read_feed_state(current(settings, "signed"))["version"] == 1

    bundle.unlink()
    (tmp_path / "publish" / "bundle.zip.sig").unlink()
    make_signed(tmp_path, key, 1, "v1-replayed")
    result = update_feed(settings, feed)
    assert result.status == "failed" and "rollback protection" in result.message
    assert update_feed(settings, feed, allow_downgrade=True).status == "updated"

    bundle.unlink()
    (tmp_path / "publish" / "bundle.zip.sig").unlink()
    make_signed(tmp_path, key, 2, "v2")
    assert update_feed(settings, feed).status == "updated"
    assert read_feed_state(current(settings, "signed"))["version"] == 2


def test_tampered_bundle_is_rejected(
    settings: Settings, tmp_path: Path, signing: tuple[Path, str]
) -> None:
    key, public = signing
    bundle = make_signed(tmp_path, key, 1, "orig")
    with open(bundle, "ab") as fh:
        fh.write(b"tampered")
    result = update_feed(settings, FeedConfig(name="signed", url=str(bundle), public_key=public))
    assert result.status == "failed" and "signature verification failed" in result.message
    assert not current(settings, "signed").exists()


def test_wrong_key_is_rejected(
    settings: Settings, tmp_path: Path, signing: tuple[Path, str]
) -> None:
    key, _ = signing
    _, other_public = generate_keypair(tmp_path / "other-keys")
    bundle = make_signed(tmp_path, key, 1, "x")
    feed = FeedConfig(name="signed", url=str(bundle), public_key=other_public)
    assert update_feed(settings, feed).status == "failed"


def test_missing_signature_is_rejected(
    settings: Settings, tmp_path: Path, signing: tuple[Path, str]
) -> None:
    _, public = signing
    feed = feed_zip(tmp_path / "unsigned.zip", {"a.yar": rule("Unsigned", "u")})
    feed.public_key = public
    result = update_feed(settings, feed)
    assert result.status == "failed"
    assert not current(settings).exists()


def test_signed_bundle_requires_manifest_version(
    settings: Settings, tmp_path: Path, signing: tuple[Path, str]
) -> None:
    key, public = signing
    path = tmp_path / "manual.zip"
    path.write_bytes(
        zip_bytes({"manifest.json": json.dumps({}).encode(), "a.yar": rule("NoVer", "nv")})
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    from venom.bundles import _load_private_key

    signature = _load_private_key(key).sign(bundle_message(digest))
    path.with_name("manual.zip.sig").write_bytes(base64.b64encode(signature))
    result = update_feed(settings, FeedConfig(name="signed", url=str(path), public_key=public))
    assert result.status == "failed" and "manifest version" in result.message


def test_verify_bundle_accepts_raw_and_base64(signing: tuple[Path, str]) -> None:
    key, public = signing
    from venom.bundles import _load_private_key

    digest = "ab" * 32
    raw = _load_private_key(key).sign(bundle_message(digest))
    verify_bundle(public, digest, raw)
    verify_bundle(public, digest, base64.b64encode(raw) + b"\n")
    with pytest.raises(BundleError):
        verify_bundle(public, "cd" * 32, raw)
    with pytest.raises(BundleError):
        verify_bundle("not-base64!", digest, raw)


def test_keygen_refuses_to_overwrite(tmp_path: Path, signing: tuple[Path, str]) -> None:
    with pytest.raises(BundleError, match="refusing to overwrite"):
        generate_keypair(tmp_path / "keys")


def test_encrypted_signing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENOM_KEY_PASSPHRASE", "correct horse")
    key, _ = generate_keypair(tmp_path / "enc")
    assert b"ENCRYPTED" in key.read_bytes()
    make_signed(tmp_path, key, 1, "enc")
    monkeypatch.delenv("VENOM_KEY_PASSPHRASE")
    with pytest.raises(BundleError, match="cannot load private key"):
        make_signed(tmp_path, key, 2, "enc2", name="second.zip")


def test_create_bundle_validates_rules(tmp_path: Path, signing: tuple[Path, str]) -> None:
    key, _ = signing
    rules_dir = tmp_path / "bad-rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_bytes(b"rule Bad { condition: nope }")
    with pytest.raises(BundleError, match="failed to compile"):
        create_bundle(rules_dir, tmp_path / "out.zip", 1, key)
    with pytest.raises(BundleError, match="positive"):
        create_bundle(rules_dir, tmp_path / "out.zip", 0, key)


# ---------------------------------------------------------------- rollback


def test_rollback_swaps_versions(settings: Settings, tmp_path: Path) -> None:
    feed = feed_zip(tmp_path / "rules.zip", {"a.yar": rule("First", "one")})
    update_feed(settings, feed)
    feed_zip(tmp_path / "rules.zip", {"a.yar": rule("Second", "two")})
    update_feed(settings, feed)
    assert b"Second" in (current(settings) / "00000-a.yar").read_bytes()

    assert rollback_feed(settings, "local").status == "rolled-back"
    assert b"First" in (current(settings) / "00000-a.yar").read_bytes()
    assert rollback_feed(settings, "local").status == "rolled-back"
    assert b"Second" in (current(settings) / "00000-a.yar").read_bytes()


def test_rollback_without_previous(settings: Settings) -> None:
    result = rollback_feed(settings, "never-installed")
    assert result.status == "failed"
