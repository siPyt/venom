from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from venom.models import Detection, Severity
from venom.quarantine import MAGIC, QuarantineError, QuarantineStore, _xor

DETECTION = Detection("yara", "Venom_Test_File", Severity.LOW, "test")


@pytest.fixture
def store(tmp_path: Path) -> QuarantineStore:
    return QuarantineStore(tmp_path / "quarantine")


def make_file(path: Path, data: bytes) -> tuple[Path, str]:
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def test_xor_is_offset_aligned() -> None:
    key = os.urandom(32)
    data = os.urandom(1000)
    whole = _xor(data, key, 0)
    assert _xor(data[:37], key, 0) + _xor(data[37:], key, 37) == whole
    assert _xor(whole, key, 0) == data


def test_quarantine_and_restore_round_trip(
    store: QuarantineStore, samples: Path, marker: bytes
) -> None:
    original, sha = make_file(samples / "bad.txt", marker * 3)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])

    assert not original.exists()
    blob = store.root / f"{entry.id}.bin"
    content = blob.read_bytes()
    assert content.startswith(MAGIC)
    assert marker not in content, "quarantined copy must be neutralized"
    assert entry.sha256 == sha and entry.size == len(marker) * 3
    assert entry.summary == "Venom_Test_File"
    assert "key" not in entry.to_public_dict()
    assert [e.id for e in store.list()] == [entry.id]

    restored = store.restore(entry.id[:12])
    assert restored == original
    assert original.read_bytes() == marker * 3
    assert store.list() == []
    assert sorted(p.name for p in samples.iterdir()) == ["bad.txt"]


def test_refuses_when_file_changed_since_scan(
    store: QuarantineStore, samples: Path, marker: bytes
) -> None:
    original, _ = make_file(samples / "bad.txt", marker)
    with pytest.raises(QuarantineError, match="changed since it was scanned"):
        store.add(original, expected_sha256="0" * 64, detections=[DETECTION])
    assert original.read_bytes() == marker
    assert list(store.root.iterdir()) == []


def test_read_only_files_can_be_quarantined(
    store: QuarantineStore, samples: Path, marker: bytes
) -> None:
    original, sha = make_file(samples / "locked.txt", marker)
    os.chmod(original, stat.S_IREAD)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])
    assert not original.exists()
    store.restore(entry.id)
    assert original.read_bytes() == marker


def test_restore_never_overwrites_by_default(
    store: QuarantineStore, samples: Path, marker: bytes
) -> None:
    original, sha = make_file(samples / "bad.txt", marker)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])
    original.write_bytes(b"new legitimate file")
    with pytest.raises(QuarantineError, match="already exists"):
        store.restore(entry.id)
    assert original.read_bytes() == b"new legitimate file"
    assert store.get(entry.id)

    elsewhere = samples / "restored"
    elsewhere.mkdir()
    target = store.restore(entry.id, elsewhere)
    assert target == elsewhere / "bad.txt"
    assert target.read_bytes() == marker


def test_restore_with_overwrite(store: QuarantineStore, samples: Path, marker: bytes) -> None:
    original, sha = make_file(samples / "bad.txt", marker)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])
    original.write_bytes(b"placeholder")
    store.restore(entry.id, overwrite=True)
    assert original.read_bytes() == marker


def test_tampered_quarantine_is_not_restored(
    store: QuarantineStore, samples: Path, marker: bytes
) -> None:
    original, sha = make_file(samples / "bad.txt", marker)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])
    blob = store.root / f"{entry.id}.bin"
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0xFF
    blob.write_bytes(bytes(data))
    with pytest.raises(QuarantineError, match="integrity"):
        store.restore(entry.id)
    assert list(samples.iterdir()) == []
    assert store.get(entry.id)


def test_bad_header_is_rejected(store: QuarantineStore, samples: Path, marker: bytes) -> None:
    original, sha = make_file(samples / "bad.txt", marker)
    entry = store.add(original, expected_sha256=sha, detections=[DETECTION])
    (store.root / f"{entry.id}.bin").write_bytes(b"not a quarantine file")
    with pytest.raises(QuarantineError, match="corrupt"):
        store.restore(entry.id)
    assert list(samples.iterdir()) == []


def test_lookup_by_prefix(store: QuarantineStore, samples: Path, marker: bytes) -> None:
    ids = []
    for name in ("a.txt", "b.txt"):
        path, sha = make_file(samples / name, marker)
        ids.append(store.add(path, expected_sha256=sha, detections=[DETECTION]).id)
    common = os.path.commonprefix(ids)
    with pytest.raises(QuarantineError, match="ambiguous"):
        store.get(common)
    with pytest.raises(QuarantineError, match="no quarantined item"):
        store.get("zzz")
    assert store.get(ids[1]).original_path.endswith("b.txt")


def test_delete(store: QuarantineStore, samples: Path, marker: bytes) -> None:
    path, sha = make_file(samples / "bad.txt", marker)
    entry = store.add(path, expected_sha256=sha, detections=[DETECTION])
    assert store.delete(entry.id).id == entry.id
    assert list(store.root.iterdir()) == []


def test_corrupt_metadata_is_ignored(store: QuarantineStore) -> None:
    store.root.mkdir(parents=True)
    (store.root / "broken.json").write_text("{not json", encoding="utf-8")
    (store.root / "other.json").write_text(json.dumps({"id": "x"}), encoding="utf-8")
    assert store.list() == []


def test_symlinks_are_refused(
    store: QuarantineStore, samples: Path, marker: bytes, tmp_path: Path
) -> None:
    target, sha = make_file(samples / "real.txt", marker)
    link = samples / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted on this system")
    with pytest.raises(QuarantineError, match="not a regular file"):
        store.add(link, expected_sha256=sha, detections=[DETECTION])
    assert link.is_symlink() and target.exists()
