from __future__ import annotations

import gzip
import hashlib
import os
import threading
from pathlib import Path

import pytest

from helpers import TEST_RULE, ScanFn, detected, tar_bytes, write_zip, zip_bytes
from venom import scanner as scanner_mod
from venom.config import Settings
from venom.engines.base import BatchResult, Engine, ScanObject
from venom.models import Detection, IssueKind, Severity
from venom.runtime import build_runtime
from venom.scanner import Scanner


def can_symlink(tmp_path: Path) -> bool:
    try:
        (tmp_path / "probe-link").symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        return False
    (tmp_path / "probe-link").unlink()
    return True


def test_detects_marker_and_ignores_clean(scan: ScanFn, samples: Path, marker: bytes) -> None:
    (samples / "bad.txt").write_bytes(marker + b"\n")
    (samples / "good.txt").write_bytes(b"hello")
    report = scan(samples)
    assert detected(report) == {str(samples / "bad.txt"): {TEST_RULE}}
    assert report.complete
    assert report.stats.files_scanned == 2
    finding = report.findings[0]
    assert finding.sha256 == hashlib.sha256(marker + b"\n").hexdigest()
    assert finding.severity is Severity.LOW


def test_marker_must_be_at_offset_zero(scan: ScanFn, samples: Path, marker: bytes) -> None:
    (samples / "quoted.txt").write_bytes(b"docs mention " + marker)
    assert scan(samples).findings == []


def test_nested_zip_member(scan: ScanFn, samples: Path, marker: bytes) -> None:
    inner = zip_bytes({"payload.txt": marker})
    outer = write_zip(samples / "outer.zip", {"inner.zip": inner, "readme.txt": b"hi"})
    report = scan(samples)
    (finding,) = report.findings
    assert finding.path == str(outer)
    assert finding.member == ("inner.zip", "payload.txt")
    assert finding.sha256 == hashlib.sha256(outer.read_bytes()).hexdigest()
    assert finding.member_sha256 == hashlib.sha256(marker).hexdigest()
    assert report.stats.members_scanned == 3
    assert report.complete


def test_tar_gz_member(scan: ScanFn, samples: Path, marker: bytes) -> None:
    (samples / "pkg.tar.gz").write_bytes(gzip.compress(tar_bytes({"pkg/run.sh": marker})))
    (finding,) = scan(samples).findings
    assert finding.member == ("pkg.tar", "pkg/run.sh")


def test_archive_depth_limit_is_reported(
    scan: ScanFn, settings: Settings, samples: Path, marker: bytes
) -> None:
    settings.limits.max_archive_depth = 1
    write_zip(samples / "outer.zip", {"inner.zip": zip_bytes({"payload.txt": marker})})
    report = scan(samples)
    assert report.findings == []
    (issue,) = report.issues
    assert issue.kind is IssueKind.ARCHIVE_LIMIT
    assert issue.member == ("inner.zip",)
    assert not report.complete


def test_archive_scanning_can_be_disabled(
    scan: ScanFn, settings: Settings, samples: Path, marker: bytes
) -> None:
    settings.scan_archives = False
    write_zip(samples / "a.zip", {"payload.txt": marker})
    report = scan(samples)
    assert report.findings == []
    assert report.stats.members_scanned == 0


def test_exclusions_apply_to_discovered_entries_only(
    scan: ScanFn, settings: Settings, samples: Path, marker: bytes
) -> None:
    settings.exclude = ["*.txt", "*/skipdir"]
    (samples / "bad.txt").write_bytes(marker)
    (samples / "skipdir").mkdir()
    (samples / "skipdir" / "bad.bin").write_bytes(marker)
    report = scan(samples)
    assert report.findings == []
    assert report.stats.excluded == 2
    assert detected(scan(samples / "bad.txt")) == {str(samples / "bad.txt"): {TEST_RULE}}


def test_own_data_and_rules_dirs_are_never_scanned(
    scan: ScanFn, settings: Settings, tmp_path: Path, marker: bytes
) -> None:
    settings.rules_dir = tmp_path / "custom-rules"
    for directory in (settings.data_dir / "feeds", settings.rules_dir):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sig.bin").write_bytes(marker)
    (tmp_path / "real.bin").write_bytes(marker)
    assert set(detected(scan(tmp_path))) == {str(tmp_path / "real.bin")}


def test_own_dirs_are_skipped_through_symlinked_roots(
    scan: ScanFn, settings: Settings, tmp_path: Path, marker: bytes
) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks are not permitted on this system")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "sig.bin").write_bytes(marker)
    alias = tmp_path.parent / f"{tmp_path.name}-alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    try:
        assert detected(scan(alias)) == {}
    finally:
        alias.unlink()


def test_missing_path_is_incomplete(scan: ScanFn, tmp_path: Path) -> None:
    report = scan(tmp_path / "does-not-exist")
    (issue,) = report.issues
    assert issue.kind is IssueKind.NOT_FOUND
    assert not report.complete


def test_too_large_file_is_reported(
    scan: ScanFn, settings: Settings, samples: Path, marker: bytes
) -> None:
    settings.limits.max_file_size = 8
    (samples / "big.bin").write_bytes(marker)
    report = scan(samples)
    assert report.findings == []
    assert [i.kind for i in report.issues] == [IssueKind.TOO_LARGE]


def test_streaming_path_for_large_files(
    scan: ScanFn, samples: Path, marker: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scanner_mod, "IN_MEMORY_LIMIT", 16)
    plain = samples / "plain.bin"
    plain.write_bytes(marker + b"\0" * 100)
    archive = write_zip(samples / "big.zip", {"inner/payload.txt": marker})
    report = scan(samples)
    found = detected(report)
    assert found[str(plain)] == {TEST_RULE}
    assert found[f"{archive} > inner/payload.txt"] == {TEST_RULE}
    by_path = {f.path: f for f in report.findings}
    assert by_path[str(plain)].sha256 == hashlib.sha256(plain.read_bytes()).hexdigest()


def test_symlinks_are_not_followed_by_default(
    scan: ScanFn, settings: Settings, tmp_path: Path, samples: Path, marker: bytes
) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks are not permitted on this system")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "bad.bin").write_bytes(marker)
    (samples / "file-link").symlink_to(outside / "bad.bin")
    (samples / "dir-link").symlink_to(outside, target_is_directory=True)
    report = scan(samples)
    assert report.findings == []
    assert report.stats.links_skipped == 2

    settings.follow_symlinks = True
    (samples / "dir-link" / "loop").symlink_to(samples, target_is_directory=True)
    report = scan(samples)
    assert len(report.findings) == 2
    assert report.complete


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_fifo_does_not_hang(scan: ScanFn, samples: Path) -> None:
    os.mkfifo(samples / "pipe")
    (samples / "ok.txt").write_bytes(b"ok")
    report = scan(samples)
    assert report.stats.special_skipped == 1
    assert report.complete


def test_cancelled_scan(scan: ScanFn, samples: Path, marker: bytes) -> None:
    (samples / "bad.txt").write_bytes(marker)
    cancel = threading.Event()
    cancel.set()
    report = scan(samples, cancel=cancel)
    assert report.cancelled
    assert not report.complete


class ExplodingEngine(Engine):
    name = "boom"

    def scan(self, obj: ScanObject) -> list[Detection]:
        raise RuntimeError("engine bug")


class FakeBatchEngine(Engine):
    name = "batchy"
    batch = True
    scans_members = False

    def __init__(self) -> None:
        self.seen: list[Path] = []

    def scan_batch(self, paths: list[Path], cancel: threading.Event) -> BatchResult:
        self.seen = list(paths)
        hits = {str(p): [Detection(self.name, "Batch.Hit", Severity.HIGH)] for p in paths}
        return BatchResult(detections=hits)


def test_engine_failures_are_isolated(settings: Settings, samples: Path, marker: bytes) -> None:
    (samples / "bad.txt").write_bytes(marker)
    runtime = build_runtime(settings, use_clamav=False, use_cache=False)
    report = Scanner(settings, [ExplodingEngine(), *runtime.engines]).scan([samples])
    assert detected(report) == {str(samples / "bad.txt"): {TEST_RULE}}
    (issue,) = report.issues
    assert issue.kind is IssueKind.ENGINE_ERROR
    assert issue.engine == "boom"


def test_batch_engine_results_merge_into_findings(
    settings: Settings, samples: Path, marker: bytes
) -> None:
    bad = samples / "bad.txt"
    bad.write_bytes(marker)
    (samples / "zip.zip").write_bytes(zip_bytes({"x": b"x"}))
    runtime = build_runtime(settings, use_clamav=False, use_cache=False)
    batch = FakeBatchEngine()
    report = Scanner(settings, [*runtime.engines, batch]).scan([samples])
    assert sorted(p.name for p in batch.seen) == ["bad.txt", "zip.zip"]
    by_path = {f.location: f for f in report.findings}
    assert {d.name for d in by_path[str(bad)].detections} == {TEST_RULE, "Batch.Hit"}
    assert by_path[str(samples / "zip.zip")].sha256 is not None
    assert by_path[str(bad)].severity is Severity.HIGH
    assert report.findings[0].severity is Severity.HIGH


def test_report_json_shape(scan: ScanFn, samples: Path, marker: bytes) -> None:
    (samples / "bad.txt").write_bytes(marker)
    data = scan(samples).to_dict()
    assert data["schema"] == 1
    assert data["complete"] is True
    assert data["findings"][0]["detections"][0]["name"] == TEST_RULE
    assert data["findings"][0]["severity"] == "low"
    assert {e["name"] for e in data["engines"]} == {"hash", "yara", "clamav"}
