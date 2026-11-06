"""End-to-end self-test using the harmless Venom test signature."""

from __future__ import annotations

import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from venom.config import Settings
from venom.quarantine import QuarantineError, QuarantineStore
from venom.runtime import build_runtime
from venom.scanner import Scanner

TEST_RULE = "Venom_Test_File"


def make_test_marker() -> bytes:
    # Built from parts so this source file never matches the test signature itself.
    return "-".join(["VENOM", "ANTIVIRUS", "TEST", "FILE"]).encode("ascii")


def run_selftest(settings: Settings, emit: Callable[[str], None]) -> bool:
    results: list[bool] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        results.append(ok)
        emit(
            f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail and not ok else "")
        )

    with tempfile.TemporaryDirectory(prefix="venom-selftest-") as tmp:
        root = Path(tmp)
        samples = root / "samples"
        samples.mkdir()
        marker = make_test_marker()
        sample = samples / "venom-test-file.txt"
        sample.write_bytes(marker + b"\n")
        archive = samples / "venom-test-archive.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("nested/venom-test-file.txt", marker)
        (samples / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")

        emit("Engines:")
        runtime = build_runtime(settings, use_clamav=True)
        for info in runtime.infos:
            state = "available" if info.available else "not available"
            version = info.version or "-"
            emit(f"  {info.name:<7} {state:<14} {version:<8} {info.detail}".rstrip())
        emit("Checks:")

        scan_settings = replace(settings, exclude=[], scan_archives=True)
        report = Scanner(scan_settings, runtime.engines, runtime.infos).scan([samples])
        by_location = {f.location: {d.name for d in f.detections} for f in report.findings}
        check("detects test file on disk", TEST_RULE in by_location.get(str(sample), set()))
        member = f"{archive} > nested/venom-test-file.txt"
        check("detects test file inside a zip archive", TEST_RULE in by_location.get(member, set()))
        check(
            "does not flag a clean file",
            str(samples / "clean.txt") not in by_location,
        )
        check(
            "scan completed without errors",
            report.complete,
            "; ".join(f"{i.location}: {i.message}" for i in report.issues),
        )

        store = QuarantineStore(root / "quarantine")
        finding = next((f for f in report.findings if f.path == str(sample) and not f.member), None)
        if finding is None:
            check("quarantine and restore", False, "test file was not detected")
        else:
            try:
                entry = store.add(
                    sample, expected_sha256=finding.sha256, detections=finding.detections
                )
                blob = (root / "quarantine" / f"{entry.id}.bin").read_bytes()
                check("quarantine removes the original", not sample.exists())
                check("quarantined copy is neutralized", marker not in blob)
                restored = store.restore(entry.id)
                check(
                    "restore recreates the verified original",
                    restored.read_bytes() == marker + b"\n",
                )
                check("restore clears the quarantine entry", not store.list())
            except QuarantineError as exc:
                check("quarantine and restore", False, str(exc))
        runtime.close()

    passed = all(results)
    emit(f"Self-test {'passed' if passed else 'FAILED'} ({sum(results)}/{len(results)} checks).")
    return passed
