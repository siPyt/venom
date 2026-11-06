"""Plain helpers shared by the test modules (fixtures live in conftest.py)."""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from venom.models import ScanReport
from venom.selftest import TEST_RULE

ScanFn = Callable[..., ScanReport]

__all__ = ["TEST_RULE", "ScanFn", "detected", "tar_bytes", "zip_bytes", "write_zip"]


def zip_bytes(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def write_zip(path: Path, members: dict[str, bytes]) -> Path:
    path.write_bytes(zip_bytes(members))
    return path


def tar_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def detected(report: ScanReport) -> dict[str, set[str]]:
    """Map each finding location to the set of detection names."""
    return {f.location: {d.name for d in f.detections} for f in report.findings}
