"""Engine interface and shared helpers."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

from venom.models import Detection, EngineInfo, Issue, Severity


class EngineError(Exception):
    pass


class EngineTimeout(EngineError):
    pass


@dataclass
class ScanObject:
    """Something to scan: a file on disk (``depth == 0``) or an archive member held in memory."""

    path: Path
    sha256: str
    size: int
    data: bytes | None = None
    member: tuple[str, ...] = ()

    @property
    def depth(self) -> int:
        return len(self.member)


@dataclass
class BatchResult:
    detections: dict[str, list[Detection]] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)


class Engine:
    name = "engine"
    scans_members = True
    """False when the engine unpacks archives itself and only needs top-level files."""
    batch = False
    """True when the engine scans all collected files at the end via :meth:`scan_batch`."""

    def info(self) -> EngineInfo:
        return EngineInfo(self.name, True)

    def scan(self, obj: ScanObject) -> list[Detection]:
        raise NotImplementedError

    def scan_batch(self, paths: list[Path], cancel: threading.Event) -> BatchResult:
        raise NotImplementedError

    def close(self) -> None:
        return None


def classify_signature(name: str) -> tuple[Severity, str]:
    """Map a ClamAV-style signature name to ``(severity, category)``."""
    lower = name.lower()
    if lower.startswith("test.") or "eicar" in lower or lower.startswith("venom.test"):
        return Severity.LOW, "test"
    if lower.startswith("pua."):
        return Severity.LOW, "pua"
    if lower.startswith("heuristics."):
        return Severity.MEDIUM, "heuristic"
    return Severity.HIGH, "malware"
