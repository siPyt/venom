"""Data types shared by the scanner, engines, and reporting."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: object, default: Severity | None = None) -> Severity | None:
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                return default
        return default


class IssueKind(enum.StrEnum):
    """Reasons an object could not be scanned completely."""

    UNREADABLE = "unreadable"
    TOO_LARGE = "too_large"
    ARCHIVE_LIMIT = "archive_limit"
    ARCHIVE_ERROR = "archive_error"
    ENCRYPTED = "encrypted"
    ENGINE_ERROR = "engine_error"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class Detection:
    engine: str
    name: str
    severity: Severity
    category: str = "malware"
    description: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "name": self.name,
            "severity": str(self.severity),
            "category": self.category,
            "description": self.description,
            "source": self.source,
        }


@dataclass
class Finding:
    """Detections for one object: a file on disk, or a member inside an archive file."""

    path: str
    sha256: str | None
    detections: list[Detection]
    member: tuple[str, ...] = ()
    member_sha256: str | None = None

    @property
    def severity(self) -> Severity:
        return max((d.severity for d in self.detections), default=Severity.INFO)

    @property
    def location(self) -> str:
        return " > ".join((self.path, *self.member))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "member": list(self.member),
            "location": self.location,
            "severity": str(self.severity),
            "sha256": self.sha256,
            "member_sha256": self.member_sha256,
            "detections": [d.to_dict() for d in self.detections],
        }


@dataclass(frozen=True)
class Issue:
    path: str
    kind: IssueKind
    message: str
    member: tuple[str, ...] = ()
    engine: str | None = None

    @property
    def location(self) -> str:
        return " > ".join((self.path, *self.member))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "member": list(self.member),
            "location": self.location,
            "kind": str(self.kind),
            "message": self.message,
            "engine": self.engine,
        }


@dataclass
class EngineInfo:
    name: str
    available: bool
    version: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "version": self.version,
            "detail": self.detail,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    bytes_scanned: int = 0
    members_scanned: int = 0
    excluded: int = 0
    links_skipped: int = 0
    special_skipped: int = 0
    offline_skipped: int = 0
    vanished: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass
class ScanReport:
    targets: list[str]
    started_at: str
    engines: list[EngineInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    finished_at: str | None = None
    duration_seconds: float = 0.0
    cancelled: bool = False

    @property
    def complete(self) -> bool:
        return not self.cancelled and not self.issues

    def to_dict(self) -> dict[str, Any]:
        from venom import __version__

        return {
            "schema": 1,
            "venom_version": __version__,
            "targets": self.targets,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "cancelled": self.cancelled,
            "complete": self.complete,
            "engines": [e.to_dict() for e in self.engines],
            "findings": [f.to_dict() for f in self.findings],
            "issues": [i.to_dict() for i in self.issues],
            "notices": self.notices,
            "stats": self.stats.to_dict(),
        }
