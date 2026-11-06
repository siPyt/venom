"""In-memory, resource-bounded inspection of archive and compressed files.

Nothing is ever extracted to disk. Every member is read with a hard byte cap, so
decompression bombs and lying size headers cannot exhaust memory.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

from venom.config import Limits, format_size
from venom.models import IssueKind

_CHUNK = 1024 * 1024
_RATIO_MIN_SIZE = 1024 * 1024
_ARCHIVE_ERRORS = (
    zipfile.BadZipFile,
    tarfile.TarError,
    zlib.error,
    lzma.LZMAError,
    EOFError,
    OSError,
    NotImplementedError,
    RuntimeError,
    ValueError,
)


@dataclass
class Member:
    name: str
    data: bytes


@dataclass
class Problem:
    kind: IssueKind
    message: str
    name: str | None = None


@dataclass
class Budget:
    """Per top-level file allowance shared by all nested archives."""

    members: int
    total_bytes: int

    @classmethod
    def from_limits(cls, limits: Limits) -> Budget:
        return cls(limits.max_archive_members, limits.max_archive_total)


def sniff(head: bytes) -> str | None:
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 3 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def read_bounded(stream: BinaryIO, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes; return ``None`` if the stream holds more."""
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = stream.read(min(_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return None if len(data) > limit else data


_SUFFIX_REPLACEMENTS = {
    ".tgz": ".tar",
    ".gz": "",
    ".tbz2": ".tar",
    ".tbz": ".tar",
    ".bz2": "",
    ".txz": ".tar",
    ".xz": "",
}


def decompressed_name(container: str) -> str:
    base = os.path.basename(container.replace("\\", "/").rstrip("/")) or "data"
    lower = base.lower()
    for suffix, replacement in _SUFFIX_REPLACEMENTS.items():
        if lower.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)] + replacement
    return base + ".decompressed"


def iter_archive(
    kind: str, stream: BinaryIO, container_name: str, limits: Limits, budget: Budget
) -> Iterator[Member | Problem]:
    try:
        if kind == "zip":
            yield from _iter_zip(stream, limits, budget)
        elif kind == "tar":
            yield from _iter_tar(stream, limits, budget)
        else:
            yield from _iter_compressed(kind, stream, container_name, limits, budget)
    except _ARCHIVE_ERRORS as exc:
        yield Problem(IssueKind.ARCHIVE_ERROR, f"cannot read {kind} archive: {exc}")


def _take(budget: Budget, limits: Limits, name: str, declared_size: int | None) -> Problem | int:
    """Reserve a member slot and return the byte allowance, or a Problem."""
    if budget.members <= 0:
        return Problem(
            IssueKind.ARCHIVE_LIMIT,
            f"member limit ({limits.max_archive_members}) reached; remaining members not scanned",
        )
    if budget.total_bytes <= 0:
        return Problem(
            IssueKind.ARCHIVE_LIMIT,
            f"total decompressed size limit ({format_size(limits.max_archive_total)}) reached; "
            "remaining members not scanned",
        )
    budget.members -= 1
    allowance = min(limits.max_member_size, budget.total_bytes)
    if declared_size is not None and declared_size > allowance:
        return Problem(
            IssueKind.ARCHIVE_LIMIT,
            f"member size {format_size(declared_size)} exceeds remaining limit "
            f"{format_size(allowance)}",
            name,
        )
    return allowance


def _read_member(stream: BinaryIO, name: str, allowance: int, budget: Budget) -> Member | Problem:
    data = read_bounded(stream, allowance)
    if data is None:
        return Problem(
            IssueKind.ARCHIVE_LIMIT,
            f"decompressed size exceeds limit {format_size(allowance)}",
            name,
        )
    budget.total_bytes -= len(data)
    return Member(name, data)


def _iter_zip(stream: BinaryIO, limits: Limits, budget: Budget) -> Iterator[Member | Problem]:
    with zipfile.ZipFile(stream) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            taken = _take(budget, limits, name, info.file_size)
            if isinstance(taken, Problem):
                yield taken
                if taken.name is None:
                    return
                continue
            if info.flag_bits & 0x1:
                yield Problem(IssueKind.ENCRYPTED, "encrypted archive member", name)
                continue
            if (
                limits.max_compression_ratio
                and info.file_size > _RATIO_MIN_SIZE
                and info.file_size > info.compress_size * limits.max_compression_ratio
            ):
                yield Problem(
                    IssueKind.ARCHIVE_LIMIT,
                    f"compression ratio exceeds {limits.max_compression_ratio}:1 "
                    "(possible decompression bomb)",
                    name,
                )
                continue
            try:
                with archive.open(info) as member:
                    yield _read_member(member, name, taken, budget)
            except _ARCHIVE_ERRORS as exc:
                yield Problem(IssueKind.ARCHIVE_ERROR, f"cannot read member: {exc}", name)


def _iter_tar(stream: BinaryIO, limits: Limits, budget: Budget) -> Iterator[Member | Problem]:
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for info in archive:
            if not info.isreg():
                continue
            taken = _take(budget, limits, info.name, info.size)
            if isinstance(taken, Problem):
                yield taken
                if taken.name is None:
                    return
                continue
            member = archive.extractfile(info)
            if member is None:
                continue
            with member:
                yield _read_member(member, info.name, taken, budget)


_DECOMPRESSORS: dict[str, Callable[[BinaryIO], BinaryIO]] = {
    # GzipFile's first positional parameter is a filename, so pass the stream by keyword.
    "gzip": lambda stream: gzip.GzipFile(fileobj=stream, mode="rb"),
    "bzip2": lambda stream: bz2.BZ2File(stream, mode="rb"),
    "xz": lambda stream: lzma.LZMAFile(stream, mode="rb"),
}


def _iter_compressed(
    kind: str, stream: BinaryIO, container: str, limits: Limits, budget: Budget
) -> Iterator[Member | Problem]:
    opener = _DECOMPRESSORS[kind]
    name = decompressed_name(container)
    taken = _take(budget, limits, name, None)
    if isinstance(taken, Problem):
        yield taken
        return
    with opener(stream) as decompressed:
        yield _read_member(decompressed, name, taken, budget)
