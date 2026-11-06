from __future__ import annotations

import bz2
import gzip
import io
import lzma

import pytest

from helpers import tar_bytes, zip_bytes
from venom import archives
from venom.archives import Budget, Member, Problem, decompressed_name, iter_archive, sniff
from venom.config import Limits, MiB
from venom.models import IssueKind


def run(kind: str, data: bytes, limits: Limits | None = None, name: str = "x") -> list:
    limits = limits or Limits()
    return list(iter_archive(kind, io.BytesIO(data), name, limits, Budget.from_limits(limits)))


def set_encrypted_flag(data: bytes) -> bytes:
    """Mark every entry as encrypted in both the local and central directory headers."""
    buf = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (index := buf.find(signature, start)) != -1:
            buf[index + flag_offset] |= 0x01
            start = index + 4
    return bytes(buf)


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (zip_bytes({"a": b"1"}), "zip"),
        (gzip.compress(b"x"), "gzip"),
        (bz2.compress(b"x"), "bzip2"),
        (lzma.compress(b"x"), "xz"),
        (tar_bytes({"a": b"1"}), "tar"),
        (b"MZ\x90\x00 plain executable header", None),
        (b"BZh", None),
        (b"", None),
    ],
)
def test_sniff(data: bytes, kind: str | None) -> None:
    assert sniff(data[:512]) == kind


def test_read_bounded() -> None:
    assert archives.read_bounded(io.BytesIO(b"abcd"), 4) == b"abcd"
    assert archives.read_bounded(io.BytesIO(b"abcde"), 4) is None
    assert archives.read_bounded(io.BytesIO(b""), 0) == b""


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("pkg.tar.gz", "pkg.tar"),
        ("pkg.tgz", "pkg.tar"),
        ("PKG.TBZ2", "PKG.tar"),
        ("notes.txt.xz", "notes.txt"),
        ("dir/sub/file.bz2", "file"),
        (".gz", ".gz.decompressed"),
        ("blob", "blob.decompressed"),
    ],
)
def test_decompressed_name(name: str, expected: str) -> None:
    assert decompressed_name(name) == expected


def test_zip_members() -> None:
    items = run("zip", zip_bytes({"a.txt": b"alpha", "dir/b.txt": b"beta"}))
    assert [(m.name, m.data) for m in items] == [("a.txt", b"alpha"), ("dir/b.txt", b"beta")]


def test_tar_members_skip_non_regular() -> None:
    items = run("tar", tar_bytes({"a.txt": b"alpha"}))
    assert [(m.name, m.data) for m in items] == [("a.txt", b"alpha")]


def test_compressed_stream_becomes_one_member() -> None:
    (item,) = run("gzip", gzip.compress(b"payload"), name="report.txt.gz")
    assert isinstance(item, Member)
    assert (item.name, item.data) == ("report.txt", b"payload")


def test_member_count_limit_stops_with_issue() -> None:
    limits = Limits(max_archive_members=2)
    items = run("zip", zip_bytes({f"f{i}": b"x" for i in range(5)}), limits)
    assert [type(i) for i in items] == [Member, Member, Problem]
    assert items[-1].kind is IssueKind.ARCHIVE_LIMIT
    assert items[-1].name is None


def test_member_size_limit_skips_only_that_member() -> None:
    limits = Limits(max_member_size=10)
    items = run("zip", zip_bytes({"big": b"x" * 100, "small": b"ok"}), limits)
    assert isinstance(items[0], Problem) and items[0].name == "big"
    assert isinstance(items[1], Member) and items[1].name == "small"


def test_total_bytes_budget_is_shared() -> None:
    limits = Limits(max_archive_total=150, max_member_size=MiB)
    items = run("zip", zip_bytes({"a": b"x" * 100, "b": b"y" * 100, "c": b"z"}), limits)
    kinds = [(type(i).__name__, i.name) for i in items]
    assert kinds[0] == ("Member", "a")
    assert kinds[1] == ("Problem", "b")
    assert any(isinstance(i, Problem) and i.kind is IssueKind.ARCHIVE_LIMIT for i in items)


def test_compression_ratio_bomb_is_refused() -> None:
    items = run("zip", zip_bytes({"zeros": b"\0" * (4 * MiB)}))
    (problem,) = items
    assert isinstance(problem, Problem)
    assert problem.kind is IssueKind.ARCHIVE_LIMIT
    assert "decompression bomb" in problem.message


def test_compressed_stream_bomb_is_bounded() -> None:
    limits = Limits(max_member_size=MiB)
    (problem,) = run("gzip", gzip.compress(b"\0" * (3 * MiB)), limits, "bomb.gz")
    assert isinstance(problem, Problem)
    assert problem.kind is IssueKind.ARCHIVE_LIMIT


def test_encrypted_member_is_reported() -> None:
    data = set_encrypted_flag(zip_bytes({"secret.txt": b"hidden"}))
    (problem,) = run("zip", data)
    assert isinstance(problem, Problem)
    assert problem.kind is IssueKind.ENCRYPTED
    assert problem.name == "secret.txt"


@pytest.mark.parametrize("kind", ["zip", "gzip", "tar", "xz", "bzip2"])
def test_corrupt_archives_become_issues(kind: str) -> None:
    items = run(kind, b"PK\x03\x04" + b"\xff" * 600 if kind == "zip" else b"\xff" * 600)
    assert items
    assert all(isinstance(i, Problem) for i in items)
    assert items[-1].kind is IssueKind.ARCHIVE_ERROR
