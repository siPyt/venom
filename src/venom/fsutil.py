"""Filesystem helpers that keep scanning safe across Windows, macOS, and Linux."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from pathlib import Path
from typing import BinaryIO

IS_WINDOWS = os.name == "nt"

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_OFFLINE = 0x1000
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
_IO_REPARSE_TAG_SYMLINK = 0xA000000C
_SF_DATALESS = 0x40000000  # macOS: iCloud/File Provider placeholder

_OFFLINE_ATTRIBUTES = (
    _FILE_ATTRIBUTE_OFFLINE | _FILE_ATTRIBUTE_RECALL_ON_OPEN | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)


class NotRegularFile(OSError):
    pass


def open_regular(
    path: str | os.PathLike[str], *, follow_symlinks: bool
) -> tuple[BinaryIO, os.stat_result]:
    """Open a regular file for reading without hanging on FIFOs or devices.

    The type check happens on the opened descriptor, so a path swapped for a FIFO
    or device after directory enumeration is still refused.
    """
    nonblock = getattr(os, "O_NONBLOCK", 0)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nonblock
    if not follow_symlinks:
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if IS_WINDOWS and is_link_path(path):
            raise NotRegularFile(f"refusing to follow link: {path}")
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if not follow_symlinks and exc.errno == errno.ELOOP:
            raise NotRegularFile(f"refusing to follow link: {path}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotRegularFile(f"not a regular file: {path}")
        # On Windows, set_blocking only supports pipes and fails on regular files.
        if nonblock:
            os.set_blocking(fd, True)
        return os.fdopen(fd, "rb"), st
    except BaseException:
        os.close(fd)
        raise


def _is_link_stat(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    if IS_WINDOWS and getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        # Cloud-file and dedup reparse points are ordinary files; only name surrogates are links.
        return getattr(st, "st_reparse_tag", 0) in (
            _IO_REPARSE_TAG_MOUNT_POINT,
            _IO_REPARSE_TAG_SYMLINK,
        )
    return False


def is_link_path(path: str | os.PathLike[str]) -> bool:
    try:
        return _is_link_stat(os.lstat(path))
    except OSError:
        return False


def is_link_entry(entry: os.DirEntry[str]) -> bool:
    """True for symlinks and, on Windows, junctions/mount points."""
    if entry.is_symlink():
        return True
    if IS_WINDOWS:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            return False
        if getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
            return is_link_path(entry.path)
    return False


def is_offline_placeholder(st: os.stat_result) -> bool:
    """True for cloud-only placeholders that would be downloaded if read."""
    if getattr(st, "st_file_attributes", 0) & _OFFLINE_ATTRIBUTES:
        return True
    return bool(getattr(st, "st_flags", 0) & _SF_DATALESS)


def normalize(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(path))


class PathFilter:
    """Glob-based exclusions.

    Patterns without a path separator match the entry name (``*.iso``, ``node_modules``);
    other patterns match the full absolute path (``/proc``, ``*/cache/*``).
    """

    def __init__(self, patterns: list[str], internal_dirs: list[Path] | None = None) -> None:
        self._name_patterns: list[str] = []
        self._path_patterns: list[str] = []
        for pattern in patterns:
            if "/" in pattern or "\\" in pattern:
                self._path_patterns.append(os.path.normcase(pattern.replace("/", os.sep)))
            else:
                self._name_patterns.append(os.path.normcase(pattern))
        self._internal = {normalize(p) for p in internal_dirs or []}
        self._internal_real = [os.path.realpath(p) for p in internal_dirs or []]

    def add_root(self, root: str | os.PathLike[str]) -> None:
        """Recognize internal directories when ``root`` reaches them through a symlinked prefix."""
        real_root = os.path.realpath(root)
        for internal in self._internal_real:
            try:
                relative = os.path.relpath(internal, real_root)
            except ValueError:  # different drives on Windows
                continue
            if relative == os.pardir or relative.startswith(os.pardir + os.sep):
                continue
            self._internal.add(normalize(os.path.join(root, relative)))

    def excluded(self, path: str) -> bool:
        norm = normalize(path)
        if norm in self._internal:
            return True
        name = os.path.basename(norm)
        if any(fnmatch.fnmatchcase(name, p) for p in self._name_patterns):
            return True
        return any(fnmatch.fnmatchcase(norm, p) for p in self._path_patterns)
