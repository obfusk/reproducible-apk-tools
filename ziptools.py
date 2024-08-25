#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

# FIXME: zip64, ...

from __future__ import annotations

import os
import struct

from dataclasses import dataclass
from functools import cached_property
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory


class Error(Exception):
    pass


# FIXME
@dataclass(frozen=True)
class DataDescriptor:
    """Data descriptor."""
    signature: Optional[bytes]  # 4
    crc32: int                  # 4
    compressed_size: int        # 4
    uncompressed_size: int      # 4


# FIXME: data descriptor, load data
@dataclass(frozen=True)
class ZipEntry:
    """ZIP entry."""
    signature: bytes            # 4
    version_extract: int        # 2
    flags: int                  # 2
    compression_method: int     # 2
    mtime: int                  # 2
    mdate: int                  # 2
    crc32: int                  # 4
    compressed_size: int        # 4
    uncompressed_size: int      # 4
    filename_len: int           # 2
    extra_len: int              # 2
    filename: bytes             # filename_len (n)
    extra: bytes                # extra_len (m)
    offset: int

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        return parse_datetime(self.mdate, self.mtime)

    @classmethod
    def load(_cls, fh: BinaryIO, offset: int) -> ZipEntry:
        fh.seek(offset)
        data = fh.read(30)
        signature = data[:4]
        if signature != ELFH_SIGNATURE:
            raise Error("Expected local file header")
        (version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
            uncompressed_size, n, m) = struct.unpack("<HHHHHIIIHH", data[4:30])
        data += fh.read(n + m)
        filename = data[30:30 + n]
        extra = data[30 + n:30 + n + m]
        return _cls(signature, version_extract, flags, compression_method, mtime, mdate, crc32,
                    compressed_size, uncompressed_size, n, m, filename, extra, offset)


@dataclass(frozen=True)
class CDEntry:
    """Central directory entry."""
    signature: bytes            # 4
    version_created: int        # 2
    version_extract: int        # 2
    flags: int                  # 2
    compression_method: int     # 2
    mtime: int                  # 2
    mdate: int                  # 2
    crc32: int                  # 4
    compressed_size: int        # 4
    uncompressed_size: int      # 4
    filename_len: int           # 2
    extra_len: int              # 2
    comment_len: int            # 2
    start_disk: int             # 2
    internal_attrs: int         # 2
    external_attrs: int         # 4
    header_offset: int          # 4
    filename: bytes             # filename_len (n)
    extra: bytes                # extra_len (m)
    comment: bytes              # comment_len (k)

    def load_entry(self, fh: BinaryIO) -> ZipEntry:
        return ZipEntry.load(fh, self.header_offset)

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        return parse_datetime(self.mdate, self.mtime)

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[CDEntry, bytes]:
        signature = data[:4]
        if signature != CDFH_SIGNATURE:
            raise Error("Expected central directory file header")
        (version_created, version_extract, flags, compression_method, mtime, mdate, crc32,
            compressed_size, uncompressed_size, n, m, k, start_disk, internal_attrs,
            external_attrs, header_offset) = struct.unpack("<HHHHHHIIIHHHHHII", data[4:46])
        filename = data[46:46 + n]
        extra = data[46 + n:46 + n + m]
        comment = data[46 + n + m:46 + n + m + k]
        return _cls(signature, version_created, version_extract, flags, compression_method,
                    mtime, mdate, crc32, compressed_size, uncompressed_size, n, m, k,
                    start_disk, internal_attrs, external_attrs, header_offset, filename,
                    extra, comment), data[46 + n + m + k:]


@dataclass(frozen=True)
class EOCD:
    """End of central directory record."""
    signature: bytes            # 4
    disk_number: int            # 2
    cd_start_disk: int          # 2
    num_cd_records_disk: int    # 2
    num_cd_records_total: int   # 2
    cd_size: int                # 4
    cd_offset: int              # 4
    comment_len: int            # 2
    comment: bytes              # comment_len
    offset: int

    @classmethod
    def parse(_cls, data: bytes, offset: int) -> EOCD:
        signature = data[:4]
        if signature != EOCD_SIGNATURE:
            raise Error("Expected end of central directory record (EOCD)")
        (disk_number, cd_start_disk, num_cd_records_disk, num_cd_records_total,
            cd_size, cd_offset, n) = struct.unpack("<HHHHIIH", data[4:22])
        comment = data[22:]
        return _cls(signature, disk_number, cd_start_disk, num_cd_records_disk,
                    num_cd_records_total, cd_size, cd_offset, n, comment, offset)


# FIXME: load entry, ...
@dataclass(frozen=True)
class ZipFile:
    """ZIP file."""
    file: Union[BinaryIO, str]
    cd_entries: List[CDEntry]
    eocd: EOCD

    # FIXME
    @cached_property
    def cd_entries_by_name(self) -> Dict[str, CDEntry]:
        return {e.filename.decode(): e for e in self.cd_entries}

    def load_entry(self, filename: str) -> Tuple[CDEntry, ZipEntry]:
        cd_entry = self.cd_entries_by_name[filename]
        if isinstance(self.file, str):
            with open(self.file, "rb") as fh:
                return cd_entry, cd_entry.load_entry(fh)
        return cd_entry, cd_entry.load_entry(self.file)

    @classmethod
    def load(cls, zipfile: Union[BinaryIO, str], *, count: int = 1024) -> ZipFile:
        if isinstance(zipfile, str):
            with open(zipfile, "rb") as fh:
                return cls._load(fh, zipfile, count)
        return cls._load(zipfile, None, count)

    @classmethod
    def _load(cls, fh: BinaryIO, filename: Optional[str], count: int) -> ZipFile:
        for pos in range(fh.seek(0, os.SEEK_END) - count, -count, -count):
            fh.seek(max(0, pos))
            data = fh.read(count + len(EOCD_SIGNATURE))
            if (idx := data.rfind(EOCD_SIGNATURE)) != -1:
                fh.seek(idx - len(data), os.SEEK_CUR)
                eocd_offset = fh.tell()
                fh.seek(16, os.SEEK_CUR)
                cd_offset = int.from_bytes(fh.read(4), "little")
                fh.seek(cd_offset)
                cd_data = fh.read(eocd_offset - cd_offset)
                eocd_data = fh.read()
                return ZipFile(filename or fh, cls._cd_entries(cd_data),
                               EOCD.parse(eocd_data, eocd_offset))
        raise Error("Expected end of central directory record (EOCD)")

    @classmethod
    def _cd_entries(_cls, data: bytes) -> List[CDEntry]:
        entries = []
        while data:
            entry, data = CDEntry.parse(data)
            entries.append(entry)
        return entries


def parse_datetime(d: int, t: int) -> Tuple[int, int, int, int, int, int]:
    return ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
            t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
