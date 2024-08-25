#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

r"""
ZIP file tools.

https://en.wikipedia.org/wiki/ZIP_(file_format)

>>> import dataclasses
>>> with ZipFile.open("test/data/golden-aligned-in.apk") as zf:
...     for e in zf.cd_entries:
...         e
...         le = zf.load_entry(e)
...         dataclasses.replace(le, extra=len(le.extra), cd_entry=None)
...     zf.eocd
ZipCDEntry(signature=b'PK\x01\x02', version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, filename_len=9, extra_len=4, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=0, filename=b'META-INF/', extra=b'\xfe\xca\x00\x00', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, filename_len=9, extra_len=4, filename=b'META-INF/', extra=4, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, filename_len=20, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=61, filename=b'META-INF/MANIFEST.MF', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, filename_len=20, extra_len=0, filename=b'META-INF/MANIFEST.MF', extra=0, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, filename_len=19, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=203, filename=b'AndroidManifest.xml', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, filename_len=19, extra_len=0, filename=b'AndroidManifest.xml', extra=0, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, filename_len=11, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=898, filename=b'classes.dex', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, filename_len=11, extra_len=9, filename=b'classes.dex', extra=9, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, filename_len=8, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2484, filename=b'temp.txt', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, filename_len=8, extra_len=0, filename=b'temp.txt', extra=0, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, filename_len=19, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2544, filename=b'lib/armeabi/fake.so', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, filename_len=19, extra_len=1503, filename=b'lib/armeabi/fake.so', extra=1503, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, filename_len=14, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=4102, filename=b'resources.arsc', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, filename_len=14, extra_len=6, filename=b'resources.arsc', extra=6, cd_entry=None)
ZipCDEntry(signature=b'PK\x01\x02', version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, filename_len=9, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=5048, filename=b'temp2.txt', extra=b'', comment=b'')
ZipEntry(signature=b'PK\x03\x04', version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, filename_len=9, extra_len=0, filename=b'temp2.txt', extra=0, cd_entry=None)
ZipEOCD(signature=b'PK\x05\x06', disk_number=0, cd_start_disk=0, num_cd_records_disk=8, num_cd_records_total=8, cd_size=481, cd_offset=5109, comment_len=0, comment=b'', offset=5590)

"""

# FIXME: zip64, ...

from __future__ import annotations

import os
import struct

from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from typing import BinaryIO, Dict, Generator, List, Optional, Tuple, Union, TYPE_CHECKING

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory

COMPRESSION_STORED = 0
COMPRESSION_DEFLATE = 8

FLAG_DATA_DESCRIPTOR = 0x08
FLAG_UTF8 = 0x800


class ZipError(Exception):
    """ZIP error base class."""
    pass


# FIXME
@dataclass(frozen=True)
class ZipDataDescriptor:
    """ZIP entry data descriptor."""
    signature: Optional[bytes]  # 4
    crc32: int                  # 4
    compressed_size: int        # 4
    uncompressed_size: int      # 4


# FIXME: data descriptor, load data, Flags, check against ZipCDEntry, ...
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
    cd_entry: ZipCDEntry

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

    @classmethod
    def load(_cls, fh: BinaryIO, cd_entry: ZipCDEntry) -> ZipEntry:
        """Load ZipEntry corresponding to ZipCDEntry from file handle."""
        fh.seek(cd_entry.header_offset)
        data = fh.read(30)
        signature = data[:4]
        if signature != ELFH_SIGNATURE:
            raise ZipError("Expected local file header")
        (version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
            uncompressed_size, n, m) = struct.unpack("<HHHHHIIIHH", data[4:30])
        data += fh.read(n + m)
        filename = data[30:30 + n]
        extra = data[30 + n:30 + n + m]
        return _cls(signature, version_extract, flags, compression_method, mtime, mdate, crc32,
                    compressed_size, uncompressed_size, n, m, filename, extra, cd_entry)


@dataclass(frozen=True)
class ZipCDEntry:
    """ZIP central directory entry."""
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
        """Load corresponding ZipEntry from file handle."""
        return ZipEntry.load(fh, self)

    @cached_property
    def decoded_filename(self) -> str:
        """Filename decoded as UTF8 or CP437 depending on .has_utf8_filename()."""
        return self.filename.decode("utf-8" if self.has_utf8_filename else "cp437")

    @property
    def has_data_descriptor(self) -> bool:
        """Whether the entry has a data descriptor."""
        return bool(self.flags & FLAG_DATA_DESCRIPTOR)

    @property
    def has_utf8_filename(self) -> bool:
        """Whether the entry has a UTF8 filename."""
        return bool(self.flags & FLAG_UTF8)

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[ZipCDEntry, bytes]:
        """Parse one ZipCDEntry from CD data, return (entry, remaining data)."""
        signature = data[:4]
        if signature != CDFH_SIGNATURE:
            raise ZipError("Expected central directory file header")
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
class ZipEOCD:
    """ZIP end of central directory record."""
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
    def parse(_cls, data: bytes, offset: int) -> ZipEOCD:
        """Parse ZipEOCD from EOCD data + offset."""
        signature = data[:4]
        if signature != EOCD_SIGNATURE:
            raise ZipError("Expected end of central directory record (EOCD)")
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
    cd_entries: List[ZipCDEntry]
    eocd: ZipEOCD

    def load_entry(self, entry: Union[ZipCDEntry, str]) -> ZipEntry:
        """Load ZipEntry from ZipCDEntry or by name."""
        if isinstance(entry, str):
            entry = self.cd_entries_by_name[entry]
        if isinstance(self.file, str):
            with open(self.file, "rb") as fh:
                return entry.load_entry(fh)
        return entry.load_entry(self.file)

    # FIXME
    @cached_property
    def cd_entries_by_name(self) -> Dict[str, ZipCDEntry]:
        """Map of decoded filename to ZipCDEntry."""
        entries: Dict[str, ZipCDEntry] = {}
        for e in self.cd_entries:
            if e.decoded_filename in entries:
                raise ZipError(f"Duplicate entry {e.decoded_filename!r}")
            entries[e.decoded_filename] = e
        return entries

    @property
    def filename(self) -> Optional[str]:
        """Get file name."""
        if isinstance(self.file, str):
            return self.file
        if hasattr(self.file, "name"):
            return self.file.name
        return None

    @classmethod
    @contextmanager
    def open(cls, zipfile: str) -> ZipFileGenerator:
        """ZipFile context manager."""
        with open(zipfile, "rb") as fh:
            yield cls.load(fh)

    @classmethod
    def load(cls, zipfile: Union[BinaryIO, str]) -> ZipFile:
        """Load ZipFile from file handle or named file."""
        if isinstance(zipfile, str):
            with open(zipfile, "rb") as fh:
                return cls._load(fh, zipfile)
        return cls._load(zipfile, None)

    @classmethod
    def _load(cls, fh: BinaryIO, filename: Optional[str], *, count: int = 1024) -> ZipFile:
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
                return ZipFile(filename or fh, cls._parse_cd_entries(cd_data),
                               ZipEOCD.parse(eocd_data, eocd_offset))
        raise ZipError("Expected end of central directory record (EOCD)")

    # FIXME: check overlap, ...
    @classmethod
    def _parse_cd_entries(_cls, data: bytes) -> List[ZipCDEntry]:
        entries = []
        while data:
            entry, data = ZipCDEntry.parse(data)
            entries.append(entry)
        return entries


def parse_datetime(d: int, t: int) -> Tuple[int, int, int, int, int, int]:
    """Parse mdate & mtime into datetime tuple."""
    return ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
            t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)


if TYPE_CHECKING:
    ZipFileGenerator = Generator[ZipFile]
else:
    ZipFileGenerator = Generator

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
