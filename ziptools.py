#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

r"""
ZIP file tools.

https://en.wikipedia.org/wiki/ZIP_(file_format)

>>> for file in ("golden-aligned-in.apk", "foo.zip"):
...     with ZipFile.open(f"test/data/{file}") as zf:
...         zf.validate()
...         zf.filename
...         for ent in zf.cd_entries:
...             lent = zf.load_entry(ent)
...             (ent.decoded_filename, lent.decoded_filename)
...             ent
...             dataclasses.replace(lent, extra=len(lent.extra))
...             lent.data_descriptor
...         zf.eocd
'test/data/golden-aligned-in.apk'
('META-INF/', 'META-INF/')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=0, filename=b'META-INF/', extra=b'\xfe\xca\x00\x00', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, filename=b'META-INF/', extra=4, size=61)
ZipDataDescriptor(crc32=0, compressed_size=2, uncompressed_size=0)
('META-INF/MANIFEST.MF', 'META-INF/MANIFEST.MF')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=61, filename=b'META-INF/MANIFEST.MF', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, filename=b'META-INF/MANIFEST.MF', extra=0, size=142)
ZipDataDescriptor(crc32=3037116564, compressed_size=76, uncompressed_size=77)
('AndroidManifest.xml', 'AndroidManifest.xml')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=203, filename=b'AndroidManifest.xml', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, filename=b'AndroidManifest.xml', extra=0, size=695)
ZipDataDescriptor(crc32=1633612288, compressed_size=630, uncompressed_size=1672)
('classes.dex', 'classes.dex')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=898, filename=b'classes.dex', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, filename=b'classes.dex', extra=9, size=50)
('temp.txt', 'temp.txt')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2484, filename=b'temp.txt', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, filename=b'temp.txt', extra=0, size=60)
ZipDataDescriptor(crc32=4286586065, compressed_size=6, uncompressed_size=29)
('lib/armeabi/fake.so', 'lib/armeabi/fake.so')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2544, filename=b'lib/armeabi/fake.so', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, filename=b'lib/armeabi/fake.so', extra=1503, size=1552)
('resources.arsc', 'resources.arsc')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=4102, filename=b'resources.arsc', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, filename=b'resources.arsc', extra=6, size=50)
('temp2.txt', 'temp2.txt')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=5048, filename=b'temp2.txt', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, filename=b'temp2.txt', extra=0, size=61)
ZipDataDescriptor(crc32=3382197893, compressed_size=6, uncompressed_size=20)
ZipEOCD(disk_number=0, cd_start_disk=0, num_cd_records_disk=8, num_cd_records_total=8, cd_size=481, cd_offset=5109, comment=b'')
'test/data/foo.zip'
('foo', 'foo')
ZipCDEntry(version_created=788, version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=2356372769, compressed_size=3, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=25165824, header_offset=0, filename=b'foo', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=0, compressed_size=0, uncompressed_size=0, filename=b'foo', extra=0, size=52)
ZipDataDescriptor(crc32=2356372769, compressed_size=3, uncompressed_size=3)
ZipEOCD(disk_number=0, cd_start_disk=0, num_cd_records_disk=1, num_cd_records_total=1, cd_size=49, cd_offset=52, comment=b'')

>>> with ZipFile.open("test/data/golden-aligned-in.apk") as zf:
...     list(zf.compressed_chunks("lib/armeabi/fake.so"))
...     list(zf.uncompressed_chunks("lib/armeabi/fake.so"))
...     list(zf.compressed_chunks("META-INF/MANIFEST.MF", chunk_size=16))
...     list(zf.uncompressed_chunks("META-INF/MANIFEST.MF", chunk_size=16))
...     list(map(len, zf.uncompressed_chunks("META-INF/MANIFEST.MF", chunk_size=16)))
...     zf.read("META-INF/MANIFEST.MF").decode()
...     zf.read("temp.txt").decode()
...     zf.read("temp2.txt").decode()
[b'Hello\n']
[b'Hello\n']
[b'\xf3M\xcc\xcbLK-.\xd1\rK-*\xce\xcc\xcf', b'\xb3R0\xd43\xe0\xe5r.JM,IM\xd1u', b'\xaa\x04\tX\xe8\x19\xc4\x9b\x98\xeaf\xe6\x95\xa4\x16\xe5', b'%\xe6(h\xf8\x17%&\xe7\xa4*8\xe7\x17\x15\xe4', b'\x17%\x96\x00\xf5i\xf2r\xf1r\x01\x00']
[b'Manifest-Versio', b'n: 1.0\r\nCreated-', b'By: 1.8.0_45-inter', b'nal (Oracle Corp', b'oration)\r\n\r\n']
[15, 16, 18, 16, 12]
'Manifest-Version: 1.0\r\nCreated-By: 1.8.0_45-internal (Oracle Corporation)\r\n\r\n'
'AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
'BBBBBBBBBBBBBBBBBBB\n'

>>> with ZipFile.open("test/data/foo.zip") as zf:
...     for filename, entry in zf.cd_entries_by_name.items():
...         filename
...         list(zf.compressed_chunks(filename))
...         zf.read(entry).decode()
'foo'
[b'foo']
'foo'

>>> import io, tempfile
>>> out = io.BytesIO()
>>> with ZipFile.open("test/data/foo.zip") as zf:
...     with ZipFile.build(out) as zb:
...         zb.copy_from(zf)
...         with zb.append(filename="bar") as zw:
...             zw.write(b"bar")
>>> zf = ZipFile.load(out)
>>> for filename, entry in zf.cd_entries_by_name.items():
...     entry
...     zf.read(entry).decode()
ZipCDEntry(version_created=788, version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=2356372769, compressed_size=3, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=25165824, header_offset=0, filename=b'foo', extra=b'', comment=b'')
'foo'
ZipCDEntry(version_created=788, version_extract=20, flags=2048, compression_method=8, mtime=0, mdate=0, crc32=1996459178, compressed_size=5, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=52, filename=b'bar', extra=b'', comment=b'')
'bar'
>>> with open("test/data/bar.zip", "rb") as fh:
...     fh.read() == out.getvalue()
True
>>> with tempfile.TemporaryDirectory() as tmpdir:
...     out_zip = os.path.join(tmpdir, "out.zip")
...     with ZipFile.open("test/data/foo.zip") as zf:
...         with ZipFile.build(out_zip) as zb:
...             zb.copy_from(zf)
...             with zb.append(filename="bar") as zw:
...                 zw.write(b"bar")
...     with open(out_zip, "rb") as fh:
...         fh.read() == out.getvalue()
...     with ZipFile.build(out_zip, append=True) as zb:
...         with zb.append(filename="baz") as zw:
...             zw.write(b"baz")
...     with ZipFile.open(out_zip) as zf:
...         for filename, entry in zf.cd_entries_by_name.items():
...             entry
...             zf.read(entry).decode()
True
ZipCDEntry(version_created=788, version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=2356372769, compressed_size=3, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=25165824, header_offset=0, filename=b'foo', extra=b'', comment=b'')
'foo'
ZipCDEntry(version_created=788, version_extract=20, flags=2048, compression_method=8, mtime=0, mdate=0, crc32=1996459178, compressed_size=5, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=52, filename=b'bar', extra=b'', comment=b'')
'bar'
ZipCDEntry(version_created=788, version_extract=20, flags=2048, compression_method=8, mtime=0, mdate=0, crc32=2015626392, compressed_size=5, uncompressed_size=3, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=90, filename=b'baz', extra=b'', comment=b'')
'baz'

"""

from __future__ import annotations

import dataclasses
import os
import struct
import zlib

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from functools import cached_property
from typing import Any, BinaryIO, ClassVar, Dict, Generator, Iterator, List, Optional, Tuple, Union

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory
ODDH_SIGNATURE = b"\x50\x4b\x07\x08"    # optional data descriptor header

CREATE_VERSION = 20
COMPRESSION_LEVEL = 6

COMPRESSION_STORED = 0
COMPRESSION_DEFLATE = 8


class Flags(IntFlag):
    """Flags."""
    DATA_DESCRIPTOR = 0x08
    UTF8 = 0x800


# FIXME
class CreateSystem(IntEnum):
    """Create system."""
    WIN32 = 0
    UNIX = 3


class ZipError(Exception):
    """ZIP error base class."""


class BrokenZipError(ZipError):
    """Broken ZIP file."""


class BadZipError(ZipError):
    """Bad (but not broken) ZIP file."""


class ZipValidationError(ZipError):
    """ZIP file validation error."""


@dataclass(frozen=True)
class ZipDataDescriptor:
    """ZIP entry data descriptor."""
    _has_signature: bool = field(repr=False)        # 4
    crc32: int                                      # 4
    compressed_size: int                            # 4
    uncompressed_size: int                          # 4

    @property
    def signature(self) -> bytes:
        return ODDH_SIGNATURE if self._has_signature else b""

    def dump(self) -> bytes:
        """Dump ZipDataDescriptor."""
        return self.signature + struct.pack("<III", self.crc32, self.compressed_size, self.uncompressed_size)


@dataclass(frozen=True)
class ZipEntry:
    """ZIP entry."""
    signature: ClassVar[bytes] = ELFH_SIGNATURE     # 4
    version_extract: int                            # 2
    flags: int                                      # 2
    compression_method: int                         # 2
    mtime: int                                      # 2
    mdate: int                                      # 2
    crc32: int                                      # 4
    compressed_size: int                            # 4
    uncompressed_size: int                          # 4
    # filename_len: int                             # 2
    # extra_len: int                                # 2
    filename: bytes                                 # filename_len (n)
    extra: bytes                                    # extra_len (m)
    size: int                                       # total size (not part of header)
    data_descriptor: Optional[ZipDataDescriptor] = field(repr=False)
    cd_entry: ZipCDEntry = field(repr=False)

    @property
    def filename_len(self) -> int:
        return len(self.filename)

    @property
    def extra_len(self) -> int:
        return len(self.extra)

    @cached_property
    def decoded_filename(self) -> str:
        """Filename decoded as UTF8 or CP437 depending on .has_utf8_filename()."""
        return self.filename.decode("utf-8" if self.has_utf8_filename else "cp437")

    @property
    def has_data_descriptor(self) -> bool:
        """Whether the entry has a data descriptor."""
        return bool(self.flags & Flags.DATA_DESCRIPTOR)

    @property
    def has_utf8_filename(self) -> bool:
        """Whether the entry has a UTF8 filename."""
        return bool(self.flags & Flags.UTF8)

    @property
    def is_dir(self) -> bool:
        """Is this entry a directory (i.e. does it end with a '/')?"""
        return self.decoded_filename.endswith("/")

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

    def compressed_chunks(self, fh: BinaryIO, *, chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of raw (compressed) data."""
        remaining = self.cd_entry.compressed_size
        pos = self.cd_entry.header_offset + 30 + self.filename_len + self.extra_len
        while remaining > 0:
            fh.seek(pos)
            data = fh.read(min(chunk_size, remaining))
            remaining -= len(data)
            pos = fh.tell()
            yield data

    def uncompressed_chunks(self, fh: BinaryIO, *, chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of uncompressed data (chunk_size applies to compressed data)."""
        if self.compression_method == COMPRESSION_STORED:
            yield from self.compressed_chunks(fh, chunk_size=chunk_size)
        elif self.compression_method == COMPRESSION_DEFLATE:
            decompressor = zlib.decompressobj(-15)
            for chunk in self.compressed_chunks(fh, chunk_size=chunk_size):
                yield decompressor.decompress(decompressor.unconsumed_tail + chunk)
            if data := decompressor.flush():
                yield data
        else:
            raise NotImplementedError(f"Unsupported compression method: {self.compression_method}")

    def validate(self, extra: bool = False) -> None:
        """Validate against cd_entry."""
        dd_fields = {"crc32", "compressed_size", "uncompressed_size"}
        exclude = {"size", "data_descriptor", "cd_entry"}
        if not extra:
            exclude.update({"extra_len", "extra"})
        for f in sorted(set(f.name for f in dataclasses.fields(self)) - exclude):
            if self.data_descriptor and f in dd_fields:
                value = getattr(self.data_descriptor, f)
                if getattr(self, f) not in (value, 0):
                    raise ZipValidationError(f"Field {f!r} differs between entry and data descriptor")
            else:
                value = getattr(self, f)
            if getattr(self.cd_entry, f) != value:
                raise ZipValidationError(f"Field {f!r} differs between entry and central directory")

    def dump(self) -> bytes:
        """Dump ZipEntry."""
        return ELFH_SIGNATURE + struct.pack(
            "<HHHHHIIIHH", self.version_extract, self.flags, self.compression_method,
            self.mtime, self.mdate, self.crc32, self.compressed_size, self.uncompressed_size,
            self.filename_len, self.extra_len,
        ) + self.filename + self.extra

    @classmethod
    def load(_cls, fh: BinaryIO, cd_entry: ZipCDEntry) -> ZipEntry:
        """Load ZipEntry corresponding to ZipCDEntry from file handle."""
        fh.seek(cd_entry.header_offset)
        data = fh.read(30)
        signature = data[:4]
        if signature != ELFH_SIGNATURE:
            raise BrokenZipError("Expected local file header")
        (version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
            uncompressed_size, n, m) = struct.unpack("<HHHHHIIIHH", data[4:30])
        data += fh.read(n + m)
        filename = data[30:30 + n]
        extra = data[30 + n:30 + n + m]
        if flags & Flags.DATA_DESCRIPTOR:
            fh.seek(cd_entry.compressed_size, os.SEEK_CUR)
            dd_data = fh.read(12)
            if dd_sig := dd_data[:4] == ODDH_SIGNATURE:
                dd_data = dd_data[4:] + fh.read(4)
            dd_crc32, dd_compressed_size, dd_uncompressed_size = struct.unpack("<III", dd_data)
            data_descriptor = ZipDataDescriptor(dd_sig, dd_crc32, dd_compressed_size, dd_uncompressed_size)
        else:
            data_descriptor = None
        size = fh.tell() - cd_entry.header_offset
        return _cls(version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
                    uncompressed_size, filename, extra, size, data_descriptor, cd_entry)


@dataclass(frozen=True)
class ZipCDEntry:
    """ZIP central directory entry."""
    signature: ClassVar[bytes] = CDFH_SIGNATURE     # 4
    version_created: int                            # 2
    version_extract: int                            # 2
    flags: int                                      # 2
    compression_method: int                         # 2
    mtime: int                                      # 2
    mdate: int                                      # 2
    crc32: int                                      # 4
    compressed_size: int                            # 4
    uncompressed_size: int                          # 4
    # filename_len: int                             # 2
    # extra_len: int                                # 2
    # comment_len: int                              # 2
    start_disk: int                                 # 2
    internal_attrs: int                             # 2
    external_attrs: int                             # 4
    header_offset: int                              # 4
    filename: bytes                                 # filename_len (n)
    extra: bytes                                    # extra_len (m)
    comment: bytes                                  # comment_len (k)

    @property
    def filename_len(self) -> int:
        return len(self.filename)

    @property
    def extra_len(self) -> int:
        return len(self.extra)

    @property
    def comment_len(self) -> int:
        return len(self.comment)

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
        return bool(self.flags & Flags.DATA_DESCRIPTOR)

    @property
    def has_utf8_filename(self) -> bool:
        """Whether the entry has a UTF8 filename."""
        return bool(self.flags & Flags.UTF8)

    @property
    def is_dir(self) -> bool:
        """Is this entry a directory (i.e. does it end with a '/')?"""
        return self.decoded_filename.endswith("/")

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

    def dump(self) -> bytes:
        """Dump ZipCDEntry."""
        return CDFH_SIGNATURE + struct.pack(
            "<HHHHHHIIIHHHHHII", self.version_created, self.version_extract, self.flags,
            self.compression_method, self.mtime, self.mdate, self.crc32, self.compressed_size,
            self.uncompressed_size, self.filename_len, self.extra_len, self.comment_len,
            self.start_disk, self.internal_attrs, self.external_attrs, self.header_offset
        ) + self.filename + self.extra + self.comment

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[ZipCDEntry, bytes]:
        """Parse one ZipCDEntry from CD data, return (entry, remaining data)."""
        signature = data[:4]
        if signature != CDFH_SIGNATURE:
            raise BrokenZipError("Expected central directory file header")
        (version_created, version_extract, flags, compression_method, mtime, mdate, crc32,
            compressed_size, uncompressed_size, n, m, k, start_disk, internal_attrs,
            external_attrs, header_offset) = struct.unpack("<HHHHHHIIIHHHHHII", data[4:46])
        filename = data[46:46 + n]
        extra = data[46 + n:46 + n + m]
        comment = data[46 + n + m:46 + n + m + k]
        data = data[46 + n + m + k:]
        return _cls(version_created, version_extract, flags, compression_method, mtime, mdate,
                    crc32, compressed_size, uncompressed_size, start_disk, internal_attrs,
                    external_attrs, header_offset, filename, extra, comment), data


@dataclass(frozen=True)
class ZipEOCD:
    """ZIP end of central directory record."""
    signature: ClassVar[bytes] = EOCD_SIGNATURE     # 4
    disk_number: int                                # 2
    cd_start_disk: int                              # 2
    num_cd_records_disk: int                        # 2
    num_cd_records_total: int                       # 2
    cd_size: int                                    # 4
    cd_offset: int                                  # 4
    # comment_len: int                              # 2
    comment: bytes                                  # comment_len

    @property
    def comment_len(self) -> int:
        return len(self.comment)

    @property
    def offset(self) -> int:
        """EOCD offset."""
        return self.cd_offset + self.cd_size

    def dump(self) -> bytes:
        """Dump ZipEOCD."""
        return EOCD_SIGNATURE + struct.pack(
            "<HHHHIIH", self.disk_number, self.cd_start_disk, self.num_cd_records_disk,
            self.num_cd_records_total, self.cd_size, self.cd_offset, self.comment_len
        ) + self.comment

    @classmethod
    def parse(_cls, data: bytes, offset: int) -> ZipEOCD:
        """Parse ZipEOCD from EOCD data + offset."""
        signature = data[:4]
        if signature != EOCD_SIGNATURE:
            raise BrokenZipError("Expected end of central directory record (EOCD)")
        (disk_number, cd_start_disk, num_cd_records_disk, num_cd_records_total,
            cd_size, cd_offset, n) = struct.unpack("<HHHHIIH", data[4:22])
        if cd_offset + cd_size != offset:
            raise BrokenZipError("Expected eocd_offset = cd_offset + cd_size")
        return _cls(disk_number, cd_start_disk, num_cd_records_disk, num_cd_records_total,
                    cd_size, cd_offset, data[22:])


# FIXME: zip64, encoding, extra fields, ...
# FIXME: check overlap etc.
# FIXME: space before/after: read & check
# FIXME: zipalign, zipinfo, zipmodify, ...
@dataclass(frozen=True)
class ZipFile:
    """ZIP file."""
    _fh: BinaryIO = field(compare=False, repr=False)
    cd_entries: List[ZipCDEntry]
    eocd: ZipEOCD

    def load_entry(self, entry: Union[ZipCDEntry, str]) -> ZipEntry:
        """Load ZipEntry from ZipCDEntry or by name."""
        return self._entry(entry).load_entry(self._fh)

    def read(self, entry: Union[ZipCDEntry, str]) -> bytes:
        """Read entire uncompressed file."""
        return b"".join(self.uncompressed_chunks(entry))

    def compressed_chunks(self, entry: Union[ZipCDEntry, str], *,
                          chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of raw (compressed) data."""
        return self.load_entry(entry).compressed_chunks(self._fh, chunk_size=chunk_size)

    def uncompressed_chunks(self, entry: Union[ZipCDEntry, str], *,
                            chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of uncompressed data (chunk_size applies to compressed data)."""
        return self.load_entry(entry).uncompressed_chunks(self._fh, chunk_size=chunk_size)

    def _entry(self, entry: Union[ZipCDEntry, str]) -> ZipCDEntry:
        return self.cd_entries_by_name[entry] if isinstance(entry, str) else entry

    @cached_property
    def cd_entries_by_name(self) -> Dict[str, ZipCDEntry]:
        """Map of decoded filename to ZipCDEntry."""
        entries: Dict[str, ZipCDEntry] = {}
        for e in self.cd_entries:
            if e.decoded_filename in entries:
                raise BadZipError(f"Duplicate entry {e.decoded_filename!r}")
            entries[e.decoded_filename] = e
        return entries

    @property
    def filename(self) -> Optional[str]:
        """Get file name."""
        return getattr(self._fh, "name", None)

    def validate(self, extra: bool = False) -> None:
        """Validate local entries against cental directory."""
        for e in self.cd_entries:
            e.load_entry(self._fh).validate(extra)

    @classmethod
    @contextmanager
    def open(cls, zipfile: str) -> Generator[ZipFile]:
        """ZipFile reader context manager."""
        with open(zipfile, "rb") as fh:
            yield cls.load(fh)

    @classmethod
    @contextmanager
    def build(cls, zipfile: Union[str, BinaryIO], *, comment: bytes = b"",
              append: bool = False) -> Generator[ZipFileBuilder]:
        """ZipFile builder context manager."""
        if isinstance(zipfile, str):
            with open(zipfile, "r+b" if append else "wb") as fh:
                builder = ZipFileBuilder(fh, comment=comment, append=append)
                yield builder
                builder.finish()
        else:
            builder = ZipFileBuilder(zipfile, comment=comment, append=append)
            yield builder
            builder.finish()

    @classmethod
    def load(cls, fh: BinaryIO, *, chunk_size: int = 1024) -> ZipFile:
        """Load ZipFile from file handle or named file."""
        for pos in range(fh.seek(0, os.SEEK_END) - chunk_size, -chunk_size, -chunk_size):
            fh.seek(max(0, pos))
            data = fh.read(chunk_size + len(EOCD_SIGNATURE))
            if (idx := data.rfind(EOCD_SIGNATURE)) != -1:
                fh.seek(idx - len(data), os.SEEK_CUR)
                eocd_offset = fh.tell()
                fh.seek(16, os.SEEK_CUR)
                cd_offset = int.from_bytes(fh.read(4), "little")
                fh.seek(cd_offset)
                cd_data = fh.read(eocd_offset - cd_offset)
                eocd_data = fh.read()
                return ZipFile(fh, cls._parse_cd_entries(cd_data), ZipEOCD.parse(eocd_data, eocd_offset))
        raise BrokenZipError("Expected end of central directory record (EOCD)")

    @classmethod
    def _parse_cd_entries(_cls, data: bytes) -> List[ZipCDEntry]:
        entries = []
        while data:
            entry, data = ZipCDEntry.parse(data)
            entries.append(entry)
        return entries


# FIXME: permissions etc.
class ZipFileBuilder:
    """ZIP file builder."""

    def __init__(self, fh: BinaryIO, *, comment: bytes = b"", append: bool = False):
        self._fh = fh
        self.comment = comment
        if append:
            zf = ZipFile.load(fh)
            self.cd_entries = zf.cd_entries
            fh.seek(zf.eocd.cd_offset)
            fh.truncate()
        else:
            self.cd_entries = []

    @contextmanager
    def append(self, *, compression_level: Optional[int] = None,
               datetime: Optional[Tuple[int, int, int, int, int, int]] = None,
               **kwargs: Any) -> Generator[ZipEntryWriter]:
        """Add new entry; context manager to write data."""
        if compression_level is None:
            compression_level = COMPRESSION_LEVEL
        if datetime:
            kwargs["mdate"], kwargs["mtime"] = unparse_datetime(*datetime)
        header_offset = self._fh.tell()
        cd_ent, lh_ent = build_zip_entries(
            **kwargs, header_offset=header_offset, local_entry_size=-1, data_descriptor=None)
        self._fh.write(lh_ent.dump())
        zw = ZipEntryWriter(self._fh, cd_ent.compression_method, compression_level)
        yield zw
        uncompressed_size, compressed_size, crc32 = zw.finish()
        if lh_ent.has_data_descriptor:
            data_descriptor = ZipDataDescriptor(True, crc32, compressed_size, uncompressed_size)
            self._fh.write(data_descriptor.dump())
        pos = self._fh.tell()
        cd_ent = dataclasses.replace(
            cd_ent, crc32=crc32, compressed_size=compressed_size, uncompressed_size=uncompressed_size)
        lh_ent = dataclasses.replace(   # discarded, no need to update other fields
            lh_ent, crc32=crc32, compressed_size=compressed_size, uncompressed_size=uncompressed_size)
        self._fh.seek(header_offset)
        self._fh.write(lh_ent.dump())
        self._fh.seek(pos)
        self.cd_entries.append(cd_ent)

    def append_file(self, file: Union[str, BinaryIO], *,
                    chunk_size: int = 4096, **kwargs: Any) -> None:
        """Add new entry from file."""
        if isinstance(file, str):
            if "filename" not in kwargs:
                kwargs["filename"] = file
            with open(file, "rb") as fh:
                with self.append(**kwargs) as zw:
                    while data := fh.read(chunk_size):
                        zw.write(data)
        else:
            if "filename" not in kwargs and hasattr(file, "name"):
                kwargs["filename"] = getattr(file, "name")
            with self.append(**kwargs) as zw:
                while data := file.read(chunk_size):
                    zw.write(data)

    def copy_from(self, zipfile: ZipFile, entry: Union[ZipCDEntry, str, None] = None) -> None:
        """Copy an entry (or all entries) from a ZipFile."""
        entries = [zipfile._entry(entry)] if entry else zipfile.cd_entries
        for cd_ent in entries:
            header_offset = self._fh.tell()
            lh_ent = zipfile.load_entry(cd_ent)
            offset = cd_ent.header_offset + 30 + lh_ent.filename_len + lh_ent.extra_len
            cd_ent = dataclasses.replace(cd_ent, header_offset=header_offset)
            lh_ent = dataclasses.replace(lh_ent, cd_entry=cd_ent)
            self.cd_entries.append(cd_ent)
            self._fh.write(lh_ent.dump())
            zipfile._fh.seek(offset)
            copy_data(zipfile._fh, self._fh, cd_ent.compressed_size)
            if lh_ent.data_descriptor:
                self._fh.write(lh_ent.data_descriptor.dump())

    def finish(self) -> None:
        """Write CD & EOCD."""
        n = len(self.cd_entries)
        cd_offset = self._fh.tell()
        for ent in self.cd_entries:
            self._fh.write(ent.dump())
        eocd_offset = self._fh.tell()
        eocd = ZipEOCD(0, 0, n, n, eocd_offset - cd_offset, cd_offset, self.comment)
        self._fh.write(eocd.dump())
        self._fh.flush()


class ZipEntryWriter:
    """ZIP entry writer."""

    def __init__(self, fh: BinaryIO, compression_method: int, compression_level: int):
        self._fh = fh
        self._compression_method = compression_method
        self._uncompressed_size = self._compressed_size = self._crc32 = 0
        if compression_method == COMPRESSION_STORED:
            self._compressor = None
        if compression_method == COMPRESSION_DEFLATE:
            self._compressor = zlib.compressobj(compression_level, zlib.DEFLATED, -15)
        else:
            raise NotImplementedError(f"Unsupported compression method: {compression_method}")

    def write(self, data: bytes) -> None:
        """Write data."""
        self._crc32 = zlib.crc32(data, self._crc32)
        if self._compressor is None:
            self._uncompressed_size += len(data)
            self._compressed_size += len(data)
            self._fh.write(data)
        else:
            cdata = self._compressor.compress(data)
            self._uncompressed_size += len(data)
            self._compressed_size += len(cdata)
            self._fh.write(cdata)

    def finish(self) -> Tuple[int, int, int]:
        if self._compressor is not None:
            cdata = self._compressor.flush()
            self._compressed_size += len(cdata)
            self._fh.write(cdata)
        return self._uncompressed_size, self._compressed_size, self._crc32


def split_version(version: int) -> Tuple[Tuple[int, int], int]:
    r"""
    Split version into ((hi, lo), os).

    >>> version = CREATE_VERSION | CreateSystem.UNIX << 8
    >>> version
    788
    >>> split_version(version)
    ((2, 0), 3)

    """
    ver, os = version & 0xFF, version >> 8
    return (ver // 10, ver % 10), os


def unsplit_version(version: Union[Tuple[Tuple[int, int], int], Tuple[int, int]]) -> int:
    r"""
    Unsplit version from ((hi, lo), os) or (ver, os).

    >>> unsplit_version((CREATE_VERSION, CreateSystem.UNIX))
    788
    >>> unsplit_version(((2, 0), 3))
    788

    """
    if isinstance(version[0], tuple):
        (hi, lo), os = version
        ver = hi * 10 + lo
    else:
        ver, os = version
    return ver | os << 8


def parse_datetime(d: int, t: int) -> Tuple[int, int, int, int, int, int]:
    """Parse mdate & mtime into datetime tuple."""
    return ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
            t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)


def unparse_datetime(year: int, month: int, day: int, hours: int,
                     minutes: int, seconds: int) -> Tuple[int, int]:
    """Turn datetime into mdate + mtime."""
    return ((year - 1980) << 9 | month << 5 | day, hours << 11 | minutes << 5 | seconds // 2)


def build_zip_entries(
        *, version_created: int = unsplit_version((CREATE_VERSION, CreateSystem.UNIX)),
        version_extract: int = CREATE_VERSION, flags: int = 0,
        compression_method: int = COMPRESSION_DEFLATE, mtime: int = 0, mdate: int = 0,
        crc32: int = 0, compressed_size: int = 0, uncompressed_size: int = 0,
        start_disk: int = 0, internal_attrs: int = 0, external_attrs: int = 0,
        header_offset: int = 0, filename: Union[bytes, str] = b"-", extra: bytes = b"",
        comment: bytes = b"", local_entry_size: int = -1,
        data_descriptor: Optional[ZipDataDescriptor] = None) -> Tuple[ZipCDEntry, ZipEntry]:
    """Build ZipCDEntry & ZipEntry from kwargs."""
    if isinstance(filename, str):
        filename = filename.encode()
        flags |= Flags.UTF8
    cd_ent = ZipCDEntry(
        version_created, version_extract, flags, compression_method, mtime, mdate, crc32,
        compressed_size, uncompressed_size, start_disk, internal_attrs, external_attrs,
        header_offset, filename, extra, comment)
    lh_ent = ZipEntry(
        version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
        uncompressed_size, filename, extra, local_entry_size, data_descriptor, cd_ent)
    return cd_ent, lh_ent


def copy_data(fin: BinaryIO, fout: BinaryIO, size: int, chunk_size: int = 4096) -> None:
    """Copy data from one file handle to another in chunks."""
    while size > 0:
        data = fin.read(min(chunk_size, size))
        size -= len(data)
        fout.write(data)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
