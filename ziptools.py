#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

r"""
ZIP file tools.

https://en.wikipedia.org/wiki/ZIP_(file_format)

>>> import dataclasses
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
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, filename_len=9, extra_len=4, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=0, filename=b'META-INF/', extra=b'\xfe\xca\x00\x00', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=0, compressed_size=2, uncompressed_size=0, filename_len=9, extra_len=4, filename=b'META-INF/', extra=4, size=61)
ZipDataDescriptor(crc32=0, compressed_size=2, uncompressed_size=0)
('META-INF/MANIFEST.MF', 'META-INF/MANIFEST.MF')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, filename_len=20, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=61, filename=b'META-INF/MANIFEST.MF', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23337, mdate=19119, crc32=3037116564, compressed_size=76, uncompressed_size=77, filename_len=20, extra_len=0, filename=b'META-INF/MANIFEST.MF', extra=0, size=142)
ZipDataDescriptor(crc32=3037116564, compressed_size=76, uncompressed_size=77)
('AndroidManifest.xml', 'AndroidManifest.xml')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, filename_len=19, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=203, filename=b'AndroidManifest.xml', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=0, mdate=14881, crc32=1633612288, compressed_size=630, uncompressed_size=1672, filename_len=19, extra_len=0, filename=b'AndroidManifest.xml', extra=0, size=695)
ZipDataDescriptor(crc32=1633612288, compressed_size=630, uncompressed_size=1672)
('classes.dex', 'classes.dex')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, filename_len=11, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=898, filename=b'classes.dex', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=2575816152, compressed_size=1536, uncompressed_size=1536, filename_len=11, extra_len=9, filename=b'classes.dex', extra=9, size=50)
('temp.txt', 'temp.txt')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, filename_len=8, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2484, filename=b'temp.txt', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23386, mdate=19119, crc32=4286586065, compressed_size=6, uncompressed_size=29, filename_len=8, extra_len=0, filename=b'temp.txt', extra=0, size=60)
ZipDataDescriptor(crc32=4286586065, compressed_size=6, uncompressed_size=29)
('lib/armeabi/fake.so', 'lib/armeabi/fake.so')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, filename_len=19, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=2544, filename=b'lib/armeabi/fake.so', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=23312, mdate=19119, crc32=831927574, compressed_size=6, uncompressed_size=6, filename_len=19, extra_len=1503, filename=b'lib/armeabi/fake.so', extra=1503, size=1552)
('resources.arsc', 'resources.arsc')
ZipCDEntry(version_created=10, version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, filename_len=14, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=4102, filename=b'resources.arsc', extra=b'', comment=b'')
ZipEntry(version_extract=10, flags=2048, compression_method=0, mtime=0, mdate=14881, crc32=1338685473, compressed_size=896, uncompressed_size=896, filename_len=14, extra_len=6, filename=b'resources.arsc', extra=6, size=50)
('temp2.txt', 'temp2.txt')
ZipCDEntry(version_created=20, version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, filename_len=9, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=0, header_offset=5048, filename=b'temp2.txt', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=2056, compression_method=8, mtime=23444, mdate=19119, crc32=3382197893, compressed_size=6, uncompressed_size=20, filename_len=9, extra_len=0, filename=b'temp2.txt', extra=0, size=61)
ZipDataDescriptor(crc32=3382197893, compressed_size=6, uncompressed_size=20)
ZipEOCD(disk_number=0, cd_start_disk=0, num_cd_records_disk=8, num_cd_records_total=8, cd_size=481, cd_offset=5109, comment_len=0, comment=b'')
'test/data/foo.zip'
('foo', 'foo')
ZipCDEntry(version_created=788, version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=2356372769, compressed_size=3, uncompressed_size=3, filename_len=3, extra_len=0, comment_len=0, start_disk=0, internal_attrs=0, external_attrs=25165824, header_offset=0, filename=b'foo', extra=b'', comment=b'')
ZipEntry(version_extract=20, flags=8, compression_method=0, mtime=44338, mdate=22809, crc32=0, compressed_size=0, uncompressed_size=0, filename_len=3, extra_len=0, filename=b'foo', extra=0, size=52)
ZipDataDescriptor(crc32=2356372769, compressed_size=3, uncompressed_size=3)
ZipEOCD(disk_number=0, cd_start_disk=0, num_cd_records_disk=1, num_cd_records_total=1, cd_size=49, cd_offset=52, comment_len=0, comment=b'')

>>> with ZipFile.open("test/data/golden-aligned-in.apk") as zf:
...     list(zf.compressed_chunks("lib/armeabi/fake.so"))
...     list(zf.uncompressed_chunks("lib/armeabi/fake.so"))
...     list(zf.compressed_chunks("META-INF/MANIFEST.MF", chunk_size=16))
...     list(zf.uncompressed_chunks("META-INF/MANIFEST.MF", chunk_size=16))
...     list(map(len, zf.uncompressed_chunks("META-INF/MANIFEST.MF", chunk_size=16)))
...     b"".join(zf.uncompressed_chunks("META-INF/MANIFEST.MF")).decode()
...     b"".join(zf.uncompressed_chunks("temp.txt")).decode()
...     b"".join(zf.uncompressed_chunks("temp2.txt")).decode()
[b'Hello\n']
[b'Hello\n']
[b'\xf3M\xcc\xcbLK-.\xd1\rK-*\xce\xcc\xcf', b'\xb3R0\xd43\xe0\xe5r.JM,IM\xd1u', b'\xaa\x04\tX\xe8\x19\xc4\x9b\x98\xeaf\xe6\x95\xa4\x16\xe5', b'%\xe6(h\xf8\x17%&\xe7\xa4*8\xe7\x17\x15\xe4', b'\x17%\x96\x00\xf5i\xf2r\xf1r\x01\x00']
[b'Manifest-Versio', b'n: 1.0\r\nCreated-', b'By: 1.8.0_45-inter', b'nal (Oracle Corp', b'oration)\r\n\r\n']
[15, 16, 18, 16, 12]
'Manifest-Version: 1.0\r\nCreated-By: 1.8.0_45-internal (Oracle Corporation)\r\n\r\n'
'AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
'BBBBBBBBBBBBBBBBBBB\n'

>>> with ZipFile.open("test/data/foo.zip") as zf:
...     list(zf.compressed_chunks("foo"))
...     list(zf.uncompressed_chunks("foo"))
[b'foo']
[b'foo']

"""

from __future__ import annotations

import dataclasses
import os
import struct
import zlib

from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import cached_property
from typing import BinaryIO, ClassVar, Dict, Generator, Iterator, List, Optional, Tuple, Union

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory
ODDH_SIGNATURE = b"\x50\x4b\x07\x08"    # optional data descriptor header

COMPRESSION_STORED = 0
COMPRESSION_DEFLATE = 8

FLAG_DATA_DESCRIPTOR = 0x08
FLAG_UTF8 = 0x800


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
    signature: Optional[bytes] = field(repr=False)  # 4
    crc32: int                                      # 4
    compressed_size: int                            # 4
    uncompressed_size: int                          # 4


# FIXME: load & decompress data, ...
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
    filename_len: int                               # 2
    extra_len: int                                  # 2
    filename: bytes                                 # filename_len (n)
    extra: bytes                                    # extra_len (m)
    size: int                                       # total size
    data_descriptor: Optional[ZipDataDescriptor] = field(repr=False)
    cd_entry: ZipCDEntry = field(repr=False)

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
    def is_dir(self) -> bool:
        return self.decoded_filename.endswith("/")

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

    def compressed_chunks(self, fh: BinaryIO, *, chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of raw (compressed) data."""
        fh.seek(self.cd_entry.header_offset + 30 + self.filename_len + self.extra_len)
        remaining = self.cd_entry.compressed_size
        while remaining > 0:
            data = fh.read(min(chunk_size, remaining))
            remaining -= len(data)
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
        if flags & FLAG_DATA_DESCRIPTOR:
            fh.seek(cd_entry.compressed_size, os.SEEK_CUR)
            dd_data = fh.read(12)
            if dd_data[:4] == ODDH_SIGNATURE:
                dd_sig, dd_data = ODDH_SIGNATURE, dd_data[4:] + fh.read(4)
            else:
                dd_sig = None
            dd_crc32, dd_compressed_size, dd_uncompressed_size = struct.unpack("<III", dd_data)
            data_descriptor = ZipDataDescriptor(dd_sig, dd_crc32, dd_compressed_size, dd_uncompressed_size)
        else:
            data_descriptor = None
        size = fh.tell() - cd_entry.header_offset
        return _cls(version_extract, flags, compression_method, mtime, mdate, crc32, compressed_size,
                    uncompressed_size, n, m, filename, extra, size, data_descriptor, cd_entry)


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
    filename_len: int                               # 2
    extra_len: int                                  # 2
    comment_len: int                                # 2
    start_disk: int                                 # 2
    internal_attrs: int                             # 2
    external_attrs: int                             # 4
    header_offset: int                              # 4
    filename: bytes                                 # filename_len (n)
    extra: bytes                                    # extra_len (m)
    comment: bytes                                  # comment_len (k)

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
    def is_dir(self) -> bool:
        return self.decoded_filename.endswith("/")

    @property
    def datetime(self) -> Tuple[int, int, int, int, int, int]:
        """Parse mdate & mtime into datetime tuple."""
        return parse_datetime(self.mdate, self.mtime)

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
        return _cls(version_created, version_extract, flags, compression_method,
                    mtime, mdate, crc32, compressed_size, uncompressed_size, n, m, k,
                    start_disk, internal_attrs, external_attrs, header_offset, filename,
                    extra, comment), data[46 + n + m + k:]


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
    comment_len: int                                # 2
    comment: bytes                                  # comment_len

    @property
    def offset(self) -> int:
        """EOCD offset."""
        return self.cd_offset + self.cd_size

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
        comment = data[22:]
        return _cls(disk_number, cd_start_disk, num_cd_records_disk, num_cd_records_total,
                    cd_size, cd_offset, n, comment)


# FIXME: zip64, write & append, modify, ...
# FIXME: check overlap etc.
# FIXME: space before/after: read & check
# FIXME: zipalign, zipinfo, ...
@dataclass(frozen=True)
class ZipFile:
    """ZIP file."""
    file: BinaryIO = field(compare=False, repr=False)
    cd_entries: List[ZipCDEntry]
    eocd: ZipEOCD

    def load_entry(self, entry: Union[ZipCDEntry, str]) -> ZipEntry:
        """Load ZipEntry from ZipCDEntry or by name."""
        return self._entry(entry).load_entry(self.file)

    def compressed_chunks(self, entry: Union[ZipCDEntry, str], *,
                          chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of raw (compressed) data."""
        return self.load_entry(entry).compressed_chunks(self.file, chunk_size=chunk_size)

    def uncompressed_chunks(self, entry: Union[ZipCDEntry, str], *,
                            chunk_size: int = 4096) -> Iterator[bytes]:
        """Read chunks of uncompressed data (chunk_size applies to compressed data)."""
        return self.load_entry(entry).uncompressed_chunks(self.file, chunk_size=chunk_size)

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
        return getattr(self.file, "name", None)

    def validate(self, extra: bool = False) -> None:
        """Validate local entries against cental directory."""
        for e in self.cd_entries:
            e.load_entry(self.file).validate(extra)

    @classmethod
    @contextmanager
    def open(cls, zipfile: str) -> Generator[ZipFile]:
        """ZipFile context manager."""
        with open(zipfile, "rb") as fh:
            yield cls.load(fh)

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


def parse_datetime(d: int, t: int) -> Tuple[int, int, int, int, int, int]:
    """Parse mdate & mtime into datetime tuple."""
    return ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
            t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
