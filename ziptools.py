#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

# FIXME: zip64, ...

from __future__ import annotations

import os
import struct

from dataclasses import dataclass
from typing import BinaryIO, Union

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory


class Error(Exception):
    pass


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

    @classmethod
    def parse(_cls, data: bytes) -> EOCD:
        signature = data[:4]
        if signature != EOCD_SIGNATURE:
            raise Error("Expected end of central directory record (EOCD)")
        (disk_number, cd_start_disk, num_cd_records_disk, num_cd_records_total,
            cd_size, cd_offset, comment_len) = struct.unpack("<HHHHIIH", data[4:22])
        comment = data[22:]
        return _cls(signature, disk_number, cd_start_disk, num_cd_records_disk,
                    num_cd_records_total, cd_size, cd_offset, comment_len, comment)


@dataclass(frozen=True)
class CentralDirectory:
    """Central directory including EOCD."""
    cd_offset: int
    eocd_offset: int
    cd_data: bytes
    eocd_data: bytes


def read_cd(zipfile: Union[BinaryIO, str], count: int = 1024) -> CentralDirectory:
    """Read CentralDirectory."""
    if isinstance(zipfile, str):
        with open(zipfile, "rb") as fh:
            return _read_cd(fh, count)
    return _read_cd(zipfile, count)


def _read_cd(fh: BinaryIO, count: int) -> CentralDirectory:
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
            return CentralDirectory(cd_offset, eocd_offset, cd_data, eocd_data)
    raise Error("Expected end of central directory record (EOCD)")


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
