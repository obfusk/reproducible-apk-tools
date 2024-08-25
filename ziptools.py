#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os

from dataclasses import dataclass
from typing import BinaryIO, Union

CDFH_SIGNATURE = b"\x50\x4b\x01\x02"    # central directory file header
ELFH_SIGNATURE = b"\x50\x4b\x03\x04"    # entry local file header
EOCD_SIGNATURE = b"\x50\x4b\x05\x06"    # end of central directory


class Error(Exception):
    pass


@dataclass(frozen=True)
class CentralDirectory:
    """Central directory including EOCD."""
    cd_offset: int
    eocd_offset: int
    cd_data: bytes


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
            cd_data = fh.read()
            return CentralDirectory(cd_offset, eocd_offset, cd_data)
    raise Error("Expected end of central directory record (EOCD)")


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
