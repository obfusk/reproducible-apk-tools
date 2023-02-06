#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import calendar
import os
import stat
import struct
import time
import zipfile

from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional

# FIXME
# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L1887
SYS_FAT, SYS_UNX, SYS_NTF = (0, 3, 11)
SYSTEM = {SYS_FAT: "fat", SYS_UNX: "unx", SYS_NTF: "ntf"}

# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L2086
EXE_EXTS = {"com", "exe", "btm", "cmd", "bat"}

# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L1896
COMPRESS_TYPE = {
    zipfile.ZIP_STORED: "stor",
    zipfile.ZIP_DEFLATED: "def",
    zipfile.ZIP_BZIP2: "bzp2",
    zipfile.ZIP_LZMA: "lzma",
}

# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L1886
# normal, maximum, fast, superfast
DEFLATE_TYPE = "NXFS"

EXTRA_DATA_INFO = {
    # extra, data descriptor
    (False, False): "-",
    (False, True): "l",
    (True, False): "x",
    (True, True): "X",
}


@dataclass(frozen=True)
class Time:
    mtime: int
    atime: Optional[int]
    ctime: Optional[int]


class Error(RuntimeError):
    pass


# FIXME
# https://github.com/obfusk/reproducible-apk-tools/issues/10
# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L1097
# https://sources.debian.org/src/zip/3.0-12/zip.h/#L211
def format_info(info: zipfile.ZipInfo, *, extended: bool = True,
                long: bool = False) -> str:
    if ut := _get_time(info.extra):
        date_time = tuple(time.localtime(ut.mtime))[:6]
    else:
        date_time = info.date_time
    perm = _perms(info, extended=extended)
    vers = "{}.{}".format(info.create_version // 10,
                          info.create_version % 10)
    syst = SYSTEM.get(info.create_system, "unx")
    xinf = "t" if info.internal_attr == 1 else "b"
    xinf += EXTRA_DATA_INFO[(bool(info.extra), bool(info.flag_bits & 0x08))]
    comp = COMPRESS_TYPE[info.compress_type]
    if info.compress_type == zipfile.ZIP_DEFLATED:
        comp += DEFLATE_TYPE[(info.flag_bits >> 1) & 3]
    if extended:
        dt = "{}-{:02d}-{:02d}".format(*date_time[:3])
        tm = "{:02d}:{:02d}:{:02d}".format(*date_time[3:])
    else:
        dt = "{:02d}-{}-{:02d}".format(
            date_time[0] % 100,
            calendar.month_abbr[date_time[1]] or "000",
            date_time[2]
        )
        tm = "{:02d}:{:02d}".format(*date_time[3:5])
    fields = [f"{perm:<11}", vers, syst, f"{info.file_size:>8}", xinf]
    if long or extended:
        fields.append(f"{info.compress_size:>8}")
    fields += [comp, dt, tm]
    if extended:
        fields.append(f"{info.CRC:08x}")
    fields.append(info.filename)
    return " ".join(fields)


# FIXME
# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L2064
def _perms(info: zipfile.ZipInfo, extended: bool = True) -> str:
    hi = info.external_attr >> 16
    if hi and info.create_system in (SYS_UNX, SYS_FAT):
        return stat.filemode(hi)
    is_dir = extended and info.filename.endswith("/")
    is_exe = os.path.splitext(info.filename)[1][1:].lower() in EXE_EXTS
    xatt = info.external_attr & 0xFF
    return "".join((
        'd' if xatt & 0x10 or is_dir else '-',
        'r',
        '-' if xatt & 0x01 else 'w',
        'x' if xatt & 0x10 or is_exe else '-',
        'a' if xatt & 0x20 else '-',
        'h' if xatt & 0x02 else '-',
        's' if xatt & 0x04 else '-',
    ))


# https://sources.debian.org/src/zip/3.0-12/zip.h/#L217
# https://sources.debian.org/src/zip/3.0-12/zipfile.c/#L6544
def _get_time(xtr: bytes, local: bool = False) -> Optional[Time]:
    while len(xtr) >= 4:
        hdr_id, size = struct.unpack("<HH", xtr[:4])
        if size > len(xtr) - 4:
            break
        if hdr_id == 0x5455 and size >= 1:
            mtime = atime = ctime = None
            flags = xtr[4]
            if flags & 0x1 and size >= 5:
                mtime = int.from_bytes(xtr[5:9], "little")
                if not local:
                    if flags & 0x2 and size >= 9:
                        atime = int.from_bytes(xtr[9:13], "little")
                    if flags & 0x4 and size >= 13:
                        ctime = int.from_bytes(xtr[13:17], "little")
                return Time(mtime, atime, ctime)
        elif hdr_id == 0x5855 and size >= 8:
            atime = int.from_bytes(xtr[4:8], "little")
            mtime = int.from_bytes(xtr[8:12], "little")
            return Time(mtime, atime, None)
        xtr = xtr[size + 4:]
    return None


def _get_lfh_extra(fh: BinaryIO, info: zipfile.ZipInfo) -> bytes:
    fh.seek(info.header_offset)
    hdr = fh.read(30)
    if hdr[:4] != b"\x50\x4b\x03\x04":
        raise Error("Expected local file header signature")
    n, m = struct.unpack("<HH", hdr[26:30])
    fh.seek(n, os.SEEK_CUR)
    return fh.read(m)


def zipinfo(zip_file: str, *, extended: bool = True, long: bool = False,
            fmt: Callable[..., str] = format_info) -> None:
    with zipfile.ZipFile(zip_file) as zf:
        size = os.path.getsize(zip_file)
        ents = len(zf.infolist())
        tot_u = tot_c = 0
        print(f"Archive:  {zip_file}")
        print(f"Zip file size: {size} bytes, number of entries: {ents}")
        for info in zf.infolist():
            tot_u += info.file_size
            tot_c += info.compress_size
            print(fmt(info, extended=extended, long=long))
        pct = (tot_u - tot_c) / tot_u * 100 if tot_u else 0
        s = "" if ents == 1 else "s"
        print(f"{ents} file{s}, {tot_u} bytes uncompressed, "
              f"{tot_c} bytes compressed:  {pct:.1f}%")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="zipinfo.py")
    parser.add_argument("-e", "--extended", action="store_true",
                        help="use extended output format")
    parser.add_argument("-l", "--long", action="store_true",
                        help="use long output format")
    parser.add_argument("zipfile", metavar="ZIPFILE")
    args = parser.parse_args()
    zipinfo(args.zipfile, extended=args.extended, long=args.long)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
