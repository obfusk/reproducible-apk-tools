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

from typing import Callable, Optional


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


class Error(RuntimeError):
    pass


# FIXME: fat file permissions, ...
# https://github.com/obfusk/reproducible-apk-tools/issues/10
# https://sources.debian.org/src/zip/3.0-12/zip.h/#L211
# https://sources.debian.org/src/unzip/6.0-27/zipinfo.c/#L1097
def format_info(info: zipfile.ZipInfo, extended: bool = True,
                long: bool = False) -> str:
    if (mtime := _get_ut(info.extra)) is not None:
        date_time = tuple(time.localtime(mtime))[:6]
    else:
        date_time = info.date_time
    if hi := info.external_attr >> 16:
        perm = stat.filemode(hi)
    elif extended and info.filename.endswith("/"):
        perm = "drw----"
    else:
        perm = "-rw----"
    vers = "{}.{}".format(info.create_version // 10,
                          info.create_version % 10)
    syst = "fat" if info.create_system == 0 else "unx"
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


# FIXME: atime, ctime (local header only) not supported
# https://sources.debian.org/src/zip/3.0-12/zipfile.c/#L6544
def _get_ut(xtr: bytes) -> Optional[int]:
    while len(xtr) >= 4:
        hdr_id, size = struct.unpack("<HH", xtr[:4])
        if size > len(xtr) - 4:
            break
        if hdr_id == 0x5455 and size >= 1:
            flags = xtr[4]
            if flags & 0x1 and size >= 5:
                mtime = int.from_bytes(xtr[5:9], "little")
                return mtime
        xtr = xtr[size + 4:]
    return None


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
