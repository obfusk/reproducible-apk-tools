#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import struct
import zipfile

from dataclasses import dataclass
from typing import Optional, Tuple

PAGE_SIZES = (4, 16, 64)


class Error(Exception):
    pass


@dataclass(frozen=True)
class AlignmentInfo:
    """Alignment info."""
    zipaligned: bool
    apksigner_padded: int
    apksigner_alignments: Tuple[int, ...]
    page_alignment: Optional[int]


def zipalignment(*apks: str) -> None:
    for apkfile in apks:
        info = alignment_info(apkfile)
        as_alignment_info = " ".join(map(str, info.apksigner_alignments)) or "none"
        so_alignment_info = f"{info.page_alignment}KiB" if info.page_alignment else "none"
        print(f"file={apkfile!r}")
        print(f"  zipaligned (4-byte alignment)               : {'yes' if info.zipaligned else 'no'}")
        print(f"  files with apksigner padding                : {info.apksigner_padded}")
        print(f"  apksigner alignments from extra fields      : {as_alignment_info}")
        print(f"  most likely uncompressed .so page alignment : {so_alignment_info}")


def alignment_info(apkfile: str) -> AlignmentInfo:
    r"""
    Get ZIP alignment info.

    >>> alignment_info("test/data/crlf-P16.apk")
    AlignmentInfo(zipaligned=True, apksigner_padded=0, apksigner_alignments=(), page_alignment=16)
    >>> alignment_info("test/data/golden-aligned-in-sorted-noalign.apk")
    AlignmentInfo(zipaligned=False, apksigner_padded=0, apksigner_alignments=(), page_alignment=None)
    >>> alignment_info("test/data/golden-aligned-in.apk")
    AlignmentInfo(zipaligned=True, apksigner_padded=3, apksigner_alignments=(4, 4096), page_alignment=4)
    """
    zipaligned = True
    apksigner_padded = 0
    apksigner_alignments = set()
    page_aligned = 0
    page_alignments = {k: 0 for k in PAGE_SIZES}
    with zipfile.ZipFile(apkfile) as zf:
        infos = zf.infolist()
    with open(apkfile, "rb") as fh:
        for info in infos:
            fh.seek(info.header_offset)
            hdr = fh.read(30)
            if hdr[:4] != b"PK\x03\x04":
                raise Error("Expected local file header signature")
            n, m = struct.unpack("<HH", hdr[26:30])
            fh.seek(n, os.SEEK_CUR)
            extra = fh.read(m)
            if apksigner_align := apksigner_padding_alignment(extra):
                apksigner_padded += 1
                apksigner_alignments.add(apksigner_align)
            if info.compress_type == 0:
                offset = fh.tell()
                if offset % 4 != 0:
                    zipaligned = False
                if info.filename.endswith(".so"):
                    page_aligned += 1
                    for page_size in PAGE_SIZES:
                        if offset % (page_size * 1024) == 0:
                            page_alignments[page_size] += 1
    align = page_aligned and max([k for k, v in page_alignments.items() if v == page_aligned],
                                 default=0)
    return AlignmentInfo(
        zipaligned=zipaligned, apksigner_padded=apksigner_padded,
        apksigner_alignments=tuple(sorted(apksigner_alignments)), page_alignment=align or None)


def apksigner_padding_alignment(extra: bytes) -> Optional[int]:
    align = None
    while len(extra) >= 4:
        hdr_id, size = struct.unpack("<HH", extra[:4])
        if size > len(extra) - 4:
            break
        if hdr_id == 0xd935 and size >= 2:
            align = int.from_bytes(extra[4:6], "little")
        extra = extra[size + 4:]
    return align


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="zipalignment.py")
    parser.add_argument("apks", metavar="APK", nargs="+")
    args = parser.parse_args()
    zipalignment(*args.apks)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
