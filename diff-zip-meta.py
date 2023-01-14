#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import difflib
import hashlib
import os
import struct
import zipfile
import zlib

from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional, Tuple, Union


CDH_ATTRS = (
    "create_version",
    "create_system",
    "extract_version",
    "reserved",
    "flag_bits",
    "compress_type",
    "date_time",
    "CRC",
    "compress_size",
    "file_size",
    "volume",
    "internal_attr",
    "external_attr",
    # skip header_offset
    "filename",
    "extra",
    "comment",
)
LFH_ATTRS = (
    # from LHF
    "extract_version",
    "flag_bits",
    "compress_type",
    "date_time",
    "CRC",
    "compress_size",
    "file_size",
    "filename",
    "extra",
    # extra metadata
    # skip offset
    "size",
    "compress_sha1",
    "data_descriptor",
    "data_before",
)
LEVELS = (9, 6, 4, 1)


class Error(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    # from LHF
    extract_version: int
    flag_bits: int
    compress_type: int
    date_time: Tuple[int, int, int, int, int, int]
    CRC: int
    compress_size: int
    file_size: int
    filename: str
    extra: bytes
    # extra metadata
    offset: int
    size: int
    compress_sha1: Optional[str]
    data_descriptor: Optional[bytes]
    data_before: Optional[bytes]


def diff_zip_meta(zipfile1: str, zipfile2: str, offsets: bool = False,
                  ordering: bool = False, verbose: bool = False) -> None:
    def diff_entries(a: List[str], b: List[str]) -> None:
        d = difflib.unified_diff(a, b, n=0, lineterm="")
        for i, line in enumerate(d):
            if i > 2 and not line.startswith("@"):
                print(f"{line[0]} filename={line[1:]}")
    with open(zipfile1, "rb") as fh1, open(zipfile2, "rb") as fh2:
        with zipfile.ZipFile(zipfile1) as zf1, zipfile.ZipFile(zipfile2) as zf2:
            info1 = zf1.infolist()
            info2 = zf2.infolist()
            ftoi1 = {i.filename: i for i in info1}
            ftoi2 = {i.filename: i for i in info2}
            name1 = zf1.namelist()
            name2 = zf2.namelist()
            nset1 = set(name1)
            nset2 = set(name2)
            data_before_cd1, ents1 = read_entries(fh1, ftoi1, verbose)
            data_before_cd2, ents2 = read_entries(fh2, ftoi2, verbose)
            print(f"--- {zipfile1!r}")
            print(f"+++ {zipfile2!r}")
            if nset1 != nset2:
                rname1 = [repr(n) for n in sorted(name1)]
                rname2 = [repr(n) for n in sorted(name2)]
                print("entries (sorted by filename):")
                diff_entries(rname1, rname2)
            if ordering:
                if name1 != name2:
                    rname1 = [repr(n) for n in name1]
                    rname2 = [repr(n) for n in name2]
                    print("entries (unsorted):")
                    diff_entries(rname1, rname2)
                ename1 = list(ents1)
                ename2 = list(ents2)
                if ename1 != ename2 and not (ename1 == name1 and ename2 == name2):
                    rname1 = [repr(n) for n in ename1]
                    rname2 = [repr(n) for n in ename2]
                    print("entries (sorted by header_offset):")
                    diff_entries(rname1, rname2)
            if data_before_cd1 != data_before_cd2:
                print("central directory:")
                print(f"- data_before={data_before_cd1!r}")
                print(f"+ data_before={data_before_cd2!r}")
            for n in sorted(nset1 & nset2):
                diff = []
                for a in CDH_ATTRS:
                    v1 = getattr(ftoi1[n], a)
                    v2 = getattr(ftoi2[n], a)
                    if v1 != v2:
                        diff.append((f"{a} (cd header)", v1, v2))
                if verbose:
                    cl1 = get_compresslevel(zf1, ftoi1[n])
                    cl2 = get_compresslevel(zf2, ftoi2[n])
                    if cl1 != cl2:
                        diff.append(("compresslevel", cl1, cl2))
                if offsets:
                    off1 = ftoi1[n].header_offset
                    off2 = ftoi2[n].header_offset
                    if off1 != off2:
                        diff.append(("header_offset", off1, off2))
                ent1 = ents1[n]
                ent2 = ents2[n]
                if ent1 != ent2:
                    for a in LFH_ATTRS:
                        v1 = getattr(ent1, a)
                        v2 = getattr(ent2, a)
                        if v1 != v2:
                            if a in CDH_ATTRS:
                                w1 = getattr(ftoi1[n], a)
                                w2 = getattr(ftoi2[n], a)
                                if v1 == w1 and v2 == w2:
                                    # don't show same difference twice
                                    continue
                            diff.append((f"{a} (entry)", v1, v2))
                if diff:
                    print(f"entry {n!r}:")
                    for a, v1, v2 in diff:
                        print(f"- {a}={v1!r}")
                        print(f"+ {a}={v2!r}")


def get_compresslevel(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> Union[int, str, None]:
    if info.compress_type == 8:
        with zf.open(info) as fh:
            comps = {lvl: zlib.compressobj(lvl, 8, -15) for lvl in LEVELS}
            clens = {lvl: 0 for lvl in LEVELS}
            while True:
                data = fh.read(4096)
                if not data:
                    break
                for lvl in LEVELS:
                    clens[lvl] += len(comps[lvl].compress(data))
            for lvl in LEVELS:
                if clens[lvl] + len(comps[lvl].flush()) == info.compress_size:
                    return lvl
            else:
                return "unknown"
    elif info.compress_type != 0:
        return "unsupported"
    return None


def read_entries(fh: BinaryIO, ftoi: Dict[str, zipfile.ZipInfo], verbose: bool) \
        -> Tuple[Optional[bytes], Dict[str, Entry]]:
    infos = sorted(ftoi.values(), key=lambda i: i.header_offset)
    ents: Dict[str, Entry] = {}
    ent = None
    for p, i in zip([None] + infos[:-1], infos):  # type: ignore[operator]
        prev = ents[p.filename] if p is not None else None
        ents[i.filename] = ent = read_entry(fh, i, prev, verbose)
    if verbose:
        # FIXME
        cd_offset = zipfile._EndRecData(fh)[zipfile._ECD_OFFSET]    # type: ignore[attr-defined]
        ent_end = ent.offset + ent.size if ent is not None else 0
        fh.seek(ent_end)
        data_before_cd = fh.read(cd_offset - ent_end)
    else:
        data_before_cd = None
    return data_before_cd, ents


# FIXME: non-utf8 filenames?
def read_entry(fh: BinaryIO, info: zipfile.ZipInfo, prev: Optional[Entry], verbose: bool) -> Entry:
    fh.seek(info.header_offset)
    hdr = fh.read(30)
    if hdr[:4] != b"PK\x03\x04":
        raise Error("Expected local file header signature")
    extract_version, flag_bits, compress_type = struct.unpack("<HHH", hdr[4:10])
    t, d = struct.unpack("<HH", hdr[10:14])
    CRC, compress_size, file_size = struct.unpack("<III", hdr[14:26])
    n, m = struct.unpack("<HH", hdr[26:30])
    date_time = ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
                 t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)
    filename = fh.read(n).decode()
    extra = fh.read(m)
    if verbose:
        sha1 = hashlib.sha1()
        size = compress_size
        while size > 0:
            sha1.update(fh.read(min(size, 4096)))
            size -= 4096
        compress_sha1 = sha1.hexdigest()
    else:
        fh.seek(compress_size, os.SEEK_CUR)
        compress_sha1 = None
    if info.flag_bits & 0x08:
        data_descriptor = fh.read(12)
        if data_descriptor[:4] == b"\x50\x4b\x07\x08":
            data_descriptor += fh.read(4)
    else:
        data_descriptor = None
    size = fh.tell() - info.header_offset
    if verbose:
        prev_end = prev.offset + prev.size if prev is not None else 0
        fh.seek(prev_end)
        data_before = fh.read(info.header_offset - prev_end)
    else:
        data_before = None
    return Entry(
        extract_version=extract_version,
        flag_bits=flag_bits,
        compress_type=compress_type,
        date_time=date_time,
        CRC=CRC,
        compress_size=compress_size,
        file_size=file_size,
        filename=filename,
        extra=extra,
        offset=info.header_offset,
        size=size,
        compress_sha1=compress_sha1,
        data_descriptor=data_descriptor,
        data_before=data_before,
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="diff-zip-meta.py")
    parser.add_argument("--offsets", action="store_true")
    parser.add_argument("--ordering", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("zipfile1", metavar="ZIPFILE1")
    parser.add_argument("zipfile2", metavar="ZIPFILE2")
    args = parser.parse_args()
    diff_zip_meta(args.zipfile1, args.zipfile2, offsets=args.offsets,
                  ordering=args.ordering, verbose=args.verbose)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
