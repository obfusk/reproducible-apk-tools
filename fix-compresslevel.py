#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import struct
import zipfile
import zlib

from fnmatch import fnmatch
from typing import Any, Dict


ATTRS = ("compress_type", "create_system", "create_version", "date_time",
         "external_attr", "extract_version", "flag_bits")
LEVELS = (9, 6, 4, 1)


class Error(RuntimeError):
    pass


# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _compresslevel: int
    _override: Dict[str, Any] = {}

    def __init__(self, zinfo: zipfile.ZipInfo, **override: Any) -> None:
        # pylint: disable=W0231
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name: str) -> Any:
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


def fix_compresslevel(input_apk: str, output_apk: str, compresslevel: int,
                      *patterns: str, verbose: bool = False) -> None:
    if not patterns:
        raise ValueError("No patterns")
    with open(input_apk, "rb") as fh_raw:
        with zipfile.ZipFile(input_apk) as zf_in:
            with zipfile.ZipFile(output_apk, "w") as zf_out:
                for info in zf_in.infolist():
                    attrs = {attr: getattr(info, attr) for attr in ATTRS}
                    zinfo = ReproducibleZipInfo(info, **attrs)
                    tofix = any(fnmatch(info.filename, p) for p in patterns)
                    level = None
                    if info.compress_type == 8:
                        fh_raw.seek(info.header_offset)
                        n, m = struct.unpack("<HH", fh_raw.read(30)[26:30])
                        fh_raw.seek(info.header_offset + 30 + m + n)
                        ccrc = 0
                        size = info.compress_size
                        while size > 0:
                            ccrc = zlib.crc32(fh_raw.read(min(size, 4096)), ccrc)
                            size -= 4096
                        with zf_in.open(info) as fh_in:
                            comps = {lvl: zlib.compressobj(lvl, 8, -15) for lvl in LEVELS}
                            ccrcs = {lvl: 0 for lvl in LEVELS}
                            while True:
                                data = fh_in.read(4096)
                                if not data:
                                    break
                                for lvl in LEVELS:
                                    ccrcs[lvl] = zlib.crc32(comps[lvl].compress(data), ccrcs[lvl])
                            for lvl in LEVELS:
                                if ccrc == zlib.crc32(comps[lvl].flush(), ccrcs[lvl]):
                                    level = lvl
                                    break
                            else:
                                raise Error(f"Unable to determine compresslevel for {info.filename!r}")
                    elif tofix or info.compress_type != 0:
                        raise Error(f"Unsupported compress_type {info.compress_type}")
                    if tofix:
                        print(f"fixing {info.filename!r}...")
                        zinfo._compresslevel = compresslevel
                    else:
                        if verbose:
                            print(f"copying {info.filename!r}...")
                        if level is not None:
                            zinfo._compresslevel = level
                    if verbose and level is not None:
                        print(f"  compresslevel={level}")
                    with zf_in.open(info) as fh_in:
                        with zf_out.open(zinfo, "w") as fh_out:
                            while True:
                                data = fh_in.read(4096)
                                if not data:
                                    break
                                fh_out.write(data)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="fix-compresslevel.py")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("input_apk", metavar="INPUT_APK")
    parser.add_argument("output_apk", metavar="OUTPUT_APK")
    parser.add_argument("compresslevel", metavar="COMPRESSLEVEL", type=int)
    parser.add_argument("patterns", metavar="PATTERN", nargs="+")
    args = parser.parse_args()
    fix_compresslevel(args.input_apk, args.output_apk, args.compresslevel,
                      *args.patterns, verbose=args.verbose)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
