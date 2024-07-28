#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import struct
import subprocess
import sys
import zipfile
import zlib

from fnmatch import fnmatch
from typing import Any, Dict, IO, List, Optional, Tuple

ATTRS = ("compress_type", "create_system", "create_version", "date_time",
         "external_attr", "extract_version", "flag_bits")
LEVELS = (9, 6, 4, 1)


class Error(RuntimeError):
    pass


# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    if "_compresslevel" not in zipfile.ZipInfo.__slots__:       # type: ignore[attr-defined]
        if "compress_level" not in zipfile.ZipInfo.__slots__:   # type: ignore[attr-defined]
            raise Error("zipfile.ZipInfo has no ._compresslevel")

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


def fix_files(input_apk: str, output_apk: str, command: Tuple[str, ...], *patterns: str,
              compresslevels: Optional[Dict[str, List[int]]] = None, verbose: bool = False) -> None:
    if not compresslevels:
        compresslevels = {}
    if not patterns:
        raise ValueError("No patterns")
    with open(input_apk, "rb") as fh_raw:
        with zipfile.ZipFile(input_apk) as zf_in:
            with zipfile.ZipFile(output_apk, "w") as zf_out:
                for info in zf_in.infolist():
                    attrs = {attr: getattr(info, attr) for attr in ATTRS}
                    zinfo = ReproducibleZipInfo(info, **attrs)
                    if info.compress_type == 8:
                        for pat, lvls in compresslevels.items():
                            if fnmatch(info.filename, pat):
                                levels = lvls
                                break
                        else:
                            levels = list(LEVELS)
                        fh_raw.seek(info.header_offset)
                        n, m = struct.unpack("<HH", fh_raw.read(30)[26:30])
                        fh_raw.seek(info.header_offset + 30 + m + n)
                        ccrc = 0
                        size = info.compress_size
                        while size > 0:
                            ccrc = zlib.crc32(fh_raw.read(min(size, 4096)), ccrc)
                            size -= 4096
                        with zf_in.open(info) as fh_in:
                            comps = {lvl: zlib.compressobj(lvl, 8, -15) for lvl in levels}
                            ccrcs = {lvl: 0 for lvl in levels}
                            while True:
                                data = fh_in.read(4096)
                                if not data:
                                    break
                                for lvl in levels:
                                    ccrcs[lvl] = zlib.crc32(comps[lvl].compress(data), ccrcs[lvl])
                            for lvl in levels:
                                if ccrc == zlib.crc32(comps[lvl].flush(), ccrcs[lvl]):
                                    zinfo._compresslevel = lvl
                                    break
                            else:
                                raise Error(f"Unable to determine compresslevel for {info.filename!r}")
                    elif info.compress_type != 0:
                        raise Error(f"Unsupported compress_type {info.compress_type}")
                    if fnmatches_with_negation(info.filename, *patterns):
                        print(f"processing {info.filename!r} with {' '.join(command)!r}...")
                        with zf_in.open(info) as fh_in:
                            with zf_out.open(zinfo, "w") as fh_out:
                                pipe_through_command(fh_in, fh_out, *command)
                    else:
                        if verbose:
                            print(f"copying {info.filename!r}...")
                        with zf_in.open(info) as fh_in:
                            with zf_out.open(zinfo, "w") as fh_out:
                                while True:
                                    data = fh_in.read(4096)
                                    if not data:
                                        break
                                    fh_out.write(data)


# FIXME: reads whole stdin/stdout into memory since subprocess doesn't handle
# file-like objects w/o .fileno() as returned by ZipFile.open()
def pipe_through_command(fh_in: IO[bytes], fh_out: IO[bytes], *args: str) -> None:
    try:
        p = subprocess.run(args, check=True, input=fh_in.read(), stdout=subprocess.PIPE)
        fh_out.write(p.stdout)
    except subprocess.CalledProcessError as e:
        raise Error(f"{args[0]} command failed") from e
    except FileNotFoundError as e:
        raise Error(f"{args[0]} command not found") from e


def fnmatches_with_negation(filename: str, *patterns: str) -> bool:
    r"""
    Filename matching with shell patterns and negation.

    Checks whether filename matches any of the fnmatch patterns.

    An optional prefix "!" negates the pattern, invalidating a successful match
    by any preceding pattern; use a backslash ("\") in front of the first "!"
    for patterns that begin with a literal "!".

    >>> fnmatches_with_negation("foo.xml", "*", "!*.png")
    True
    >>> fnmatches_with_negation("foo.png", "*", "!*.png")
    False
    >>> fnmatches_with_negation("!foo.png", r"\!*.png")
    True

    """
    matches = False
    for p in patterns:
        if p.startswith("!"):
            if fnmatch(filename, p[1:]):
                matches = False
        else:
            if p.startswith(r"\!"):
                p = p[1:]
            if fnmatch(filename, p):
                matches = True
    return matches


def compresslevels_from_spec(*specs: str) -> Dict[str, List[int]]:
    r"""
    Get compresslevels from PATTERN:LEVELS specs.

    >>> compresslevels_from_spec("foo/*.bar:6,9", "*:4")
    {'foo/*.bar': [6, 9], '*': [4]}
    >>> try:
    ...     compresslevels_from_spec("foo:4", "oops")
    ... except ValueError as e:
    ...     str(e)
    "Invalid PATTERN:LEVELS spec: 'oops'"
    >>> try:
    ...     compresslevels_from_spec("oops:x,y")
    ... except ValueError as e:
    ...     str(e)
    "Invalid PATTERN:LEVELS spec: 'oops:x,y'"

    """
    levels = {}
    for spec in specs:
        try:
            pat, lvls = spec.rsplit(":", 1)
            levels[pat] = [int(x) for x in lvls.split(",")]
        except ValueError as e:
            raise ValueError(f"Invalid PATTERN:LEVELS spec: {spec!r}") from e
    return levels


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="fix-files.py")
    parser.add_argument("--compresslevel", action="append", metavar="PATTERN:LEVELS")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("input_apk", metavar="INPUT_APK")
    parser.add_argument("output_apk", metavar="OUTPUT_APK")
    parser.add_argument("command", metavar="COMMAND")
    parser.add_argument("patterns", metavar="PATTERN", nargs="+")
    args = parser.parse_args()
    try:
        clevels = compresslevels_from_spec(*args.compresslevel) if args.compresslevel else None
    except ValueError as e:
        print(f"Error: {e}.")
        sys.exit(1)
    fix_files(args.input_apk, args.output_apk, tuple(args.command.split()),
              *args.patterns, compresslevels=clevels, verbose=args.verbose)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
