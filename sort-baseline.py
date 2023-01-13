#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import struct
import zlib

from typing import Any, Tuple

# https://android.googlesource.com/platform/tools/base
#   profgen/profgen/src/main/kotlin/com/android/tools/profgen/ArtProfileSerializer.kt

PROF_MAGIC = b"pro\x00"
PROFM_MAGIC = b"prm\x00"

PROF_001_N = b"001\x00"
PROF_005_O = b"005\x00"
PROF_009_O_MR1 = b"009\x00"
PROF_010_P = b"010\x00"
PROF_015_S = b"015\x00"

PROFM_001_N = b"001\x00"
PROFM_002 = b"002\x00"

ASSET_PROF = "assets/dexopt/baseline.prof"
ASSET_PROFM = "assets/dexopt/baseline.profm"


class Error(RuntimeError):
    pass


def sort_baseline(input_file: str, output_file: str) -> None:
    with open(input_file, "rb") as fhi:
        data = _sort_baseline(fhi.read())
        with open(output_file, "wb") as fho:
            fho.write(data)


# FIXME
# pylint: disable=W0613
def sort_baseline_apk(input_file: str, output_file: str) -> None:
    raise NotImplementedError("TODO")


# FIXME
# Supported .prof: none
# Unsupported .prof: all
# Supported .profm: 002
# Unsupported .profm: 001 N
def _sort_baseline(data: bytes) -> bytes:
    magic, data = _split(data, 4)
    version, data = _split(data, 4)
    if magic == PROF_MAGIC:
        raise Error(f"Unsupported prof version {version!r}")
    elif magic == PROFM_MAGIC:
        if version == PROFM_002:
            return PROFM_MAGIC + PROFM_002 + sort_profm_002(data)
        else:
            raise Error(f"Unsupported profm version {version!r}")
    else:
        raise Error(f"Unsupported magic {magic!r}")


def sort_profm_002(data: bytes) -> bytes:
    num_dex_files, uncompressed_data_size, compressed_data_size, data = _unpack("<HII", data)
    profiles = []
    if len(data) != compressed_data_size:
        raise Error("Compressed data size does not match")
    data = zlib.decompress(data)
    if len(data) != uncompressed_data_size:
        raise Error("Uncompressed data size does not match")
    for _ in range(num_dex_files):
        profile = data[:4]
        profile_idx, profile_key_size, data = _unpack("<HH", data)
        profile_key, data = _split(data, profile_key_size)
        profile += profile_key + data[:6]
        num_type_ids, num_class_ids, data = _unpack("<IH", data)
        class_ids, data = _split(data, num_class_ids * 2)
        profile += class_ids
        profiles.append((profile_key, profile))
    if data:
        raise Error("Expected end of data")
    srtd = b"".join(int.to_bytes(i, 2, "little") + p[1][2:]
                    for i, p in enumerate(sorted(profiles)))
    cdata = zlib.compress(srtd, 1)
    hdr = struct.pack("<HII", num_dex_files, uncompressed_data_size, len(cdata))
    return hdr + cdata


def _unpack(fmt: str, data: bytes) -> Any:
    assert all(c in "<BHI" for c in fmt)
    size = fmt.count("B") + 2 * fmt.count("H") + 4 * fmt.count("I")
    return struct.unpack(fmt, data[:size]) + (data[size:],)


def _split(data: bytes, size: int) -> Tuple[bytes, bytes]:
    return data[:size], data[size:]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="sort-baseline.py")
    parser.add_argument("--apk", action="store_true")
    parser.add_argument("input_prof_or_apk", metavar="INPUT_PROF_OR_APK")
    parser.add_argument("output_prof_or_apk", metavar="OUTPUT_PROF_OR_APK")
    args = parser.parse_args()
    if args.apk:
        sort_baseline_apk(args.input_prof_or_apk, args.output_prof_or_apk)
    else:
        sort_baseline(args.input_prof_or_apk, args.output_prof_or_apk)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
