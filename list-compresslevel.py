#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import zipfile
import zlib


LEVELS = (9, 6, 4, 1)


class Error(RuntimeError):
    pass


def list_compresslevel(apk: str) -> None:
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            level = None
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
                            level = lvl
                            break
                    else:
                        raise Error(f"Unable to determine compresslevel for {info.filename!r}")
            elif info.compress_type != 0:
                raise Error(f"Unsupported compress_type {info.compress_type}")
            print(f"filename={info.filename!r} compresslevel={level}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="list-compresslevel.py")
    parser.add_argument("apk", metavar="APK")
    args = parser.parse_args()
    list_compresslevel(args.apk)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
