#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2022 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import zipfile
import zlib

from typing import Any, Dict


ATTRS = ("compress_type", "create_system", "create_version", "date_time",
         "external_attr", "extract_version", "flag_bits")
LEVELS = (9, 6, 4, 1)


# FIXME: is there a better alternative?
class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _override: Dict[str, Any] = {}

    def __init__(self, zinfo, **override):  # pylint: disable=W0231
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name):
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


def fix_services_newlines(apk_in, apk_out, *, prefix="META-INF/services/",
                          replace=("\n", "\r\n"), verbose=False):
    with zipfile.ZipFile(apk_in) as zf_in:
        with zipfile.ZipFile(apk_out, "w") as zf_out:
            for info in zf_in.infolist():
                attrs = {attr: getattr(info, attr) for attr in ATTRS}
                zinfo = ReproducibleZipInfo(info, **attrs)
                if info.filename.startswith(prefix):
                    print(f"fixing {info.filename!r}...")
                    data = zf_in.read(info)
                    if info.compress_type == 8:
                        for lvl in LEVELS:
                            comp = zlib.compressobj(lvl, 8, -15)
                            if len(comp.compress(data) + comp.flush()) == info.compress_size:
                                zinfo._compresslevel = lvl
                                break
                        else:
                            raise RuntimeError(f"Unable to determine compresslevel for {info.filename!r}")
                    elif info.compress_type != 0:
                        raise RuntimeError(f"Unsupported compress_type {info.compress_type}")
                    zf_out.writestr(zinfo, data.decode().replace(*replace))
                else:
                    if verbose:
                        print(f"copying {info.filename!r}...")
                    if info.compress_type == 8:
                        with zf_in.open(info) as fh_in:
                            comps = {lvl: zlib.compressobj(lvl, 8, -15) for lvl in LEVELS}
                            clens = {lvl: 0 for lvl in LEVELS}
                            while True:
                                data = fh_in.read(4096)
                                if not data:
                                    break
                                for lvl in LEVELS:
                                    clens[lvl] += len(comps[lvl].compress(data))
                            for lvl in LEVELS:
                                if clens[lvl] + len(comps[lvl].flush()) == info.compress_size:
                                    zinfo._compresslevel = lvl
                                    break
                            else:
                                raise RuntimeError(f"Unable to determine compresslevel for {info.filename!r}")
                    elif info.compress_type != 0:
                        raise RuntimeError(f"Unsupported compress_type {info.compress_type}")
                    with zf_in.open(info) as fh_in:
                        with zf_out.open(zinfo, "w") as fh_out:
                            while True:
                                data = fh_in.read(4096)
                                if not data:
                                    break
                                fh_out.write(data)


if __name__ == "__main__":
    args = sys.argv[1:]
    verbose = "--verbose" in args or "-v" in args
    replace = ("\r\n", "\n") if "--from-crlf" in args else ("\n", "\r\n")
    args = [a for a in args if not a.startswith("-")]
    fix_services_newlines(*args, replace=replace, verbose=verbose)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
