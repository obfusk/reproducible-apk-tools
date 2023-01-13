#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys

from typing import Tuple

from . import dump_arsc as _dump_arsc
from . import fix_compresslevel as _fix_compresslevel
from . import fix_newlines as _fix_newlines
from . import list_compresslevel as _list_compresslevel
from . import sort_apk as _sort_apk

import click

__version__ = "0.1.1"
NAME = "repro-apk"

ERRORS = (_dump_arsc.Error, _fix_newlines.Error, _sort_apk.Error)


def main() -> None:
    @click.group(help="""
        repro-apk - scripts to make apks reproducible
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.command(help="""
        Dump resources.arsc (extracted or inside an APK) using aapt2.
    """)
    @click.option("--apk", is_flag=True,
                  help="ARSC_OR_APK is an APK, not an extracted resources.arsc.")
    @click.argument("arsc_or_apk", type=click.Path(exists=True, dir_okay=False))
    def dump_arsc(arsc_or_apk: str, apk: bool) -> None:
        if apk:
            _dump_arsc.dump_arsc_apk(arsc_or_apk)
        else:
            _dump_arsc.dump_arsc(arsc_or_apk)

    @cli.command(help="""
        Recompress with different compression level.

        Specify which files to change by providing at least one fnmatch-style
        pattern, e.g. 'assets/foo/*.bar'.
    """)
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("compresslevel", type=click.INT)
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    def fix_compresslevel(input_apk: str, output_apk: str, compresslevel: int,
                          patterns: Tuple[str], verbose: bool) -> None:
        _fix_compresslevel.fix_compresslevel(input_apk, output_apk, compresslevel,
                                             *patterns, verbose=verbose)

    @cli.command(help="""
        Change line endings from LF to CRLF (or vice versa).

        Specify which files to change by providing at least one fnmatch-style
        PATTERN, e.g. 'META-INF/services/*'.
    """)
    @click.option("--from-crlf/--to-crlf", is_flag=True,
                  help="Change from CRLF to LF.  [default: LF to CRLF]")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    def fix_newlines(input_apk: str, output_apk: str, patterns: Tuple[str],
                     from_crlf: bool, verbose: bool) -> None:
        replace = ("\r\n", "\n") if from_crlf else ("\n", "\r\n")
        _fix_newlines.fix_newlines(input_apk, output_apk, *patterns,
                                   replace=replace, verbose=verbose)

    @cli.command(help="""
        List ZIP entries with compression level.
    """)
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    def list_compresslevel(apk: str) -> None:
        _list_compresslevel.list_compresslevel(apk)

    @cli.command(help="""
        Sort (and realign) the ZIP entries of an APK.
    """)
    @click.option("--no-realign", is_flag=True, help="Do not realign.")
    @click.option("--no-force-align", is_flag=True, help="Do not force recreating alignment.")
    @click.option("--reset-lh-extra", is_flag=True, help="Reset ZIP LH extra fields using CD.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def sort_apk(input_apk: str, output_apk: str, no_realign: bool,
                 no_force_align: bool, reset_lh_extra: bool) -> None:
        _sort_apk.sort_apk(input_apk, output_apk, realign=not no_realign,
                           force_align=not no_force_align, reset_lh_extra=reset_lh_extra)

    try:
        cli(prog_name=NAME)
    except ERRORS as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
