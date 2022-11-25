#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2022 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys

from typing import Tuple

from . import fix_newlines as _fix_newlines, sort_apk as _sort_apk

import click

__version__ = "0.1.1"
NAME = "repro-apk"


def main() -> None:
    @click.group(help="""
        repro-apk - scripts to make apks reproducible
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

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
    except (_fix_newlines.Error, _sort_apk.Error) as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
