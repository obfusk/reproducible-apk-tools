#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys

from typing import Tuple

from . import diff_zip_meta as _diff_zip_meta
from . import dump_arsc as _dump_arsc
from . import dump_axml as _dump_axml
from . import dump_baseline as _dump_baseline
from . import fix_compresslevel as _fix_compresslevel
from . import fix_newlines as _fix_newlines
from . import list_compresslevel as _list_compresslevel
from . import sort_apk as _sort_apk
from . import sort_baseline as _sort_baseline

import click

__version__ = "0.2.2"
NAME = "repro-apk"

ERRORS = (
    _diff_zip_meta.Error,
    _dump_arsc.Error,
    _dump_axml.Error,
    _dump_baseline.Error,
    _fix_compresslevel.Error,
    _fix_newlines.Error,
    _list_compresslevel.Error,
    _sort_apk.Error,
    _sort_baseline.Error,
)


def main() -> None:
    @click.group(help="""
        repro-apk - scripts to make apks reproducible
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.command(help="""
        Diff ZIP file metadata.
    """)
    @click.option("--no-additional", is_flag=True, help="Skip additional tests.")
    @click.option("--no-lfh-extra", is_flag=True, help="Ignore LFH extra field.")
    @click.option("--no-offsets", is_flag=True, help="Ignore header offsets.")
    @click.option("--no-ordering", is_flag=True, help="Ignore entry ordering.")
    @click.argument("zipfile1", type=click.Path(exists=True, dir_okay=False))
    @click.argument("zipfile2", type=click.Path(exists=True, dir_okay=False))
    def diff_zip_meta(zipfile1: str, zipfile2: str, no_additional: bool, no_lfh_extra: bool,
                      no_offsets: bool, no_ordering: bool) -> None:
        verbosity = _diff_zip_meta.Verbosity(
            additional=not no_additional,
            lfh_extra=not no_lfh_extra,
            offsets=not no_offsets,
            ordering=not no_ordering,
        )
        if _diff_zip_meta.diff_zip_meta(zipfile1, zipfile2, verbosity=verbosity):
            sys.exit(4)

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
        Dump Android binary XML (extracted or inside an APK) using aapt2.
    """)
    @click.option("--apk", metavar="APK",
                  help="APK that contains the (non-extracted) AXML file.")
    @click.argument("axml", type=click.Path(exists=False, dir_okay=False))
    def dump_axml(axml: str, apk: str) -> None:
        if apk:
            _dump_axml.dump_axml_apk(apk, axml)
        else:
            _dump_axml.dump_axml(axml)

    @cli.command(help="""
        Dump baseline.prof/baseline.profm (extracted or inside an APK).
    """)
    @click.option("--apk", is_flag=True,
                  help="PROF_OR_APK is an APK, not an extracted .prof/.profm.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("prof_or_apk", type=click.Path(exists=True, dir_okay=False))
    def dump_baseline(prof_or_apk: str, apk: bool, verbose: bool) -> None:
        if apk:
            _dump_baseline.dump_baseline_apk(prof_or_apk, verbose=verbose)
        else:
            _dump_baseline.dump_baseline(prof_or_apk, verbose=verbose)

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

    @cli.command(help="""
        Sort baseline.profm (extracted or inside an APK).
    """)
    @click.option("--apk", is_flag=True,
                  help="PROF_OR_APK is an APK, not an extracted .profm.")
    @click.argument("input_prof_or_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_prof_or_apk", type=click.Path(dir_okay=False))
    def sort_baseline(input_prof_or_apk: str, output_prof_or_apk: str, apk: bool) -> None:
        if apk:
            _sort_baseline.sort_baseline_apk(input_prof_or_apk, output_prof_or_apk)
        else:
            _sort_baseline.sort_baseline(input_prof_or_apk, output_prof_or_apk)

    try:
        cli(prog_name=NAME)
    except ERRORS as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(3)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
