#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys
import zipfile

from typing import Optional, Tuple

from . import binres as _binres
from . import diff_zip_meta as _diff_zip_meta
from . import dump_arsc as _dump_arsc
from . import dump_axml as _dump_axml
from . import dump_baseline as _dump_baseline
from . import fix_compresslevel as _fix_compresslevel
from . import fix_files as _fix_files
from . import fix_newlines as _fix_newlines
from . import fix_pg_map_id as _fix_pg_map_id
from . import list_compresslevel as _list_compresslevel
from . import rm_files as _rm_files
from . import sort_apk as _sort_apk
from . import sort_baseline as _sort_baseline
from . import zipalign as _zipalign
from . import zipalignment as _zipalignment
from . import zipinfo as _zipinfo

import click

__version__ = "0.3.0"
NAME = "repro-apk"

ERRORS = (
    _binres.Error,
    _diff_zip_meta.Error,
    _dump_arsc.Error,
    _dump_axml.Error,
    _dump_baseline.Error,
    _fix_compresslevel.Error,
    _fix_files.Error,
    _fix_newlines.Error,
    _fix_pg_map_id.Error,
    _list_compresslevel.Error,
    _rm_files.Error,
    _sort_apk.Error,
    _sort_baseline.Error,
    _zipalign.Error,
    _zipalignment.Error,
    _zipinfo.Error,
    zipfile.BadZipFile,
)


def main() -> None:
    @click.group(help="""
        repro-apk - scripts to make android apks reproducible
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.group(help="""
        Parse/dump android binary XML (AXML) or resources (ARSC).
    """)
    def binres() -> None:
        pass

    @binres.command(help="""
        Parse & dump ARSC or AXML.
    """, name="dump")
    @click.option("--apk", metavar="APK", type=click.Path(exists=True, dir_okay=False),
                  help="APK that contains the AXML/ARSC file(s).")
    @click.option("--json", is_flag=True, help="Output JSON.")
    @click.option("--xml", is_flag=True, help="Output XML (AXML only).")
    @click.option("--deref", is_flag=True, help="Follow references (with --xml).")
    @click.option("--prolog", is_flag=True, help="Output XML prolog (with --xml).")
    @click.option("-q", "--quiet", is_flag=True, help="Don't show filenames.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("files_or_patterns", metavar="FILE_OR_PATTERN...", nargs=-1, required=True)
    @click.pass_context
    def binres_dump(ctx: click.Context, files_or_patterns: Tuple[str, ...], apk: str,
                    json: bool, deref: bool, prolog: bool, quiet: bool, xml: bool, verbose: bool) -> None:
        if json and xml:
            raise click.exceptions.BadParameter("Conflicting options: --json and --xml.", ctx)
        if deref and not xml:
            raise click.exceptions.BadParameter("Conflicting options: --deref without --xml.", ctx)
        if prolog and not xml:
            raise click.exceptions.BadParameter("Conflicting options: --prolog without --xml.", ctx)
        if apk:
            _binres.dump_apk(apk, *files_or_patterns, json=json, quiet=quiet,
                             verbose=verbose, xml=xml, xml_deref=deref, xml_prolog=prolog)
        else:
            _binres.dump(*files_or_patterns, json=json, quiet=quiet, verbose=verbose,
                         xml=xml, xml_deref=deref, xml_prolog=prolog)

    @binres.command(help="""
        Quickly get appid & version code/name from APK(s).
    """, name="fastid")
    @click.option("--json", is_flag=True, help="Output JSON.")
    @click.option("--short", is_flag=True, help="Only show values.")
    @click.argument("apks", metavar="APK...", nargs=-1, required=True,
                    type=click.Path(exists=True, dir_okay=False))
    def binres_fastid(apks: Tuple[str, ...], json: bool, short: bool) -> None:
        _binres.fastid(*apks, json=json, short=short)

    @binres.command(help="""
        Quickly get permissions from APK(s).
    """, name="fastperms")
    @click.option("--json", is_flag=True, help="Output JSON.")
    @click.option("--with-id", is_flag=True,
                  help="Also get appid & version code/name.")
    @click.option("-q", "--quiet", is_flag=True, help="Don't show filenames.")
    @click.argument("apks", metavar="APK...", nargs=-1, required=True,
                    type=click.Path(exists=True, dir_okay=False))
    def binres_fastperms(apks: Tuple[str, ...], json: bool, quiet: bool, with_id: bool) -> None:
        _binres.fastperms(*apks, json=json, quiet=quiet, with_id=with_id)

    @binres.command(help="""
        Dump basic manifest info from APK(s) as JSON.
    """, name="manifest-info")
    @click.option("-e", "--extended", is_flag=True, help="Also extract app label and icon.")
    @click.argument("apks", metavar="APK...", nargs=-1, required=True,
                    type=click.Path(exists=True, dir_okay=False))
    def binres_manifest_info(apks: Tuple[str, ...], extended: bool) -> None:
        if _binres.manifest_info(*apks, extended=extended):
            sys.exit(1)

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
    @click.option("--apk", metavar="APK", type=click.Path(exists=True, dir_okay=False),
                  help="APK that contains the (non-extracted) AXML file.")
    @click.argument("axml", type=click.Path(dir_okay=False))
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
        PATTERN, e.g. 'assets/foo/*.bar'.
    """)
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("compresslevel", type=click.INT)
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    def fix_compresslevel(input_apk: str, output_apk: str, compresslevel: int,
                          patterns: Tuple[str, ...], verbose: bool) -> None:
        _fix_compresslevel.fix_compresslevel(input_apk, output_apk, compresslevel,
                                             *patterns, verbose=verbose)

    @cli.command(help="""
        Process ZIP entries using an external command.

        Runs the command for each specified file, providing the old file
        contents as stdin and using stdout as the new file contents.

        The provided command is split on whitespace to allow passing arguments
        (e.g. 'foo --bar'), but shell syntax is not supported.

        Specify which files to process by providing at least one fnmatch-style
        PATTERN, e.g. 'META-INF/services/*'.
    """)
    @click.option("--compresslevel", multiple=True, metavar="PATTERN:LEVELS",
                  help="Specify compresslevel(s) (e.g '*.foo:6,9').")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("command")
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    @click.pass_context
    def fix_files(ctx: click.Context, input_apk: str, output_apk: str, command: str,
                  patterns: Tuple[str, ...], compresslevel: Tuple[str, ...],
                  verbose: bool) -> None:
        try:
            clevels = _fix_files.compresslevels_from_spec(*compresslevel)
        except ValueError as e:
            raise click.exceptions.BadParameter(str(e), ctx)
        _fix_files.fix_files(input_apk, output_apk, tuple(command.split()),
                             *patterns, compresslevels=clevels, verbose=verbose)

    @cli.command(help="""
        Change line endings from LF to CRLF (or vice versa).

        Specify which files to change by providing at least one fnmatch-style
        PATTERN, e.g. 'META-INF/services/*'.
    """)
    @click.option("--from-crlf/--to-crlf", is_flag=True,
                  help="Change from CRLF to LF.  [default: LF to CRLF]")
    @click.option("--compresslevel", multiple=True, metavar="PATTERN:LEVELS",
                  help="Specify compresslevel(s) (e.g '*.foo:6,9').")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    @click.pass_context
    def fix_newlines(ctx: click.Context, input_apk: str, output_apk: str,
                     patterns: Tuple[str, ...], from_crlf: bool,
                     compresslevel: Tuple[str, ...], verbose: bool) -> None:
        replace = ("\r\n", "\n") if from_crlf else ("\n", "\r\n")
        try:
            clevels = _fix_newlines.compresslevels_from_spec(*compresslevel)
        except ValueError as e:
            raise click.exceptions.BadParameter(str(e), ctx)
        _fix_newlines.fix_newlines(input_apk, output_apk, *patterns, compresslevels=clevels,
                                   replace=replace, verbose=verbose)

    @cli.command(help="""
        Replace non-deterministic R8 pg-map-id in classes{,N}.dex and update
        checksums, also in baseline.prof.
    """)
    @click.argument("input_dir_or_apk", type=click.Path(exists=True, dir_okay=True))
    @click.argument("output_dir_or_apk", type=click.Path(dir_okay=True))
    @click.argument("pg_map_id")
    def fix_pg_map_id(input_dir_or_apk: str, output_dir_or_apk: str, pg_map_id: str) -> None:
        if os.path.isdir(input_dir_or_apk):
            _fix_pg_map_id.fix_pg_map_id(input_dir_or_apk, output_dir_or_apk, pg_map_id)
        else:
            _fix_pg_map_id.fix_pg_map_id_apk(input_dir_or_apk, output_dir_or_apk, pg_map_id)

    @cli.command(help="""
        List ZIP entries with compression level.

        You can optionally specify which files to list by providing one or more
        fnmatch-style patterns, e.g. 'assets/foo/*.bar'.
    """)
    @click.option("--error", is_flag=True, help="Raise error when unable to determine level.")
    @click.option("--levels", metavar="LEVELS", help="Level(s) (0-9) to try"
                  f" [default: '{','.join(map(str, _list_compresslevel.LEVELS))}'].")
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("patterns", metavar="[PATTERN...]", nargs=-1)
    @click.pass_context
    def list_compresslevel(ctx: click.Context, apk: str, patterns: Tuple[str, ...],
                           levels: Optional[str], error: bool) -> None:
        try:
            clevels = _list_compresslevel.levels_from_spec(levels)
        except ValueError as e:
            raise click.exceptions.BadParameter(str(e), ctx)
        _list_compresslevel.list_compresslevel(apk, *patterns, levels=clevels, error=error)

    @cli.command(help="""
        Remove entries from ZIP file.

        Specify which files to remove by providing at least one fnmatch-style
        PATTERN, e.g. 'META-INF/MANIFEST.MF'.
    """)
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.argument("patterns", metavar="PATTERN...", nargs=-1, required=True)
    def rm_files(input_apk: str, output_apk: str, patterns: Tuple[str, ...],
                 verbose: bool) -> None:
        _rm_files.rm_files(input_apk, output_apk, *patterns, verbose=verbose)

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

    @cli.command(help="""
        Align uncompressed ZIP/APK entries to 4-byte boundaries (and .so shared
        object files to 4096-byte boundaries with -p/--page-align, or other page
        sizes with -P/--page-size).
    """)
    @click.option("-p", "--page-align", is_flag=True,
                  help="Use 4096-byte memory page alignment for .so files.")
    @click.option("-P", "--page-size", type=click.INT, metavar="N",
                  help="Use N*1024-byte memory page alignment for .so files.")
    @click.option("--pad-like-apksigner", is_flag=True,
                  help="Use 0xd935 Android ZIP Alignment Extra Field instead of zero padding.")
    @click.option("--replace", is_flag=True, help="Always replace existing alignment.")
    @click.option("--copy-extra", is_flag=True,
                  help="Copy extra bytes between ZIP entries.")
    @click.option("--no-update-lfh", is_flag=True,
                  help="Don't update the LFH using the data descriptor.")
    @click.argument("align", nargs=-1, metavar="[ALIGN]")
    @click.argument("input_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    @click.pass_context
    def zipalign(ctx: click.Context, align: Tuple[str, ...], input_apk: str,
                 output_apk: str, page_align: bool, page_size: Optional[int],
                 pad_like_apksigner: bool, replace: bool, copy_extra: bool,
                 no_update_lfh: bool) -> None:
        if len(align) > 1:
            s = "s" if len(align) > 2 else ""
            ctx.fail(f"Got unexpected extra argument{s} ({' '.join(align[1:])})")
        if align not in ((), ("4",)):
            raise click.exceptions.BadParameter("ALIGN must be 4.", ctx)
        if page_size not in (None, 4, 16, 64):
            print("Warning: specified page size is not 4, 16, or 64 KiB", file=sys.stderr)
        _zipalign.zipalign(input_apk, output_apk, page_align=bool(page_align or page_size),
                           page_size=page_size, pad_like_apksigner=pad_like_apksigner,
                           replace=replace, copy_extra=copy_extra, update_lfh=not no_update_lfh)

    @cli.command(help="""
        Show info about ZIP alignment.
    """)
    @click.argument("apks", metavar="APK...", nargs=-1, required=True,
                    type=click.Path(exists=True, dir_okay=False))
    def zipalignment(apks: Tuple[str, ...]) -> None:
        _zipalignment.zipalignment(*apks)

    @cli.command(help="""
        List ZIP entries (like zipinfo).

        The -l/--long option adds the compressed size before the compression
        type; -e/--extended does the same, adds the CRC32 checksum before the
        filename as well, uses a more standard date format, and treats filenames
        ending with a "/" as directories.
    """)
    @click.option("-1", "--filenames-only", is_flag=True,
                  help="Only print filenames, one per line.")
    @click.option("-e", "--extended", is_flag=True, help="Use extended output format.")
    @click.option("-l", "--long", is_flag=True, help="Use long output format.")
    @click.option("--sort-by-offset", is_flag=True, help="Sort entries by header offset.")
    @click.argument("zipfile", type=click.Path(exists=True, dir_okay=False))
    def zipinfo(zipfile: str, extended: bool, filenames_only: bool, long: bool,
                sort_by_offset: bool) -> None:
        if filenames_only and not (extended or long):
            _zipinfo.zip_filenames(zipfile, sort_by_offset=sort_by_offset)
        else:
            _zipinfo.zipinfo(zipfile, extended=extended, long=long,
                             sort_by_offset=sort_by_offset)

    try:
        cli(prog_name=NAME)
    except ERRORS as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(3)
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
