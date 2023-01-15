<!-- SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/reproducible-apk-tools.svg?logo=github)](https://github.com/obfusk/reproducible-apk-tools/releases)
[![PyPI Version](https://img.shields.io/pypi/v/repro-apk.svg)](https://pypi.python.org/pypi/repro-apk)
[![Python Versions](https://img.shields.io/pypi/pyversions/repro-apk.svg)](https://pypi.python.org/pypi/repro-apk)
[![CI](https://github.com/obfusk/reproducible-apk-tools/workflows/CI/badge.svg)](https://github.com/obfusk/reproducible-apk-tools/actions?query=workflow%3ACI)
[![GPLv3+](https://img.shields.io/badge/license-GPLv3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

<!--
<a href="https://repology.org/project/repro-apk/versions">
  <img src="https://repology.org/badge/vertical-allrepos/repro-apk.svg?header="
    alt="Packaging status" align="right" />
</a>

<a href="https://repology.org/project/python:repro-apk/versions">
  <img src="https://repology.org/badge/vertical-allrepos/python:repro-apk.svg?header="
    alt="Packaging status" align="right" />
</a>
-->

# reproducible-apk-tools

[`fix-compresslevel.py`](#fix-compresslevelpy),
[`fix-newlines.py`](#fix-newlinespy),
[`sort-apk.py`](#sort-apkpy),
[`sort-baseline.py`](#sort-baselinepy),
[`diff-zip-meta.py`](#diff-zip-metapy),
[`dump-arsc.py`](#dump-arscpy),
[`dump-baseline.py`](#dump-baselinepy),
[`list-compresslevel.py`](#list-compresslevelpy).

## scripts to make apks reproducible

### fix-compresslevel.py

Recompress with different compression level.

Specify which files to change by providing at least one fnmatch-style pattern,
e.g. `'assets/foo/*.bar'`.

If two APKs have identical contents but some ZIP entries are compressed with a
different compression level, thus making the APKs not bit-by-bit identical, this
script may help.

```bash
$ fix-compresslevel.py --help
usage: fix-compresslevel.py [-h] [-v] INPUT_APK OUTPUT_APK COMPRESSLEVEL PATTERN [PATTERN ...]
[...]
$ apksigcopier compare signed.apk --unsigned unsigned.apk
DOES NOT VERIFY
[...]
$ fix-compresslevel.py unsigned.apk fixed.apk 6 assets/foo/bar.js
fixing 'assets/foo/bar.js'...
$ zipalign -f 4 fixed.apk fixed-aligned.apk
$ apksigcopier compare signed.apk --unsigned fixed-aligned.apk && echo OK
OK
```

NB: this builds a new ZIP file, preserving most ZIP metadata (and recompressing
entries not matching the pattern using the same compression level as in the
original APK) but not everything: e.g. copying the existing local header extra
fields which contain padding for alignment is not supported by Python's
`ZipFile`, which is why `zipalign` is usually needed.

### fix-newlines.py

Change line endings from LF to CRLF (or vice versa w/ `--from-crlf`).

Specify which files to change by providing at least one fnmatch-style pattern,
e.g. `'META-INF/services/*'`.

If the signed APK was built on Windows and has e.g. `META-INF/services/` files
with CRLF line endings whereas the unsigned APK was build on Linux/macOS and has
LF line endings, this script may help.

```bash
$ fix-newlines.py --help
usage: fix-newlines.py [-h] [--from-crlf] [--to-crlf] [-v] INPUT_APK OUTPUT_APK PATTERN [PATTERN ...]
[...]
$ apksigcopier compare signed.apk --unsigned unsigned.apk
DOES NOT VERIFY
[...]
$ fix-newlines.py unsigned.apk fixed.apk 'META-INF/services/*'
fixing 'META-INF/services/foo'...
fixing 'META-INF/services/bar'...
$ zipalign -f 4 fixed.apk fixed-aligned.apk
$ apksigcopier compare signed.apk --unsigned fixed-aligned.apk && echo OK
OK
```

NB: this builds a new ZIP file, preserving most ZIP metadata (and recompressing
using the same compression level) but not everything: e.g. copying the existing
local header extra fields which contain padding for alignment is not supported
by Python's `ZipFile`, which is why `zipalign` is usually needed.

### sort-apk.py

Sort (and w/o `--no-realign` also realign) the ZIP entries of an APK.

If the ordering of the ZIP entries in an APK is not deterministic/reproducible,
this script may help.  You'll almost certainly need to use it for all builds
though, since it can only sort the APK, not recreate a different ordering that
is deterministic but not sorted; see also the alignment CAVEAT.

```bash
$ sort-apk.py --help
usage: sort-apk.py [-h] [--no-realign] [--no-force-align] [--reset-lh-extra] INPUT_APK OUTPUT_APK
[...]
$ unzip -l some.apk
Archive:  some.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
        6  2017-05-15 11:24   lib/armeabi/fake.so
     1672  2009-01-01 00:00   AndroidManifest.xml
      896  2009-01-01 00:00   resources.arsc
     1536  2009-01-01 00:00   classes.dex
---------                     -------
     4110                     4 files
$ sort-apk.py some.apk sorted.apk
$ unzip -l sorted.apk
Archive:  sorted.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
     1672  2009-01-01 00:00   AndroidManifest.xml
     1536  2009-01-01 00:00   classes.dex
        6  2017-05-15 11:24   lib/armeabi/fake.so
      896  2009-01-01 00:00   resources.arsc
---------                     -------
     4110                     4 files
```

NB: this directly copies the (bytes of the) original ZIP entries from the
original file, thus preserving all ZIP metadata.

#### CAVEAT: alignment

Unfortunately, the padding added to ZIP local header extra fields for alignment
makes it hard to make sorting deterministic: unless the original APK was not
aligned at all, the padding is often different when the APK entries had a
different order (and thus a different offset) before sorting.

Because of this, `sort-apk` forcefully recreates the padding even if the entry
is already aligned (since that doesn't mean the padding is identical) to make
its output as deterministic as possible.  The downside is that it'll often add
"unnecessary" 8-byte padding to entries that didn't need alignment.

You can disable this using `--no-force-align`, or skip realignment completely
using `--no-realign`.  If you're certain you don't need to keep the old values,
you can also choose to reset the local header extra fields to the values from
the central directory entries with `--reset-lh-extra`.

If you use `--reset-lh-extra`, you'll probably want to combine it with either
`--no-force-align` (which should prevent the "unnecessary" 8-byte padding) or
`--no-realign` + `zipalign` (which uses smaller padding).

NB: the alignment padding used by `sort-apk` is the same as that used by
`apksigner` (a `0xd935` "Android ZIP Alignment Extra Field" which stores the
alignment itself plus zero padding and is thus always at least 6 bytes), whereas
`zipalign` just uses plain zero padding.

### sort-baseline.py

Sort `baseline.profm` (extracted or inside an APK).

```bash
$ sort-baseline.py --help
usage: sort-baseline.py [-h] [--apk] INPUT_PROF_OR_APK OUTPUT_PROF_OR_APK
[...]
$ diff -qs a/baseline.profm b/baseline.profm
Files a/baseline.profm and b/baseline.profm differ
$ sort-baseline.py a/baseline.profm a/baseline-sorted.profm
$ sort-baseline.py b/baseline.profm b/baseline-sorted.profm
$ diff -qs a/baseline-sorted.profm b/baseline-sorted.profm
Files a/baseline-sorted.profm and b/baseline-sorted.profm are identical
```

```bash
$ sort-baseline.py --apk some.apk sorted-baseline.apk
$ zipalign -f 4 sorted-baseline.apk sorted-baseline-aligned.apk
```

NB: does not support all file format versions yet.

NB: with `--apk`, this builds a new ZIP file, preserving most ZIP metadata (and
recompressing using the same compression level) but not everything: e.g. copying
the existing local header extra fields which contain padding for alignment is
not supported by Python's `ZipFile`, which is why `zipalign` is usually needed.

## scripts to dump info from apks and related file formats

### diff-zip-meta.py

Diff ZIP file metadata.

This will show differences in filenames, central directory headers, local file
headers, data descriptors, entry sizes, etc.

Additional tests include compression level (if it can be determined), CRC32
checksum of compressed data, and extra data before entries or the central
directory; you can skip these (relatively slow) tests using `--no-additional`.

Some differences make the output quite verbose and/or are usually the result of
other differences; you can skip/ignore these using `--no-lfh-extra`,
`--no-offsets`, `--no-ordering`.

```bash
$ diff-zip-meta.py --help
usage: diff-zip-meta.py [-h] [--no-additional] [--no-lfh-extra] [--no-offsets] [--no-ordering]
                        ZIPFILE1 ZIPFILE2
$ diff-zip-meta.py a.apk b.apk
--- a.apk
+++ b.apk
entry foo:
- compresslevel=6
+ compresslevel=9
- compress_crc=0x9ed711dc
+ compress_crc=0xd9776b0c
$ diff-zip-meta.py a.apk c.apk --no-offsets --no-ordering
--- a.apk
+++ c.apk
entries (sorted by filename):
- filename=META-INF/CERT.RSA
- filename=META-INF/CERT.SF
- filename=META-INF/MANIFEST.MF
central directory:
  data_before:
-   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
-   bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
entry foo:
- compresslevel=6
+ compresslevel=9
- compress_crc=0x9ed711dc
+ compress_crc=0xd9776b0c
entry META-INF/com/android/build/gradle/app-metadata.properties:
  data_before (entry):
-   504b030400000000000021082102000000000000000000000000000066000000000000000000
-   0000000000000000000000000000000000000000000000000000000000000000000000000000
-   0000000000000000000000000000000000000000000000000000000000000000000000000000
-   000000000000000000000000000000000000
```

NB: work in progress; output format may change.

### dump-arsc.py

Dump `resources.arsc` (extracted or inside an APK) using `aapt2`.

```bash
$ dump-arsc.py --help
usage: dump-arsc.py [-h] [--apk] ARSC_OR_APK
[...]
$ dump-arsc.py resources.arsc
Binary APK
Package name=com.example.app id=7f
[...]
$ dump-arsc.py --apk some.apk
Binary APK
Package name=com.example.app id=7f
[...]
```

### dump-baseline.py

Dump `baseline.prof`/`baseline.profm` (extracted or inside an APK).

```bash
$ dump-baseline.py --help
usage: dump-baseline.py [-h] [--apk] [-v] PROF_OR_APK
[...]
$ dump-baseline.py baseline.prof
prof version=010 P
num_dex_files=4
[...]
$ dump-baseline.py baseline.profm
profm version=002
num_dex_files=4
[...]
$ dump-baseline.py some.apk
entry=assets/dexopt/baseline.prof
prof version=010 P
num_dex_files=4
[...]
entry=assets/dexopt/baseline.profm
profm version=002
num_dex_files=4
[...]
```

NB: does not support all file format versions yet.

### list-compresslevel.py

List ZIP entries with compression level.

```bash
$ list-compresslevel.py --help
usage: list-compresslevel.py [-h] APK
[...]
$ list-compresslevel.py some.apk
filename='AndroidManifest.xml' compresslevel=9|6
filename='classes.dex' compresslevel=None
filename='resources.arsc' compresslevel=None
[...]
filename='META-INF/CERT.SF' compresslevel=9|6
filename='META-INF/CERT.RSA' compresslevel=9|6|4
filename='META-INF/MANIFEST.MF' compresslevel=9|6|4
```

NB: the compression level is not actually stored anywhere in the ZIP file, and
is thus calculated by recompressing the data with different compression levels
and checking the CRC32 of the result against the CRC32 of the original
compressed data.

## CLI

NB: you can just use the scripts stand-alone; alternatively, you can install the
`repro-apk` Python package and use them as subcommands of `repro-apk`:

```bash
$ repro-apk diff-zip-meta a.apk b.apk
$ repro-apk diff-zip-meta a.apk c.apk --no-offsets --no-ordering
$ repro-apk dump-arsc resources.arsc
$ repro-apk dump-arsc --apk some.apk
$ repro-apk dump-baseline baseline.prof
$ repro-apk dump-baseline baseline.profm
$ repro-apk dump-baseline --apk some.apk
$ repro-apk fix-compresslevel unsigned.apk fixed.apk 6 assets/foo/bar.js
$ repro-apk fix-newlines unsigned.apk fixed.apk 'META-INF/services/*'
$ repro-apk list-compresslevel some.apk
$ repro-apk sort-apk some.apk sorted.apk
$ repro-apk sort-baseline baseline.profm baseline-sorted.profm
$ repro-apk sort-baseline --apk some.apk sorted-baseline.apk
```

### Help

```bash
$ repro-apk --help
$ repro-apk diff-zip-meta --help
$ repro-apk dump-arsc --help
$ repro-apk dump-baseline --help
$ repro-apk fix-compresslevel --help
$ repro-apk fix-newlines --help
$ repro-apk list-compresslevel --help
$ repro-apk sort-apk --help
$ repro-apk sort-baseline --help
```

## Installing

### Using pip

```bash
$ pip install repro-apk
```

NB: depending on your system you may need to use e.g. `pip3 --user`
instead of just `pip`.

### From git

NB: this installs the latest development version, not the latest
release.

```bash
$ git clone https://github.com/obfusk/reproducible-apk-tools.git
$ cd reproducible-apk-tools
$ pip install -e .
```

NB: you may need to add e.g. `~/.local/bin` to your `$PATH` in order
to run `repro-apk`.

To update to the latest development version:

```bash
$ cd reproducible-apk-tools
$ git pull --rebase
```

## Dependencies

* Python >= 3.8 + click (`repro-apk` package only, the stand-alone scripts have
  no dependencies besides Python).

* The `dump-arsc.py` script requires `aapt2`.

### Debian/Ubuntu

```bash
$ apt install python3-click
$ apt install aapt      # for dump-arsc.py
$ apt install zipalign  # for realignment; see examples
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
