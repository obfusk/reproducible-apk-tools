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

## scripts to make apks reproducible

### fix-newlines.py

If the signed APK was built on Windows and has e.g. `META-INF/services/` files
with CRLF line endings whereas the unsigned APK was build on Linux/macOS and has
LF line endings, this script may help.

```bash
$ fix-newlines.py --help
Usage: fix-newlines.py [--from-crlf] [--verbose] INPUT_APK OUTPUT_APK PATTERN...
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

### sort-apk.py

Sorts (and w/o `--no-realign` also realigns) the ZIP entries of an APK.

```bash
$ sort-apk.py --help
Usage: sort-apk.py [--no-realign] [--no-force-align] INPUT_APK OUTPUT_APK
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

## CLI

NB: you can just use the scripts stand-alone; alternatively, you can install the
`repro-apk` Python package and use them as subcommands of `repro-apk`:

```bash
$ repro-apk fix-newlines unsigned.apk fixed.apk 'META-INF/services/*'
$ repro-apk sort-apk some.apk sorted.apk
```

### Help

```bash
$ repro-apk --help
$ repro-apk fix-newlines --help
$ repro-apk sort-apk --help
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

### Debian/Ubuntu

```bash
$ apt install python3-click
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
