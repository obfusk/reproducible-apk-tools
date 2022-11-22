# reproducible-apk-tools

## scripts to make apks reproducible

### fix-services-newlines.py

If the signed APK was built on Windows and has `META-INF/services/` files with
CRLF line endings whereas the unsigned APK was build on Linux/macOS and has LF
line endings, this script may help.

```bash
$ fix-services-newlines.py --help
Usage: fix-services-newlines.py [--from-crlf] [--verbose] INPUT_APK OUTPUT_APK
$ apksigcopier compare signed.apk --unsigned unsigned.apk
DOES NOT VERIFY
[...]
$ fix-services-newlines.py unsigned.apk fixed.apk
$ zipalign -f 4 fixed.apk fixed-aligned.apk
$ apksigcopier compare signed.apk --unsigned fixed-aligned.apk && echo OK
OK
```

### sort-apk.py

Sorts (and w/o `--no-realign` also realigns) the ZIP entries of an APK.

```bash
$ sort-apk.py --help
Usage: sort-apk.py [--no-realign] INPUT_APK OUTPUT_APK
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
