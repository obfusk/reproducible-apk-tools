# reproducible-apk-tools

## scripts to make apks reproducible

### fix-services-newlines.py

If the signed APK was built on Windows and has `META-INF/services/`
files with CRLF line endings whereas the unsigned APK was build on
Linux/macOS and has LF line endings, this script may help.

```bash
$ apksigcopier compare signed.apk --unsigned unsigned.apk
DOES NOT VERIFY
[...]
$ fix-services-newlines.py unsigned.apk fixed.apk
$ zipalign -f 4 fixed.apk fixed-aligned.apk
$ apksigcopier compare signed.apk --unsigned fixed-aligned.apk && echo OK
OK
```
