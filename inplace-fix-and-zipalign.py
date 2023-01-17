#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import subprocess
import sys
import tempfile


def run_command(*args: str) -> None:
    args_ = (os.path.basename(args[0]),) + args[1:]
    print(f"[RUN] {' '.join(args_)}")
    try:
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError:
        print(f"Error: {args[0]} command failed.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: {args[0]} command not found.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    usage = "%(prog)s COMMAND INPUT_APK [...]"
    parser = argparse.ArgumentParser(prog="inplace-fix-and-zipalign.py", usage=usage)
    parser.add_argument("command", metavar="COMMAND")
    parser.add_argument("input_apk", metavar="INPUT_APK")
    args, rest = parser.parse_known_args()
    script = os.path.join(os.path.dirname(__file__), args.command + ".py")
    with tempfile.TemporaryDirectory() as tdir:
        fixed_apk = os.path.join(tdir, "fixed.apk")
        aligned_apk = os.path.join(tdir, "aligned.apk")
        run_command(script, args.input_apk, fixed_apk, *rest)
        run_command("zipalign", "4", fixed_apk, aligned_apk)
        print(f"[MOVE] {aligned_apk} to {args.input_apk}")
        os.replace(aligned_apk, args.input_apk)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
