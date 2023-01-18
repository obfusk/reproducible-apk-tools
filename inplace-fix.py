#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import os
import shutil
import subprocess
import sys
import tempfile


ZIPALIGN = ("zipalign", "4")


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


def main() -> None:
    usage = "%(prog)s [-h] [--zipalign] COMMAND INPUT_FILE [...]"
    parser = argparse.ArgumentParser(prog="inplace-fix.py", usage=usage)
    parser.add_argument("--zipalign", action="store_true")
    parser.add_argument("command", metavar="COMMAND")
    parser.add_argument("input_file", metavar="INPUT_FILE")
    args, rest = parser.parse_known_args()
    script = os.path.join(os.path.dirname(__file__), args.command + ".py")
    ext = os.path.splitext(args.input_file)[1]
    with tempfile.TemporaryDirectory() as tdir:
        fixed = os.path.join(tdir, "fixed" + ext)
        run_command(script, args.input_file, fixed, *rest)
        if args.zipalign:
            aligned = os.path.join(tdir, "aligned" + ext)
            run_command(*ZIPALIGN, fixed, aligned)
            print(f"[MOVE] {aligned} to {args.input_file}")
            shutil.move(aligned, args.input_file)
        else:
            print(f"[MOVE] {fixed} to {args.input_file}")
            shutil.move(fixed, args.input_file)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
