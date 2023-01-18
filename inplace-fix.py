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


COMMANDS = (
    "fix-compresslevel",
    "fix-newlines",
    "sort-apk",
    "sort-baseline",
)

ZIPALIGN = ("zipalign", "4")


class Error(RuntimeError):
    pass


def inplace_fix(command: str, input_file: str, *args: str,
                zipalign: bool = False) -> None:
    if command not in COMMANDS:
        raise Error(f"Unknown command {command}")
    script_dir = os.path.dirname(__file__)
    for cmd in (command, command.replace("-", "_")):
        script = os.path.join(script_dir, cmd + ".py")
        if os.path.exists(script):
            break
    else:
        raise Error(f"Script for {command} not found")
    ext = os.path.splitext(input_file)[1]
    exe = sys.executable or "python3"
    with tempfile.TemporaryDirectory() as tdir:
        fixed = os.path.join(tdir, "fixed" + ext)
        run_command(exe, script, input_file, fixed, *args, trim=2)
        if zipalign:
            aligned = os.path.join(tdir, "aligned" + ext)
            run_command(*ZIPALIGN, fixed, aligned)
            print(f"[MOVE] {aligned} to {input_file}")
            shutil.move(aligned, input_file)
        else:
            print(f"[MOVE] {fixed} to {input_file}")
            shutil.move(fixed, input_file)


def run_command(*args: str, trim: int = 1) -> None:
    targs = tuple(os.path.basename(a) for a in args[:trim]) + args[trim:]
    print(f"[RUN] {' '.join(targs)}")
    try:
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError as e:
        raise Error(f"{args[0]} command failed") from e
    except FileNotFoundError as e:
        raise Error(f"{args[0]} command not found") from e


def main() -> None:
    usage = "%(prog)s [-h] [--zipalign] COMMAND INPUT_FILE [...]"
    epilog = f"Commands: {', '.join(COMMANDS)}."
    parser = argparse.ArgumentParser(usage=usage, epilog=epilog)
    parser.add_argument("--zipalign", action="store_true")
    parser.add_argument("command", metavar="COMMAND")
    parser.add_argument("input_file", metavar="INPUT_FILE")
    args, rest = parser.parse_known_args()
    try:
        inplace_fix(args.command, args.input_file, *rest, zipalign=args.zipalign)
    except Error as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
