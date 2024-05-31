#!/bin/bash
set -ex
python="$1" dir="$2" cmd="$3"
shift 3
pycov() { "$python" -mcoverage run --data-file="$dir"/.coverage --source "$dir" "$@"; }
case "$cmd" in
  repro-apk)
    subcmd="$1"
    shift
    pycov -a "$dir"/"$subcmd".py "$@"
  ;;
  repro-apk-inplace-fix)
    pycov -a "$dir"/inplace-fix.py "$@"
  ;;
  *)
    exit 1
  ;;
esac
