#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

r"""
parse/dump android DEX

NB: work in progress; output format may change.
"""

from __future__ import annotations

import binascii
import dataclasses
import hashlib
import json as _json
import re
import struct
import sys
import zipfile
import zlib

from dataclasses import dataclass, field
from enum import Enum, Flag
from fnmatch import fnmatch
from typing import Any, Dict, Iterator, Tuple

# https://source.android.com/docs/core/runtime/dex-format

DEX_MAGIC = b"dex\n"
DEX_MAGIC_RE = re.compile(rb"dex\n(\d{3})\x00")

HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412
NO_INDEX = 0xFFFFFFFF


class Error(Exception):
    """Base class for errors."""


class ParseError(Error):
    """Parse failure."""


class ChecksumError(Error):
    """Checksum mismatch."""


class AccessFlags(Flag):
    """Accessibility and other properties of classes and class members."""
    PUBLIC = 0x1
    PRIVATE = 0x2
    PROTECTED = 0x4
    STATIC = 0x8
    FINAL = 0x10
    SYNCHRONIZED = 0x20
    VOLATILE = 0x40
    BRIDGE = 0x40
    TRANSIENT = 0x80                # field
    VARARGS = 0x80                  # method
    NATIVE = 0x100
    INTERFACE = 0x200
    ABSTRACT = 0x400
    STRICT = 0x800
    SYNTHETIC = 0x1000
    ANNOTATION = 0x2000
    ENUM = 0x4000
    CONSTRUCTOR = 0x10000
    DECLARED_SYNCHRONIZED = 0x20000


# FIXME: unused
class Visibility(Enum):
    """Annotation item visibility."""
    BUILD = 0x00
    RUNTIME = 0x01
    SYSTEM = 0x02


@dataclass(frozen=True)
class EncodedValue:
    """Encoded value."""
    type: Type
    value: Any

    class Type(Enum):
        BYTE = 0x00
        SHORT = 0x02
        CHAR = 0x03
        INT = 0x04
        LONG = 0x06
        FLOAT = 0x10
        DOUBLE = 0x11
        METHOD_TYPE = 0x15
        METHOD_HANDLE = 0x16
        STRING = 0x17
        TYPE = 0x18
        FIELD = 0x19
        METHOD = 0x1a
        ENUM = 0x1b
        ARRAY = 0x1c
        ANNOTATION = 0x1d
        NULL = 0x1e
        BOOLEAN = 0x1f


# FIXME: unused
@dataclass(frozen=True)
class MapItem:
    """Map item."""
    type: Type
    size: int
    offset: int

    class Type(Enum):
        HEADER_ITEM = 0x0000
        STRING_ID_ITEM = 0x0001
        TYPE_ID_ITEM = 0x0002
        PROTO_ID_ITEM = 0x0003
        FIELD_ID_ITEM = 0x0004
        METHOD_ID_ITEM = 0x0005
        CLASS_DEF_ITEM = 0x0006
        CALL_SITE_ID_ITEM = 0x0007
        METHOD_HANDLE_ITEM = 0x0008
        MAP_LIST = 0x1000
        TYPE_LIST = 0x1001
        ANNOTATION_SET_REF_LIST = 0x1002
        ANNOTATION_SET_ITEM = 0x1003
        CLASS_DATA_ITEM = 0x2000
        CODE_ITEM = 0x2001
        STRING_DATA_ITEM = 0x2002
        DEBUG_INFO_ITEM = 0x2003
        ANNOTATION_ITEM = 0x2004
        ENCODED_ARRAY_ITEM = 0x2005
        ANNOTATIONS_DIRECTORY_ITEM = 0x2006
        HIDDENAPI_CLASS_DATA_ITEM = 0xF000


@dataclass(frozen=True)
class ProtoID:
    shorty_idx: int                 # strings index
    return_type_idx: int            # types index
    parameters_off: int


@dataclass(frozen=True)
class FieldID:
    class_idx: int                  # types index
    type_idx: int                   # types index
    name_idx: int                   # strings index


@dataclass(frozen=True)
class MethodID:
    class_idx: int                  # types index
    proto_idx: int                  # protos index
    name_idx: int                   # strings index


@dataclass(frozen=True)
class ClassDef:
    class_idx: int                  # types index
    access_flags: AccessFlags
    superclass_idx: int             # types index or NO_INDEX
    interfaces_off: int
    source_file_idx: int            # string index
    annotations_off: int
    class_data_off: int
    static_values_off: int


# FIXME
@dataclass(frozen=True)
class ClassData:
    ...


# FIXME: unused
@dataclass(frozen=True)
class MethodHandle:
    method_handle_type: Type
    field_or_method_id: int

    class Type(Enum):
        STATIC_PUT = 0x00
        STATIC_GET = 0x01
        INSTANCE_PUT = 0x02
        INSTANCE_GET = 0x03
        INVOKE_STATIC = 0x04
        INVOKE_INSTANCE = 0x05
        INVOKE_CONSTRUCTOR = 0x06
        INVOKE_DIRECT = 0x07
        INVOKE_INTERFACE = 0x08


@dataclass(frozen=True)
class Header:
    """DEX header."""
    magic: bytes
    checksum: int                   # Adler-32 of data[12:]
    signature: str                  # SHA-1 of data[32:]
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    @property
    def version(self) -> int:
        """Version from magic."""
        return int(self.magic[4:7])


# FIXME: incomplete
# FIXME: protos, fields, methods, class defs, ...
@dataclass(frozen=True)
class DexFile:
    """DEX file."""
    header: Header
    map_list: Tuple[MapItem, ...]
    string_offsets: Tuple[int, ...]
    type_ids: Tuple[int, ...]       # strings indices
    proto_ids: Tuple[ProtoID, ...]
    field_ids: Tuple[FieldID, ...]
    method_ids: Tuple[MethodID, ...]
    class_defs: Tuple[ClassDef, ...]
    raw_data: bytes
    _string_cache: Dict[int, str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_string_cache", {})

    @property
    def map_as_dict(self) -> Dict[MapItem.Type, MapItem]:
        """Map as dict."""
        return {x.type: x for x in self.map_list}

    def string(self, i: int) -> str:
        """Get string by index."""
        if i not in self._string_cache:
            o = self.string_offsets[i]
            _utf16_size, dat = uleb128(self.raw_data[o:o + 5])
            if b"\x00" not in dat:
                dat += self.raw_data[o + 5:self.raw_data.index(b"\x00", o + 5) + 1]
            self._string_cache[i] = mutf8(dat)[0]
        return self._string_cache[i]


# FIXME
def dump(*files: str, check_sums: bool = True, json: bool = False,
         verbose: bool = False) -> None:
    """Parse DEX & dump to stdout."""
    one = len(files) == 1
    for file in files:
        with open(file, "rb") as fh:
            if not one:
                if json:
                    print(_json.dumps([dict(file=file)]))
                else:
                    print(f"file={file!r}")
            _dump(fh.read(), check_sums=check_sums, json=json, verbose=verbose)


# FIXME
def dump_apk(apk: str, *patterns: str, check_sums: bool = True,
             json: bool = False, verbose: bool = False) -> None:
    """Parse DEX in APK & dump to stdout."""
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            if fnmatches_with_negation(info.filename, *patterns):
                if json:
                    print(_json.dumps([dict(entry=info.filename)]))
                else:
                    print(f"entry={info.filename!r}")
                with zf.open(info.filename) as fh:
                    _dump(fh.read(), check_sums=check_sums, json=json, verbose=verbose)


def _dump(data: bytes, *, check_sums: bool, json: bool, verbose: bool) -> None:
    magic = data[:8]
    if magic[:4] == DEX_MAGIC and DEX_MAGIC_RE.match(magic):
        dump_dex(parse(data, check_sums=check_sums), json=json, verbose=verbose)
    else:
        raise Error(f"Unsupported magic {magic!r}")


# FIXME: incomplete, no JSON
def dump_dex(dex: DexFile, *, json: bool, verbose: bool) -> None:
    """Dump DexFile to stdout."""
    if json:
        raise NotImplementedError("JSON not yet implemented")
    else:
        print("DEX HEADER")
        print(f"  version={dex.header.version:03d}")
        if verbose:
            for f in dataclasses.fields(Header)[1:]:
                v = getattr(dex.header, f.name)
                x = hex(v) if f.name in ("checksum", "endian_tag") else _safe(v)
                print(f"  {f.name}={x}")
        ...


# FIXME: incomplete
# FIXME: link_{size,off}?!
def parse(data: bytes, *, check_sums: bool = True) -> DexFile:
    """Parse DEX data to DexFile."""
    header = parse_header(data)
    if check_sums:
        csum = zlib.adler32(data[12:])
        sha1 = hashlib.sha1(data[32:])
        if csum != header.checksum:
            raise ChecksumError("Checksum mismatch (Adler-32): "
                                f"expected {header.checksum}, got {csum}")
        if (sign := sha1.hexdigest()) != header.signature:
            raise ChecksumError("Checksum mismatch (SHA-1): "
                                f"expected {header.signature}, got {sign}")
    if len(data) != header.file_size:
        raise ParseError(f"Filesize mismatch: expected {header.file_size}, got {len(data)}")
    map_list = tuple(parse_map_list(data, header.map_off))
    string_offsets = parse_string_ids(data, header.string_ids_size, header.string_ids_off)
    type_ids = parse_type_ids(data, header.type_ids_size, header.type_ids_off)
    proto_ids = parse_proto_ids(data, header.proto_ids_size, header.proto_ids_off)
    field_ids = parse_field_ids(data, header.field_ids_size, header.field_ids_off)
    method_ids = parse_method_ids(data, header.method_ids_size, header.method_ids_off)
    class_defs = parse_class_defs(data, header.class_defs_size, header.class_defs_off)
    return DexFile(header=header, map_list=map_list, string_offsets=string_offsets,
                   type_ids=type_ids, proto_ids=proto_ids, field_ids=field_ids,
                   method_ids=method_ids, class_defs=class_defs, raw_data=data)


def parse_header(data: bytes) -> Header:
    """Parse DEX header data to Header."""
    magic, checksum, signature, file_size, header_size, endian_tag \
        = struct.unpack("<8sI20sIII", data[:44])
    data = data[44:]
    assert header_size == HEADER_SIZE
    assert endian_tag == ENDIAN_CONSTANT
    rest = struct.unpack("<17I", data[:68])
    return Header(magic, checksum, binascii.hexlify(signature).decode(),
                  file_size, header_size, endian_tag, *rest)


def parse_map_list(data: bytes, off: int) -> Iterator[MapItem]:
    n_items, = struct.unpack("<I", data[off:off + 4])
    for i in range(n_items):
        dat = data[off + 4 + 12 * i:off + 4 + 12 * (i + 1)]
        typ, _, size, offset = struct.unpack("<HHII", dat)
        yield MapItem(MapItem.Type(typ), size, offset)


def parse_string_ids(data: bytes, size: int, off: int) -> Tuple[int, ...]:
    if not size:
        return ()
    return struct.unpack(f"<{size}I", data[off:off + 4 * size])


def parse_type_ids(data: bytes, size: int, off: int) -> Tuple[int, ...]:
    if not size:
        return ()
    return struct.unpack(f"<{size}I", data[off:off + 4 * size])


def parse_proto_ids(data: bytes, size: int, off: int) -> Tuple[ProtoID, ...]:
    if not size:
        return ()
    result = []
    for i in range(size):
        values = struct.unpack("<III", data[off + 12 * i:off + 12 * (i + 1)])
        result.append(ProtoID(*values))
    return tuple(result)


def parse_field_ids(data: bytes, size: int, off: int) -> Tuple[FieldID, ...]:
    if not size:
        return ()
    result = []
    for i in range(size):
        values = struct.unpack("<HHI", data[off + 8 * i:off + 8 * (i + 1)])
        result.append(FieldID(*values))
    return tuple(result)


def parse_method_ids(data: bytes, size: int, off: int) -> Tuple[MethodID, ...]:
    if not size:
        return ()
    result = []
    for i in range(size):
        values = struct.unpack("<HHI", data[off + 8 * i:off + 8 * (i + 1)])
        result.append(MethodID(*values))
    return tuple(result)


def parse_class_defs(data: bytes, size: int, off: int) -> Tuple[ClassDef, ...]:
    if not size:
        return ()
    result = []
    for i in range(size):
        class_idx, access_flags, *rest = \
            struct.unpack("<8I", data[off + 32 * i:off + 32 * (i + 1)])
        result.append(ClassDef(class_idx, AccessFlags(access_flags), *rest))
    return tuple(result)


# FIXME: unused
def parse_call_site_ids(data: bytes, size: int, off: int) -> Tuple[int, ...]:
    if not size:
        return ()
    return struct.unpack(f"<{size}I", data[off:off + 4 * size])


# FIXME: unused
def parse_method_handles(data: bytes, size: int, off: int) -> Tuple[MethodHandle, ...]:
    if not size:
        return ()
    result = []
    for i in range(size):
        method_handle_type, _, field_or_method_id, _ = \
            struct.unpack("<4H", data[off + 16 * i:off + 16 * (i + 1)])
        result.append(MethodHandle(MethodHandle.Type(method_handle_type), field_or_method_id))
    return tuple(result)


# FIXME
def encoded_value(data: bytes) -> Tuple[EncodedValue, bytes]:
    """Parse encoded value."""
    T = EncodedValue.Type
    arg_typ, data = _unpack("<B", data)
    arg = arg_typ >> 5
    typ = T(arg_typ & 0x1f)
    val: Any = None
    if typ == T.BYTE:
        assert arg == 0
        val, data = _split(data, 1)
    elif T.SHORT.value <= typ.value <= T.ENUM.value:
        val, data = _split(data, arg + 1)
    elif typ == T.ARRAY:
        assert arg == 0
        val, data = encoded_array(data)
    elif typ == T.ANNOTATION:
        assert arg == 0
        val, data = encoded_annotation(data)
    elif typ == T.NULL:
        assert arg == 0
    elif typ == T.BOOLEAN:
        assert arg in (0, 1)
        val = bool(arg)
    else:
        assert False
    return EncodedValue(typ, val), data


def encoded_array(data: bytes) -> Tuple[Tuple[EncodedValue, ...], bytes]:
    """Parse encoded array value."""
    size, data = uleb128(data)
    result = []
    for i in range(size):
        val, data = encoded_value(data)
        result.append(val)
    return tuple(result), data


def encoded_annotation(data: bytes) -> Tuple[Tuple[Tuple[int, EncodedValue], ...], bytes]:
    """Parse encoded annotation."""
    type_idx, data = uleb128(data)
    size, data = uleb128(data)
    result = []
    for i in range(size):
        name_idx, data = uleb128(data)
        val, data = encoded_value(data)
        result.append((name_idx, val))
    return tuple(result), data


def mutf8(data: bytes) -> Tuple[str, bytes]:
    """Parse MUTF-8 (modified UTF-8)."""
    s, data = data.split(b"\x00", 1)
    s = s.replace(b"\xc0\x80", b"\x00")
    try:
        return s.decode("utf8"), data
    except UnicodeDecodeError:
        return _decode_utf8_with_surrogates(s)[1], data


def _decode_utf8_with_surrogates(b: bytes) -> Tuple[int, str]:
    s = b.decode("utf8", errors="surrogatepass")
    i, n, t = 0, len(s), []
    while i < n:
        if i != n - 1:
            o1, o2 = ord(s[i]), ord(s[i + 1])
            if 0xd800 <= o1 <= 0xdbff and 0xdc00 <= o2 <= 0xdfff:
                t.append(chr(0x10000 + (((o1 - 0xd800) << 10) | (o2 - 0xdc00))))
                i += 2
                continue
        t.append(s[i])
        i += 1
    return n, "".join(t)


def sleb128(data: bytes) -> Tuple[int, bytes]:
    r"""
    Parse signed LEB128.

    >>> sleb128(b"\x00")
    (0, b'')
    >>> sleb128(b"\x01")
    (1, b'')
    >>> sleb128(b"\x7f")
    (-1, b'')
    >>> sleb128(b"\x80\x7f")
    (-128, b'')

    """
    return _leb128(data, signed=True)


def uleb128(data: bytes) -> Tuple[int, bytes]:
    r"""
    Parse unsigned LEB128.

    >>> uleb128(b"\x00")
    (0, b'')
    >>> sleb128(b"\x01")
    (1, b'')
    >>> uleb128(b"\x7f")
    (127, b'')
    >>> uleb128(b"\x80\x7f")
    (16256, b'')

    """
    return _leb128(data, signed=False)


def uleb128p1(data: bytes) -> Tuple[int, bytes]:
    r"""
    Parse signed LEB128, encoded as value plus one (unsigned).

    >>> uleb128p1(b"\x00")
    (-1, b'')
    >>> uleb128p1(b"\x01")
    (0, b'')
    >>> uleb128p1(b"\x7f")
    (126, b'')
    >>> uleb128p1(b"\x80\x7f")
    (16255, b'')

    """
    n, rest = uleb128(data)
    return n - 1, rest


# https://en.wikipedia.org/wiki/LEB128
def _leb128(data: bytes, *, signed: bool) -> Tuple[int, bytes]:
    n = 0
    for i in range(5):
        n |= (data[i] & 0x7f) << (i * 7)
        if data[i] & 0x80 == 0:
            if signed and i < 4 and data[i] & 0x40:
                n |= -1 << ((i + 1) * 7)
            return n, data[i + 1:]
    raise ParseError("Expected significant bit set")


def _unpack(fmt: str, data: bytes) -> Tuple[Any, ...]:
    f = fmt.upper()
    assert all(c in "<BHIQ" for c in f)
    size = f.count("B") + 2 * f.count("H") + 4 * f.count("I") + 8 * f.count("Q")
    return struct.unpack(fmt, data[:size]) + (data[size:],)


def _split(data: bytes, size: int) -> Tuple[bytes, bytes]:
    return data[:size], data[size:]


def _safe(x: Any) -> str:
    if not isinstance(x, str):
        return repr(x)
    return "".join(c if c.isprintable() and c != '\\' else repr(c)[1:-1] for c in x)


def fnmatches_with_negation(filename: str, *patterns: str) -> bool:
    r"""
    Filename matching with shell patterns and negation.

    Checks whether filename matches any of the fnmatch patterns.

    An optional prefix "!" negates the pattern, invalidating a successful match
    by any preceding pattern; use a backslash ("\") in front of the first "!"
    for patterns that begin with a literal "!".

    >>> fnmatches_with_negation("foo.xml", "*", "!*.png")
    True
    >>> fnmatches_with_negation("foo.png", "*", "!*.png")
    False
    >>> fnmatches_with_negation("!foo.png", r"\!*.png")
    True

    """
    matches = False
    for p in patterns:
        if p.startswith("!"):
            if fnmatch(filename, p[1:]):
                matches = False
        else:
            if p.startswith(r"\!"):
                p = p[1:]
            if fnmatch(filename, p):
                matches = True
    return matches


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="dex.py")
    subs = parser.add_subparsers(title="subcommands", dest="command")
    subs.required = True
    sub_dump = subs.add_parser("dump", help="parse & dump DEX")
    sub_dump.add_argument("--apk", help="APK that contains the DEX file(s)")
    sub_dump.add_argument("--json", action="store_true", help="output JSON")
    sub_dump.add_argument("--no-check-sums", dest="check_sums", action="store_false",
                          help="don't check Adler-32/SHA-1")
    sub_dump.add_argument("-v", "--verbose", action="store_true")
    sub_dump.add_argument("files_or_patterns", metavar="FILE_OR_PATTERN", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "dump":
            if args.apk:
                dump_apk(args.apk, *args.files_or_patterns, check_sums=args.check_sums,
                         json=args.json, verbose=args.verbose)
            else:
                dump(*args.files_or_patterns, check_sums=args.check_sums,
                     json=args.json, verbose=args.verbose)
        else:
            raise Error(f"Unknown command: {args.command}")
    except Error as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        pass

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
