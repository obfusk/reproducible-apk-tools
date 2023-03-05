#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

r"""
parse/dump android DEX

NB: work in progress; output format may change.

>>> types_apk("test/data/golden-aligned-in.apk", "*.dex")
entry='classes.dex'
android/app/Activity
android/appsecurity/cts/tinyapp/MainActivity
android/appsecurity/cts/tinyapp/R
android/appsecurity/cts/tinyapp/R$attr
android/appsecurity/cts/tinyapp/R$string
android/os/Bundle
dalvik/annotation/EnclosingClass
dalvik/annotation/InnerClass
dalvik/annotation/MemberClasses
int
java/lang/Object
void

"""

from __future__ import annotations

import binascii
import dataclasses
import hashlib
import json as _json
import logging
import re
import struct
import sys
import zipfile
import zlib

from dataclasses import dataclass, field
from enum import Enum, Flag
from fnmatch import fnmatch
from functools import cached_property
from typing import cast, Any, Callable, Dict, FrozenSet, Iterator, Optional, Tuple

# https://source.android.com/docs/core/runtime/dex-format

DEX_MAGIC = b"dex\n"
DEX_MAGIC_RE = re.compile(rb"dex\n(\d{3})\x00")

HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412
NO_INDEX = 0xFFFFFFFF

PRIMITIVES = dict(V="void", Z="boolean", B="byte", S="short", C="char",
                  I="int", J="long", F="float", D="double")
SHORTYNAME = re.compile(r"[VZBSCIJFDL][ZBSCIJFDL]*")
SIMPLENAME = re.compile(r"[\w$ -]+")
MEMBERNAME = re.compile(fr"{SIMPLENAME.pattern}|<{SIMPLENAME.pattern}>")
QUALIFIEDNAME = re.compile(fr"L((?:{SIMPLENAME.pattern}/)*(?:{SIMPLENAME.pattern}));")


class Error(Exception):
    """Base class for errors."""


class ParseError(Error):
    """Parse failure."""


class ChecksumError(Error):
    """Checksum mismatch."""


class AssertionFailed(Error):
    """Assertion failure."""


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


@dataclass(frozen=True)
class EncodedAnnotation:
    """Encoded annotation."""
    type_idx: int
    elements: Tuple[Tuple[int, EncodedValue], ...]  # name_idx + value


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
    """Method prototype ID."""
    shorty_idx: int                 # strings index
    return_type_idx: int            # types index
    parameters_off: int


@dataclass(frozen=True)
class Proto:
    """Method prototype."""
    shorty: str
    return_type: str
    parameters: Tuple[str, ...]


@dataclass(frozen=True)
class FieldID:
    """Field ID."""
    class_idx: int                  # types index
    type_idx: int                   # types index
    name_idx: int                   # strings index


@dataclass(frozen=True)
class Field:
    """Field."""
    definer: str
    type: str
    name: str


@dataclass(frozen=True)
class MethodID:
    """Method ID."""
    class_idx: int                  # types index
    proto_idx: int                  # protos index
    name_idx: int                   # strings index


@dataclass(frozen=True)
class Method:
    """Method."""
    definer: str
    proto: Proto
    name: str


@dataclass(frozen=True)
class ClassDef:
    """Class definition."""
    class_idx: int                  # types index
    access_flags: AccessFlags
    superclass_idx: int             # types index or NO_INDEX
    interfaces_off: int
    source_file_idx: int            # string index
    annotations_off: int
    class_data_off: int
    static_values_off: int


@dataclass(frozen=True)
class Class:
    """Class."""
    type: str
    access_flags: AccessFlags
    superclass: Optional[str]
    interfaces: Tuple[str, ...]
    source_file: Optional[str]
    annotations: Tuple[Annotation, ...]
    static_fields: Tuple[ClassField, ...]
    instance_fields: Tuple[ClassField, ...]
    direct_methods: Tuple[ClassMethod, ...]
    virtual_methods: Tuple[ClassMethod, ...]
    static_values: Tuple[EncodedValue, ...]


@dataclass(frozen=True)
class ClassField:
    """Class field."""
    field: Field
    access_flags: AccessFlags


@dataclass(frozen=True)
class ClassMethod:
    """Class method."""
    method: Method
    access_flags: AccessFlags
    code: Optional[Code]


# FIXME
@dataclass(frozen=True)
class Annotation:
    """Annotation."""


# FIXME
@dataclass(frozen=True)
class Code:
    """Code."""


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


# FIXME: class defs, ...
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

    @cached_property
    def types(self) -> FrozenSet[str]:
        """Types used in this DEX."""
        return frozenset(type_name(self.string(i)) for i in self.type_ids)

    @property
    def protos(self) -> Iterator[Proto]:
        """Method prototypes."""
        for p in self.proto_ids:
            yield self.proto(p)

    @property
    def fields(self) -> Iterator[Field]:
        """Fields."""
        for f in self.field_ids:
            yield self.field(f)

    @property
    def methods(self) -> Iterator[Method]:
        """Methods."""
        for m in self.method_ids:
            yield self.method(m)

    @property
    def classes(self) -> Iterator[Class]:
        """Classes."""
        for c in self.class_defs:
            yield self.klass(c)

    # FIXME: check shorty matches return type & params
    def proto(self, p: ProtoID) -> Proto:
        """Get method prototype from ID."""
        shorty = self.string(p.shorty_idx)
        _assert(SHORTYNAME.fullmatch(shorty), "shorty name")
        return Proto(shorty, self.type(p.return_type_idx),
                     tuple(map(self.type, self.type_list(p.parameters_off))))

    # FIXME: check is class
    def field(self, f: FieldID) -> Field:
        """Get field from ID."""
        name = self.string(f.name_idx)
        _assert(MEMBERNAME.fullmatch(name), "member name")
        return Field(self.type(f.class_idx), self.type(f.type_idx), name)

    # FIXME: check is class
    def method(self, m: MethodID) -> Method:
        """Get method from ID."""
        name = self.string(m.name_idx)
        _assert(MEMBERNAME.fullmatch(name), "member name")
        p = self.proto_ids[m.proto_idx]
        return Method(self.type(m.class_idx), self.proto(p), name)

    # FIXME: checks, annotations, ...
    def klass(self, c: ClassDef) -> Class:
        """Get class from def."""
        supr = None if c.superclass_idx == NO_INDEX else self.type(c.superclass_idx)
        file = None if c.source_file_idx == NO_INDEX else self.string(c.source_file_idx)
        return Class(
            type=self.type(c.class_idx),
            access_flags=c.access_flags,
            superclass=supr,
            interfaces=tuple(map(self.type, self.type_list(c.interfaces_off))),
            source_file=file,
            annotations=(),
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
            static_values=(),
        )

    def string(self, i: int) -> str:
        """Get string by index."""
        if i not in self._string_cache:
            off = self.string_offsets[i]
            _assert(off >= self.header.data_off, "in data section")
            _utf16_size, off = uleb128(self.raw_data, off)
            self._string_cache[i], _ = mutf8(self.raw_data, off)
        return self._string_cache[i]

    def type(self, i: int) -> str:
        """Get type name by type ID index."""
        return type_name(self.string(self.type_ids[i]))

    def type_list(self, off: int) -> Tuple[int, ...]:
        """Get type indices by offset."""
        if not off:
            return ()
        _assert(off >= self.header.data_off, "in data section")
        size, = struct.unpack("<I", self.raw_data[off:off + 4])
        return struct.unpack(f"<{size}H", self.raw_data[off + 4:off + 4 + size * 2])


def _assert(b: Any, what: Optional[str] = None) -> None:
    if not b:
        raise AssertionFailed("Assertion failed" + (f": {what}" if what else ""))


def dump(*files: str, json: bool = False, offsets: bool = True,
         quiet: bool = False, verbose: bool = False) -> None:
    """Parse DEX & dump to stdout."""
    _process_files(_dump, *files, json=json, offsets=offsets, quiet=quiet, verbose=verbose)


def dump_apk(apk: str, *patterns: str, json: bool = False, offsets: bool = True,
             quiet: bool = False, verbose: bool = False) -> None:
    """Parse DEX in APK & dump to stdout."""
    _process_apk(_dump, apk, *patterns, json=json, offsets=offsets, quiet=quiet, verbose=verbose)


def types(*files: str, json: bool = False, quiet: bool = False) -> None:
    """List types used in DEX to stdout."""
    _process_files(_types, *files, json=json, quiet=quiet)


def types_apk(apk: str, *patterns: str, json: bool = False, quiet: bool = False) -> None:
    """List types used in DEX in APK to stdout."""
    _process_apk(_types, apk, *patterns, json=json, quiet=quiet)


def _process_files(f: Callable[..., None], *files: str, json: bool,
                   quiet: bool, **kwargs: Any) -> None:
    for file in files:
        with open(file, "rb") as fh:
            if not quiet:
                if json:
                    print(_json.dumps([dict(file=file)]))
                else:
                    print(f"file={file!r}")
            f(fh.read(), json=json, **kwargs)


def _process_apk(f: Callable[..., None], apk: str, *patterns: str,
                 json: bool, quiet: bool, **kwargs: Any) -> None:
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            if fnmatches_with_negation(info.filename, *patterns):
                if not quiet:
                    if json:
                        print(_json.dumps([dict(entry=info.filename)]))
                    else:
                        print(f"entry={info.filename!r}")
                with zf.open(info.filename) as fh:
                    f(fh.read(), json=json, **kwargs)


def _dump(data: bytes, *, json: bool, offsets: bool, verbose: bool) -> None:
    _check_magic(data)
    dump_dex(parse(data), json=json, offsets=offsets, verbose=verbose)


def _types(data: bytes, *, json: bool) -> None:
    _check_magic(data)
    types_dex(parse(data), json=json)


def _check_magic(data: bytes) -> None:
    magic = data[:8]
    if magic[:4] != DEX_MAGIC or not DEX_MAGIC_RE.fullmatch(magic):
        raise Error(f"Unsupported magic {magic!r}")


# FIXME: incomplete, no JSON
# FIXME: protos, fields, methods, class_defs
def dump_dex(dex: DexFile, *, json: bool, offsets: bool, verbose: bool) -> None:
    """Dump DexFile to stdout."""
    if json:
        raise NotImplementedError("JSON not yet implemented")
    else:
        print("header:")
        print(f"  version={dex.header.version:03d}")
        if verbose:
            for f in dataclasses.fields(Header)[1:]:
                if f.name.endswith("_off") and not offsets:
                    continue
                v = getattr(dex.header, f.name)
                x = hex(v) if f.name in ("checksum", "endian_tag") else _safe(v)
                print(f"  {f.name}={x}")
        if verbose:
            print("map list:")
            for item in dex.map_list:
                info = f"size={item.size}"
                if offsets:
                    info += f", offset={item.offset}"
                print(f"  {item.type.name.lower()} [{info}]")
        for c in dex.classes:
            print(f"class {_safe(c.type)}:")
            if flags := '|'.join(cast(str, t.name).lower() for t in c.access_flags):
                print(f"  access_flags={flags}")
            if c.superclass:
                print(f"  superclass={_safe(c.superclass)}")
            if c.interfaces:
                print("  interfaces:")
                for t in c.interfaces:
                    print(f"    {_safe(t)}")
            if c.source_file:
                print(f"  source_file={_safe(c.source_file)}")
            ...


def types_dex(dex: DexFile, *, json: bool) -> None:
    """List types in DexFile to stdout."""
    if json:
        _json.dump(sorted(dex.types), sys.stdout, indent=2)
        print()
    else:
        for t in sorted(dex.types):
            print(_safe(t))


# FIXME: incomplete
# FIXME: link_{size,off}?!
def parse(data: bytes, *, verify_checksum: bool = True, verify_signature: bool = False,
          verify_header: bool = True, verify_map: bool = True) -> DexFile:
    """Parse DEX data to DexFile."""
    header = parse_header(data)
    if verify_header:
        check_header(data, header, verify_checksum=verify_checksum,
                     verify_signature=verify_signature)
    map_list = parse_map_list(data, header.map_off)
    if verify_map:
        check_map_list(header, map_list)
    string_offsets = parse_string_ids(data, header.string_ids_size, header.string_ids_off)
    type_ids = parse_type_ids(data, header.type_ids_size, header.type_ids_off)
    proto_ids = parse_proto_ids(data, header.proto_ids_size, header.proto_ids_off)
    field_ids = parse_field_ids(data, header.field_ids_size, header.field_ids_off)
    method_ids = parse_method_ids(data, header.method_ids_size, header.method_ids_off)
    class_defs = parse_class_defs(data, header.class_defs_size, header.class_defs_off)
    return DexFile(header=header, map_list=map_list, string_offsets=string_offsets,
                   type_ids=type_ids, proto_ids=proto_ids, field_ids=field_ids,
                   method_ids=method_ids, class_defs=class_defs, raw_data=data)


# FIXME
def check_header(data: bytes, header: Header, *, verify_checksum: bool,
                 verify_signature: bool) -> None:
    """Check header."""
    if (csum := zlib.adler32(data[12:])) != header.checksum:
        msg = f"Checksum mismatch (Adler-32): expected {header.checksum}, got {csum}"
        if verify_checksum:
            raise ChecksumError(msg)
        logging.getLogger(__name__).warning(msg)
    if (sign := hashlib.sha1(data[32:]).hexdigest()) != header.signature:
        msg = f"Checksum mismatch (SHA-1): expected {header.signature}, got {sign}"
        if verify_signature:
            raise ChecksumError(msg)
        logging.getLogger(__name__).warning(msg)
    if len(data) != header.file_size:
        raise ParseError(f"Filesize mismatch: expected {header.file_size}, got {len(data)}")


# FIXME
def check_map_list(header: Header, map_list: Tuple[MapItem, ...]) -> None:
    """Check map list."""
    prev_off, T = -1, MapItem.Type
    for x in map_list:
        _assert(x.offset > prev_off, "offsets increasing")
        prev_off = x.offset
        if x.type == T.HEADER_ITEM:
            _assert(x.offset == 0, "header at offset zero")
        elif T.STRING_ID_ITEM.value <= x.type.value <= T.CLASS_DEF_ITEM.value:
            k = x.type.name.replace("_ITEM", "").lower()
            _assert(x.offset == getattr(header, f"{k}s_off"), "offset equal")
            _assert(x.size == getattr(header, f"{k}s_size"), "size equal")
        else:
            if x.type == T.MAP_LIST:
                _assert(x.offset == header.map_off, "offset equal")
            _assert(x.offset >= header.data_off, "in data section")


def parse_header(data: bytes) -> Header:
    """Parse DEX header data to Header."""
    magic, checksum, signature, file_size, header_size, endian_tag \
        = struct.unpack("<8sI20sIII", data[:44])
    data = data[44:]
    _assert(header_size == HEADER_SIZE, "header size")
    _assert(endian_tag == ENDIAN_CONSTANT, "endian constant")
    rest = struct.unpack("<17I", data[:68])
    return Header(magic, checksum, binascii.hexlify(signature).decode(),
                  file_size, header_size, endian_tag, *rest)


def parse_map_list(data: bytes, off: int) -> Tuple[MapItem, ...]:
    n_items, = struct.unpack("<I", data[off:off + 4])
    result = []
    for i in range(n_items):
        dat = data[off + 4 + 12 * i:off + 4 + 12 * (i + 1)]
        typ, _, size, offset = struct.unpack("<HHII", dat)
        result.append(MapItem(MapItem.Type(typ), size, offset))
    return tuple(result)


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


def type_name(s: str) -> str:
    """
    Type descriptor to type name.

    >>> type_name("Z")
    'boolean'
    >>> type_name("[[I")
    'int[][]'
    >>> type_name("Ljava/lang/Object;")
    'java/lang/Object'

    """
    if s.startswith("["):
        t = s.lstrip("[")
        return type_name(t) + "[]" * (len(s) - len(t))
    if s in PRIMITIVES:
        return PRIMITIVES[s]
    if m := QUALIFIEDNAME.fullmatch(s):
        return m[1]
    raise Error(f"Unsupported type descriptor: {s!r}")


# FIXME
def encoded_value(data: bytes, off: int) -> Tuple[EncodedValue, int]:
    """Parse encoded value."""
    T = EncodedValue.Type
    arg_typ, = struct.unpack("<B", data[off:off + 1])
    off += 1
    arg = arg_typ >> 5
    typ = T(arg_typ & 0x1f)
    val: Any = None
    if typ == T.BYTE:
        _assert(arg == 0, "arg is zero")
        val = data[off:off + 1]
        off += 1
    elif T.SHORT.value <= typ.value <= T.ENUM.value:
        val = data[off:off + arg + 1]
        off += arg + 1
    elif typ == T.ARRAY:
        _assert(arg == 0, "arg is zero")
        val, off = encoded_array(data, off)
    elif typ == T.ANNOTATION:
        _assert(arg == 0, "arg is zero")
        val, off = encoded_annotation(data, off)
    elif typ == T.NULL:
        _assert(arg == 0, "arg is zero")
    elif typ == T.BOOLEAN:
        _assert(arg in (0, 1), "arg is 0 or 1")
        val = bool(arg)
    else:
        _assert(False, "unreachable")
    return EncodedValue(typ, val), off


def encoded_array(data: bytes, off: int) -> Tuple[Tuple[EncodedValue, ...], int]:
    """Parse encoded array value."""
    size, off = uleb128(data, off)
    result = []
    for i in range(size):
        val, off = encoded_value(data, off)
        result.append(val)
    return tuple(result), off


def encoded_annotation(data: bytes, off: int) -> Tuple[EncodedAnnotation, int]:
    """Parse encoded annotation."""
    type_idx, off = uleb128(data, off)
    size, off = uleb128(data, off)
    elements = []
    for i in range(size):
        name_idx, off = uleb128(data, off)
        val, off = encoded_value(data, off)
        elements.append((name_idx, val))
    return EncodedAnnotation(type_idx, tuple(elements)), off


def mutf8(data: bytes, off: int) -> Tuple[str, int]:
    """Parse MUTF-8 (modified UTF-8)."""
    end = data.index(b"\x00", off)
    s = data[off:end].replace(b"\xc0\x80", b"\x00")
    try:
        return s.decode("utf8"), end + 1
    except UnicodeDecodeError:
        return _decode_utf8_with_surrogates(s)[1], end + 1


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


def sleb128(data: bytes, off: int) -> Tuple[int, int]:
    r"""
    Parse signed LEB128.

    >>> sleb128(b"\x00", 0)
    (0, 1)
    >>> sleb128(b"\x01", 0)
    (1, 1)
    >>> sleb128(b"\x7f", 0)
    (-1, 1)
    >>> sleb128(b"\x80\x7f", 0)
    (-128, 2)

    """
    return _leb128(data, off, signed=True)


def uleb128(data: bytes, off: int) -> Tuple[int, int]:
    r"""
    Parse unsigned LEB128.

    >>> uleb128(b"\x00", 0)
    (0, 1)
    >>> sleb128(b"\x01", 0)
    (1, 1)
    >>> uleb128(b"\x7f", 0)
    (127, 1)
    >>> uleb128(b"\x80\x7f", 0)
    (16256, 2)

    """
    return _leb128(data, off, signed=False)


def uleb128p1(data: bytes, off: int) -> Tuple[int, int]:
    r"""
    Parse signed LEB128, encoded as value plus one (unsigned).

    >>> uleb128p1(b"\x00", 0)
    (-1, 1)
    >>> uleb128p1(b"\x01", 0)
    (0, 1)
    >>> uleb128p1(b"\x7f", 0)
    (126, 1)
    >>> uleb128p1(b"\x80\x7f", 0)
    (16255, 2)

    """
    n, off = uleb128(data, off)
    return n - 1, off


# https://en.wikipedia.org/wiki/LEB128
def _leb128(data: bytes, off: int, *, signed: bool) -> Tuple[int, int]:
    n = 0
    for i in range(5):
        n |= (data[off + i] & 0x7f) << (i * 7)
        if data[off + i] & 0x80 == 0:
            if signed and i < 4 and data[off + i] & 0x40:
                n |= -1 << ((i + 1) * 7)
            return n, off + i + 1
    raise ParseError("Expected significant bit set")


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
    sub_dump.add_argument("--no-offsets", action="store_true", help="don't show offsets")
    sub_dump.add_argument("-q", "--quiet", action="store_true", help="don't show filenames")
    sub_dump.add_argument("-v", "--verbose", action="store_true")
    sub_dump.add_argument("files_or_patterns", metavar="FILE_OR_PATTERN", nargs="+")
    sub_types = subs.add_parser("types", help="list types used in DEX")
    sub_types.add_argument("--apk", help="APK that contains the DEX file(s)")
    sub_types.add_argument("--json", action="store_true", help="output JSON")
    sub_types.add_argument("-q", "--quiet", action="store_true", help="don't show filenames")
    sub_types.add_argument("files_or_patterns", metavar="FILE_OR_PATTERN", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "dump":
            if args.apk:
                dump_apk(args.apk, *args.files_or_patterns, json=args.json,
                         offsets=not args.no_offsets, quiet=args.quiet, verbose=args.verbose)
            else:
                dump(*args.files_or_patterns, json=args.json, offsets=not args.no_offsets,
                     quiet=args.quiet, verbose=args.verbose)
        elif args.command == "types":
            if args.apk:
                types_apk(args.apk, *args.files_or_patterns, json=args.json, quiet=args.quiet)
            else:
                types(*args.files_or_patterns, json=args.json, quiet=args.quiet)
        else:
            raise Error(f"Unknown command: {args.command}")
    except Error as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        pass

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
