#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

r"""
parse/dump android binary XML (AXML) or resources (ARSC)

NB: work in progress; output format may change.

>>> dump("test/data/AndroidManifest.xml")
file='test/data/AndroidManifest.xml'
XML
  STRING POOL [#strings=16, #styles=0]
  XML RESOURCE MAP [#resources=6]
  XML NS START [lineno=1, prefix='android', uri='http://schemas.android.com/apk/res/android']
    XML ELEM START [lineno=1, name='manifest', #attributes=7]
      ATTR: http://schemas.android.com/apk/res/android:versionCode=1
      ATTR: http://schemas.android.com/apk/res/android:versionName='1'
      ATTR: http://schemas.android.com/apk/res/android:compileSdkVersion=29
      ATTR: http://schemas.android.com/apk/res/android:compileSdkVersionCodename='10.0.0'
      ATTR: package='com.example'
      ATTR: platformBuildVersionCode=29
      ATTR: platformBuildVersionName='10.0.0'
      XML ELEM START [lineno=2, name='uses-sdk', #attributes=2]
        ATTR: http://schemas.android.com/apk/res/android:minSdkVersion=21
        ATTR: http://schemas.android.com/apk/res/android:targetSdkVersion=29
      XML ELEM END [lineno=2, name='uses-sdk']
    XML ELEM END [lineno=1, name='manifest']
  XML NS END [lineno=1, prefix='android', uri='http://schemas.android.com/apk/res/android']

>>> dump_apk("test/data/golden-aligned-in.apk", "resources.arsc")
entry='resources.arsc'
RESOURCE TABLE
  STRING POOL [flags=0x100, #strings=3, #styles=0]
  PACKAGE [id=0x7f, package_name='android.appsecurity.cts.tinyapp']
    STRING POOL [flags=0x100, #strings=2, #styles=0]
    STRING POOL [flags=0x100, #strings=1, #styles=0]
    TYPE SPEC [id=0x1, type_name='attr', #resources=0]
    TYPE SPEC [id=0x2, type_name='string', #resources=1]
    TYPE [id=0x2, type_name='string', #entries=1]
      CONFIG [default]
      ENTRY [id=0x7f020000, key='app_name']
        VALUE: 'Tiny App for CTS'
    TYPE [id=0x2, type_name='string', #entries=1]
      CONFIG [language='en', region='XA']
      ENTRY [id=0x7f020000, key='app_name']
        VALUE: '[Ţîñý Åþþ ƒöŕ ÇŢŠ one two three]'
    TYPE [id=0x2, type_name='string', #entries=1]
      CONFIG [language='ar', region='XB']
      ENTRY [id=0x7f020000, key='app_name']
        VALUE: '\u200f\u202eTiny\u202c\u200f \u200f\u202eApp\u202c\u200f \u200f\u202efor\u202c\u200f \u200f\u202eCTS\u202c\u200f'

>>> dump("test/data/AndroidManifest.xml", xml=True)
<!-- file='test/data/AndroidManifest.xml' -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1" android:compileSdkVersion="29" android:compileSdkVersionCodename="10.0.0" package="com.example" platformBuildVersionCode="29" platformBuildVersionName="10.0.0">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29" />
</manifest>

>>> dump("test/data/network_security_config.xml", xml=True)
<!-- file='test/data/network_security_config.xml' -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">amazonaws.com</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">f-droid.org</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">github.com</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">githubusercontent.com</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">github.io</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">gitlab.com</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">gitlab.io</domain>
  </domain-config>
</network-security-config>

>>> dump_apk("test/data/golden-aligned-in.apk", "AndroidManifest.xml", xml=True)
<!-- entry='AndroidManifest.xml' -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="10" android:versionName="1.0" package="android.appsecurity.cts.tinyapp" platformBuildVersionCode="23" platformBuildVersionName="6.0-2166767">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="23" />
  <application android:label="@0x7f020000">
    <activity android:label="@0x7f020000" android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>

>>> dump_apk("test/data/golden-aligned-in.apk", "AndroidManifest.xml", xml=True, xml_deref=True)
<!-- entry='AndroidManifest.xml' -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="10" android:versionName="1.0" package="android.appsecurity.cts.tinyapp" platformBuildVersionCode="23" platformBuildVersionName="6.0-2166767">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="23" />
  <application android:label="Tiny App for CTS">
    <activity android:label="Tiny App for CTS" android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>

>>> fastid("test/data/golden-aligned-in.apk")
package=android.appsecurity.cts.tinyapp versionCode=10 versionName=1.0

>>> fastperms("test/data/perms.apk", with_id=True)
file='test/data/perms.apk'
package=com.example versionCode=1 versionName=1
permission=android.permission.CAMERA
permission=android.permission.READ_EXTERNAL_STORAGE [maxSdkVersion=23]

>>> fastperms("test/data/perms.apk", json=True, with_id=True)
[
  {
    "package": "com.example",
    "versionCode": 1,
    "versionName": "1",
    "permissions": [
      {
        "permission": "android.permission.CAMERA",
        "attributes": {}
      },
      {
        "permission": "android.permission.READ_EXTERNAL_STORAGE",
        "attributes": {
          "maxSdkVersion": "23"
        }
      }
    ]
  }
]

>>> _ = manifest_info("test/data/golden-aligned-in.apk", extended=True)
{
  "test/data/golden-aligned-in.apk": {
    "appid": "android.appsecurity.cts.tinyapp",
    "version_code": 10,
    "version_name": "1.0",
    "min_sdk": 23,
    "target_sdk": 23,
    "features": [],
    "permissions": [],
    "abis": [
      "armeabi"
    ],
    "app_label": {
      "": [
        "Tiny App for CTS"
      ],
      "ar-XB": [
        "\u200f\u202eTiny\u202c\u200f \u200f\u202eApp\u202c\u200f \u200f\u202efor\u202c\u200f \u200f\u202eCTS\u202c\u200f"
      ],
      "en-XA": [
        "[\u0162\u00ee\u00f1\u00fd \u00c5\u00fe\u00fe \u0192\u00f6\u0155 \u00c7\u0162\u0160 one two three]"
      ]
    },
    "app_icon": null
  }
}

"""

from __future__ import annotations

import binascii
import dataclasses
import io
import itertools
import json as _json
import logging
import os
import re
import struct
import sys
import textwrap
import weakref
import xml.etree.ElementTree as ET
import zipfile
import zlib

from collections import namedtuple
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from functools import cached_property, lru_cache
from typing import (cast, Any, BinaryIO, Callable, ClassVar, Dict, Iterable, Iterator,
                    List, Optional, Set, TextIO, Tuple, Union, TYPE_CHECKING)

# https://android.googlesource.com/platform/tools/base
#   apkparser/binary-resources/src/main/java/com/google/devrel/gmscore/tools/apk/arsc/*.java
# https://android.googlesource.com/platform/frameworks/base
#   libs/androidfw/include/androidfw/ResourceTypes.h
#   tools/aapt2/ResourceValues.cpp

ARSC_MAGIC = b"\x02\x00\x0c\x00"
AXML_MAGIC = b"\x03\x00\x08\x00"

MANIFEST = "AndroidManifest.xml"
ARSC_FILE = "resources.arsc"
AXML_FILES = (MANIFEST, "res/*.xml")

SCHEMA_ANDROID = "http://schemas.android.com/apk/res/android"
UTF8, UTF16 = ("utf8", "utf_16_le")

XML_PROLOG = '<?xml version="1.0" encoding="UTF-8"?>'

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))


class Error(Exception):
    """Base class for errors."""


class ParseError(Error):
    """Parse failure."""


class ParentError(Error):
    """Missing/deallocated parent."""


class ChildError(Error):
    """Missing child."""


class ZipError(Error):
    """Something wrong with ZIP file."""


class ResourceError(Error):
    """Resource retrieval failure."""


class ResourceNotFound(ResourceError):
    """Resource not found."""


@dataclass(frozen=True)
class Chunk:
    """Base class for chunks."""
    header_size: int
    chunk_size: int
    parent: Optional[ChunkRef] = field(repr=False, compare=False)
    level: int = field(compare=False)
    offset: int = field(compare=False)

    TYPE_ID: ClassVar[Optional[int]] = None
    HIDDEN_FIELDS: ClassVar[Tuple[str, ...]] = ("header_size", "chunk_size", "level", "offset")

    @classmethod
    def _parse(_cls, header: bytes, payload: bytes, **kwargs: Any) -> Dict[str, Any]:
        header_size = len(header) + 8
        chunk_size = len(payload) + header_size
        return dict(header_size=header_size, chunk_size=chunk_size, **kwargs)

    @property
    def type_id(self) -> int:
        if self.__class__.TYPE_ID is not None:
            return self.__class__.TYPE_ID
        raise NotImplementedError("No .TYPE_ID or custom .type_id")

    @classmethod
    def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
        return _fields(cls)     # type: ignore[arg-type]


@dataclass(frozen=True)
class ParentChunk(Chunk):
    """Base class for chunks with children."""
    children: Tuple[Chunk, ...] = field(repr=False, compare=False)

    @classmethod
    def _parse(_cls, header: bytes, payload: bytes, **kwargs: Any) -> Dict[str, Any]:
        return Chunk._parse(header=header, payload=payload, children=None, **kwargs)

    def _parse_children(self, payload: bytes) -> None:
        c = tuple(read_chunks(payload, weakref.ref(self), self.level + 1, self.header_size))
        object.__setattr__(self, "children", c)


@dataclass(frozen=True)
class StringPoolChunk(Chunk):
    """String pool."""
    flags: int
    strings: Tuple[str, ...]
    styles: Tuple[Style, ...]

    TYPE_ID: ClassVar[int] = 0x0001

    FLAG_SORTED: ClassVar[int] = 0x1
    FLAG_UTF8: ClassVar[int] = 0x100

    @dataclass(frozen=True)
    class Style:
        """String pool style."""
        spans: Tuple[StringPoolChunk.Span, ...]

        SPAN_END: ClassVar[int] = 0xFFFFFFFF

        @classmethod
        def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
            return _fields(cls)     # type: ignore[arg-type]

    @dataclass(frozen=True)
    class Span:
        """String pool style span."""
        name_idx: int
        start: int
        stop: int
        parent: StringPoolChunkRef = field(repr=False, compare=False)

        @property
        def name(self) -> str:
            """Get name from parent."""
            if (p := self.parent()) is not None:
                return p.string(self.name_idx)
            raise ParentError("Parent deallocated")

        @classmethod
        def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
            return _fields(cls)     # type: ignore[arg-type]

    # FIXME: check payload size
    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> StringPoolChunk:
        """Parse StringPoolChunk."""
        d = Chunk._parse(header=header, payload=payload, **kwargs)
        n_strs, n_styles, flags, strs_start, styles_start = struct.unpack("<IIIII", header)
        codec = UTF8 if flags & cls.FLAG_UTF8 else UTF16
        strings = tuple(_read_strings(payload, strs_start - d["header_size"], n_strs, codec))
        chunk = cls(**d, flags=flags, strings=strings, styles=())
        styles = tuple(_read_styles(payload, styles_start - d["header_size"],
                                    n_styles, n_strs, weakref.ref(chunk)))
        object.__setattr__(chunk, "styles", styles)
        return chunk

    @property
    def is_sorted(self) -> bool:
        """Whether the sorted flag is set."""
        return bool(self.flags & self.FLAG_SORTED)

    @property
    def is_utf8(self) -> bool:
        """Whether the UTF-8 flag is set."""
        return bool(self.flags & self.FLAG_UTF8)

    def string(self, idx: Optional[int]) -> str:
        """Get string by index."""
        return "" if idx is None else self.strings[idx]

    def style(self, idx: int) -> Style:
        """Get style by index."""
        return self.styles[idx]

    @property
    def styled_strings(self) -> Iterable[Tuple[Optional[str], Optional[Style]]]:
        """Paired strings & styles."""
        return itertools.zip_longest(self.strings, self.styles)


# FIXME: string array, styled string, ...
@dataclass(frozen=True)
class ResourceTableChunk(ParentChunk):
    """Resource table; contains string pool and packages."""
    string_pool: StringPoolChunk = field(repr=False, compare=False)
    packages: Tuple[Tuple[str, PackageChunk], ...] = field(repr=False, compare=False)

    TYPE_ID: ClassVar[int] = 0x0002

    EntryFilter = Enum("EntryFilter", ("ALL",), start=0)

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> ResourceTableChunk:
        """Parse ResourceTableChunk."""
        d = ParentChunk._parse(header=header, payload=payload, **kwargs)
        _size, = struct.unpack("<I", header)
        chunk = cls(**d, string_pool=cast(StringPoolChunk, None), packages=())
        chunk._parse_children(payload)
        string_pool, packages = None, []
        for c in chunk.children:
            if isinstance(c, PackageChunk):
                packages.append((c.package_name, c))
            elif isinstance(c, StringPoolChunk):
                if string_pool is not None:
                    raise ParseError("Multiple StringPoolChunk children")
                string_pool = c
        if string_pool is None:
            raise ParseError("No StringPoolChunk child")
        object.__setattr__(chunk, "string_pool", string_pool)
        object.__setattr__(chunk, "packages", tuple(packages))
        return chunk

    def get_bool(self, id: int, *, language: Optional[str] = None,
                 region: Optional[str] = None, density: int = 0) -> bool:
        """Get bool value."""
        e = self.get_entry(id, typ=BinResVal.Type.INT_BOOLEAN, language=language,
                           region=region, density=density)
        assert e.value is not None
        return False if e.value.data == 0 else True

    # FIXME: INT_HEX?!
    def get_int(self, id: int, *, language: Optional[str] = None,
                region: Optional[str] = None, density: int = 0) -> int:
        """Get int value."""
        e = self.get_entry(id, typ=BinResVal.Type.INT_DEC, language=language,
                           region=region, density=density)
        assert e.value is not None
        return e.value.data

    def get_float(self, id: int, *, language: Optional[str] = None,
                  region: Optional[str] = None, density: int = 0) -> float:
        """Get float value."""
        e = self.get_entry(id, typ=BinResVal.Type.FLOAT, language=language,
                           region=region, density=density)
        assert e.value is not None
        return e.value.float_value

    def get_str(self, id: int, *, language: Optional[str] = None,
                region: Optional[str] = None, density: int = 0) -> str:
        r"""
        Get str value.

        >>> chunk = quick_get_resources("test/data/golden-aligned-in.apk")
        >>> chunk.get_str(0x7f020000)
        'Tiny App for CTS'
        >>> chunk.get_str(0x7f020000, language="en", region="XA")
        '[Ţîñý Åþþ ƒöŕ ÇŢŠ one two three]'

        >>> with open("test/data/resources1.arsc", "rb") as fh:
        ...     chunk = read_chunk(fh.read())[0]
        >>> chunk.get_str(0x7f010001)
        'res/drawable/presplash.jpg'

        """
        e = self.get_entry(id, typ=BinResVal.Type.STRING, language=language,
                           region=region, density=density)
        return e.str_value()

    def _get_value(self, typ: type, *args: Any, **kwargs: Any) -> Any:
        if typ is bool:
            return self.get_bool(*args, **kwargs)
        if typ is int:
            return self.get_int(*args, **kwargs)
        if typ is float:
            return self.get_float(*args, **kwargs)
        if typ is str:
            return self.get_str(*args, **kwargs)
        raise ValueError(f"Unsupported type {typ.__name__}")

    def get_entry(self, id: int, *, typ: Optional[BinResVal.Type] = None, array: bool = False,
                  language: Optional[str] = None, region: Optional[str] = None,
                  density: int = 0) -> TypeChunk.Entry:
        r"""
        Get (first matching) type chunk entry with specified ID.

        >>> chunk = quick_get_resources("test/data/golden-aligned-in.apk")
        >>> e = chunk.get_entry(0x7f020000)
        >>> e
        TypeChunk.Entry(header_size=8, flags=0, key_idx=0, value=BinResVal(size=8, type=<Type.STRING: 3>, data=0, res0=0), values=(), parent_entry=0)
        >>> e.key
        'app_name'
        >>> e.str_value()
        'Tiny App for CTS'

        """
        entries = self.find_entries(id, typ=typ, array=array, return_first=True,
                                    language=language, region=region, density=density)
        if not entries:
            raise ResourceNotFound(f"No matching entry for {hex(id)}")
        return entries[0]

    def find_entries(self, id: int, *, typ: Optional[BinResVal.Type] = None, array: bool = False,
                     return_first: bool = True, language: Optional[str] = None,
                     region: Optional[str] = None, density: int = 0) -> List[TypeChunk.Entry]:
        r"""
        Get (first/all matching) type chunk entries with specified ID.

        NB: there should only be one matching entry for a specific combination
        of language/region/density, but this is not enforced; finding all
        entries using return_first=False is thus provided for analysis purposes;
        see select_entries() to select entries from all densities etc.

        >>> chunk = quick_get_resources("test/data/golden-aligned-in.apk")
        >>> entries = chunk.find_entries(0x7f020000)
        >>> [e.str_value() for e in entries]
        ['Tiny App for CTS']

        """
        entries = self.select_entries(id, typ=typ, array=array, return_first=return_first,
                                      language=language, region=region, density=density)
        return [entry for configuration, entry in entries]

    def select_entries(self, id: int, *, typ: Optional[BinResVal.Type] = None, array: bool = False,
                       return_first: bool = False, language: Union[str, EntryFilter, None] = None,
                       region: Union[str, EntryFilter, None] = None,
                       density: Union[int, EntryFilter] = 0) -> List[Tuple[BinResCfg, TypeChunk.Entry]]:
        r"""
        Select type chunk entries with specified ID; returns results from all
        configurations when EntryFilter.ALL is used; unlike find_entries(),
        return_first defaults to False and it returns pairs of (configuration,
        entry).

        >>> ALL = ResourceTableChunk.EntryFilter.ALL
        >>> chunk = quick_get_resources("test/data/golden-aligned-in.apk")
        >>> entries = chunk.select_entries(0x7f020000, language=ALL, region=ALL)
        >>> for c, e in entries:
        ...     (e.parent().type_name, c.locale, e.str_value())
        ('string', '', 'Tiny App for CTS')
        ('string', 'en-XA', '[Ţîñý Åþþ ƒöŕ ÇŢŠ one two three]')
        ('string', 'ar-XB', '\u200f\u202eTiny\u202c\u200f \u200f\u202eApp\u202c\u200f \u200f\u202efor\u202c\u200f \u200f\u202eCTS\u202c\u200f')

        >>> with open("test/data/resources-catima.arsc", "rb") as fh:
        ...     chunk = _quick_get_resources(fh.read())
        >>> entries = chunk.select_entries(0x7f120036, language=ALL, region=ALL)
        >>> [(e.parent().type_name, c.locale, e.str_value()) for c, e in entries]
        [('string', '', 'Catima'), ('string', 'da', 'Catima'), ('string', 'ja', 'Catima'), ('string', 'de', 'Catima'), ('string', 'bg', 'Catima'), ('string', 'fi', 'Catima'), ('string', 'hi', 'कैटिमा'), ('string', 'vi', 'Catima'), ('string', 'sk', 'Catima'), ('string', 'uk', 'Catima'), ('string', 'nl', 'Catima'), ('string', 'pl', 'Catima'), ('string', 'bn', 'ক্যাটিমা'), ('string', 'eo', 'Catima'), ('string', 'ko', 'Catima'), ('string', 'ar', 'كاتيما'), ('string', 'fr', 'Catima'), ('string', 'hr', 'Catima'), ('string', 'tr', 'Catima'), ('string', 'cs', 'Catima'), ('string', 'es', 'Catima'), ('string', 'it', 'Catima'), ('string', 'hu', 'Catima'), ('string', 'ru', 'Catima'), ('string', 'sv', 'Catima'), ('string', 'in-ID', 'Catima'), ('string', 'zh-CN', 'Catima'), ('string', 'nb-NO', 'Catima'), ('string', 'ro-RO', 'Catima'), ('string', 'es-AR', 'Catima'), ('string', 'el-GR', 'Catima'), ('string', 'pt-PT', 'Catima'), ('string', 'zh-TW', 'Catima')]
        >>> entries = chunk.select_entries(0x7f0f0000, density=ALL)
        >>> for c, e in entries:
        ...     (e.parent().type_name, c.density, e.str_value())
        ('mipmap', 160, 'res/9w.png')
        ('mipmap', 240, 'res/yn.png')
        ('mipmap', 320, 'res/FS.png')
        ('mipmap', 480, 'res/RJ.png')
        ('mipmap', 640, 'res/o-.png')
        ('mipmap', 65534, 'res/BW.xml')

        """
        entries = []
        fltr = dict(language=language, region=region, density=density)
        rid = BinResId.from_int(id)
        if rid.package_id not in self.packages_by_id:
            raise ResourceError(f"No package with id {rid.package_id}")
        for t in self.package_with_id(rid.package_id).type_chunks(rid.type_id):
            for k, v in fltr.items():
                if v is not self.EntryFilter.ALL and getattr(t.configuration, k) != v:
                    break
            else:
                for i, e in t.entries:
                    if i == rid.entry_id:
                        if e.is_complex and not array:
                            raise ResourceError(f"Type mismatch for {hex(id)}: expected scalar")
                        if not e.is_complex and array:
                            raise ResourceError(f"Type mismatch for {hex(id)}: expected complex")
                        for val in e.values_as_dict.values():
                            if typ and val.type is not typ:
                                raise ResourceError(f"Type mismatch for {hex(id)}: expected "
                                                    f"{typ.name}, got {val.type.name}")
                        entries.append((t.configuration, e))
                        if return_first:
                            return entries
        return entries

    @cached_property
    def packages_as_dict(self) -> Dict[str, PackageChunk]:
        """Packages as dict, indexed by name."""
        return dict(self.packages)

    @cached_property
    def packages_by_id(self) -> Dict[int, PackageChunk]:
        """Packages as dict, indexed by ID."""
        return {p.id: p for _, p in self.packages}

    def package(self, name: str) -> PackageChunk:
        """Get package by name."""
        return self.packages_as_dict[name]

    def package_with_id(self, id: int) -> PackageChunk:
        """Get package by ID."""
        return self.packages_by_id[id]


@dataclass(frozen=True)
class XMLChunk(ParentChunk):
    """XML chunk; contains string pool and XML nodes."""
    TYPE_ID: ClassVar[int] = 0x0003

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLChunk:
        """Parse XMLChunk."""
        if header:
            raise ParseError("Expected empty header")
        chunk = cls(**ParentChunk._parse(header=header, payload=payload, **kwargs))
        chunk._parse_children(payload)
        return chunk

    @cached_property
    def string_pool(self) -> StringPoolChunk:
        """Get string pool child."""
        for c in self.children:
            if isinstance(c, StringPoolChunk):
                return c
        raise ChildError("No StringPoolChunk child")

    def string(self, idx: Optional[int]) -> str:
        """Get string from string pool by index."""
        return self.string_pool.string(idx)


@dataclass(frozen=True)
class XMLNodeChunk(Chunk):
    """Base class for XML node chunks."""
    lineno: int
    comment_idx: Optional[int]

    @classmethod
    def _parse(_cls, header: bytes, payload: bytes, **kwargs: Any) -> Dict[str, Any]:
        d = Chunk._parse(header=header, payload=payload, **kwargs)
        lineno, comment_idx = struct.unpack("<II", header)
        return dict(**d, lineno=lineno, comment_idx=_noref(comment_idx))

    # FIXME: weakref?
    @cached_property
    def xml_chunk(self) -> XMLChunk:
        """Get XMLChunk parent."""
        r = self.parent
        while r is not None:
            if (p := r()) is None:
                raise ParentError("Parent deallocated")
            if isinstance(p, XMLChunk):
                return p
            r = p.parent
        raise ParentError("No XMLChunk parent")

    def string(self, idx: Optional[int]) -> str:
        """Get string from XML chunk parent by index."""
        return "" if idx is None else self.xml_chunk.string(idx)

    @property
    def comment(self) -> str:
        """Get comment string."""
        return self.string(self.comment_idx)


@dataclass(frozen=True)
class XMLNSChunk(XMLNodeChunk):
    """Base class for XML namespace chunks."""
    prefix_idx: int
    uri_idx: int

    @classmethod
    def _parse(_cls, header: bytes, payload: bytes, **kwargs: Any) -> Dict[str, Any]:
        d = XMLNodeChunk._parse(header=header, payload=payload, **kwargs)
        prefix_idx, uri_idx = struct.unpack("<II", payload)
        return dict(**d, prefix_idx=prefix_idx, uri_idx=uri_idx)

    @property
    def prefix(self) -> str:
        """Get prefix string."""
        return self.string(self.prefix_idx)

    @property
    def uri(self) -> str:
        """Get uri string."""
        return self.string(self.uri_idx)


@dataclass(frozen=True)
class XMLNSStartChunk(XMLNSChunk):
    """XML namespace start."""
    TYPE_ID: ClassVar[int] = 0x0100

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLNSStartChunk:
        """Parse XMLNSStartChunk."""
        return cls(**XMLNSChunk._parse(header=header, payload=payload, **kwargs))


@dataclass(frozen=True)
class XMLNSEndChunk(XMLNSChunk):
    """XML namespace end."""
    TYPE_ID: ClassVar[int] = 0x0101

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLNSEndChunk:
        """Parse XMLNSEndChunk."""
        return cls(**XMLNSChunk._parse(header=header, payload=payload, **kwargs))


@dataclass(frozen=True)
class XMLElemStartChunk(XMLNodeChunk):
    """XML element start; contains XML attributes."""
    namespace_idx: Optional[int]
    name_idx: int
    id_idx: Optional[int]
    class_idx: Optional[int]
    style_idx: Optional[int]
    attributes: Tuple[XMLAttr, ...]

    TYPE_ID: ClassVar[int] = 0x0102

    # FIXME: check payload size
    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLElemStartChunk:
        """Parse XMLElemStartChunk."""
        d = XMLNodeChunk._parse(header=header, payload=payload, **kwargs)
        ns_idx, name_idx, attr_start, attr_size, n_attrs, id_idx, class_idx, \
            style_idx, data = _unpack("<IIHHHHHH", payload)
        if attr_size != 20:
            raise ParseError("Wrong XML attribute size")
        # NB: adjust 1-based indices
        chunk = cls(**d, namespace_idx=_noref(ns_idx), name_idx=name_idx,
                    id_idx=_noref(id_idx - 1), class_idx=_noref(class_idx - 1),
                    style_idx=_noref(style_idx - 1), attributes=())
        attrs = tuple(_read_attrs(data, weakref.ref(chunk), attr_start - 20, n_attrs))
        object.__setattr__(chunk, "attributes", attrs)
        return chunk

    def attr_as_bool(self, name: str, **kwargs: Any) -> Optional[bool]:
        """Get bool attr."""
        value = self._attr_as(bool, name, **kwargs)
        assert value is None or isinstance(value, bool)
        return value

    def attr_as_int(self, name: str, **kwargs: Any) -> Optional[int]:
        """Get int attr."""
        value = self._attr_as(int, name, **kwargs)
        assert value is None or isinstance(value, int)
        return value

    def attr_as_float(self, name: str, **kwargs: Any) -> Optional[float]:
        """Get float attr."""
        value = self._attr_as(float, name, **kwargs)
        assert value is None or isinstance(value, float)
        return value

    def attr_as_str(self, name: str, **kwargs: Any) -> Optional[str]:
        """Get str attr."""
        value = self._attr_as(str, name, **kwargs)
        assert value is None or isinstance(value, str)
        return value

    def _attr_as(self, typ: type, name: str, *, android: bool = False, optional: bool = False,
                 resources: Optional[ResourceTableChunk] = None) -> Any:
        brv_type = py_type_to_brv_type(typ)
        if android:
            name = f"{{{SCHEMA_ANDROID}}}{name}"
        if name not in self.attrs_as_dict:
            if optional:
                return None
            raise ParseError(f"No such attribute: {name!r}")
        attr = self.attrs_as_dict[name]
        if resources and attr.typed_value.type is BinResVal.Type.REFERENCE:
            value = resources._get_value(typ, attr.typed_value.data)
            if not isinstance(value, typ):
                raise ParseError(f"Wrong type for resource referenced by attribute {name!r}: "
                                 f"expected {typ.__name__}, got {type(value).__name__}")
            return value
        if attr.typed_value.type is not brv_type:
            raise ParseError(f"Wrong type for attribute {name!r}: "
                             f"expected {brv_type.name}, got {attr.typed_value.type.name}")
        return brv_to_py(attr.typed_value, attr.raw_value)[2]

    @cached_property
    def attrs_as_dict(self) -> Dict[str, XMLAttr]:
        """XML attributes as dict."""
        d = {}
        for a in self.attributes:
            if (n := a.name_with_ns) in d:
                raise ParseError(f"Duplicate attribute name: {n!r}")
            d[n] = a
        return d

    @property
    def namespace(self) -> str:
        """Get namespace string."""
        return self.string(self.namespace_idx)

    @property
    def name(self) -> str:
        """Get name string."""
        return self.string(self.name_idx)


@dataclass(frozen=True)
class XMLElemEndChunk(XMLNodeChunk):
    """XML element end."""
    namespace_idx: Optional[int]
    name_idx: int

    TYPE_ID: ClassVar[int] = 0x0103

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLElemEndChunk:
        """Parse XMLElemEndChunk."""
        d = XMLNodeChunk._parse(header=header, payload=payload, **kwargs)
        namespace_idx, name_idx = struct.unpack("<II", payload)
        return cls(**d, namespace_idx=_noref(namespace_idx), name_idx=name_idx)

    @property
    def namespace(self) -> str:
        """Get namespace string."""
        return self.string(self.namespace_idx)

    @property
    def name(self) -> str:
        """Get name string."""
        return self.string(self.name_idx)


@dataclass(frozen=True)
class XMLCDATAChunk(XMLNodeChunk):
    """XML CDATA."""
    raw_value_idx: int
    typed_value: BinResVal

    TYPE_ID: ClassVar[int] = 0x0104

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLCDATAChunk:
        """Parse XMLCDATAChunk."""
        d = XMLNodeChunk._parse(header=header, payload=payload, **kwargs)
        raw_value_idx, tv_data = _unpack("<I", payload)
        return cls(**d, raw_value_idx=raw_value_idx, typed_value=_read_brv(tv_data))

    @property
    def raw_value(self) -> str:
        """Get raw value string."""
        return self.string(self.raw_value_idx)


@dataclass(frozen=True)
class XMLResourceMapChunk(Chunk):
    """XML resource map."""
    resources: Tuple[int, ...]

    TYPE_ID: ClassVar[int] = 0x0180

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> XMLResourceMapChunk:
        """Parse XMLResourceMapChunk."""
        d = Chunk._parse(header=header, payload=payload, **kwargs)
        n = (d["chunk_size"] - d["header_size"]) // 4
        return cls(**d, resources=struct.unpack(f"<{n}I", payload))

    def resource(self, i: int) -> BinResId:
        """Get resource by index."""
        return BinResId.from_int(self.resources[i])


@dataclass(frozen=True)
class PackageChunk(ParentChunk):
    """
    Package chunk; contains type specs and types.

    NB: types can have multiple values for the same key.
    """
    id: int
    package_name: str
    type_specs: Tuple[Tuple[int, TypeSpecChunk], ...] = field(repr=False, compare=False)
    types: Tuple[Tuple[int, TypeChunk], ...] = field(repr=False, compare=False)
    library_chunk: Optional[LibraryChunk] = field(repr=False, compare=False)
    type_strings_offset: int = field(compare=False)
    key_strings_offset: int = field(compare=False)

    TYPE_ID: ClassVar[int] = 0x0200

    # NB: last public type/key offset in string pool & type id offset are unused;
    #     type id offset can be missing in some (older) APKs
    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> PackageChunk:
        """Parse PackageChunk."""
        d = ParentChunk._parse(header=header, payload=payload, **kwargs)
        hdr = header + bytes(4) if len(header) == 276 else header
        id_, name_b, t_off, last_pub_t, k_off, last_pub_k, tid_off = \
            struct.unpack("<I256sIIIII", hdr)
        name = _decode_package_name(name_b)
        chunk = cls(**d, id=id_, package_name=name, type_specs=(), types=(),
                    library_chunk=None, key_strings_offset=k_off, type_strings_offset=t_off)
        chunk._parse_children(payload)
        type_specs, types, library_chunk = [], [], None
        for c in chunk.children:
            if isinstance(c, TypeSpecChunk):
                type_specs.append((c.id, c))
            elif isinstance(c, TypeChunk):
                types.append((c.id, c))
            elif isinstance(c, LibraryChunk):
                if library_chunk is not None:
                    raise ParseError("Multiple LibraryChunk children")
                library_chunk = c
            elif not isinstance(c, StringPoolChunk):
                raise ParseError(f"Unexpected {c.__class__.__name__} child")
        object.__setattr__(chunk, "type_specs", tuple(type_specs))
        object.__setattr__(chunk, "types", tuple(types))
        object.__setattr__(chunk, "library_chunk", library_chunk)
        return chunk

    @cached_property
    def type_specs_as_dict(self) -> Dict[int, TypeSpecChunk]:
        """Type specs as dict."""
        return dict(self.type_specs)

    @cached_property
    def types_as_dict(self) -> Dict[int, List[TypeChunk]]:
        """Types as dict of lists."""
        d: Dict[int, List[TypeChunk]] = {}
        for i, c in self.types:
            d.setdefault(i, []).append(c)
        return d

    def type_spec_chunks(self) -> Tuple[TypeSpecChunk, ...]:
        """Get all type specs."""
        return tuple(c for _, c in self.type_specs)

    def type_spec_chunk(self, type_id: Union[int, str]) -> TypeSpecChunk:
        """Get type spec by id"""
        if isinstance(type_id, str):
            type_id = self.type_string_pool.strings.index(type_id) + 1
        return self.type_specs_as_dict[type_id]

    def type_chunks(self, type_id: Union[int, str, None]) -> Tuple[TypeChunk, ...]:
        """Get all types or types by id."""
        if type_id is None:
            return tuple(c for _, c in self.types)
        if isinstance(type_id, str):
            type_id = self.type_string_pool.strings.index(type_id) + 1
        return tuple(self.types_as_dict[type_id])

    @cached_property
    def type_string_pool(self) -> StringPoolChunk:
        """Get type string pool child."""
        return self._string_pool(self.type_strings_offset, "type")

    @cached_property
    def key_string_pool(self) -> StringPoolChunk:
        """Get key string pool child."""
        return self._string_pool(self.key_strings_offset, "key")

    def _string_pool(self, offset: int, what: str) -> StringPoolChunk:
        pool = None
        for c in self.children:
            if c.offset == offset:
                pool = c
                break
        if not isinstance(pool, StringPoolChunk):
            raise ChildError(f"Unable to find {what} string pool")
        return pool


@dataclass(frozen=True)
class TypeOrSpecChunk(Chunk):
    """Base class for TypeChunk and TypeSpecChunk."""
    id: int

    SUBFIELDS: ClassVar[Dict[str, Tuple[str, ...]]] = dict(id=("#keep", "type_name"))

    @classmethod
    def _parse(_cls, header: bytes, payload: bytes, **kwargs: Any) -> Dict[str, Any]:
        return Chunk._parse(header=header, payload=payload, **kwargs)

    # FIXME: weakref?
    @cached_property
    def package_chunk(self) -> Optional[PackageChunk]:
        """Get PackageChunk parent."""
        r = self.parent
        while r is not None:
            if (p := r()) is None:
                raise ParentError("Parent deallocated")
            if isinstance(p, PackageChunk):
                return p
            r = p.parent
        return None

    @property
    def type_name(self) -> str:
        """Get type name from package chunk type string pool."""
        if (c := self.package_chunk) is None:
            raise ParentError("No PackageChunk parent")
        return c.type_string_pool.strings[self.id - 1]

    def resource_id(self, entry_id: int) -> BinResId:
        """Get resource ID (package + type + entry) for entry."""
        if (c := self.package_chunk) is None:
            raise ParentError("No PackageChunk parent")
        return BinResId(c.id, self.id, entry_id)


# FIXME: FLAG_SPARSE untested!
# FIXME: overlay packages
@dataclass(frozen=True)
class TypeChunk(TypeOrSpecChunk):
    """Type chunk; contains entries and configuration."""
    entries: Tuple[Tuple[int, Entry], ...]
    configuration: BinResCfg
    flags: int

    TYPE_ID: ClassVar[int] = 0x0201

    NO_ENTRY: ClassVar[int] = 0xFFFFFFFF
    NO_ENTRY_OFFSET16: ClassVar[int] = 0xFFFF

    FLAG_SPARSE: ClassVar[int] = 0x01
    FLAG_OFFSET16: ClassVar[int] = 0x02

    @dataclass(frozen=True)
    class Entry:
        """Type chunk entry."""
        header_size: int
        flags: int
        key_idx: int
        value: Optional[BinResVal]
        values: Tuple[Tuple[int, BinResVal], ...]
        parent_entry: int
        parent: TypeChunkRef = field(repr=False, compare=False)

        HIDDEN_FIELDS: ClassVar[Tuple[str, ...]] = ("header_size",)

        FLAG_COMPLEX: ClassVar[int] = 0x1
        FLAG_PUBLIC: ClassVar[int] = 0x2
        FLAG_WEAK: ClassVar[int] = 0x4
        FLAG_COMPACT: ClassVar[int] = 0x8

        @cached_property
        def values_as_dict(self) -> Dict[Optional[int], BinResVal]:
            """Values as dict (array will be enumerated)."""
            if self.is_complex:
                if self.is_array:
                    return dict(enumerate(self.values_as_list))
                d: Dict[Optional[int], BinResVal] = {}
                for k, v in self.values:
                    if k in d:
                        raise ParseError(f"Duplicate value ID: {k}")
                    d[k] = v
                return d
            assert self.value is not None
            return {None: self.value}

        @cached_property
        def values_as_list(self) -> List[BinResVal]:
            """Values as list (must be array)."""
            if not self.is_array:
                raise ParseError("Expected array")
            return [v for k, v in self.values]

        @cached_property
        def is_array(self) -> bool:
            """Whether the entry is complex with all zero keys."""
            return self.is_complex and all(k == 0 for k, v in self.values)

        @property
        def is_complex(self) -> bool:
            """Whether the entry has multiple values (instead of one value)."""
            return bool(self.flags & self.FLAG_COMPLEX)

        @property
        def is_public(self) -> bool:
            """Whether the entry is public (libraries can reference it)."""
            return bool(self.flags & self.FLAG_PUBLIC)

        @property
        def is_weak(self) -> bool:
            """Whether the entry is weak (can be overridden)."""
            return bool(self.flags & self.FLAG_WEAK)

        @property
        def is_compact(self) -> bool:
            """Whether the entry is compact."""
            return bool(self.flags & self.FLAG_COMPACT)

        @property
        def key(self) -> str:
            """Get key name from TypeChunk parent."""
            if (p := self.parent()) is not None:
                return p.key_name(self.key_idx)
            raise ParentError("Parent deallocated")

        def string(self, idx: Optional[int]) -> str:
            """Get string from string pool by index."""
            if (p := self.parent()) is not None:
                return p.string(idx)
            raise ParentError("Parent deallocated")

        def str_value(self, *, resources: Optional[ResourceTableChunk] = None,
                      deref_limit: int = 16) -> str:
            """Get string value."""
            if self.is_complex:
                raise ResourceError("Expected scalar value")
            assert self.value is not None
            if resources and self.value.type is BinResVal.Type.REFERENCE and deref_limit > 0:
                return brv_str_deref(self.value, "", resources=resources, deref_limit=deref_limit - 1)
            if self.value.type is not BinResVal.Type.STRING:
                raise ResourceError("Expected string value")
            return self.string(self.value.data)

        @classmethod
        def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
            return _fields(cls)     # type: ignore[arg-type]

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> TypeChunk:
        """Parse TypeChunk."""
        d = TypeOrSpecChunk._parse(header=header, payload=payload, **kwargs)
        id_, t_flags, reserved, n_ents, start, cfg_data = _unpack("<BBHII", header)
        chunk = cls(**d, id=id_, entries=(), configuration=_read_cfg(cfg_data), flags=t_flags)
        entries = []
        if t_flags & cls.FLAG_SPARSE:
            _untested("FLAG_SPARSE")
        for i in range(n_ents):
            if t_flags & cls.FLAG_SPARSE:
                idx, off16 = struct.unpack("<HH", payload[4 * i:4 * (i + 1)])
                off = off16 * 4
            elif t_flags & cls.FLAG_OFFSET16:
                idx = i
                off16, = struct.unpack("<H", payload[2 * i:2 * (i + 1)])
                off = cls.NO_ENTRY if off16 == cls.NO_ENTRY_OFFSET16 else off16 * 4
            else:
                idx = i
                off, = struct.unpack("<I", payload[4 * i:4 * (i + 1)])
            if off == cls.NO_ENTRY:
                continue
            o = off + start - d["header_size"]
            hdr_sz_or_key, e_flags, key_idx_or_data = struct.unpack("<HHI", payload[o:o + 8])
            values = []
            if e_flags & cls.Entry.FLAG_COMPLEX:
                hdr_sz, key_idx = hdr_sz_or_key, key_idx_or_data
                value = None
                par_ent, n = struct.unpack("<II", payload[o + 8:o + 16])
                for j in range(n):
                    data = payload[o + 16 + 12 * j:o + 16 + 12 * (j + 1)]
                    k, brv_data = _unpack("<I", data)
                    values.append((k, _read_brv(brv_data)))
            elif e_flags & cls.Entry.FLAG_COMPACT:
                hdr_sz, key_idx = 8, hdr_sz_or_key
                value = _brv(8, e_flags >> 8, payload[o + 4:o + 8])
                par_ent = 0
            else:
                hdr_sz, key_idx = hdr_sz_or_key, key_idx_or_data
                value = _read_brv(payload[o + 8:o + 16])
                par_ent = 0
            e = cls.Entry(header_size=hdr_sz, flags=e_flags, key_idx=key_idx,
                          value=value, values=tuple(values), parent_entry=par_ent,
                          parent=weakref.ref(chunk))
            entries.append((idx, e))
        object.__setattr__(chunk, "entries", tuple(entries))
        return chunk

    @cached_property
    def entries_as_dict(self) -> Dict[int, Entry]:
        """Entries as dict."""
        return dict(self.entries)

    # FIXME: weakref?
    @cached_property
    def resource_table_chunk(self) -> Optional[ResourceTableChunk]:
        """Get ResourceTableChunk parent."""
        r = self.parent
        while r is not None:
            if (p := r()) is None:
                raise ParentError("Parent deallocated")
            if isinstance(p, ResourceTableChunk):
                return p
            r = p.parent
        return None

    def string(self, idx: Optional[int]) -> str:
        """Get string from resource table parent string pool by index."""
        if (c := self.resource_table_chunk) is None:
            raise ParentError("No ResourceTableChunk parent")
        return c.string_pool.string(idx)

    def key_name(self, idx: Optional[int]) -> str:
        """Get key from package chunk parent key string pool by index."""
        if (c := self.package_chunk) is None:
            raise ParentError("No PackageChunk parent")
        return c.key_string_pool.string(idx)

    def contains_resource(self, rid: BinResId) -> bool:
        """Whether the entries contain the resource."""
        if (c := self.package_chunk) is None:
            raise ParentError("No PackageChunk parent")
        return rid.package_id == c.id and rid.type_id == self.id \
            and rid.entry_id in self.entries_as_dict

    @property
    def is_sparse(self) -> bool:
        """Whether the entry is sparse."""
        return bool(self.flags & self.FLAG_SPARSE)

    @property
    def is_offset16(self) -> bool:
        """Whether the entry is using 16-bit offsets."""
        return bool(self.flags & self.FLAG_OFFSET16)


@dataclass(frozen=True)
class TypeSpecChunk(TypeOrSpecChunk):
    """Type spec chunk."""
    resources: Tuple[int, ...]
    res0: int
    res1: int

    TYPE_ID: ClassVar[int] = 0x0202

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> TypeSpecChunk:
        "Parse TypeSpecChunk."""
        d = TypeOrSpecChunk._parse(header=header, payload=payload, **kwargs)
        id_, res0, res1, n = struct.unpack("<BBHI", header)
        return cls(**d, id=id_, resources=struct.unpack(f"<{n}I", payload), res0=res0, res1=res1)


# FIXME: untested!
@dataclass(frozen=True)
class LibraryChunk(Chunk):
    """Library chunk."""
    entries: Tuple[Entry, ...]

    TYPE_ID: ClassVar[int] = 0x0203

    @dataclass(frozen=True)
    class Entry:
        """Library chunk entry."""
        id: int
        package_name: str

    @classmethod
    def parse(cls, header: bytes, payload: bytes, **kwargs: Any) -> LibraryChunk:
        """Parse LibraryChunk."""
        d = Chunk._parse(header=header, payload=payload, **kwargs)
        n, = _unpack("<I", header)
        if len(payload) != 256 * n:
            raise ParseError(f"Payload size mismatch: expected {256 * n}, got {len(payload)}")
        entries = []
        for i in range(n):
            id_, name_b, payload = _unpack("<I256s", payload)
            entries.append(cls.Entry(id_, _decode_package_name(name_b)))
        return cls(**d, entries=tuple(entries))


@dataclass(frozen=True)
class UnknownChunk(Chunk):
    """Unknown chunk."""
    header: bytes = field(repr=False)
    payload: bytes = field(repr=False)
    _type_id: int

    SUBFIELDS: ClassVar[Dict[str, Tuple[str, ...]]] = dict(_type_id=("type_id",))

    @property
    def type_id(self) -> int:
        return self._type_id


@dataclass(frozen=True)
class BinResVal:
    """Binary resource value."""
    size: int
    type: Type
    data: int
    res0: int

    COMPLEX_UNITS: ClassVar[Tuple[str, ...]] = ("px", "dp", "sp", "pt", "in", "mm")
    COMPLEX_UNIT_FRACTIONS: ClassVar[Tuple[str, ...]] = ("%", "%p")
    COMPLEX_UNIT_MASK: ClassVar[int] = 0xf

    COMPLEX_RADIX_MASK: ClassVar[int] = 0x3
    COMPLEX_RADIX_SHIFT: ClassVar[int] = 4
    COMPLEX_RADIX_SHIFTS: ClassVar[Tuple[int, ...]] = (23, 16, 8, 0)

    COMPLEX_MANTISSA_MASK: ClassVar[int] = 0xffffff
    COMPLEX_MANTISSA_SHIFT: ClassVar[int] = 8

    class Type(Enum):
        """Binary resource value type."""
        NULL = 0x00                 # 0 = undef, 1 = empty
        REFERENCE = 0x01            # reference to resource table entry
        ATTRIBUTE = 0x02            # attribute resource identifier
        STRING = 0x03               # string pool index
        FLOAT = 0x04
        DIMENSION = 0x05            # see complex2pair
        FRACTION = 0x06             # see complex2pair
        DYNAMIC_REFERENCE = 0x07
        DYNAMIC_ATTRIBUTE = 0x08
        INT_DEC = 0x10
        INT_HEX = 0x11
        INT_BOOLEAN = 0x12
        INT_COLOR_ARGB8 = 0x1c      # #aarrggbb
        INT_COLOR_RGB8 = 0x1d       # #rrggbb
        INT_COLOR_ARGB4 = 0x1e      # #argb
        INT_COLOR_RGB4 = 0x1f       # #rgb

    @property
    def float_value(self) -> float:
        """Parse self.data as FLOAT."""
        if self.type is not self.Type.FLOAT:
            raise ValueError("Expected FLOAT")
        value = struct.unpack("<f", struct.pack("<I", self.data))[0]
        assert isinstance(value, float)
        return value

    @classmethod
    def complex2pair(c, i: int, *, fraction: bool) -> Tuple[float, str]:
        """Parse dimension/fraction to (float, suffix)."""
        unt = i & c.COMPLEX_UNIT_MASK
        rad = (i >> c.COMPLEX_RADIX_SHIFT) & c.COMPLEX_RADIX_MASK
        man = ((i >> c.COMPLEX_MANTISSA_SHIFT) & c.COMPLEX_MANTISSA_MASK) \
            << c.COMPLEX_RADIX_SHIFTS[rad]
        val = man * (1.0 / (1 << 23))
        suf = c.COMPLEX_UNIT_FRACTIONS[unt] if fraction else c.COMPLEX_UNITS[unt]
        return val, suf


@dataclass(frozen=True)
class BinResId:
    """Binary resource ID."""
    package_id: int
    type_id: int
    entry_id: int

    @classmethod
    def from_int(cls, i: int) -> BinResId:
        """Convert from int."""
        p = (i & 0xFF000000) >> 24
        t = (i & 0x00FF0000) >> 16
        e = (i & 0x0000FFFF)
        return cls(package_id=p, type_id=t, entry_id=e)

    @property
    def to_int(self) -> int:
        """Convert to int."""
        return self.package_id << 24 | self.type_id << 16 | self.entry_id


# FIXME: incomplete?
@dataclass(frozen=True, order=True)
class BinResCfg:
    """Binary resource configuration."""
    size: int
    mcc: int
    mnc: int
    language: Optional[str]
    region: Optional[str]
    orientation: Orientation
    touchscreen: Touchscreen
    density: int
    keyboard: Keyboard
    navigation: Navigation
    input_flags: int            # keys_hidden, nav_hidden
    screen_width: int
    screen_height: int
    sdk_version: int
    minor_version: int
    screen_layout: int          # layout_direction, screen_layout_size, screen_layout_long
    ui_mode: int                # ui_mode_type, ui_mode_night
    smallest_screen_width_dp: int
    screen_width_dp: int
    screen_height_dp: int
    locale_script: Optional[bytes]
    locale_variant: Optional[bytes]
    screen_layout2: int         # screen_round, FIXME
    unknown: Optional[bytes]

    @property
    def locale(self) -> str:
        return (self.language or "") + (f"-{self.region}" if self.region else "")

    @property
    def mobile_country_code(self) -> int:
        return self.mcc

    @property
    def mobile_network_code(self) -> int:
        return self.mnc

    @property
    def keys_hidden(self) -> KeysHidden:
        return self.KeysHidden(self.input_flags & 0x3)

    @property
    def nav_hidden(self) -> NavHidden:
        return self.NavHidden((self.input_flags >> 2) & 0x3)

    @property
    def layout_direction(self) -> LayoutDirection:
        return self.LayoutDirection((self.screen_layout >> 6) & 0x3)

    @property
    def screen_layout_size(self) -> ScreenLayoutSize:
        return self.ScreenLayoutSize(self.screen_layout & 0xF)

    @property
    def screen_layout_long(self) -> ScreenLayoutLong:
        return self.ScreenLayoutLong((self.screen_layout >> 4) & 0x3)

    @property
    def screen_round(self) -> ScreenRound:
        return self.ScreenRound(self.screen_layout2 & 0x3)

    @property
    def ui_mode_type(self) -> UiModeType:
        return self.UiModeType(self.ui_mode & 0xF)

    @property
    def ui_mode_night(self) -> UiModeNight:
        return self.UiModeNight((self.ui_mode >> 4) & 0x3)

    HIDDEN_FIELDS: ClassVar[Tuple[str, ...]] = ("size", "unknown")
    SUBFIELDS: ClassVar[Dict[str, Tuple[str, ...]]] = dict(
        input_flags=("keys_hidden", "nav_hidden"),
        screen_layout=("layout_direction", "screen_layout_size", "screen_layout_long"),
        screen_layout2=("screen_round",),
        ui_mode=("ui_mode_type", "ui_mode_night"),
    )

    Orientation = Enum("Orientation", ("UNSET", "PORT", "LAND", "SQUARE"), start=0)
    Touchscreen = Enum("Touchscreen", ("UNSET", "NOTOUCH", "STYLUS", "FINGER"), start=0)
    Keyboard = Enum("Keyboard", ("UNSET", "NOKEYS", "QWERTY", "12KEY"), start=0)
    Navigation = Enum("Navigation", ("UNSET", "NONAV", "DPAD", "TRACKBALL", "WHEEL"), start=0)

    KeysHidden = Enum("KeysHidden", ("UNSET", "KEYSEXPOSED", "KEYSHIDDEN", "KEYSSOFT"), start=0)
    NavHidden = Enum("NavHidden", ("UNSET", "NAVEXPOSED", "NAVHIDDEN"), start=0)

    LayoutDirection = Enum("LayoutDirection", ("UNSET", "LDLTR", "LDRTL"), start=0)
    ScreenLayoutSize = Enum("ScreenLayoutSize", ("UNSET", "SMALL", "NORMAL",
                                                 "LARGE", "XLARGE"), start=0)
    ScreenLayoutLong = Enum("ScreenLayoutLong", ("UNSET", "NOTLONG", "LONG"), start=0)
    ScreenRound = Enum("ScreenRound", ("UNSET", "NOTROUND", "ROUND"), start=0)

    UiModeType = Enum("UiModeType", ("UNSET", "NORMAL", "DESK", "CAR", "TELEVISION",
                                     "APPLIANCE", "WATCH", "VR"), start=0)
    UiModeNight = Enum("UiModeNight", ("UNSET", "NOTNIGHT", "NIGHT"), start=0)

    # WideColorGamut = Enum("WideColorGamut", ("UNSET", "NOWIDECG", "WIDECG"), start=0)
    # Hdr = Enum("Hdr", ("UNSET", "LOWDR", "HIGHDR"), start=0)

    class Density(Enum):
        UNDEFINED = 0
        LDPI = 120
        MDPI = 160
        TVDPI = 213
        HDPI = 240
        XHDPI = 320
        XXHDPI = 480
        XXXHDPI = 640
        ANYDPI = 0xFFFE
        NODPI = 0xFFFF

    @property
    def is_default(self) -> bool:
        """Whether any fields have non-default values."""
        return not self.fields_to_show

    @property
    def fields_to_show(self) -> Dict[str, Any]:
        """Fields (with non-default values) to show."""
        d = {}
        for k, _, h, _ in self.fields():
            if h:
                continue
            v = getattr(self, k)
            if k == "density":
                try:
                    v = self.Density(v)
                except ValueError:
                    v = f"{v}dpi"
            if isinstance(v, Enum):
                if v.value == 0:
                    continue
                v = v.name.lower()
            elif v in (0, None):
                continue
            d[k] = v
        return d

    @classmethod
    def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
        return _fields(cls)     # type: ignore[arg-type]


@dataclass(frozen=True)
class XMLAttr:
    """XML attribute; contains typed and/or raw value."""
    namespace_idx: Optional[int]
    name_idx: int
    raw_value_idx: Optional[int]
    typed_value: BinResVal
    parent: XMLNodeChunkRef = field(repr=False, compare=False)

    def string(self, idx: Optional[int]) -> str:
        """Get string from XML node parent by index."""
        if idx is None:
            return ""
        if (p := self.parent()) is not None:
            return p.string(idx)
        raise ParentError("Parent deallocated")

    @property
    def namespace(self) -> str:
        """Get namespace string."""
        return self.string(self.namespace_idx)

    @property
    def name(self) -> str:
        """Get name string."""
        return self.string(self.name_idx)

    @property
    def name_with_ns(self) -> str:
        """Get name with namespace (if any) prepended; e.g. '{{foo}}bar'."""
        return f"{{{self.namespace}}}{self.name}" if self.namespace else self.name

    @property
    def raw_value(self) -> str:
        """Get raw value string."""
        return self.string(self.raw_value_idx)

    @classmethod
    def fields(cls) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
        return _fields(cls)     # type: ignore[arg-type]


@dataclass(frozen=True)
class UsesFeature:
    """AndroidManifest.xml uses-feature."""
    name: str
    required: bool


@dataclass(frozen=True)
class UsesPermission:
    """AndroidManifest.xml uses-permission(-sdk-23)."""
    name: str
    min_sdk_version: Optional[int]
    max_sdk_version: Optional[int]


@dataclass(frozen=True)
class ManifestInfo:
    """AndroidManifest.xml data."""
    appid: str
    version_code: int
    version_name: str
    min_sdk: int
    target_sdk: int
    features: List[UsesFeature]
    permissions: List[UsesPermission]
    abis: Optional[List[str]] = None
    app_label: Optional[Dict[str, List[str]]] = None
    app_icon: Optional[Dict[int, List[str]]] = None


if TYPE_CHECKING:
    ChunkRef = weakref.ReferenceType[Chunk]
    StringPoolChunkRef = weakref.ReferenceType[StringPoolChunk]
    XMLNodeChunkRef = weakref.ReferenceType[XMLNodeChunk]
    TypeChunkRef = weakref.ReferenceType[TypeChunk]
else:
    ChunkRef = weakref.ReferenceType
    StringPoolChunkRef = weakref.ReferenceType
    XMLNodeChunkRef = weakref.ReferenceType
    TypeChunkRef = weakref.ReferenceType


def _subclasses(cls: Any) -> Iterator[Any]:
    for c in cls.__subclasses__():
        yield c
        yield from _subclasses(c)


CHUNK_TYPES = {c.TYPE_ID: c for c in _subclasses(Chunk) if c.TYPE_ID is not None}


# FIXME
def dump(*files: str, json: bool = False, quiet: bool = False,
         verbose: bool = False, xml: bool = False, xml_deref: bool = False,
         xml_prolog: bool = False) -> None:
    """Parse AXML/ARSC & dump to stdout."""
    resources, skip = None, set()
    if xml and xml_deref:
        for file in files:
            with open(file, "rb") as fh:
                if fh.read(4) == ARSC_MAGIC:
                    resources = _quick_get_resources(ARSC_MAGIC + fh.read())
                    skip.add(file)
                    break
    for file in files:
        if file in skip:
            continue
        with open(file, "rb") as fh:
            if xml and xml_prolog:
                print(XML_PROLOG)
            if not quiet:
                if json:
                    print(_json.dumps([dict(file=file)]))
                elif xml:
                    print(f"<!-- file={file!r} -->")
                else:
                    print(f"file={file!r}")
            _dump(fh.read(), json=json, verbose=verbose, xml=xml, resources=resources)


# FIXME
def dump_apk(apk: str, *patterns: str, json: bool = False, quiet: bool = False,
             verbose: bool = False, xml: bool = False, xml_deref: bool = False,
             xml_prolog: bool = False) -> None:
    """Parse AXML/ARSC in APK & dump to stdout."""
    with zipfile.ZipFile(apk) as zf:
        if xml and xml_deref:
            resources = _quick_get_resources(zf.read(ARSC_FILE))
        else:
            resources = None
        for info in zf.infolist():
            if fnmatches_with_negation(info.filename, *patterns):
                if xml and xml_prolog:
                    print(XML_PROLOG)
                if not quiet:
                    if json:
                        print(_json.dumps([dict(entry=info.filename)]))
                    elif xml:
                        print(f"<!-- entry={info.filename!r} -->")
                    else:
                        print(f"entry={info.filename!r}")
                with zf.open(info.filename) as fh:
                    _dump(fh.read(), json=json, verbose=verbose, xml=xml, resources=resources)


def fastid(*apks: str, json: bool = False, short: bool = False) -> None:
    """Quickly get appid & version code/name from APK & print to stdout."""
    if json:
        print(_json.dumps([dict(_idver_kv(quick_get_idver(apk))) for apk in apks], indent=2))
    else:
        for idver in map(quick_get_idver, apks):
            if short:
                print(" ".join(map(_safe, idver)))
            else:
                print(" ".join(f"{k}={_safe(v)}" for k, v in _idver_kv(idver)))


def fastperms(*apks: str, json: bool = False, quiet: bool = False,
              with_id: bool = False) -> None:
    """Quickly get permissions from APK & print to stdout."""
    if json:
        result = []
        for apk in apks:
            if with_id:
                idver, perms = quick_get_idver_perms(apk)
                d = dict(_idver_kv(idver))
            else:
                perms, d = quick_get_perms(apk), {}
            d["permissions"] = [dict(permission=perm, attributes=dict(attrs))
                                for perm, attrs in perms]
            result.append(d)
        print(_json.dumps(result, indent=2))
    else:
        for apk in apks:
            if not quiet:
                print(f"file={apk!r}")
            if with_id:
                idver, perms = quick_get_idver_perms(apk)
                print(" ".join(f"{k}={_safe(v)}" for k, v in _idver_kv(idver)))
            else:
                perms = quick_get_perms(apk)
            for perm, attrs in perms:
                info = ", ".join(f"{_safe(k)}={_safe(v)}" for k, v in attrs)
                print(f"permission={_safe(perm)}{f' [{info}]' if info else ''}")


def manifest_info(*apks: str, extended: bool = False) -> int:
    """Dump basic manifest info as JSON; returns number of errors."""
    data, errors = {}, 0
    for apkfile in apks:
        try:
            m = get_manifest_info_apk(apkfile, extended=extended)
            data[apkfile] = dataclasses.asdict(m)
        except Error as e:
            errors += 1
            data[apkfile] = dict(error=str(e))
    _json.dump(data, sys.stdout, indent=2)
    print()
    return errors


def _idver_kv(idver: Tuple[str, int, str]) -> Iterator[Tuple[str, Any]]:
    return zip(["package", "versionCode", "versionName"], idver)


def _dump(data: bytes, *, json: bool, verbose: bool, xml: bool,
          resources: Optional[ResourceTableChunk] = None) -> None:
    magic = data[:4]
    if magic == ARSC_MAGIC:
        if xml:
            raise Error("ARSC does not contain XML")
        dump_arsc(*parse(data), json=json, verbose=verbose)
    elif magic == AXML_MAGIC:
        dump_axml(*parse(data), json=json, verbose=verbose, xml=xml, resources=resources)
    else:
        raise Error(f"Unsupported magic {magic!r}")


# FIXME
def dump_arsc(*chunks: Chunk, json: bool = False, verbose: bool = False) -> None:
    """Dump ARSC chunks to stdout."""
    if json:
        show_chunks_json(*chunks)
    else:
        show_chunks(*chunks, verbose=verbose)


# FIXME
def dump_axml(*chunks: Chunk, json: bool = False, verbose: bool = False,
              xml: bool = False, resources: Optional[ResourceTableChunk] = None) -> None:
    """Dump AXML chunks to stdout."""
    if json:
        show_chunks_json(*chunks)
    elif xml:
        show_chunks_xml(*chunks, resources=resources)
    else:
        show_chunks(*chunks, verbose=verbose)


# FIXME
def show_chunks(*chunks: Chunk, file: Optional[TextIO] = None,
                verbose: bool = False) -> None:
    """Show AXML/ARSC chunks as parse tree."""
    if file is None:
        file = sys.stdout
    for chunk in chunks:
        indent = 2 * chunk.level
        if isinstance(chunk, UnknownChunk):
            show_unknown_chunk(chunk, indent, file=file, verbose=verbose)
            continue
        fs, subs, children, cfg = [], [], None, None
        for k, t, h, _ in chunk.fields():
            if h or t.rstrip("]").endswith("Ref") or k.endswith("_offset") \
                    or k.endswith("_idx"):
                continue
            v = getattr(chunk, k)
            if k == "children":
                children = v
            elif k == "configuration":
                cfg = v
            elif v in ("", None) or "Chunk" in t or k == "typed_value":
                continue
            elif isinstance(v, tuple):
                fs.append((f"#{k}", len(v)))
                if k in ("strings", "styles"):
                    continue
                if (verbose or k in ("attributes", "entries")) and v:
                    subs.append((k, v))
            else:
                fs.append((k, v))
        print(f"{' ' * indent}{_clsname(chunk.__class__)}{_fs_info(fs)}", file=file)
        if cfg is not None:
            show_cfg(cfg, indent + 2, file=file)
        if subs:
            _show_subs(chunk, subs, indent + 2, file=file)
        if verbose and isinstance(chunk, StringPoolChunk):
            _show_strings_styles(chunk, indent + 2, file=file)
        if children is not None:
            show_chunks(*children, file=file, verbose=verbose)


# FIXME: LibraryChunk not implemented
def _show_subs(chunk: Chunk, subs: List[Tuple[str, Any]], indent: int, *,
               file: Optional[TextIO] = None) -> None:
    if file is None:
        file = sys.stdout
    for k, v in subs:
        if isinstance(v, tuple):
            if k == "attributes":
                for attr in v:
                    show_xmlattr(attr, indent, file=file)
            elif k == "entries":
                if isinstance(chunk, TypeChunk):
                    for i, entry in v:
                        show_type_entry(chunk, i, entry, indent, file=file)
                else:
                    # FIXME: LibraryChunk
                    raise _notimplemented(f"Showing entries for {chunk.__class__.__name__}")
            else:
                print(f"{' ' * indent}{k.upper()}:", file=file)
                for x in v:
                    y = f"0x{x:08x}" if isinstance(x, int) else repr(x)
                    print(f"{' ' * indent}  {y}", file=file)
        else:
            print(f"{' ' * indent}{k.upper()}: {v!r}", file=file)


def _show_strings_styles(chunk: StringPoolChunk, indent: int, *,
                         file: Optional[TextIO] = None) -> None:
    if file is None:
        file = sys.stdout
    if chunk.styles:
        print(f"{' ' * indent}STRINGS (SOME STYLED):", file=file)
        for string, style in chunk.styled_strings:
            s = repr(string) if string is not None else "[no string]"
            print(f"{' ' * indent}  {s}", file=file)
            if style is not None:
                spans = ", ".join(f"{s.name!r}:{s.start}-{s.stop}" for s in style.spans)
                print(f"{' ' * indent}    STYLE: {spans}", file=file)
    elif chunk.strings:
        _show_subs(chunk, [("strings", chunk.strings)], indent, file=file)


def show_unknown_chunk(c: UnknownChunk, indent: int, *,
                       file: Optional[TextIO] = None, verbose: bool = False) -> None:
    """Show UnknownChunk."""
    def wrap(s: str, i: str) -> str:
        return "\n".join(textwrap.wrap(s, width=80, initial_indent=i, subsequent_indent=i))
    if file is None:
        file = sys.stdout
    print(f"{' ' * indent}UNKNOWN CHUNK [type_id={c.type_id}]", file=file)
    if verbose:
        print(f"{' ' * indent}  HEADER (HEX):", file=file)
        print(wrap(binascii.hexlify(c.header).decode(), " " * (indent + 4)), file=file)
        print(f"{' ' * indent}  PAYLOAD (HEX):", file=file)
        print(wrap(binascii.hexlify(c.payload).decode(), " " * (indent + 4)), file=file)


def show_xmlattr(attr: XMLAttr, indent: int, *, file: Optional[TextIO] = None) -> None:
    """Show XMLAttr."""
    if file is None:
        file = sys.stdout
    ns, name, tv = attr.namespace, attr.name, attr.typed_value
    ns_info = f"{_safe(ns)}:" if ns else ""
    v = brv_repr(tv, attr.raw_value)
    print(f"{' ' * indent}ATTR: {ns_info}{_safe(name)}={v}", file=file)


def show_type_entry(c: TypeChunk, i: int, e: TypeChunk.Entry, indent: int, *,
                    file: Optional[TextIO] = None) -> None:
    """Show TypeChunk.Entry."""
    if file is None:
        file = sys.stdout
    info = f"id=0x{c.resource_id(i).to_int:08x}, key={e.key!r}"
    if e.parent_entry:
        info += f", parent=0x{e.parent_entry:08x}"
    print(f"{' ' * indent}ENTRY [{info}]", file=file)
    for k, brv in e.values_as_dict.items():
        r = c.string(brv.data) if brv.type is BinResVal.Type.STRING else ""
        v = brv_repr(brv, r)
        print(f"{' ' * indent}  VALUE{'' if k is None else f' 0x{k:08x}'}: {v}", file=file)


# FIXME: show size?
def show_cfg(c: BinResCfg, indent: int, *, file: Optional[TextIO] = None) -> None:
    """Show BinResCfg."""
    if file is None:
        file = sys.stdout
    info = _fs_info(list(c.fields_to_show.items())) or " [default]"
    print(f"{' ' * indent}CONFIG{info}", file=file)


def _fs_info(fs: List[Tuple[str, Any]]) -> str:
    zero_keys = ("flags", "res0", "res1")
    hex_keys = ("id",) + zero_keys
    fs_ = [(k, v) for k, v in fs if not (k in zero_keys and v == 0)]
    fs_joined = ", ".join(f"{k}={hex(v) if k in hex_keys else repr(v)}" for k, v in fs_)
    return f" [{fs_joined}]" if fs else ""


def show_chunks_json(*chunks: Chunk, file: Optional[TextIO] = None) -> None:
    """Show AXML/ARSC chunks as JSON."""
    if file is None:
        file = sys.stdout
    _json.dump(json_serialisable(chunks), file, indent=2, sort_keys=True)
    print(file=file)


# FIXME
def json_serialisable(obj: Any) -> Any:
    """Convert Chunk etc. to JSON serialisable data."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (tuple, list)):
        return [json_serialisable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: json_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, bytes):
        return dict(_type="bytes", value=binascii.hexlify(obj).decode())
    if isinstance(obj, Enum):
        return dict(name=obj.name, value=obj.value)
    d: Dict[str, Any] = dict(_type=obj.__class__.__name__)
    if isinstance(obj, (Chunk, BinResCfg, XMLAttr, TypeChunk.Entry,
                        StringPoolChunk.Style, StringPoolChunk.Span)):
        for k, t, _, _ in obj.fields():
            if not t.rstrip("]").endswith("Ref"):
                d[k] = json_serialisable(getattr(obj, k))
        return d
    if isinstance(obj, (BinResVal, LibraryChunk.Entry)):
        d.update(dataclasses.asdict(obj))
        return json_serialisable(d)
    raise TypeError(f"Unserializable {obj.__class__.__name__}")


def show_chunks_xml(*chunks: Chunk, file: Optional[TextIO] = None,
                    resources: Optional[ResourceTableChunk] = None) -> None:
    """Show XML chunk(s) in AXML chunks as XML."""
    if file is None:
        file = sys.stdout
    found = False
    for chunk in chunks:
        if isinstance(chunk, XMLChunk):
            found = True
            bio = io.BytesIO()
            tree = xmlchunk_to_etree(chunk, resources=resources)
            tree.write(bio)
            print(bio.getvalue().decode(), file=file)
    if not found:
        raise Error("No XML chunks")


def xmlchunk_to_etree(chunk: XMLChunk, *, indent: int = 2,
                      resources: Optional[ResourceTableChunk] = None) -> ET.ElementTree:
    """
    Convert XML chunk to xml.etree.ElementTree.ElementTree.

    NB: not thread-safe as it has to temporarily replace _namespace_map in the
    xml.etree.ElementTree module during this function and any later .write()
    since .register_namespace() uses a global registry.
    """
    def indent_tree(root: ET.Element, indent: str) -> None:
        def _indent_children(elem: ET.Element, level: int) -> None:
            if not elem.text or not elem.text.strip():
                elem.text = "\n" + indent * (level + 1)
            for child in elem:
                if len(child):
                    _indent_children(child, level + 1)
                if not child.tail or not child.tail.strip():
                    last_tail = child.tail = "\n" + indent * (level + 1)
                else:
                    last_tail = None
            if child.tail and last_tail is not None:
                child.tail = child.tail[:-2]
        if len(root):
            _indent_children(root, 0)

    def write(orig_write: Callable[..., None], nsmap: Dict[str, str]) -> Callable[..., None]:
        def f(*args: Any, **kwargs: Any) -> None:
            old_nsmap = ET._namespace_map           # type: ignore[attr-defined]
            ET._namespace_map = nsmap               # type: ignore[attr-defined]
            try:
                orig_write(*args, **kwargs)
            finally:
                ET._namespace_map = old_nsmap       # type: ignore[attr-defined]
        return f

    old_nsmap = ET._namespace_map                   # type: ignore[attr-defined]
    ET._namespace_map = nsmap = old_nsmap.copy()    # type: ignore[attr-defined]
    try:
        tb = ET.TreeBuilder()
        for c in chunk.children:
            if isinstance(c, XMLNSStartChunk):
                ET.register_namespace(c.prefix, c.uri)
            elif isinstance(c, XMLElemStartChunk):
                attrs = {}
                for a in c.attributes:
                    attrs[a.name_with_ns] = brv_str_deref(a.typed_value, a.raw_value,
                                                          resources=resources)
                tb.start(c.name, attrs)
            elif isinstance(c, XMLElemEndChunk):
                tb.end(c.name)
            elif isinstance(c, XMLCDATAChunk):
                tb.data(brv_str_deref(c.typed_value, c.raw_value, resources=resources))
        tree = ET.ElementTree(tb.close())
        if indent:
            indent_tree(tree.getroot(), " " * indent)
        setattr(tree, "write", write(tree.write, nsmap))
    finally:
        ET._namespace_map = old_nsmap               # type: ignore[attr-defined]
    return tree


def brv_repr(brv: BinResVal, raw_value: str) -> str:
    """repr() for BinResVal."""
    f_repr, _, x = brv_to_py(brv, raw_value)
    return f_repr(x)


def brv_str(brv: BinResVal, raw_value: str) -> str:
    """str() for BinResVal."""
    _, f_str, x = brv_to_py(brv, raw_value)
    return f_str(x)


def brv_str_deref(brv: BinResVal, raw_value: str, *,
                  resources: Optional[ResourceTableChunk] = None, deref_limit: int = 16) -> str:
    """brv_str() that follows references (if resouces is provided)."""
    if resources and brv.type is BinResVal.Type.REFERENCE:
        try:
            entries = resources.select_entries(brv.data, density=ResourceTableChunk.EntryFilter.ALL)
        except ResourceError:
            pass
        else:
            if entries:
                _, entry = min(entries, key=lambda x: (-x[0].density, x[0]))
                assert entry.value is not None
                if entry.value.type is BinResVal.Type.REFERENCE and deref_limit > 0:
                    return entry.str_value(resources=resources, deref_limit=deref_limit - 1)
                if entry.value.type is BinResVal.Type.STRING:
                    return entry.str_value()
                return brv_str(entry.value, "")
    return brv_str(brv, raw_value)


# FIXME: incomplete
def brv_to_py(brv: BinResVal, raw_value: str) \
        -> Tuple[Callable[[Any], str], Callable[[Any], str], Any]:
    """Convert BinResVal to value + repr/str functions to show it."""
    def null2s(i: int) -> str:
        return "@empty" if i == 1 else "@null"

    def ref2s(i: int) -> str:
        return f"@{i2h(i)}"

    def attr2s(i: int) -> str:
        return f"?{i2h(i)}"

    def f2s(f: float) -> str:
        return f"{f:g}"

    def c2s(c: Tuple[float, str]) -> str:
        val, suf = c
        return f"{val:f}{suf}"

    def i2h(i: int) -> str:
        return f"0x{i:08x}"

    def b2s(b: bool) -> str:
        return str(b).lower()

    def clr2s(i: int) -> str:
        return f"#{i:08x}"

    t, T = brv.type, BinResVal.Type
    if t is T.NULL:
        if brv.size == 0 and raw_value:
            return repr, str, raw_value
        return null2s, null2s, brv.data
    if t is T.REFERENCE:
        return ref2s, ref2s, brv.data
    if t is T.ATTRIBUTE:
        return attr2s, attr2s, brv.data
    if t is T.STRING:
        return repr, str, raw_value
    if t is T.FLOAT:
        return f2s, f2s, brv.float_value
    if t is T.DIMENSION:
        return c2s, c2s, BinResVal.complex2pair(brv.data, fraction=False)
    if t is T.FRACTION:
        return c2s, c2s, BinResVal.complex2pair(brv.data, fraction=True)
    if t in (T.DYNAMIC_REFERENCE, T.DYNAMIC_ATTRIBUTE):
        raise _notimplemented("Dynamic reference/attribute")
    if t is T.INT_DEC:
        return str, str, brv.data
    if t is T.INT_HEX:
        return i2h, i2h, brv.data
    if t is T.INT_BOOLEAN:
        return b2s, b2s, (False if brv.data == 0 else True)
    if t in (T.INT_COLOR_ARGB8, T.INT_COLOR_RGB8, T.INT_COLOR_ARGB4, T.INT_COLOR_RGB4):
        return clr2s, clr2s, brv.data
    raise ValueError(f"Unsupported value type {t.name}")


def py_type_to_brv_type(typ: type) -> BinResVal.Type:
    """Python type to BinResVal.Type (must be bool, int, float, str)."""
    if typ is bool:
        return BinResVal.Type.INT_BOOLEAN
    if typ is int:
        return BinResVal.Type.INT_DEC
    if typ is float:
        return BinResVal.Type.FLOAT
    if typ is str:
        return BinResVal.Type.STRING
    raise ValueError(f"Unsupported type {typ.__name__}")


def parse(data: bytes) -> Tuple[Chunk, ...]:
    """Parse raw data to AXML/ARSC chunks."""
    return tuple(read_chunks(data))


def read_chunks(data: bytes, parent: Optional[ChunkRef] = None, level: int = 0,
                offset: int = 0) -> Iterator[Chunk]:
    """Read multiple chunks."""
    while len(data) >= 8:
        chunk, data, level = read_chunk(data, parent, level, offset)
        offset += chunk.chunk_size
        yield chunk
    if data:
        raise ParseError("Expected end of data")


def read_chunk(data: bytes, parent: Optional[ChunkRef] = None,
               level: int = 0, offset: int = 0) -> Tuple[Chunk, bytes, int]:
    """Read one chunk; returns chunk, remainder, level."""
    type_id, d, data = _read_chunk(data, parent)
    if ct := CHUNK_TYPES.get(type_id):
        if "End" in ct.__name__:
            level -= 1
        chunk = ct.parse(**d, level=level, offset=offset)
        if "Start" in ct.__name__:
            level += 1
    else:
        kw = {**d, **Chunk._parse(**d)}
        chunk = UnknownChunk(_type_id=type_id, level=level, offset=offset, **kw)
    return chunk, data, level


def _read_chunk(data: bytes, parent: Optional[ChunkRef] = None) \
        -> Tuple[int, Dict[str, Any], bytes]:
    type_id, header_size, chunk_size, data = _unpack("<HHI", data)
    if header_size > chunk_size:
        raise ParseError("Header size > chunk size")
    if chunk_size - 8 > len(data):
        raise ParseError("Not enough data for chunk")
    header, data = _split(data, header_size - 8)
    chunk_data, data = _split(data, chunk_size - header_size)
    d = dict(header=header, payload=chunk_data, parent=parent)
    return type_id, d, data


def _read_attrs(data: bytes, parent: XMLNodeChunkRef,
                start: int, n: int) -> Iterator[XMLAttr]:
    for i in range(n):
        attr_data = data[start + 20 * i:start + 20 * (i + 1)]
        ns_idx, name_idx, raw_value_idx, tv_data = _unpack("<III", attr_data)
        yield XMLAttr(_noref(ns_idx), name_idx, _noref(raw_value_idx),
                      _read_brv(tv_data), parent)


def _read_brv(data: bytes) -> BinResVal:
    size, res0, typ = struct.unpack("<HBB", data[:4])
    return _brv(size, typ, data[4:], res0)


def _brv(size: int, typ: int, data: bytes, res0: int = 0) -> BinResVal:
    i, = struct.unpack("<i" if typ == BinResVal.Type.INT_DEC.value else "<I", data)
    return BinResVal(size, BinResVal.Type(typ), i, res0)


def _read_strings(data: bytes, off: int, n: int, codec: str) -> Iterator[str]:
    for i in range(n):
        o, = struct.unpack("<I", data[4 * i:4 * (i + 1)])
        yield _decode_string(data, off + o, codec)


def _read_styles(data: bytes, off: int, n: int, m: int,
                 parent: StringPoolChunkRef) -> Iterator[StringPoolChunk.Style]:
    for i in range(n):
        o, = struct.unpack("<I", data[4 * (m + i):4 * (m + i + 1)])
        yield StringPoolChunk.Style(tuple(_read_spans(data, off + o, parent)))


def _read_spans(data: bytes, off: int,
                parent: StringPoolChunkRef) -> Iterator[StringPoolChunk.Span]:
    while True:
        name_idx, = struct.unpack("<I", data[off:off + 4])
        if name_idx == StringPoolChunk.Style.SPAN_END:
            break
        start, stop = struct.unpack("<II", data[off + 4:off + 12])
        yield StringPoolChunk.Span(name_idx, start, stop, parent)
        off += 12


def _read_cfg(data: bytes) -> BinResCfg:
    size, mcc, mnc, lang, reg, orientation, touchscreen, density, \
        keyboard, navigation, input_flags, _, screen_width, screen_height, \
        sdk_version, minor_version = struct.unpack("<IHH2s2sBBHBBBBHHHH", data[:28])
    data = data[28:]
    language, region = _unpack_lang(lang, 0x61), _unpack_lang(reg, 0x30)
    screen_layout = ui_mode = smallest_screen_width_dp = 0
    screen_width_dp = screen_height_dp = 0
    locale_script = locale_variant = None
    screen_layout2 = 0
    if len(data) >= 4:
        screen_layout, ui_mode, smallest_screen_width_dp, data = _unpack("<BBH", data)
        if len(data) >= 4:
            screen_width_dp, screen_height_dp, data = _unpack("<HH", data)
            if len(data) >= 12:
                locale_script, locale_variant = struct.unpack("<4s8s", data[:12])
                data = data[12:]
                if locale_script == 4 * b"\x00":
                    locale_script = None
                if locale_variant == 8 * b"\x00":
                    locale_variant = None
                if len(data) >= 4:
                    screen_layout2, _, _, data = _unpack("<BBH", data)
    unknown = data or None
    return BinResCfg(
        size=size, mcc=mcc, mnc=mnc, language=language, region=region,
        orientation=BinResCfg.Orientation(orientation),
        touchscreen=BinResCfg.Touchscreen(touchscreen), density=density,
        keyboard=BinResCfg.Keyboard(keyboard),
        navigation=BinResCfg.Navigation(navigation), input_flags=input_flags,
        screen_width=screen_width, screen_height=screen_height, sdk_version=sdk_version,
        minor_version=minor_version, screen_layout=screen_layout, ui_mode=ui_mode,
        smallest_screen_width_dp=smallest_screen_width_dp,
        screen_width_dp=screen_width_dp, screen_height_dp=screen_height_dp,
        locale_script=locale_script, locale_variant=locale_variant,
        screen_layout2=screen_layout2, unknown=unknown,
    )


def _unpack_lang(b: bytes, base: int) -> Optional[str]:
    if len(b) != 2:
        raise ParseError("Expected language/region of 2 bytes")
    if b == b"\x00\x00":
        return None
    if b[0] & 0x80:
        b = bytes([base + (b[1] & 0x1F),
                   base + ((b[1] & 0xE0) >> 5) + ((b[0] & 0x03) << 3),
                   base + ((b[0] & 0x7C) >> 2)])
    return b.decode("ascii")


def _decode_string(data: bytes, off: int, codec: str) -> str:
    if codec == UTF8:
        i, m = _decode_strlen(data, off, codec)
        j, n = _decode_strlen(data, off + i, codec)
        a, b = off + i + j, off + i + j + n
        if data[b] != 0:
            if j != 2:
                raise ParseError("UTF-8 string not null-terminated")
            b = data.index(b"\x00", b)
            x = b - a
            if data[off + i:off + i + 2] != bytes([(x & 0x7F00) >> 8 | 0x80, x & 0xFF]):
                raise ParseError("UTF-8 string not null-terminated")
            log = logging.getLogger(__name__)
            log.warning(f"UTF-8 string null-terminator/length mismatch: expected {n}, got {x}")
        try:
            s = data[a:b].decode(codec)
            k = len(s)
        except UnicodeDecodeError:
            k, s = _decode_utf8_with_surrogates(data[a:b])
        if k != m:
            log = logging.getLogger(__name__)
            log.warning(f"UTF-8 string length mismatch: expected {m}, got {k}")
    elif codec == UTF16:
        i, n = _decode_strlen(data, off, codec)
        a, b = off + i, off + i + 2 * n
        if data[b:b + 2] != b"\x00\x00":
            raise ParseError("UTF-16 string not null-terminated")
        s = data[a:b].decode(codec)
    else:
        raise ValueError(f"Unsupported codec {codec!r}")
    return s


# https://en.wikipedia.org/wiki/UTF-16 surrogate pair
def _decode_utf8_with_surrogates(b: bytes) -> Tuple[int, str]:
    s = b.decode(UTF8, errors="surrogatepass")
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


def _decode_strlen(data: bytes, off: int, codec: str) -> Tuple[int, int]:
    if codec == UTF8:
        i, n = 1, data[off]
        if n & 0x80:
            i, n = 2, (n & 0x7F) << 8 | data[off + 1]
    elif codec == UTF16:
        i, n = 2, int.from_bytes(data[off:off + 2], "little")
        if n & 0x8000:
            i, n = 4, (n & 0x7FFF) << 16 | int.from_bytes(data[off + 2:off + 4], "little")
    else:
        raise ValueError(f"Unsupported codec {codec!r}")
    return i, n


def _decode_package_name(b: bytes) -> str:
    i = -1
    while (i := b.index(b"\x00\x00", i + 1)) % 2:
        pass
    return b[:i].decode(UTF16)


def _noref(idx: int) -> Optional[int]:
    return None if idx in (-1, -1 & 0xFFFFFFFF) else idx


def _clsname(cls: type) -> str:
    name = cls.__name__.replace("Chunk", "").replace("XML", "XML ")
    name_sp = re.sub(r"([A-Z][a-z])", r" \1", name)
    return " ".join(x.upper() for x in name_sp.split())


@lru_cache(maxsize=None)
def _fields(cls: Any) -> Tuple[Tuple[str, str, int, Optional[str]], ...]:
    # key, type, hidden (0=no, 1=yes, 2=sub(no), 3=sub(yes)), orig_key
    hf = getattr(cls, "HIDDEN_FIELDS", ())
    sf = getattr(cls, "SUBFIELDS", {})
    fs: List[Tuple[str, str, int, Optional[str]]] = []
    for f in dataclasses.fields(cls):
        assert isinstance(f.type, str)
        h = f.name in hf
        if names := sf.get(f.name):
            if names[0] == "#keep":     # FIXME
                names = names[1:]
                fs.append((f.name, f.type, h, None))
            else:
                fs.append((f.name, f.type, h + 2, None))
            for name in names:
                t = getattr(cls, name).fget.__annotations__["return"]
                fs.append((name, t, h, f.name))
        elif f.name.endswith("_idx") and hasattr(cls, k := f.name[:-4]):
            t = getattr(cls, k).fget.__annotations__["return"]
            fs.append((k, t, h, f.name))
        else:
            fs.append((f.name, f.type, h, None))
    return tuple(fs)


def _unpack(fmt: str, data: bytes) -> Any:
    assert all(c in "<BHI" for c in fmt)
    size = fmt.count("B") + 2 * fmt.count("H") + 4 * fmt.count("I")
    return struct.unpack(fmt, data[:size]) + (data[size:],)


def _split(data: bytes, size: int) -> Tuple[bytes, bytes]:
    return data[:size], data[size:]


def _safe(x: Any) -> str:
    if not isinstance(x, str):
        return repr(x)
    return "".join(c if c.isprintable() and c != '\\' else repr(c)[1:-1] for c in x)


def _notimplemented(what: str) -> NotImplementedError:
    msg = f"{what} not (yet) supported; please file an issue with a test case"
    return NotImplementedError(msg)


def _untested(what: str) -> None:
    msg = f"{what} not (yet) tested; please file an issue with a test case"
    log = logging.getLogger(__name__)
    log.warning(msg)


def quick_get_idver_perms(apk: str) \
        -> Tuple[Tuple[str, int, str], Iterator[Tuple[str, Tuple[Tuple[str, str], ...]]]]:
    chunk = read_chunk(quick_load(apk, MANIFEST))[0]
    if not isinstance(chunk, XMLChunk):
        raise ParseError("Expected XMLChunk")
    return quick_get_idver(apk, chunk=chunk), quick_get_perms(apk, chunk=chunk)


# FIXME
def quick_get_idver(apk: str, *, chunk: Optional[XMLChunk] = None) -> Tuple[str, int, str]:
    """Quickly get appid & version code/name from APK."""
    manifest = quick_get_manifest(apk, chunk=chunk)
    try:
        return _manifest_idver(manifest)
    except ParseError:
        return _manifest_idver(manifest, resources=quick_get_resources(apk))


# FIXME
def quick_get_perms(apk: str, *, chunk: Optional[XMLChunk] = None) \
        -> Iterator[Tuple[str, Tuple[Tuple[str, str], ...]]]:
    """Quickly get permissions from APK."""
    if chunk is None:
        first = read_chunk(quick_load(apk, MANIFEST))[0]
        if not isinstance(first, XMLChunk):
            raise ParseError("Expected XMLChunk")
        chunk = first
    manifest = None
    tag_stack: List[XMLElemStartChunk] = []
    for c in chunk.children:
        if isinstance(c, XMLElemStartChunk):
            parent_tag = tag_stack[-1] if tag_stack else None
            tag_stack.append(c)
            if not manifest and not parent_tag and c.name == "manifest" and not c.namespace:
                manifest = c
            elif manifest and parent_tag is manifest and _is_perm_tag(c):
                yield _perm_from_tag(c)
        elif isinstance(c, XMLElemEndChunk):
            if not tag_stack:
                raise ParseError("End tag with empty stack")
            if c.name != tag_stack.pop().name:
                raise ParseError("Expected end tag to match start")


# FIXME
def get_manifest_info(axml: bytes, files: Optional[Set[str]] = None, *, extended: bool = False,
                      resources: Optional[ResourceTableChunk] = None) -> ManifestInfo:
    r"""
    Get ManifestInfo from AXML (and optionally list of APK files for abis).

    >>> import dataclasses
    >>> with open("test/data/AndroidManifest-catima.xml", "rb") as fh:
    ...     axml = fh.read()
    >>> man = get_manifest_info(axml)
    >>> for field in dataclasses.fields(man):
    ...     x = getattr(man, field.name)
    ...     if isinstance(x, list):
    ...         print(f"{field.name}:")
    ...         for y in x:
    ...             print(f"  {y!r}")
    ...     else:
    ...         print(f"{field.name}={x!r}")
    appid='me.hackerchick.catima'
    version_code=134
    version_name='2.29.0'
    min_sdk=21
    target_sdk=34
    features:
      UsesFeature(name='android.hardware.camera', required=True)
      UsesFeature(name='android.hardware.camera.autofocus', required=False)
      UsesFeature(name='android.hardware.camera.front', required=False)
      UsesFeature(name='android.hardware.camera.flash', required=False)
      UsesFeature(name='android.hardware.screen.landscape', required=False)
      UsesFeature(name='android.hardware.wifi', required=False)
    permissions:
      UsesPermission(name='android.permission.CAMERA', min_sdk_version=None, max_sdk_version=None)
      UsesPermission(name='android.permission.READ_EXTERNAL_STORAGE', min_sdk_version=None, max_sdk_version=23)
      UsesPermission(name='me.hackerchick.catima.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', min_sdk_version=None, max_sdk_version=None)
    abis=None
    app_label=None
    app_icon=None
    >>> with open("test/data/resources-catima.arsc", "rb") as fh:
    ...     resources = _quick_get_resources(fh.read())
    >>> man = get_manifest_info(axml, extended=True, resources=resources)
    >>> man.app_label
    {'': ['Catima'], 'ar': ['كاتيما'], 'bg': ['Catima'], 'bn': ['ক্যাটিমা'], 'cs': ['Catima'], 'da': ['Catima'], 'de': ['Catima'], 'el-GR': ['Catima'], 'eo': ['Catima'], 'es': ['Catima'], 'es-AR': ['Catima'], 'fi': ['Catima'], 'fr': ['Catima'], 'hi': ['कैटिमा'], 'hr': ['Catima'], 'hu': ['Catima'], 'in-ID': ['Catima'], 'it': ['Catima'], 'ja': ['Catima'], 'ko': ['Catima'], 'nb-NO': ['Catima'], 'nl': ['Catima'], 'pl': ['Catima'], 'pt-PT': ['Catima'], 'ro-RO': ['Catima'], 'ru': ['Catima'], 'sk': ['Catima'], 'sv': ['Catima'], 'tr': ['Catima'], 'uk': ['Catima'], 'vi': ['Catima'], 'zh-CN': ['Catima'], 'zh-TW': ['Catima']}
    >>> man.app_icon
    {160: ['res/9w.png'], 240: ['res/yn.png'], 320: ['res/FS.png'], 480: ['res/RJ.png'], 640: ['res/o-.png'], 65534: ['res/BW.xml']}

    """
    chunk = read_chunk(axml)[0]
    if not isinstance(chunk, XMLChunk):
        raise ParseError("Expected XMLChunk")
    return _get_manifest_info(chunk, files, extended=extended, resources=resources)


# FIXME
# FIXME: minSdkVersion/targetSdkVersion="Q"
def _get_manifest_info(chunk: XMLChunk, files: Optional[Set[str]] = None, *, extended: bool = False,
                       resources: Optional[ResourceTableChunk] = None) -> ManifestInfo:
    manifest = uses_sdk = application = abis = app_label = None
    min_sdk = target_sdk = 1
    features: List[UsesFeature] = []
    permissions: List[UsesPermission] = []
    app_icon: Optional[Dict[int, List[str]]] = None
    if files:
        abis = sorted(set(f.split("/")[1] for f in files
                          if f.startswith("lib/") and f.endswith(".so")))
    tag_stack: List[XMLElemStartChunk] = []
    for c in chunk.children:
        if isinstance(c, XMLElemStartChunk):
            parent_tag = tag_stack[-1] if tag_stack else None
            tag_stack.append(c)
            if not parent_tag and c.name == "manifest" and not c.namespace:
                if manifest:
                    raise ParseError("Expected only one manifest element")
                manifest = c
            elif not manifest:
                raise ParseError("Expected manifest element")
            elif not (parent_tag is manifest and not c.namespace):
                continue
            if c.name == "uses-sdk":
                if uses_sdk:
                    raise ParseError("Expected only one uses-sdk element")
                uses_sdk = c
                msv = c.attr_as_int("minSdkVersion", android=True, optional=True)
                tsv = c.attr_as_int("targetSdkVersion", android=True, optional=True)
                min_sdk = msv if msv is not None else 1
                target_sdk = tsv if tsv is not None else min_sdk
            elif c.name == "uses-feature":
                if f"{{{SCHEMA_ANDROID}}}glEsVersion" in c.attrs_as_dict:
                    continue    # FIXME
                name = c.attr_as_str("name", android=True)
                assert name is not None
                req = c.attr_as_bool("required", android=True, optional=True)
                required = req if req is not None else True
                features.append(UsesFeature(name=name, required=required))
            elif c.name in ("uses-permission", "uses-permission-sdk-23"):
                name = c.attr_as_str("name", android=True)
                assert name is not None
                min_sdk_version = 23 if c.name.endswith("-sdk-23") else None
                max_sdk_version = c.attr_as_int("maxSdkVersion", android=True, optional=True)
                permissions.append(UsesPermission(name=name, min_sdk_version=min_sdk_version,
                                                  max_sdk_version=max_sdk_version))
            elif c.name == "application" and extended:
                if application:
                    raise ParseError("Expected only one application element")
                application = c
                ALL = ResourceTableChunk.EntryFilter.ALL
                if label := c.attrs_as_dict.get(f"{{{SCHEMA_ANDROID}}}label"):
                    if label.typed_value.type is BinResVal.Type.STRING:
                        label_str = c.attr_as_str("label", android=True, resources=resources)
                        assert label_str is not None
                        app_label = {"": [label_str]}
                    elif label.typed_value.type is not BinResVal.Type.REFERENCE:
                        raise ResourceError("Expected reference value for label")
                    elif resources:
                        app_label = {}
                        entries = resources.select_entries(label.typed_value.data, language=ALL, region=ALL)
                        for config, entry in sorted(entries, key=lambda x: (x[0].locale, x[0])):
                            app_label.setdefault(config.locale, []).append(entry.str_value(resources=resources))
                if icon := c.attrs_as_dict.get(f"{{{SCHEMA_ANDROID}}}icon"):
                    if icon.typed_value.type is not BinResVal.Type.REFERENCE:
                        raise ResourceError("Expected reference value for icon")
                    if resources:
                        app_icon = {}
                        entries = resources.select_entries(icon.typed_value.data, density=ALL)
                        for config, entry in sorted(entries, key=lambda x: (x[0].density, x[0])):
                            app_icon.setdefault(config.density, []).append(entry.str_value(resources=resources))
        elif isinstance(c, XMLElemEndChunk):
            if not tag_stack:
                raise ParseError("End tag with empty stack")
            if c.name != tag_stack.pop().name:
                raise ParseError("Expected end tag to match start")
    if not manifest:
        raise ParseError("No manifest element")
    appid, vercode, vername = _manifest_idver(manifest, resources=resources)
    return ManifestInfo(
        appid=appid, version_code=vercode, version_name=vername, min_sdk=min_sdk,
        target_sdk=target_sdk, features=features, permissions=permissions, abis=abis,
        app_label=app_label, app_icon=app_icon)


def get_manifest_info_apk(apk: str, *, extended: bool = False) -> ManifestInfo:
    r"""
    Get ManifestInfo from APK.

    >>> get_manifest_info_apk("test/data/golden-aligned-in.apk")
    ManifestInfo(appid='android.appsecurity.cts.tinyapp', version_code=10, version_name='1.0', min_sdk=23, target_sdk=23, features=[], permissions=[], abis=['armeabi'], app_label=None, app_icon=None)
    >>> get_manifest_info_apk("test/data/golden-aligned-in.apk", extended=True)
    ManifestInfo(appid='android.appsecurity.cts.tinyapp', version_code=10, version_name='1.0', min_sdk=23, target_sdk=23, features=[], permissions=[], abis=['armeabi'], app_label={'': ['Tiny App for CTS'], 'ar-XB': ['\u200f\u202eTiny\u202c\u200f \u200f\u202eApp\u202c\u200f \u200f\u202efor\u202c\u200f \u200f\u202eCTS\u202c\u200f'], 'en-XA': ['[Ţîñý Åþþ ƒöŕ ÇŢŠ one two three]']}, app_icon=None)

    """
    file_data, files = load_and_list_apk(apk, MANIFEST)
    have_arsc = ARSC_FILE in files
    if have_arsc and not extended:
        try:
            return get_manifest_info(file_data[MANIFEST], files)
        except ParseError:
            pass
    resources = quick_get_resources(apk) if have_arsc else None
    return get_manifest_info(file_data[MANIFEST], files, extended=extended, resources=resources)


# NB: includes declarations
def _is_perm_tag(chunk: XMLElemStartChunk) -> bool:
    return not chunk.namespace and chunk.name in (
        "uses-permission", "uses-permission-sdk-23", "permission")


# FIXME
def _perm_from_tag(chunk: XMLElemStartChunk) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    perm = chunk.attr_as_str("name", android=True)
    assert perm is not None
    attrs = {a.name: brv_str(a.typed_value, a.raw_value)
             for a in chunk.attrs_as_dict.values()
             if a.name_with_ns != f"{{{SCHEMA_ANDROID}}}name"}
    if chunk.name == "uses-permission-sdk-23":
        attrs["minSdkVersion"] = "23"
    elif chunk.name == "permission":
        attrs["declaration"] = "true"
    return perm, tuple(attrs.items())


def _manifest_idver(manifest: XMLElemStartChunk,
                    resources: Optional[ResourceTableChunk] = None) -> Tuple[str, int, str]:
    appid = manifest.attr_as_str("package")
    vercode = manifest.attr_as_int("versionCode", android=True)
    vername = manifest.attr_as_str("versionName", android=True, resources=resources)
    assert appid is not None and vercode is not None and vername is not None
    return appid, vercode, vername


# FIXME
def quick_get_manifest(apk: str, *, chunk: Optional[XMLChunk] = None) -> XMLElemStartChunk:
    """Quickly get manifest XMLElemStartChunk (w/o children) from APK."""
    if chunk is None:
        tid, d, _ = _read_chunk(quick_load(apk, MANIFEST))
        if tid != XMLChunk.TYPE_ID:
            raise ParseError("Expected XMLChunk")
        data, d["payload"] = d["payload"], b""
        xml = XMLChunk.parse(**d, level=0, offset=-1)
        ref: Optional[ChunkRef] = weakref.ref(xml)
        pool = start = None
        while data:
            tid, d, data = _read_chunk(data, parent=ref)
            if not pool and tid == StringPoolChunk.TYPE_ID:
                pool = StringPoolChunk.parse(**d, level=0, offset=-1)
            elif not start and tid == XMLElemStartChunk.TYPE_ID:
                start = XMLElemStartChunk.parse(**d, level=0, offset=-1)
            if pool and start:
                break
        else:
            raise ParseError("Expected StringPoolChunk and XMLElemStartChunk")
        object.__setattr__(xml, "children", (pool, start))
    else:
        for c in chunk.children:
            if isinstance(c, XMLElemStartChunk):
                start = c
                break
        else:
            raise ParseError("Expected XMLElemStartChunk")
    if not (start.name == "manifest" and not start.namespace):
        raise ParseError("Expected manifest element")
    return start


def quick_get_resources(apk: str) -> ResourceTableChunk:
    """Quickly get resources.arsc ResourceTableChunk from APK."""
    return _quick_get_resources(quick_load(apk, ARSC_FILE))


def _quick_get_resources(data: bytes) -> ResourceTableChunk:
    chunk = read_chunk(data)[0]
    if not isinstance(chunk, ResourceTableChunk):
        raise ParseError("Expected ResourceTableChunk")
    return chunk


def quick_load(apk: str, filename: str) -> bytes:
    """Quickly load one file from APK."""
    filename_b = filename.encode()
    zdata = zip_data(apk)
    with open(apk, "rb") as fh:
        fh.seek(zdata.cd_offset)
        while fh.tell() < zdata.eocd_offset:
            name, offset, ctype, csize = _zip_read_cdh(fh)
            if name == filename_b:
                return _zip_read_data(fh, offset, ctype, csize)
    raise Error(f"Entry not found: {filename!r}")


# FIXME
def load_and_list_apk(apk: str, *filenames: str,
                      expand: bool = False) -> Tuple[Dict[str, bytes], Set[str]]:
    r"""
    Load files from APK and list all files.

    >>> fd, fs = load_and_list_apk("test/data/golden-aligned-in.apk", "AndroidManifest.xml")
    >>> sorted(fs)
    ['AndroidManifest.xml', 'META-INF/', 'META-INF/MANIFEST.MF', 'classes.dex', 'lib/armeabi/fake.so', 'resources.arsc', 'temp.txt', 'temp2.txt']
    >>> sorted(fd.keys())
    ['AndroidManifest.xml']
    >>> fd, fs = load_and_list_apk("test/data/golden-aligned-in.apk", "*.xml", "*.dex",
    ...                            "*.arsc", "*.so", expand=True)
    >>> sorted(fs)
    ['AndroidManifest.xml', 'META-INF/', 'META-INF/MANIFEST.MF', 'classes.dex', 'lib/armeabi/fake.so', 'resources.arsc', 'temp.txt', 'temp2.txt']
    >>> sorted(fd.keys())
    ['AndroidManifest.xml', 'classes.dex', 'lib/armeabi/fake.so', 'resources.arsc']
    >>> fd["lib/armeabi/fake.so"]
    b'Hello\n'
    >>> fd["AndroidManifest.xml"][:4] == AXML_MAGIC
    True

    """
    if not expand:
        find = set(filenames)
    read = {}
    files = set()
    zdata = zip_data(apk)
    with open(apk, "rb") as fh:
        fh.seek(zdata.cd_offset)
        while fh.tell() < zdata.eocd_offset:
            name, offset, ctype, csize = _zip_read_cdh(fh)
            filename = name.decode()
            if filename in files:
                raise ZipError(f"Duplicate entry: {filename!r}")
            files.add(filename)
            if not expand and filename not in find:
                continue
            if expand and not fnmatches_with_negation(filename, *filenames):
                continue
            read[filename] = (offset, ctype, csize)
        if not expand and len(find) != len(read):
            raise Error(f"Entries not found: {sorted(find - set(read))}")
        file_data = {k: _zip_read_data(fh, o, t, s) for k, (o, t, s) in read.items()}
    return file_data, files


def _zip_read_cdh(fh: BinaryIO) -> Tuple[bytes, int, int, int]:
    hdr = fh.read(46)
    if hdr[:4] != b"\x50\x4b\x01\x02":
        raise ZipError("Expected central directory file header signature")
    n, m, k = struct.unpack("<HHH", hdr[28:34])
    hdr += fh.read(n + m + k)
    ctype = int.from_bytes(hdr[10:12], "little")
    csize = int.from_bytes(hdr[20:24], "little")
    offset = int.from_bytes(hdr[42:46], "little")
    return hdr[46:46 + n], offset, ctype, csize


def _zip_read_data(fh: BinaryIO, offset: int, ctype: int, csize: int) -> bytes:
    fh.seek(offset)
    hdr = fh.read(30)
    if hdr[:4] != b"\x50\x4b\x03\x04":
        raise ZipError("Expected local file header signature")
    n, m = struct.unpack("<HH", hdr[26:30])
    hdr += fh.read(n + m)
    if ctype == 0:
        return fh.read(csize)
    elif ctype == 8:
        return zlib.decompress(fh.read(csize), -15)
    else:
        raise ZipError(f"Unsupported compress_type {ctype}")


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


def zip_data(apkfile: str, count: int = 1024) -> ZipData:
    """Extract central directory, EOCD, and offsets from ZIP."""
    with open(apkfile, "rb") as fh:
        fh.seek(-min(os.path.getsize(apkfile), count), os.SEEK_END)
        data = fh.read()
        pos = data.rfind(b"\x50\x4b\x05\x06")
        if pos == -1:
            raise ZipError("Expected end of central directory record (EOCD)")
        fh.seek(pos - len(data), os.SEEK_CUR)
        eocd_offset = fh.tell()
        fh.seek(16, os.SEEK_CUR)
        cd_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(cd_offset)
        cd_and_eocd = fh.read()
    return ZipData(cd_offset, eocd_offset, cd_and_eocd)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="binres.py")
    subs = parser.add_subparsers(title="subcommands", dest="command")
    subs.required = True
    sub_dump = subs.add_parser("dump", help="parse & dump ARSC or AXML")
    sub_dump.add_argument("--apk", help="APK that contains the AXML/ARSC file(s)")
    sub_dump.add_argument("--json", action="store_true", help="output JSON")
    sub_dump.add_argument("--xml", action="store_true", help="output XML (AXML only)")
    sub_dump.add_argument("--deref", action="store_true", help="follow references (with --xml)")
    sub_dump.add_argument("--prolog", action="store_true", help="output XML prolog (with --xml)")
    sub_dump.add_argument("-q", "--quiet", action="store_true", help="don't show filenames")
    sub_dump.add_argument("-v", "--verbose", action="store_true")
    sub_dump.add_argument("files_or_patterns", metavar="FILE_OR_PATTERN", nargs="+")
    sub_fastid = subs.add_parser("fastid", help="quickly get appid & version code/name")
    sub_fastid.add_argument("--json", action="store_true", help="output JSON")
    sub_fastid.add_argument("--short", action="store_true", help="only show values")
    sub_fastid.add_argument("apks", metavar="APK", nargs="+")
    sub_fastperms = subs.add_parser("fastperms", help="quickly get permissions")
    sub_fastperms.add_argument("--json", action="store_true", help="output JSON")
    sub_fastperms.add_argument("--with-id", action="store_true",
                               help="also get appid & version code/name")
    sub_fastperms.add_argument("-q", "--quiet", action="store_true", help="don't show filenames")
    sub_fastperms.add_argument("apks", metavar="APK", nargs="+")
    sub_manifest_info = subs.add_parser("manifest-info", help="dump basic manifest info as JSON")
    sub_manifest_info.add_argument("-e", "--extended", action="store_true", help="also extract app label and icon")
    sub_manifest_info.add_argument("apks", metavar="APK", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "dump":
            if args.json and args.xml:
                raise Error("Conflicting options: --json and --xml")
            if args.deref and not args.xml:
                raise Error("Conflicting options: --deref without --xml")
            if args.prolog and not args.xml:
                raise Error("Conflicting options: --prolog without --xml")
            if args.apk:
                dump_apk(args.apk, *args.files_or_patterns, json=args.json, quiet=args.quiet,
                         verbose=args.verbose, xml=args.xml, xml_deref=args.deref,
                         xml_prolog=args.prolog)
            else:
                dump(*args.files_or_patterns, json=args.json, quiet=args.quiet,
                     verbose=args.verbose, xml=args.xml, xml_deref=args.deref,
                     xml_prolog=args.prolog)
        elif args.command == "fastid":
            fastid(*args.apks, json=args.json, short=args.short)
        elif args.command == "fastperms":
            fastperms(*args.apks, json=args.json, quiet=args.quiet, with_id=args.with_id)
        elif args.command == "manifest-info":
            if manifest_info(*args.apks, extended=args.extended):
                sys.exit(1)
        else:
            raise Error(f"Unknown command: {args.command}")
    except Error as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        pass

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
