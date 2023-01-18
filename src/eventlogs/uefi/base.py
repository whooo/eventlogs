# SPDX-License-Identifier: LGPL-3.0-or-later

"""
This module implements UEFI structures and encodings.
"""

from ..common import DigestAlgorithm
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional, Type, Union, Tuple
from uuid import UUID


class UEFIEventType(IntEnum):
    ev_post_code = 0x00000001
    ev_no_action = 0x00000003
    ev_separator = 0x00000004
    ev_action = 0x00000005
    ev_event_tag = 0x00000006
    ev_s_crtm_contents = 0x00000007
    ev_s_crtm_version = 0x00000008
    ev_cpu_microcode = 0x00000009
    ev_platform_config_flags = 0x0000000A
    ev_table_of_devices = 0x0000000B
    ev_compact_hash = 0x0000000C
    ev_ipl = 0x0000000D
    ev_ipl_partition_data = 0x0000000E
    ev_nonhost_code = 0x0000000F
    ev_nonhost_config = 0x00000010
    ev_nonhost_info = 0x00000011
    ev_omit_boot_device_events = 0x00000012
    ev_efi_event_base = 0x80000000
    ev_efi_variable_driver_config = 0x80000001
    ev_efi_variable_boot = 0x80000002
    ev_efi_boot_services_application = 0x80000003
    ev_efi_boot_services_driver = 0x80000004
    ev_efi_runtime_services_driver = 0x80000005
    ev_efi_gpt_event = 0x80000006
    ev_efi_action = 0x80000007
    ev_efi_platform_firmware_blob = 0x80000008
    ev_efi_handoff_tables = 0x80000009
    ev_efi_platform_firmware_blob2 = 0x8000000A
    ev_efi_handoff_tables2 = 0x8000000B
    ev_efi_variable_boot2 = 0x8000000C
    ev_efi_hcrtm_event = 0x80000010
    ev_efi_variable_authority = 0x800000E0
    ev_efi_spdm_firmware_blob = 0x800000E1
    ev_efi_spdm_firmware_config = 0x800000E2


@dataclass
class UEFIEvent:
    pcr: int
    event_type: UEFIEventType
    digests: Dict[DigestAlgorithm, bytes]

    @classmethod
    def parse(cls, parser: "UEFIParser", header: "UEFIEvent") -> "UEFIEvent":
        raise NotImplementedError


@dataclass
class UEFIUnknownEvent(UEFIEvent):
    event_data: bytes

    @classmethod
    def parse(
        cls, parser: "UEFIParser", header: UEFIEvent
    ) -> "UEFIUnknownEvent":
        event_data = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            event_data=event_data
        )


@dataclass
class UEFIVariable:
    @classmethod
    def parse(cls, parser: "UEFIParser") -> "UEFIVariable":
        raise NotImplementedError


@dataclass
class UEFIUnknownVariable(UEFIVariable):
    data: bytes

    @classmethod
    def parse(cls, parser: "UEFIParser") -> "UEFIUnknownVariable":
        data = parser.get_bytes(parser.left)
        return cls(data=data)


@dataclass
class SpecIDEvent(UEFIEvent):
    signature: bytes
    platform_class: int
    spec_version_minor: int
    spec_version_major: int
    spec_errata: int
    uintn_size: int
    digest_sizes: Dict[DigestAlgorithm, int]
    vendor_info_size: int


_event_handlers = dict()


def register_event_handler(
    event_type: UEFIEventType,
    handler: Type[UEFIEvent],
    pcr: Optional[int] = None,
) -> None:
    key: Union[UEFIEventType, Tuple[UEFIEventType, int]]
    key = event_type
    if pcr is not None:
        key = (event_type, pcr)
    _event_handlers[key] = handler


def lookup_event_handler(
    event_type: UEFIEventType, pcr: int
) -> Type[UEFIEvent]:
    key: Union[UEFIEventType, Tuple[UEFIEventType, int]]
    key = (event_type, pcr)
    if key in _event_handlers:
        return _event_handlers[key]
    key = event_type
    return _event_handlers.get(key, UEFIUnknownEvent)


_variable_handlers = dict()


def register_variable_handler(
    variable_name: UUID,
    unicode_name: Union[bytes, str],
    handler: Type[UEFIVariable],
) -> None:
    if isinstance(unicode_name, str):
        unicode_name = unicode_name.encode("utf-16-le")
    _variable_handlers[(variable_name, unicode_name)] = handler


def lookup_variable_handler(
    variable_name: UUID, unicode_name: bytes
) -> Type[UEFIVariable]:
    return _variable_handlers.get(
        (variable_name, unicode_name), UEFIUnknownVariable
    )


class UEFIParser:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0
        self._uintn = 2
        self._digest_sizes: Dict[DigestAlgorithm, int] = dict()

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def left(self) -> int:
        return len(self._data) - self.offset

    @property
    def uintn_size(self) -> int:
        if self._uintn == 2:
            return 8
        elif self._uintn == 1:
            return 4
        raise AttributeError

    def get_bytes(self, size: int) -> bytes:
        if size > self.left:
            raise EOFError
        elif size < 0:
            raise ValueError
        b = self._data[self.offset:self.offset+size]
        self._offset += size
        return b

    def get_int(self, size: int) -> int:
        vb = self.get_bytes(size)
        return int.from_bytes(vb, byteorder="little")

    def get_uint32(self) -> int:
        return self.get_int(4)

    def get_len_bytes(self) -> bytes:
        vl = self.get_uint32()
        b = self.get_bytes(vl)
        return b

    def get_subparser(self, data: bytes) -> "UEFIParser":
        subparser = type(self)(
            data
        )
        subparser._uintn = self._uintn
        return subparser

    def get_guid(self) -> UUID:
        b = self.get_bytes(16)
        return UUID(bytes_le=b)

    def get_utf16(self) -> bytes:
        b = bytearray()
        while True:
            c = self.get_bytes(2)
            b.extend(c)
            if c == b"\x00\x00":
                break
        return bytes(b)

    def get_digests(self) -> Dict[DigestAlgorithm, bytes]:
        num_digs = self.get_uint32()
        digests = dict()
        while num_digs:
            algid = self.get_int(2)
            alg = DigestAlgorithm(algid)
            digsize = self._digest_sizes[alg]
            digest = self.get_bytes(digsize)
            digests[alg] = digest
            num_digs -= 1
        return digests

    def parse_header_event(self) -> SpecIDEvent:
        pcr = self.get_uint32()
        event_type = self.get_uint32()
        digest = self.get_bytes(20)
        subdata = self.get_len_bytes()
        subparser = self.get_subparser(subdata)
        signature = subparser.get_bytes(16)
        platform_class = subparser.get_uint32()
        spec_version_minor = subparser.get_int(1)
        spec_version_major = subparser.get_int(1)
        spec_errata = subparser.get_int(1)
        uintn_size = subparser.get_int(1)
        num_digs = subparser.get_uint32()
        digest_sizes = dict()
        while num_digs:
            algid = subparser.get_int(2)
            algsize = subparser.get_int(2)
            alg = DigestAlgorithm(algid)
            digest_sizes[alg] = algsize
            num_digs -= 1
        vendor_info_size = subparser.get_int(1)
        self._uintn = uintn_size
        self._digest_sizes = digest_sizes
        digests = {DigestAlgorithm.sha1: digest}
        return SpecIDEvent(
            pcr=pcr,
            event_type=UEFIEventType(event_type),
            digests=digests,
            signature=signature,
            platform_class=platform_class,
            spec_version_minor=spec_version_minor,
            spec_version_major=spec_version_major,
            spec_errata=spec_errata,
            uintn_size=uintn_size,
            digest_sizes=digest_sizes,
            vendor_info_size=vendor_info_size,
        )

    def parse_event(self) -> UEFIEvent:
        pcr = self.get_uint32()
        event_type = self.get_uint32()
        event_type = UEFIEventType(event_type)
        digests = self.get_digests()
        header = UEFIEvent(
            pcr=pcr,
            event_type=event_type,
            digests=digests,
        )
        subdata = self.get_len_bytes()
        subparser = self.get_subparser(subdata)
        cls = lookup_event_handler(event_type, pcr)
        event = cls.parse(subparser, header)
        return event
