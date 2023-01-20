# SPDX-License-Identifier: LPL-3.0-or-later

from enum import IntEnum
from typing import Iterable, Union


class _EnumBase(IntEnum):
    """Simple class to override default Enum __str__"""
    def __str__(self) -> str:
        return f"{self.name}"


class DigestAlgorithm(_EnumBase):
    """Digest algorihtms"""
    sha1 = 4
    sha256 = 11
    sha384 = 12
    sha512 = 13
    sm3_256 = 18


class UEFIEventType(_EnumBase):
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


class ShortBufferError(Exception):
    def __init__(self, offset: int, requested: int, left: int):
        self._offset = offset
        self._requested = requested
        self._left = left

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def requested(self) -> int:
        return self._requested

    @property
    def left(self) -> int:
        return self._left

    def __str__(self) -> str:
        return (
            f"requested {self.requested} bytes, "
            f"but only {self.left} at offset {self.offset}"
        )


class NotConsumedError(Exception):
    def __init__(self, left: int):
        self._left = left

    @property
    def left(self) -> int:
        return self._left

    def __str__(self) -> str:
        return f"{self.left} bytes not consumed"


class UnexpectedTypeError(Exception):
    def __init__(
        self, got: Union[int, str], expected: Iterable[Union[int, str]]
    ):
        self._got = got
        self._expected = expected

    @property
    def got(self) -> Union[int, str]:
        return self._got

    @property
    def expected(self) -> Iterable[Union[int, str]]:
        return self._expected

    def __str__(self) -> str:
        estr = ", ".join([str(x) for x in self.expected])
        return f"unexpected type {self.got}, expected one of: {estr}"
