# SPDX-License-Identifier: LGPL-3.0-or-later

"""
This module implements UEFI structures
"""

from .base import (
    UEFIEventType,
    UEFIEvent,
    UEFIParser,
    register_event_handler,
    lookup_variable_handler,
    UEFIVariable,
)
from .device_path import DevicePath, parse_device_path
from . import secureboot
from dataclasses import dataclass
from uuid import UUID
from typing import Tuple


@dataclass
class UEFI_EV_S_CRTM_ContentsEvent(UEFIEvent):
    blob_description: bytes
    blob_base: int
    blob_length: int

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_S_CRTM_ContentsEvent":
        ds = parser.get_int(1)
        blob_description = parser.get_bytes(ds)
        blob_base = parser.get_int(8)
        blob_length = parser.get_int(8)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            blob_description=blob_description,
            blob_base=blob_base,
            blob_length=blob_length,
        )


register_event_handler(
    UEFIEventType.ev_s_crtm_contents, UEFI_EV_S_CRTM_ContentsEvent, pcr=0
)


@dataclass
class UEFI_EV_S_CRTM_VersionEvent(UEFIEvent):
    version_string: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_S_CRTM_VersionEvent":
        version_string = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            version_string=version_string,
        )


register_event_handler(
    UEFIEventType.ev_s_crtm_version, UEFI_EV_S_CRTM_VersionEvent, pcr=0
)


@dataclass
class UEFI_EV_EFI_PlatformFirmwareBlobEvent(UEFIEvent):
    blob_base: int
    blob_length: int

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EFI_PlatformFirmwareBlobEvent":
        blob_base = parser.get_int(8)
        blob_length = parser.get_int(8)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            blob_base=blob_base,
            blob_length=blob_length,
        )


register_event_handler(
    UEFIEventType.ev_efi_platform_firmware_blob,
    UEFI_EV_EFI_PlatformFirmwareBlobEvent,
    pcr=0,
)


register_event_handler(
    UEFIEventType.ev_efi_platform_firmware_blob,
    UEFI_EV_EFI_PlatformFirmwareBlobEvent,
    pcr=2,
)


register_event_handler(
    UEFIEventType.ev_efi_platform_firmware_blob,
    UEFI_EV_EFI_PlatformFirmwareBlobEvent,
    pcr=4,
)


@dataclass
class UEFIVariableDataEvent(UEFIEvent):
    variable_name: UUID
    unicode_name: str
    variable_data: UEFIVariable

    @property
    def name(self):
        nstr = self.unicode_name.decode("utf-16-le")
        gstr = str(self.variable_name)
        return f"{nstr}-{gstr}"

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFIVariableDataEvent":
        variable_name = parser.get_guid()
        unlen = parser.get_int(8)
        vdlen = parser.get_int(8)
        unicode_name = parser.get_bytes(unlen * 2)
        vdata = parser.get_bytes(vdlen)
        subparser = parser.get_subparser(vdata)
        handler = lookup_variable_handler(variable_name, unicode_name)
        variable_data = handler.parse(subparser)
        if parser.left:
            raise ValueError
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            variable_name=variable_name,
            unicode_name=unicode_name,
            variable_data=variable_data,
        )


register_event_handler(
    UEFIEventType.ev_efi_variable_driver_config, UEFIVariableDataEvent
)


register_event_handler(
    UEFIEventType.ev_efi_variable_boot, UEFIVariableDataEvent
)


@dataclass
class UEFI_EV_SeparatorEvent(UEFIEvent):
    data: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_SeparatorEvent":
        data = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            data=data,
        )


register_event_handler(
    UEFIEventType.ev_separator, UEFI_EV_SeparatorEvent
)


@dataclass
class UEFI_EV_EFI_ActionEvent(UEFIEvent):
    action: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EFI_ActionEvent":
        action = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            action=action,
        )


register_event_handler(
    UEFIEventType.ev_efi_action, UEFI_EV_EFI_ActionEvent
)


@dataclass
class UEFI_EF_EFI_BootServicesApplicationEvent(UEFIEvent):
    image_location_in_memory: int
    image_length_in_memory: int
    image_link_time_address: int
    device_path: DevicePath

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EF_EFI_BootServicesApplicationEvent":
        image_location_in_memory = parser.get_int(8)
        image_length_in_memory = parser.get_int(8)
        image_link_time_address = parser.get_int(8)
        dpl = parser.get_int(8)
        dp_data = parser.get_bytes(dpl)
        dpparser = parser.get_subparser(dp_data)
        device_path = parse_device_path(dpparser)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            image_location_in_memory=image_location_in_memory,
            image_length_in_memory=image_length_in_memory,
            image_link_time_address=image_link_time_address,
            device_path=device_path,
        )


register_event_handler(
    UEFIEventType.ev_efi_boot_services_application,
    UEFI_EF_EFI_BootServicesApplicationEvent,
)


@dataclass
class UEFI_EV_IPLEvent(UEFIEvent):
    data: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_IPLEvent":
        data = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            data=data,
        )


register_event_handler(
    UEFIEventType.ev_ipl, UEFI_EV_IPLEvent,
)


@dataclass
class UEFI_EV_PostCodeEvent(UEFIEvent):
    post_code: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_PostCodeEvent":
        post_code = parser.get_bytes(parser.left)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            post_code=post_code,
        )


register_event_handler(
    UEFIEventType.ev_post_code, UEFI_EV_PostCodeEvent,
)


@dataclass
class UEFI_EV_EFI_HandoffTablesEvent(UEFIEvent):
    table_entries: Tuple[Tuple[UUID, int]]

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EFI_HandoffTablesEvent":
        num_tables = parser.get_int(8)
        entries = list()
        while num_tables:
            guid = parser.get_guid()
            table = parser.get_int(8)
            entries.append((guid, table))
            num_tables -= 1
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            table_entries=tuple(entries),
        )


register_event_handler(
    UEFIEventType.ev_efi_handoff_tables, UEFI_EV_EFI_HandoffTablesEvent,
)


@dataclass
class UEFI_EV_EventTagEvent(UEFIEvent):
    tagged_event_id: int
    tagged_event_data: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EventTagEvent":
        tagged_event_id = parser.get_uint32()
        data_len = parser.get_uint32()
        tagged_event_data = parser.get_bytes(data_len)
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            tagged_event_id=tagged_event_id,
            tagged_event_data=tagged_event_data,
        )


register_event_handler(
    UEFIEventType.ev_event_tag, UEFI_EV_EventTagEvent,
)


@dataclass
class UEFIPartitionHeader:
    signature: int
    revision: int
    header_size: int
    header_crc32: int
    my_lba: int
    alternate_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: UUID
    partition_entry_lba: int
    number_of_partition_entries: int
    size_of_partition_entry: int
    partition_entry_array_crc32: int

    @classmethod
    def parse(cls, parser: UEFIParser) -> "UEFIPartitionHeader":
        signature = parser.get_int(8)
        revision = parser.get_uint32()
        header_size = parser.get_uint32()
        header_crc32 = parser.get_uint32()
        parser.get_uint32()  # Reserved field
        my_lba = parser.get_int(8)
        alternate_lba = parser.get_int(8)
        first_usable_lba = parser.get_int(8)
        last_usable_lba = parser.get_int(8)
        disk_guid = parser.get_guid()
        partition_entry_lba = parser.get_int(8)
        number_of_partition_entries = parser.get_uint32()
        size_of_partition_entry = parser.get_uint32()
        partition_entry_array_crc32 = parser.get_uint32()
        return cls(
            signature=signature,
            revision=revision,
            header_size=header_size,
            header_crc32=header_crc32,
            my_lba=my_lba,
            alternate_lba=alternate_lba,
            first_usable_lba=first_usable_lba,
            last_usable_lba=last_usable_lba,
            disk_guid=disk_guid,
            partition_entry_lba=partition_entry_lba,
            number_of_partition_entries=number_of_partition_entries,
            size_of_partition_entry=size_of_partition_entry,
            partition_entry_array_crc32=partition_entry_array_crc32,
        )


@dataclass
class UEFIPartitionEntry:
    partition_type_guid: UUID
    unique_partition_guid: UUID
    starting_lba: int
    ending_lba: int
    attributes: int  # FIXME, add enum
    partition_name: bytes

    @property
    def name(self):
        return self.partition_name.decode("utf-16-le")

    @classmethod
    def parse(cls, parser: UEFIParser) -> "UEFIPartitionHeader":
        partition_type_guid = parser.get_guid()
        unique_partition_guid = parser.get_guid()
        starting_lba = parser.get_int(8)
        ending_lba = parser.get_int(8)
        attributes = parser.get_int(8)
        partition_name = parser.get_bytes(36 * 2)
        return cls(
            partition_type_guid=partition_type_guid,
            unique_partition_guid=unique_partition_guid,
            starting_lba=starting_lba,
            ending_lba=ending_lba,
            attributes=attributes,
            partition_name=partition_name,
        )


@dataclass
class UEFI_EV_EFI_GPTEvent(UEFIEvent):
    partition_header: UEFIPartitionHeader
    partition_entries: Tuple[UEFIPartitionEntry]

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EFI_GPTEvent":
        partition_header = UEFIPartitionHeader.parse(parser)
        num_partitions = parser.get_int(8)
        entries = list()
        while num_partitions:
            entry = UEFIPartitionEntry.parse(parser)
            entries.append(entry)
            num_partitions -= 1
        return cls(
            pcr=header.pcr,
            event_type=header.event_type,
            digests=header.digests,
            partition_header=partition_header,
            partition_entries=tuple(entries),
        )


register_event_handler(
    UEFIEventType.ev_efi_gpt_event, UEFI_EV_EFI_GPTEvent,
)
