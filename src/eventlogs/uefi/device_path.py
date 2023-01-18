# SPDX-License-Identifier: LGPL-3.0-or-later

"""
This module implements UEFI device path structures.
"""


from .base import UEFIParser, UEFIVariable, register_variable_handler
from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple, Union, Type
from uuid import UUID


class DeviceType(IntEnum):
    hardware = 1
    acpi = 2
    messaging = 3
    media = 4
    bios_boot_speciciation = 5
    end = 0x7F


class BaseDeviceSubType(IntEnum):
    end = 1
    entire_end = 0xFF


class AcpiDeviceSubType(IntEnum):
    acpi = 1
    extended_acpi = 2
    adr = 3
    nvdimm = 4


class HardwareDeviceSubType(IntEnum):
    pci = 1
    pccard = 2
    memmap = 3
    vendor = 4
    controller = 5
    bmc = 6


class MsgDeviceSubType(IntEnum):
    nvme_namespace = 0x17


class MediaDeviceSubType(IntEnum):
    harddrive = 1
    filepath = 4


class MBRType(IntEnum):
    mbr = 1
    gpt = 2


class PartitionSignatureType(IntEnum):
    none = 0
    mbr = 1
    guid = 2


@dataclass
class DevicePath:
    device_type: DeviceType
    device_subtype: int

    @classmethod
    def parse(cls, parser: UEFIParser, header: "DevicePath") -> "DevicePath":
        raise NotImplementedError


@dataclass
class UnknownDevicePath(DevicePath):
    data: bytes

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "UnknownDevicePath":
        data = parser.get_bytes(parser.left)
        return cls(
            device_type=header.device_type,
            device_subtype=header.device_subtype,
            data=data,
        )


_device_path_handlers = dict()


def register_device_path_handler(
    device_type: DeviceType, device_subtype: int, handler: Type[DevicePath]
):
    _device_path_handlers[(device_type, device_subtype)] = handler


def lookup_device_path_handler(
    device_type: DeviceType, device_subtype: int
):
    return _device_path_handlers.get(
        (device_type, device_subtype), UnknownDevicePath
    )


@dataclass
class AcpiDevicePath(DevicePath):
    device_subtype: AcpiDeviceSubType
    hid: int
    uid: int

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "AcpiDevicePath":
        hid = parser.get_uint32()
        uid = parser.get_uint32()
        return cls(
            device_type=header.device_type,
            device_subtype=AcpiDeviceSubType(header.device_subtype),
            hid=hid,
            uid=uid,
        )


register_device_path_handler(
    DeviceType.acpi, AcpiDeviceSubType.acpi, AcpiDevicePath
)


@dataclass
class PCIDevicePath(DevicePath):
    device_subtype: HardwareDeviceSubType
    function: int
    device: int

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "PCIDevicePath":
        function = parser.get_int(1)
        device = parser.get_int(1)
        return cls(
            device_type=header.device_type,
            device_subtype=HardwareDeviceSubType(header.device_subtype),
            function=function,
            device=device,
        )


register_device_path_handler(
    DeviceType.hardware, HardwareDeviceSubType.pci, PCIDevicePath
)


@dataclass
class MsgDevicePath(DevicePath):
    device_subtype: MsgDeviceSubType


@dataclass
class MsgNVMENamespaceDevicePath(MsgDevicePath):
    namespace_id: int
    namespace_uuid: int

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "MsgNVMENamespaceDevicePath":
        namespace_id = parser.get_uint32()
        namespace_uuid = parser.get_int(8)  # FIXME, might be big endian
        return cls(
            device_type=header.device_type,
            device_subtype=MsgDeviceSubType(header.device_subtype),
            namespace_id=namespace_id,
            namespace_uuid=namespace_uuid,
        )


register_device_path_handler(
    DeviceType.messaging,
    MsgDeviceSubType.nvme_namespace,
    MsgNVMENamespaceDevicePath,
)


@dataclass
class MediaDevicePath(DevicePath):
    device_subtype: MediaDeviceSubType


@dataclass
class HarddriveDevicePath(MediaDevicePath):
    partition_number: int
    partition_start: int
    partition_size: int
    signature: Union[None, int, UUID]
    mbr_type: MBRType
    signature_type: PartitionSignatureType

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "HarddriveDevicePath":
        signature: Union[None, int, UUID]
        partition_number = parser.get_uint32()
        partition_start = parser.get_int(8)
        partition_size = parser.get_int(8)
        sb = parser.get_bytes(16)
        mbr_type = parser.get_int(1)
        signature_type = parser.get_int(1)
        signature_type = PartitionSignatureType(signature_type)
        if signature_type == PartitionSignatureType.none:
            signature = None
        elif signature_type == PartitionSignatureType.mbr:
            signature = int.from_bytes(sb[0:4], byteorder="big")
        elif signature_type == PartitionSignatureType.guid:
            signature = UUID(bytes_le=sb)
        return cls(
            device_type=header.device_type,
            device_subtype=MediaDeviceSubType(header.device_subtype),
            partition_number=partition_number,
            partition_start=partition_start,
            partition_size=partition_size,
            signature=signature,
            mbr_type=mbr_type,
            signature_type=signature_type,
        )


register_device_path_handler(
    DeviceType.media,
    MediaDeviceSubType.harddrive,
    HarddriveDevicePath,
)


@dataclass
class FileDevicePath(MediaDevicePath):
    path_name: bytes

    @classmethod
    def parse(cls, parser: UEFIParser, header: DevicePath) -> "FileDevicePath":
        path_name = parser.get_bytes(parser.left)
        return cls(
            device_type=header.device_type,
            device_subtype=MediaDeviceSubType(header.device_subtype),
            path_name=path_name
        )


register_device_path_handler(
    DeviceType.media,
    MediaDeviceSubType.filepath,
    FileDevicePath,
)


@dataclass
class EntireEndDevicePath(DevicePath):
    device_subtype: BaseDeviceSubType

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: DevicePath
    ) -> "EntireEndDevicePath":
        return cls(
            device_type=header.device_type,
            device_subtype=BaseDeviceSubType(header.device_subtype)
        )


register_device_path_handler(
    DeviceType.end,
    BaseDeviceSubType.entire_end,
    EntireEndDevicePath,
)


def parse_device_path(parser: UEFIParser) -> Tuple[DevicePath, ...]:
    entries = list()
    while parser.left:
        device_type = parser.get_int(1)
        device_subtype = parser.get_int(1)
        header = DevicePath(
            device_type=DeviceType(device_type),
            device_subtype=device_subtype,
        )
        dl = parser.get_int(2)
        subdata = parser.get_bytes(dl - 4)
        subparser = parser.get_subparser(subdata)
        handler = lookup_device_path_handler(device_type, device_subtype)
        dp = handler.parse(subparser, header)
        entries.append(dp)
    return tuple(entries)


@dataclass
class UEFIBootVariable(UEFIVariable):
    attributes: int  # FIXME, add enum
    description: bytes
    file_path_list: Tuple[DevicePath, ...]
    optional_data: bytes

    @classmethod
    def parse(cls, parser: UEFIParser) -> "UEFIBootVariable":
        attributes = parser.get_uint32()
        fpl = parser.get_int(2)
        description = parser.get_utf16()
        subdata = parser.get_bytes(fpl)
        subparser = parser.get_subparser(subdata)
        file_path_list = parse_device_path(subparser)
        optional_data = parser.get_bytes(parser.left)
        return cls(
            attributes=attributes,
            description=description,
            file_path_list=file_path_list,
            optional_data=optional_data,
        )


for order in range(0, 65535):
    register_variable_handler(
        UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        f"Boot{order:04X}",
        UEFIBootVariable,
    )


@dataclass
class UEFIBootOrderVariable(UEFIVariable):
    boot_order: Tuple[int, ...]

    @classmethod
    def parse(cls, parser: UEFIParser) -> "UEFIBootOrderVariable":
        entries = list()
        while parser.left:
            entry = parser.get_int(2)
            entries.append(entry)
        return cls(boot_order=tuple(entries))


register_variable_handler(
    UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
    "BootOrder",
    UEFIBootOrderVariable,
)
