# SPDX-License-Identifier: LGPL-3.0-or-later

"""
This module implements UEFI secure boot structures.
"""

from .base import (
    UEFIParser,
    UEFIVariable,
    UEFIEvent,
    register_variable_handler,
    register_event_handler
)
from ..common import UEFIEventType
from dataclasses import dataclass
from typing import Tuple, Type
from uuid import UUID


@dataclass
class SecureBootVariable(UEFIVariable):
    enabled: bool

    @classmethod
    def parse(cls, parser: UEFIParser) -> "SecureBootVariable":
        enabled = parser.get_int(1)
        return cls(
            enabled=bool(enabled),
        )


register_variable_handler(
    UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
    "SecureBoot",
    SecureBootVariable,
)


@dataclass
class SignatureData:
    signature_owner: UUID

    @classmethod
    def parse(cls, parser: UEFIParser) -> "SignatureData":
        raise NotImplementedError


@dataclass
class UnknownSignatureData(SignatureData):
    signature_data: bytes

    @classmethod
    def parse(cls, parser: UEFIParser) -> "UnknownSignatureData":
        signature_owner = parser.get_guid()
        signature_data = parser.get_bytes(parser.left)
        return cls(
            signature_owner=signature_owner,
            signature_data=signature_data,
        )


_signature_type_handlers = dict()


def register_signature_type_handler(
    signature_type: UUID, handler: Type[SignatureData]
) -> None:
    _signature_type_handlers[signature_type] = handler


def lookup_signature_type_handler(
    signature_type: UUID
) -> Type[SignatureData]:
    return _signature_type_handlers.get(signature_type, UnknownSignatureData)


@dataclass
class X509SignatureData(SignatureData):
    certificate: bytes

    @classmethod
    def parse(cls, parser: UEFIParser) -> "X509SignatureData":
        signature_owner = parser.get_guid()
        certificate = parser.get_bytes(parser.left)
        return cls(
            signature_owner=signature_owner,
            certificate=certificate,
        )


register_signature_type_handler(
    UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072"), X509SignatureData
)


@dataclass
class SignatureList:
    signature_type: UUID
    signature_header: bytes
    signatures: Tuple[SignatureData, ...]

    @classmethod
    def parse(cls, parser: UEFIParser) -> "SignatureList":
        signature_type = parser.get_guid()
        list_size = parser.get_uint32()
        header_size = parser.get_uint32()
        signature_size = parser.get_uint32()
        signature_header = parser.get_bytes(header_size)
        list_left = list_size - (16+4+4+4)
        signatures = list()
        while list_left:
            subdata = parser.get_bytes(signature_size)
            subparser = parser.get_subparser(subdata)
            handler = lookup_signature_type_handler(signature_type)
            data = handler.parse(subparser)
            signatures.append(data)
            list_left -= len(subdata)
        return cls(
            signature_type=signature_type,
            signature_header=signature_header,
            signatures=tuple(signatures),
        )


@dataclass
class SignaturesVariable(UEFIVariable):
    signature_lists: Tuple[SignatureList, ...]

    @classmethod
    def parse(cls, parser: UEFIParser) -> "SignaturesVariable":
        sigs = list()
        while parser.left:
            entry = SignatureList.parse(parser)
            sigs.append(entry)
        return cls(
            signature_lists=tuple(sigs)
        )


for db in ("PK", "KEK"):
    register_variable_handler(
        UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        db,
        SignaturesVariable,
    )


for db in ("db", "dbx"):
    register_variable_handler(
        UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
        db,
        SignaturesVariable,
    )


@dataclass
class UEFI_EV_EFI_VariableAuthorityEvent(UEFIEvent):
    variable_name: UUID
    unicode_name: bytes
    variable_data: SignatureData

    @classmethod
    def parse(
        cls, parser: UEFIParser, header: UEFIEvent
    ) -> "UEFI_EV_EFI_VariableAuthorityEvent":
        variable_name = parser.get_guid()
        unlen = parser.get_int(8)
        vdlen = parser.get_int(8)
        unicode_name = parser.get_bytes(unlen * 2)
        vdata = parser.get_bytes(vdlen)
        subparser = parser.get_subparser(vdata)
        handler = UnknownSignatureData
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
    UEFIEventType.ev_efi_variable_authority,
    UEFI_EV_EFI_VariableAuthorityEvent,
    7,
)
