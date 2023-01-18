# SPDX-License-Identifier: LGPL-3.0-or-later

"""
This module implements IMA structures and encodings.
"""

from .common import DigestAlgorithm
from dataclasses import dataclass
from enum import Enum
from typing import Tuple, Dict, List, Literal


class IMATemplateField(Enum):
    d = b"d"
    n = b"n"
    d_ng = b"d-ng"
    d_ngv2 = b"d-ngv2"
    d_modsig = b"d-modsig"
    n_ng = b"n-ng"
    sig = b"sig"
    modsig = b"modsig"
    buf = b"buf"
    evmsig = b"evmsig"
    iuid = b"iuid"
    igid = b"igid"
    imode = b"imode"
    xattrnames = b"xattrnames"
    xattrlengths = b"xattrlengths"
    xattrvalues = b"xattrvalues"


class IMATemplateDescriptor:
    ima = (IMATemplateField.d, IMATemplateField.n)
    ima_ng = (IMATemplateField.d_ng, IMATemplateField.n_ng)
    ima_ngv2 = (IMATemplateField.d_ngv2, IMATemplateField.n_ng)
    ima_sig = (
        IMATemplateField.d_ng, IMATemplateField.n_ng, IMATemplateField.sig
    )
    ima_sigv2 = (
        IMATemplateField.d_ngv2, IMATemplateField.n_ng, IMATemplateField.sig
    )
    ima_buf = (
        IMATemplateField.d_ng, IMATemplateField.n_ng, IMATemplateField.buf
    )
    ima_modsig = (
        IMATemplateField.d_ng,
        IMATemplateField.n_ng,
        IMATemplateField.sig,
        IMATemplateField.d_modsig,
        IMATemplateField.modsig,
    )
    evm_sig = (
        IMATemplateField.d_ng,
        IMATemplateField.n_ng,
        IMATemplateField.evmsig,
        IMATemplateField.xattrnames,
        IMATemplateField.xattrlengths,
        IMATemplateField.xattrvalues,
        IMATemplateField.iuid,
        IMATemplateField.igid,
        IMATemplateField.imode,
    )

    @classmethod
    def expand(cls, descriptor: bytes) -> Tuple[IMATemplateField, ...]:
        if descriptor == b"ima":
            return cls.ima
        elif descriptor == b"ima-ng":
            return cls.ima_ng
        elif descriptor == b"ima-ngv2":
            return cls.ima_ngv2
        elif descriptor == b"ima-sig":
            return cls.ima_sig
        elif descriptor == b"ima-sigv2":
            return cls.ima_sigv2
        elif descriptor == b"ima-buf":
            return cls.ima_buf
        elif descriptor == b"ima-modsig":
            return cls.ima_modsig
        elif descriptor == b"evm-sig":
            return cls.evm_sig
        raise KeyError


@dataclass
class IMAField:
    field: IMATemplateField


@dataclass
class IMAFieldD(IMAField):
    field = IMATemplateField.d
    digest: bytes


@dataclass
class IMAFieldN(IMAField):
    field = IMATemplateField.n
    name: bytes


@dataclass
class IMAFieldD_NG(IMAField):
    field = IMATemplateField.d_ng
    algorithm: bytes
    digest: bytes


@dataclass
class IMAFieldD_NGv2(IMAField):
    field = IMATemplateField.d_ngv2
    type: bytes
    algorithm: bytes
    digest: bytes


@dataclass
class IMAFieldD_ModSig(IMAField):
    field = IMATemplateField.d_modsig
    digest: bytes


@dataclass
class IMAFieldN_NG(IMAField):
    field = IMATemplateField.n_ng
    name: bytes


@dataclass
class IMAFieldSig(IMAField):
    field = IMATemplateField.sig
    signature: bytes


@dataclass
class IMAFieldModSig(IMAField):
    field = IMATemplateField.modsig
    signature: bytes


@dataclass
class IMAFieldBuf(IMAField):
    field = IMATemplateField.buf
    buffer: bytes


@dataclass
class IMAFieldEVMSig(IMAField):
    field = IMATemplateField.evmsig
    signature: bytes


@dataclass
class IMAFieldIUID(IMAField):
    field = IMATemplateField.iuid
    iuid: int


@dataclass
class IMAFieldIGID(IMAField):
    field = IMATemplateField.igid
    igid: int


@dataclass
class IMAFieldIMode(IMAField):
    field = IMATemplateField.imode
    imode: int


@dataclass
class IMAFieldXattrNames(IMAField):
    field = IMATemplateField.xattrnames
    names: Tuple[bytes, ...]


@dataclass
class IMAFieldXattrLengths(IMAField):
    field = IMATemplateField.xattrlengths
    lengths: Tuple[int, ...]


@dataclass
class IMAFieldXattrValues(IMAField):
    field = IMATemplateField.xattrvalues
    values: Tuple[bytes, ...]


@dataclass
class IMATemplateEvent:
    pcr: int
    fields: Tuple[IMAField, ...]
    digests: Dict[DigestAlgorithm, bytes]


class IMAParser:
    def __init__(
        self, data: bytes, byteorder: Literal["little", "big"] = "little"
    ):
        self._data = data
        self._offset = 0
        self._byteorder = byteorder

    @property
    def left(self) -> int:
        return len(self._data) - self.offset

    @property
    def offset(self) -> int:
        return self._offset

    def get_bytes(self, size) -> bytes:
        if size > self.left:
            raise EOFError
        b = self._data[self.offset:self.offset + size]
        self._offset += size
        return b

    def get_uint32(self) -> int:
        b = self.get_bytes(4)
        return int.from_bytes(b, byteorder=self._byteorder)

    def get_len_bytes(self) -> bytes:
        cl = self.get_uint32()
        b = self.get_bytes(cl)
        return b

    def get_subparser(self, data: bytes) -> "IMAParser":
        return type(self)(data=data, byteorder=self._byteorder)

    def parse_field(self, field_type: IMATemplateField) -> IMAField:
        field: IMAField
        fv = self.get_len_bytes()
        if field_type == IMATemplateField.d:
            field = IMAFieldD(field=field_type, digest=fv)
        elif field_type == IMATemplateField.n:
            field = IMAFieldN(field=field_type, name=fv)
        elif field_type == IMATemplateField.d_ng:
            ab, db = fv.split(b":", 1)
            field = IMAFieldD_NG(field=field_type, algorithm=ab, digest=db)
        elif field_type == IMATemplateField.d_ngv2:
            sb, ab, db = fv.split(b":", 2)
            field = IMAFieldD_NGv2(
                field=field_type, type=sb, algorithm=ab, digest=db
            )
        elif field_type == IMATemplateField.d_modsig:
            field = IMAFieldD_ModSig(field=field_type, digest=fv)
        elif field_type == IMATemplateField.n_ng:
            field = IMAFieldN_NG(field=field_type, name=fv)
        elif field_type == IMATemplateField.sig:
            field = IMAFieldSig(field=field_type, signature=fv)
        elif field_type == IMATemplateField.modsig:
            field = IMAFieldModSig(field=field_type, signature=fv)
        elif field_type == IMATemplateField.buf:
            field = IMAFieldBuf(field=field_type, buffer=fv)
        elif field_type == IMATemplateField.evmsig:
            field = IMAFieldEVMSig(field=field_type, signature=fv)
        elif field_type == IMATemplateField.iuid:
            iuid = int.from_bytes(fv, byteorder=self._byteorder)
            field = IMAFieldIUID(field=field_type, iuid=iuid)
        elif field_type == IMATemplateField.igid:
            igid = int.from_bytes(fv, byteorder=self._byteorder)
            field = IMAFieldIGID(field=field_type, igid=igid)
        elif field_type == IMATemplateField.imode:
            imode = int.from_bytes(fv, byteorder=self._byteorder)
            field = IMAFieldIMode(field=field_type, imode=imode)
        elif field_type == IMATemplateField.xattrnames:
            xnames = fv.split(b"|")
            field = IMAFieldXattrNames(field=field_type, names=tuple(xnames))
        elif field_type == IMATemplateField.xattrlengths:
            subparser = self.get_subparser(fv)
            lens = list()
            while subparser.left:
                xl = subparser.get_uint32()
                lens.append(xl)
            field = IMAFieldXattrLengths(field=field_type, lengths=tuple(lens))
        elif field_type == IMATemplateField.xattrvalues:
            # FIXME, figure out how to parse this
            raise NotImplementedError
        else:
            raise ValueError
        return field

    def parse_fields(
        self, field_types: Tuple[IMATemplateField, ...]
    ) -> List[IMAField]:
        fields = list()
        for ft in field_types:
            field = self.parse_field(ft)
            fields.append(field)
        return fields

    def parse_event(self) -> IMATemplateEvent:
        pcr = self.get_uint32()
        dig = self.get_bytes(20)
        digests = {
            DigestAlgorithm.sha1: dig
        }
        descriptor = self.get_len_bytes()
        field_types = IMATemplateDescriptor.expand(descriptor)
        subdata = self.get_len_bytes()
        subparser = self.get_subparser(subdata)
        fields = subparser.parse_fields(field_types)
        return IMATemplateEvent(
            pcr=pcr,
            fields=tuple(fields),
            digests=digests
        )
