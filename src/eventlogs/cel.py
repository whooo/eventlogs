# SPDX-License-Identifier: LPL-3.0-or-later

"""
This module implements the Canonical Event Log structures and encodings
"""

from .common import _EnumBase, DigestAlgorithm
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple, Union


class CELBaseType(_EnumBase):
    """Base CLV types

    Attributes:
      recnum (int): The CEL type event record number.
      pcr (int): The CEL type for PCR handles.
      nv_index (int): The CEL type for NV indexes.
      digests (int): The CEL type for digests.
    """
    recnum = 0
    pcr = 1
    nv_index = 2
    digests = 3


class CELContentType(_EnumBase):
    """CEL content types

    Attributes:
      cel (int): The CEL type for CEL management events.
      pcclient_std (int): The CEL type for UEFI events.
      ima_template (int): The CEL type for IMA template events.
    """
    cel = 4
    pcclient_std = 5
    ima_template = 7


class CELMgmtType(_EnumBase):
    """CEL management types

    Attributes:
      cel_version (int): The CEL type for CEL log version events.
      firmware_end (int): The CEL type for firmware end events.
      cel_timestamp (int): The CEL type for CEL timestamp events.
      state_trans (int): The CEL type for state transition events.
    """
    cel_version = 1
    firmware_end = 2
    cel_timestamp = 0x80
    state_trans = 0x81


class StateTransType(_EnumBase):
    """CEL state transistion types

    Attributes:
      suspend (int): The CEL type for suspend state transistion.
      hibernate (int): The CEL type for hibernation transistion.
      kexec (int): The CEL type for kexec transistion.
    """
    suspend = 0
    hibernate = 1
    kexec = 2


class CELVersionType(_EnumBase):
    """CEL verstion types

    Attributes:
      major (int): The CEL type for the major CEL version.
      minor (int): The CEL type for the minor CEL version.
    """
    major = 0
    minor = 1


class CELPCClientSTDType(_EnumBase):
    """CEL PC Client event log types

    Attributes:
      event_type (int): The CEL type for PC Client event type.
      event_data (int): The CEL type for PC Client event data.
    """
    event_type = 0
    event_data = 1


class CELIMATemplateType(_EnumBase):
    """CEL IMA Template types

    Attributes:
      template_name (int): The CEL type for IMA template name.
      template_data (int): The CEL type for IMA template data.
    """
    template_name = 0
    template_data = 1


@dataclass
class CELEvent:
    """Base class for CEL events

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
    """
    recnum: int
    handle: int
    digests: Dict[DigestAlgorithm, bytes]
    content_type: CELContentType


@dataclass
class CELMgmtEvent(CELEvent):
    """Base class for CEL management events

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.cel`.
      type (CELMgmtType): The CEL management type.
    """
    type: CELMgmtType


@dataclass
class CELPCClientSTDEvent(CELEvent):
    """CEL PC Client event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.pcclient_std`.
      event_type (int): The PC Client event type.
      event_data (int): The PC Client event data.
    """
    event_type: int
    event_data: bytes


@dataclass
class CELIMATemplateEvent(CELEvent):
    """CEL IMA template event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.ima_template`.
      template_name (bytes): The template name.
      template_data (bytes): The template data.
    """
    template_name: bytes
    template_data: bytes


@dataclass
class CELVersionEvent(CELMgmtEvent):
    """CEL version event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.cel`.
      type (CELMgmtType): The CEL management type.
        Set to `CELMgmtType.cel_version`.
      major (int): The major CEL version.
      minor (int): The minor CEL version.
    """
    major: int
    minor: int


@dataclass
class CELFirmwareEndEvent(CELMgmtEvent):
    """CEL firmware end event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.cel`.
      type (CELMgmtType): The CEL management type.
        Set to `CELMgmtType.firmware_end`.
    """
    pass


@dataclass
class CELTimestampEvent(CELMgmtEvent):
    """CEL timestamp event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.cel`.
      type (CELMgmtType): The CEL management type.
        Set to `CELMgmtType.cel_timestamp`.
      timestamp (int): The timestamp.
    """
    timestamp: int


@dataclass
class CELStateTransEvent(CELMgmtEvent):
    """CEL firmware end event

    Attributes:
      recnum (int): The event record number.
      handle (int): The handle for the PCR or NV index.
      digests (dict): A dict of the digests.
      content_type (CELContentType): The content type of the event.
        Set to `CELContentType.cel`.
      type (CELMgmtType): The CEL management type.
        Set to `CELMgmtType.state_trans`.
      state_trans (StateTransType): The state transisition type.
    """
    state_trans: StateTransType


class TLVParser:
    """CEL TLV Parser

    Parses TLV encoded events.

    Args:
      data (bytes): The data to be parsed.
    """
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def left(self) -> int:
        """left (int): The number of unparsed bytes."""
        return len(self._data) - self._offset

    @property
    def offset(self) -> int:
        """offset (int): The current offet into the data."""
        return self._offset

    def get_bytes(self, size: int) -> bytes:
        """Get size amount of bytes from the data updating the offset.

        Args:
          size (int): The number of bytes to get.

        Raises:
          EOFError: if size is larger then the number of bytes left.
        """
        if size > self.left:
            raise EOFError
        b = self._data[self.offset:self.offset+size]
        self._offset += len(b)
        return b

    def get_int(self, size: int, max_size: int) -> int:
        """Get int from bytes.

        Args:
          size: The number of bytes to consume.
          max_size: The max number of bytes that represent the number.

        Raises:
          EOFError: If size is larger then the number of bytes left.
          ValueError: If size is larger then max_size.
        """
        if size > max_size:
            raise ValueError("valute too large")
        ib = self.get_bytes(size)
        return int.from_bytes(ib, byteorder="big")

    def get_tl(self, expect: Union[int, Iterable[int]]) -> Tuple[int, int]:
        """Get the type and length.

        Args:
          expect: (Iterable[int]): The list of CEL types to expect.

        Raises:
          EOFError: If there isn't enough bytes left to consume.
          ValueError: If the type is not in expect.
        """
        b = self.get_bytes(5)
        t = int(b[0])
        if isinstance(expect, int):
            expect = (expect,)
        if expect and t not in expect:
            raise ValueError(f"expected one of {expect}, got {t}")
        vl = int.from_bytes(b[1:5], byteorder="big")
        return t, vl

    def get_tlv_int(
        self, max_size: int, expect: Union[int, Iterable[int]]
    ) -> Tuple[int, int]:
        """Get an TLV encoded number.

        Args:
          max_size (int): The max number of bytes that represent the number.
          expect: (Iterable[int]): The list of CEL types to expect.

        Raises:
          EOFError: If there isn't enough bytes left to consume.
          ValueError: If the type is not in expect.
          ValueError: If the number bytes is larger then max_size.
        """
        t, vl = self.get_tl(expect)
        v = self.get_int(vl, max_size)
        return t, v

    def get_digests(self) -> Dict[DigestAlgorithm, bytes]:
        """Get a list of digests.

        Raises:
          EOFError: If there isn't enough bytes left to consume.
          ValueError: If any type or digest algorithm is unsupported.
        """
        _, vl = self.get_tl(expect=CELBaseType.digests)
        left = vl
        digs = {}
        while left > 0:
            a, vl = self.get_tl(expect=tuple(DigestAlgorithm))
            dig = self.get_bytes(vl)
            da = DigestAlgorithm(a)
            digs[da] = dig
            left -= 5 + vl
        if left != 0:
            raise ValueError
        return digs

    def parse_mgmt_version_event(self, header: CELEvent) -> CELVersionEvent:
        """Parses a CEL version event."""
        left = list(CELVersionType)
        major = -1
        minor = -1
        while left:
            t, v = self.get_tlv_int(2, left)
            t = CELVersionType(t)
            left.remove(t)
            if t == CELVersionType.major:
                major = v
            elif t == CELVersionType.minor:
                minor = v
        if self.left > 0:
            raise ValueError
        return CELVersionEvent(
            recnum=header.recnum,
            handle=header.handle,
            digests=header.digests,
            content_type=header.content_type,
            type=CELMgmtType(CELMgmtType.cel_version),
            major=major,
            minor=minor,
        )

    def parse_mgmt_event(self, header: CELEvent) -> CELMgmtEvent:
        """Parses CEL managment events."""
        event: CELMgmtEvent
        t, vl = self.get_tl(expect=tuple(CELMgmtType))
        if t == CELMgmtType.cel_version:
            subdata = self.get_bytes(vl)
            subparser = TLVParser(subdata)
            event = subparser.parse_mgmt_version_event(header)
        elif t == CELMgmtType.firmware_end:
            event = CELFirmwareEndEvent(
                recnum=header.recnum,
                handle=header.handle,
                digests=header.digests,
                content_type=header.content_type,
                type=CELMgmtType(t),
            )
        elif t == CELMgmtType.cel_timestamp:
            timestamp = self.get_int(vl, 8)
            event = CELTimestampEvent(
                recnum=header.recnum,
                handle=header.handle,
                digests=header.digests,
                content_type=header.content_type,
                type=CELMgmtType(t),
                timestamp=timestamp,
            )
        elif t == CELMgmtType.state_trans:
            state_trans = self.get_int(vl, 1)
            event = CELStateTransEvent(
                recnum=header.recnum,
                handle=header.handle,
                digests=header.digests,
                content_type=header.content_type,
                type=CELMgmtType(t),
                state_trans=StateTransType(state_trans),
            )
        else:
            raise ValueError
        return event

    def parse_pcclient_std_event(
        self, header: CELEvent
    ) -> CELPCClientSTDEvent:
        """Parses a PC Client event."""
        left = list(CELPCClientSTDType)
        event_type = -1
        event_data = b""
        while left:
            t, vl = self.get_tl(left)
            t = CELPCClientSTDType(t)
            left.remove(t)
            if t == CELPCClientSTDType.event_type:
                event_type = self.get_int(vl, 4)
            elif t == CELPCClientSTDType.event_data:
                event_data = self.get_bytes(vl)
        if self.left > 0:
            raise ValueError
        return CELPCClientSTDEvent(
            recnum=header.recnum,
            handle=header.handle,
            digests=header.digests,
            content_type=header.content_type,
            event_type=event_type,
            event_data=event_data,
        )

    def parse_ima_template_event(
        self, header: CELEvent
    ) -> CELIMATemplateEvent:
        """Parses a IMA template event."""
        left = list(CELIMATemplateType)
        template_name = b""
        template_data = b""
        while left:
            t, vl = self.get_tl(left)
            t = CELIMATemplateType(t)
            left.remove(t)
            if t == CELIMATemplateType.template_name:
                template_name = self.get_bytes(vl)
            elif t == CELIMATemplateType.template_data:
                template_data = self.get_bytes(vl)
        if self.left > 0:
            raise ValueError
        return CELIMATemplateEvent(
            recnum=header.recnum,
            handle=header.handle,
            digests=header.digests,
            content_type=header.content_type,
            template_name=template_name,
            template_data=template_data,
        )

    def parse_event(self) -> CELEvent:
        """Parses an event.

        Raises:
          EOFError: If the buffer too small.
          ValueError: If there is any unexpected type.

        Returns:
          A subclass of CELEvent
        """
        event: CELEvent
        _, recnum = self.get_tlv_int(8, CELBaseType.recnum)
        _, handle = self.get_tlv_int(
            4, (CELBaseType.pcr, CELBaseType.nv_index)
        )
        digests = self.get_digests()
        ct, cl = self.get_tl(tuple(CELContentType))
        content_type = CELContentType(ct)
        header = CELEvent(
            recnum=recnum,
            handle=handle,
            digests=digests,
            content_type=content_type,
        )
        subdata = self.get_bytes(cl)
        subparser = TLVParser(subdata)
        if content_type == CELContentType.cel:
            event = subparser.parse_mgmt_event(header)
        elif content_type == CELContentType.pcclient_std:
            event = subparser.parse_pcclient_std_event(header)
        elif content_type == CELContentType.ima_template:
            event = subparser.parse_ima_template_event(header)
        else:
            raise ValueError
        return event
