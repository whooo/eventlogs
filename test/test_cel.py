# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from pathlib import Path
from base64 import b64decode
from eventlogs.common import (
    DigestAlgorithm,
    ShortBufferError,
    NotConsumedError,
    UnexpectedTypeError,
    UEFIEventType,
)
from eventlogs.cel import (
    TLVParser,
    CELFirmwareEndEvent,
    CELContentType,
    CELMgmtType,
    CELVersionEvent,
    CELTimestampEvent,
    CELStateTransEvent,
    StateTransType,
    CELPCClientSTDEvent,
    CELIMATemplateEvent,
    CELVersionType,
)


class CELTest(unittest.TestCase):
    def parser_with_snippets(self, *snippets):
        data = bytes()
        for s in snippets:
            p = Path(s)
            if len(p.parts) > 1:
                raise ValueError
            fp = Path(__file__).parent / "snippets" / "cel" / p
            with fp.open("rb") as sf:
                b64data = sf.read()
            sdata = b64decode(b64data)
            data += sdata
        return TLVParser(data)

    def test_cel_TLVParser_firmware_end(self):
        parser = self.parser_with_snippets("tlv_firmware_end.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELFirmwareEndEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.cel)
        self.assertEqual(event.type, CELMgmtType.firmware_end)

    def test_cel_TLVParser_cel_version(self):
        parser = self.parser_with_snippets("tlv_cel_version.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELVersionEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.cel)
        self.assertEqual(event.type, CELMgmtType.cel_version)
        self.assertEqual(event.major, 2)
        self.assertEqual(event.minor, 0)

    def test_cel_TLVParser_cel_timestamp(self):
        parser = self.parser_with_snippets("tlv_cel_timestamp.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELTimestampEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.cel)
        self.assertEqual(event.type, CELMgmtType.cel_timestamp)
        self.assertEqual(event.timestamp, 0xFFFFFFFFFF)

    def test_cel_TLVParser_cel_state_trans(self):
        parser = self.parser_with_snippets("tlv_state_trans.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELStateTransEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.cel)
        self.assertEqual(event.type, CELMgmtType.state_trans)
        self.assertEqual(event.state_trans, StateTransType.kexec)

    def test_cel_TLVParser_pcclient_std(self):
        parser = self.parser_with_snippets("tlv_pcclient_std.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELPCClientSTDEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.pcclient_std)
        self.assertEqual(event.event_type, UEFIEventType.ev_efi_spdm_firmware_config)
        self.assertEqual(event.event_data, b"falafel")

    def test_cel_TLVParser_ima_template(self):
        parser = self.parser_with_snippets("tlv_ima_template.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertIsInstance(event, CELIMATemplateEvent)
        self.assertEqual(event.recnum, 0)
        self.assertEqual(event.handle, 1)
        self.assertEqual(event.digests, {DigestAlgorithm.sha1: b"\x00" * 20})
        self.assertEqual(event.content_type, CELContentType.ima_template)
        self.assertEqual(event.template_name, b"eat")
        self.assertEqual(event.template_data, b"falafel")

    def test_cel_TLVParser_bad(self):
        parser = TLVParser(b"\x00")
        with self.assertRaises(ShortBufferError) as e:
            parser.get_bytes(2)
        self.assertEqual(e.exception.offset, 0)
        self.assertEqual(e.exception.requested, 2)
        self.assertEqual(e.exception.left, 1)
        self.assertEqual(
            str(e.exception), "requested 2 bytes, but only 1 at offset 0"
        )

        parser = TLVParser(b"\x00\x00\x00\x00\x00")
        with self.assertRaises(ValueError) as e:
            parser.get_int(5, 2)
        self.assertEqual(
            str(e.exception), "requested int size 5 larger then 2"
        )

        parser = self.parser_with_snippets("tlv_cel_version_extra_byte.b64")
        with self.assertRaises(NotConsumedError) as e:
            parser.parse_event()
        self.assertEqual(e.exception.left, 1)
        self.assertEqual(str(e.exception), "1 bytes not consumed")

        parser = self.parser_with_snippets("tlv_cel_bad_cel_version_type.b64")
        with self.assertRaises(UnexpectedTypeError) as e:
            parser.parse_event()
        self.assertEqual(
            str(e.exception),
            "unexpected type 255, expected one of: major",
        )
        self.assertEqual(e.exception.got, 255)
        self.assertEqual(e.exception.expected, [CELVersionType.major,])

        parser = self.parser_with_snippets("tlv_pcclient_std_extra_byte.b64")
        with self.assertRaises(NotConsumedError) as e:
            parser.parse_event()
        self.assertEqual(e.exception.left, 1)

        parser = self.parser_with_snippets("tlv_ima_template_extra_byte.b64")
        with self.assertRaises(NotConsumedError) as e:
            parser.parse_event()
        self.assertEqual(e.exception.left, 1)
