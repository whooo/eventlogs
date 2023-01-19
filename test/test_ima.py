# SPDX-License-Identifier: LGPL-3.0-or-later

import unittest
from pathlib import Path
from base64 import b64decode
from eventlogs.ima import IMAParser, IMATemplateField, IMAFieldD_NG
from eventlogs.common import (
    DigestAlgorithm,
    NotConsumedError,
    ShortBufferError,
    UnexpectedTypeError,
)


class IMATest(unittest.TestCase):
    def parser_with_snippets(self, *snippets):
        data = bytes()
        for s in snippets:
            p = Path(s)
            if len(p.parts) > 1:
                raise ValueError
            fp = Path(__file__).parent / "snippets" / "ima" / p
            with fp.open("rb") as sf:
                b64data = sf.read()
            sdata = b64decode(b64data)
            data += sdata
        return IMAParser(data)

    def test_IMAParser_ima_ng(self):
        parser = self.parser_with_snippets("boot_aggregate.b64")
        event = parser.parse_event()
        self.assertFalse(parser.left)
        self.assertEqual(event.pcr, 10)
        self.assertIsInstance(event.fields[0], IMAFieldD_NG)
        self.assertEqual(event.fields[0].field, IMATemplateField.d_ng)
        self.assertEqual(event.fields[0].algorithm, b"sha256")
        self.assertEqual(
            event.fields[0].digest,
            (
                b"\x00\xd6R\xc4\xdd\xefE~\xa0\xb8\x12\xed\xc8I?p\\"
                b"\xce\xf5'5k\x8d\xc0\xe2\x9e\x16(I\x86/\t6"
            ),
        )
        self.assertEqual(event.fields[1].field, IMATemplateField.n_ng)
        self.assertEqual(event.fields[1].name, b"boot_aggregate\x00")
        self.assertEqual(len(event.digests), 1)
        self.assertEqual(
            event.digests,
            {
                DigestAlgorithm.sha1:
                (
                    b'\xfe\xeeS\xf2\xc5#\xbc\x97 \xe9'
                    b'\xcc\x1f\xb3\x1d\x95w\xf7LL\x83'
                )
            }
        )

    def test_IMAParser_bad(self):
        parser = self.parser_with_snippets("boot_aggregate_extra_byte.b64")
        with self.assertRaises(NotConsumedError) as e:
            parser.parse_event()
        self.assertEqual(str(e.exception), "1 bytes not consumed")
        self.assertEqual(e.exception.left, 1)

        parser = self.parser_with_snippets("boot_aggregate_short.b64")
        with self.assertRaises(ShortBufferError) as e:
            parser.parse_event()
        self.assertEqual(
            str(e.exception), "requested 15 bytes, but only 9 at offset 48"
        )
        self.assertEqual(e.exception.requested, 15)
        self.assertEqual(e.exception.left, 9)
        self.assertEqual(e.exception.offset, 48)

        parser = self.parser_with_snippets("bad_descriptor.b64")
        with self.assertRaises(UnexpectedTypeError) as e:
            parser.parse_event()
        self.assertEqual(
            str(e.exception),
            (
                "unexpected type iiiiii, expected one of: ima, ima-ng, "
                "ima-ngv2, ima-sig, ima-sigv2, ima-buf, ima-modsig, evm-sig"
            )
        )
        self.assertEqual(e.exception.got, "iiiiii")
