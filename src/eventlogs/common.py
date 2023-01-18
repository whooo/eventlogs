# SPDX-License-Identifier: LPL-3.0-or-later

from enum import IntEnum


class _EnumBase(IntEnum):
    """Simple class to override default Enum __str__"""
    def __str__(self):
        return f"{self.name}"


class DigestAlgorithm(_EnumBase):
    """Digest algorihtms"""
    sha1 = 4
    sha256 = 11
    sha384 = 12
    sha512 = 13
    sm3_256 = 18
