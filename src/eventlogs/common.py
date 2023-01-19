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
    def __init__(self, got: int, expected: Iterable[Union[int, str]]):
        self._got = got
        self._expected = expected

    @property
    def got(self) -> int:
        return self._got

    @property
    def expected(self) -> Iterable[Union[int, str]]:
        return self._expected

    def __str__(self) -> str:
        estr = ", ".join([str(x) for x in self.expected])
        return f"unexpected type {self.got}, expected one of: {estr}"
