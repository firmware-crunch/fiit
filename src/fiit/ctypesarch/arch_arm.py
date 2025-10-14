################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

import ctypes
import struct
from typing import Literal, cast, Type

from .defines import FACTORY_TYPE, BASIC_TYPE, EXTRA_TYPE
from .defines import (
    DataPointerBase, CodePointerBase, Enum, Void, Char, SignedChar,
    UnsignedChar, Short, ShortInt, SignedShort, SignedShortInt,
    UnsignedShortInt, UnsignedShort, Int, Signed, SignedInt, UnsignedInt,
    Unsigned, Long, LongInt, SignedLongInt, SignedLong, UnsignedLong,
    UnsignedLongLongInt, UnsignedLongLong, UnsignedLongInt, LongUnsignedInt,
    LongLong, LongLongInt, SignedLongLong, SignedLongLongInt, Float, Double,
    _Bool, Bool, Int16T, Uint16T, FloatType, FloatCodecBase
)


class HalfFloatCodecIeee754(FloatCodecBase):
    name = 'IEEE754'
    _type_code: Literal['<e', '>e']

    def __init__(self, endian_code: Literal['<', '>']):
        self._type_code = f'{endian_code}e'

    def decode(self, raw: bytes) -> float:
        return cast(float, struct.unpack(self._type_code, raw)[0])

    def encode(self, value: float) -> bytes:
        return struct.pack(self._type_code, value)


_FP_16_CODEC = {
    HalfFloatCodecIeee754.name: HalfFloatCodecIeee754
}

_FP_16_CODEC_DEFAULT = HalfFloatCodecIeee754


class Fp16(FloatType):
    _name_ = '__fp16'
    endian: Literal['<', '>']
    codec: Type[FloatCodecBase]
    _codec: FloatCodecBase

    # BUG: ctype library not use __init__() if from_buffer_copy() is use
    #      as factory, so _codec classe variable must be set during runtime
    #      c type configuration.
    # def __init__(self, *args, **kwargs):
    #     print(args)
    #     self._codec = self.codec(self.endian)
    #     FloatType.__init__(self, *args, **kwargs)

    @property
    def value(self) -> float:
        return self._codec.decode(self._raw_)

    @value.setter
    def value(self, value: float):
        self._raw_ = self._codec.encode(value)


arm_el_32_ctype_config = {
    FACTORY_TYPE: {
        DataPointerBase: dict(
            _fields_=[('target_address', ctypes.c_uint32.__ctype_le__)], _align_=4),
        CodePointerBase: dict(
            _fields_=[('target_address', ctypes.c_uint32.__ctype_le__)], _align_=4),
        Enum: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
    },

    BASIC_TYPE: {
        Void: dict(),

        Char: dict(
            _fields_=[('value', ctypes.c_int8.__ctype_le__)], _align_=1),
        SignedChar: dict(
            _fields_=[('value', ctypes.c_int8.__ctype_le__)], _align_=1),

        UnsignedChar: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_le__)], _align_=1),

        Short: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_le__)], _align_=2),
        ShortInt: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_le__)], _align_=2),
        SignedShort: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_le__)], _align_=2),
        SignedShortInt: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_le__)], _align_=2),

        UnsignedShort: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_le__)], _align_=2),
        UnsignedShortInt: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_le__)], _align_=2),

        Int: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
        Signed: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
        SignedInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),

        Unsigned: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_le__)], _align_=4),
        UnsignedInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_le__)], _align_=4),

        Long: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
        LongInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
        SignedLong: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),
        SignedLongInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_le__)], _align_=4),

        UnsignedLong: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_le__)], _align_=4),
        UnsignedLongInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_le__)], _align_=4),
        LongUnsignedInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_le__)], _align_=4),

        LongLong: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_le__)], _align_=8),
        LongLongInt: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_le__)], _align_=8),
        SignedLongLong: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_le__)], _align_=8),
        SignedLongLongInt: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_le__)], _align_=8),

        UnsignedLongLong: dict(
            _fields_=[('value', ctypes.c_uint64.__ctype_le__)], _align_=8),
        UnsignedLongLongInt: dict(
            _fields_=[('value', ctypes.c_uint64.__ctype_le__)], _align_=8),

        Float: dict(
            _fields_=[('value', ctypes.c_float.__ctype_le__)], _align_=4),
        Double: dict(
            _fields_=[('value', ctypes.c_double.__ctype_le__)], _align_=8),
    },

    EXTRA_TYPE: {
        Fp16: dict(
            _fields_=[('_value', ctypes.c_uint16.__ctype_le__)], _align_=2,
            codec=HalfFloatCodecIeee754, endian='<',
            _codec=HalfFloatCodecIeee754('<')),

        _Bool: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_le__)], _align_=1),

        Bool: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_le__)], _align_=1),
        Int16T: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_le__)], _align_=2),
        Uint16T: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_le__)], _align_=2),
    }
}

arm_eb_32_ctype_config = {
    FACTORY_TYPE: {
        DataPointerBase: dict(
            _fields_=[('target_address', ctypes.c_uint32.__ctype_be__)], _align_=4),
        CodePointerBase: dict(
            _fields_=[('target_address', ctypes.c_uint32.__ctype_be__)], _align_=4),
        Enum: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
    },

    BASIC_TYPE: {
        Void: dict(),

        Char: dict(
            _fields_=[('value', ctypes.c_int8.__ctype_be__)], _align_=1),
        SignedChar: dict(
            _fields_=[('value', ctypes.c_int8.__ctype_be__)], _align_=1),

        UnsignedChar: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_be__)], _align_=1),

        Short: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_be__)], _align_=2),
        ShortInt: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_be__)], _align_=2),
        SignedShort: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_be__)], _align_=2),
        SignedShortInt: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_be__)], _align_=2),

        UnsignedShort: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_be__)], _align_=2),
        UnsignedShortInt: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_be__)], _align_=2),

        Int: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
        Signed: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
        SignedInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),

        Unsigned: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_be__)], _align_=4),
        UnsignedInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_be__)], _align_=4),

        Long: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
        LongInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
        SignedLong: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),
        SignedLongInt: dict(
            _fields_=[('value', ctypes.c_int32.__ctype_be__)], _align_=4),

        UnsignedLong: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_be__)], _align_=4),
        UnsignedLongInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_be__)], _align_=4),
        LongUnsignedInt: dict(
            _fields_=[('value', ctypes.c_uint32.__ctype_be__)], _align_=4),

        LongLong: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_be__)], _align_=8),
        LongLongInt: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_be__)], _align_=8),
        SignedLongLong: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_be__)], _align_=8),
        SignedLongLongInt: dict(
            _fields_=[('value', ctypes.c_int64.__ctype_be__)], _align_=8),

        UnsignedLongLong: dict(
            _fields_=[('value', ctypes.c_uint64.__ctype_be__)], _align_=8),
        UnsignedLongLongInt: dict(
            _fields_=[('value', ctypes.c_uint64.__ctype_be__)], _align_=8),

        Float: dict(
            _fields_=[('value', ctypes.c_float.__ctype_be__)], _align_=4),
        Double: dict(
            _fields_=[('value', ctypes.c_double.__ctype_be__)], _align_=8),
    },

    EXTRA_TYPE: {
        Fp16: dict(
            _fields_=[('_value', ctypes.c_uint16.__ctype_be__)], _align_=2,
            codec=HalfFloatCodecIeee754, endian='>',
            _codec=HalfFloatCodecIeee754('>')),

        _Bool: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_be__)], _align_=1),

        Bool: dict(
            _fields_=[('value', ctypes.c_uint8.__ctype_be__)], _align_=1),
        Int16T: dict(
            _fields_=[('value', ctypes.c_int16.__ctype_be__)], _align_=2),
        Uint16T: dict(
            _fields_=[('value', ctypes.c_uint16.__ctype_be__)], _align_=2),
    }
}
