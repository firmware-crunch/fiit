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

from fiit.arch_ctypes import configure_ctypes
from fiit.arch_ctypes.arch_arm import Fp16, HalfFloatCodecIeee754


# HalfFloatCodecIeee754

def test_half_float_codec_ieee754_encode_little_endian():
    assert HalfFloatCodecIeee754('<').encode(3.875) == b'\xc0\x43'


def test_half_float_codec_ieee754_encode_big_endian():
    assert HalfFloatCodecIeee754('>').encode(3.875) == b'\x43\xc0'


def test_half_float_codec_ieee754_decode_little_endian():
    assert HalfFloatCodecIeee754('<').decode(b'\xc0\x43') == 3.875


def test_half_float_codec_ieee754_decode_big_endian():
    assert HalfFloatCodecIeee754('>').decode(b'\x43\xc0') == 3.875


# Fp16 (specific ARM)

def test_fp16_set_value_armel():
    configure_ctypes('arm:el:32', [globals()])
    x = Fp16()
    x.value = 0.5
    assert x.value == 0.5


def test_fp16_set_raw_value_armel():
    configure_ctypes('arm:el:32', [globals()])
    x = Fp16()
    x._raw_ = b'\x00\x38'
    assert x.value == 0.5


def test_fp_16_check_values_arch_armel():
    configure_ctypes('arm:el:32', [globals()])
    value = Fp16(0.5)
    assert value.value == 0.5
    assert value._raw_ == b'\x00\x38'


def test_fp16_set_value_armbe():
    configure_ctypes('arm:eb:32', [globals()])
    x = Fp16()
    x.value = 0.5
    assert x.value == 0.5


def test_fp16_set_raw_value_armbe():
    configure_ctypes('arm:eb:32', [globals()])
    x = Fp16()
    x._raw_ = b'\x38\x00'
    assert x.value == 0.5


def test_fp_16_check_values_arch_armbe():
    configure_ctypes('arm:eb:32', [globals()])
    value = Fp16(0.5)
    assert value.value == 0.5
    assert value._raw_ == b'\x38\x00'
