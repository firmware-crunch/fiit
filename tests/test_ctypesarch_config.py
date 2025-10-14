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

from typing import Tuple
import ctypes

from fiit.ctypesarch import configure_ctypes, CTypesConfig
from fiit.ctypesarch.defines import Void, UnsignedInt
from fiit.ctypesarch.arch_arm import HalfFloatCodecIeee754



def template_test_configure_ctypes(
    arch: str, unsigned_int_endian_test_value: Tuple
) -> CTypesConfig:
    ctypes_config = configure_ctypes(arch, [globals()])
    for _, c_type in ctypes_config.get_all_types().items():
        if issubclass(c_type, Void):
            continue

        # CBaseType properties check
        assert isinstance(c_type._name_, str)
        assert isinstance(c_type._align_, int)
        assert isinstance(c_type._fields_, list)
        # Underlying container type description check
        for type_description in c_type._fields_:
            assert isinstance(type_description, Tuple)
            assert len(type_description) == 2
            assert isinstance(type_description[0], str)
            assert issubclass(type_description[1], ctypes._SimpleCData)

    assert (UnsignedInt(unsigned_int_endian_test_value[0])._raw_
            == unsigned_int_endian_test_value[1])

    return ctypes_config


def test_configure_ctypes_armel():
    template_test_configure_ctypes(
        'arm:el:32',
        unsigned_int_endian_test_value=(0x12abcdef, b'\xef\xcd\xab\x12'))


def test_configure_ctypes_armbe():
    template_test_configure_ctypes(
        'arm:eb:32',
        unsigned_int_endian_test_value=(0x12abcdef, b'\x12\xab\xcd\xef'))


def test_configure_option_fp16_format():
    ctypes_config = configure_ctypes(
        'arm:el:32', [globals()], options={'fp16_format': 'IEEE754'})
    assert ctypes_config.extra_type['__fp16'].codec == HalfFloatCodecIeee754
