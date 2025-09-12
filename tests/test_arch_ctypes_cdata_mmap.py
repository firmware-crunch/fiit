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

import pytest

from .fixtures.fixture_utils import minimal_address_space

from fiit.arch_ctypes import(
    configure_ctypes, CDataMemMapper, CDataMemMapError, CDataMemMapCache
)
from fiit.arch_ctypes.base_types import DataPointerBase, UnsignedInt


def test_map_cdata_to_host_memory(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50

    mapping.seek(raw_value_offset_1)
    mapping.write(raw_value_1)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)
    cdata = mem_mapper.map_cdata(' unsigned   int ', 'xy',
                                 mem_base + raw_value_offset_1)

    assert isinstance(cdata, UnsignedInt)
    assert cdata.value == 0x01020304


def test_map_cdata_pointer_to_host_memory(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50
    raw_value_2 = b'\x08\x07\x06\x05'
    raw_value_offset_2 = 0x58
    prt_address_offset = 0x8

    mapping.seek(prt_address_offset)
    mapping.write(b'\x50\x20\x00\x00')
    mapping.seek(raw_value_offset_1)
    mapping.write(raw_value_1)
    mapping.seek(raw_value_offset_2)
    mapping.write(raw_value_2)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)

    cdata = mem_mapper.map_cdata(' unsigned   int *', 'xy_ptr',
                                 mem_base + prt_address_offset)

    assert issubclass(type(cdata), DataPointerBase)
    assert cdata.type == UnsignedInt
    assert cdata.contents.value == 0x01020304

    cdata.target_address += 8

    assert cdata.contents.value == 0x05060708


def test_map_cdata_to_host_memory_invalid_overflow(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)

    with pytest.raises(CDataMemMapError):
        mem_mapper.map_cdata('unsigned int ', 'y', mem_base + mem_size - 2)


def test_map_cdata_to_host_memory_invalid_region(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)

    with pytest.raises(CDataMemMapError):
        mem_mapper.map_cdata('unsigned int ', 'y', mem_base + mem_size * 2)


def test_map_cdata_to_host_memory_region_not_hosted(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    address_space.memory_regions[0].host_mem_area = None
    address_space.memory_regions[0].host_base_address = None
    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)

    with pytest.raises(CDataMemMapError):
        mem_mapper.map_cdata('unsigned int ', 'y', mem_base + 4)


def test_map_cdata_mem_map_cache_find_cdata_by_name(minimal_address_space):
    address_space, mem_base, mem_size, mapping = minimal_address_space
    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50

    mapping.seek(raw_value_offset_1)
    mapping.write(raw_value_1)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(address_space, ctypes_config)
    mem_mapper.map_cdata(' unsigned   int ', 'xy',
                         mem_base + raw_value_offset_1)

    cdata_entry = CDataMemMapCache().find_cdata_by_name(address_space, 'xy')

    assert cdata_entry.cdata.value == 0x01020304
