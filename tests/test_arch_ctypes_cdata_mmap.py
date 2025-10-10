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

from .fixtures.fixture_utils import (
    minimal_memory, minimal_memory_host, MinimalMemory
)

from fiit.arch_ctypes import (
    configure_ctypes, CDataMemMapper, CDataMemMapError, CDataMemMapCache
)
from fiit.arch_ctypes.base_types import DataPointerBase, UnsignedInt



def test_map_cdata_to_host_memory(minimal_memory_host):
    fake_mem = minimal_memory_host
    region = fake_mem.regions[0]

    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50

    region.host_mem.seek(raw_value_offset_1)
    region.host_mem.write(raw_value_1)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(fake_mem, ctypes_config)
    cdata = mem_mapper.map_cdata(' unsigned   int ', 'xy',
                                 region.base_address + raw_value_offset_1)

    assert isinstance(cdata, UnsignedInt)
    assert cdata.value == 0x01020304


def map_cdata_pointer_to_memory(mem: MinimalMemory):
    region = mem.regions[0]

    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50
    raw_value_2 = b'\x08\x07\x06\x05'
    raw_value_offset_2 = 0x58
    prt_address_offset = 0x8

    mem.host_mem.seek(prt_address_offset)
    mem.host_mem.write(b'\x50\x20\x00\x00')
    mem.host_mem.seek(raw_value_offset_1)
    mem.host_mem.write(raw_value_1)
    mem.host_mem.seek(raw_value_offset_2)
    mem.host_mem.write(raw_value_2)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(mem, ctypes_config)

    cdata = mem_mapper.map_cdata(' unsigned   int *', 'xy_ptr',
                                 region.base_address + prt_address_offset)

    assert issubclass(type(cdata), DataPointerBase)
    assert cdata.type == UnsignedInt
    assert cdata.target_address == region.base_address + raw_value_offset_1
    assert cdata.contents.value == 0x01020304

    cdata.target_address += 8

    assert cdata.contents.value == 0x05060708


def test_map_cdata_pointer_to_host_memory(minimal_memory_host):
    map_cdata_pointer_to_memory(minimal_memory_host)


def test_map_cdata_pointer_to_memory(minimal_memory):
    map_cdata_pointer_to_memory(minimal_memory)


def test_map_cdata_to_host_memory_invalid_overflow(minimal_memory):
    mem = minimal_memory
    region = mem.regions[0]
    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(mem, ctypes_config)

    with pytest.raises(CDataMemMapError):
        overflow_addr = region.base_address + region.size - 2
        mem_mapper.map_cdata('unsigned int ', 'y', overflow_addr)


def test_map_cdata_to_invalid_region(minimal_memory):
    mem = minimal_memory
    region = mem.regions[0]

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(mem, ctypes_config)

    with pytest.raises(CDataMemMapError):
        invalid_addr = region.base_address + region.size + 128
        mem_mapper.map_cdata('unsigned int ', 'y', invalid_addr)


def test_cache_find_cdata_by_name(minimal_memory):
    mem = minimal_memory
    region = mem.regions[0]

    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50

    mem.host_mem.seek(raw_value_offset_1)
    mem.host_mem.write(raw_value_1)

    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    mem_mapper = CDataMemMapper(mem, ctypes_config)
    mem_mapper.map_cdata(' unsigned   int ', 'xy',
                         region.base_address + raw_value_offset_1)

    cdata_entry = CDataMemMapCache().find_cdata_by_name(mem, 'xy')

    assert cdata_entry.cdata.value == 0x01020304
