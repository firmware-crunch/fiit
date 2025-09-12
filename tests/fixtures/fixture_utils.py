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

import os
import tempfile
import mmap
import ctypes
from typing import Tuple

from fiit.emu.emu_types import AddressSpace, MemoryRegion

import pytest


def get_file_content(fixture_filename: str):
    current_path = os.path.dirname(os.path.realpath(__file__))
    with open(f'{current_path}/{fixture_filename}', 'r') as f:
        data = f.read()
    return data


@pytest.fixture
def temp_named_txt_file(request):
    with tempfile.NamedTemporaryFile(mode='w', suffix=request.param[1]) as temp:
        temp.write(request.param[0])
        temp.flush()
        yield temp


@pytest.fixture
def minimal_address_space() -> Tuple[AddressSpace, int, int, mmap.mmap]:
    mem_base = 0x2000
    mem_size = 4096
    host_mem_area = mmap.mmap(
        -1, 4096, flags=mmap.MAP_PRIVATE,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    host_base_address = ctypes.addressof(
        ctypes.c_ubyte.from_buffer(host_mem_area))
    mr = MemoryRegion(
        'mem0', mem_base, mem_size, 'rwx', host_base_address, host_mem_area)
    address_space = AddressSpace([mr])
    return address_space, mem_base, mem_size, host_mem_area
