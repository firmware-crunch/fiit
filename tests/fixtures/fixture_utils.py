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

__all__ = [
    'get_file_content',
    'temp_named_txt_file',
    'MinimalMemory',
    'minimal_memory',
    'minimal_memory_host'
]

import os
import tempfile
import mmap
import ctypes
from typing import (
    List,
    Optional
)

import pytest

from fiit.machine import (
    MemoryRegion,
    Memory,
    MemoryProtection,
    CpuBits,
    CpuEndian
)

# ------------------------------------------------------------------------------


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
def temp_named_bin_file(request):
    with tempfile.NamedTemporaryFile(mode='wb', suffix=request.param[1]) as temp:
        temp.write(request.param[0])
        temp.flush()
        yield temp


class MinimalMemory(Memory):
    def __init__(
        self,
        bits: CpuBits = CpuBits.BITS_32,
        endian: CpuEndian = CpuEndian.EL,
        name: Optional[str] = None,
        expose_mem: bool = False
    ):
        self.mem_base = 0x2000
        self.mem_size = 10 * 4096

        self.host_mem = mmap.mmap(
            -1, self.mem_size, flags=mmap.MAP_PRIVATE,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.host_base_address = ctypes.addressof(
            ctypes.c_ubyte.from_buffer(self.host_mem))

        mem_region_kwargs = {
            'base_address': self.mem_base,
            'size': self.mem_size,
        }
        if expose_mem:
            mem_region_kwargs.update({
                'host_mem': self.host_mem,
                'host_base_address': self.host_base_address
            })

        self._regions = [MemoryRegion(**mem_region_kwargs)]
        Memory.__init__(self, bits, endian, name)

    @property
    def regions(self) -> List[MemoryRegion]:
        return self._regions

    def write(self, address: int, data: bytes) -> int:
        self.host_mem.seek(address - self.mem_base)
        count = self.host_mem.write(data)
        self.host_mem.flush(0, self.mem_size)
        self.host_mem.seek(0)
        return count

    def read(self, address: int, count: int) -> bytes:
        self.host_mem.seek(address - self.mem_base)
        content = self.host_mem.read(count)
        self.host_mem.seek(0)
        return content

    def create_region(self, base_address: int, size: int,
                      protection: MemoryProtection = MemoryProtection.ALL,
                      name: Optional[str] = None,
                      memory_type: Optional[str] = None) -> MemoryRegion:
        raise NotImplementedError()

    def remove_region(self, base_address: int, size: int) -> None:
        raise NotImplementedError()


@pytest.fixture
def minimal_memory() -> MinimalMemory:
    return MinimalMemory()


@pytest.fixture
def minimal_memory_host() -> MinimalMemory:
    return MinimalMemory(expose_mem=True)

