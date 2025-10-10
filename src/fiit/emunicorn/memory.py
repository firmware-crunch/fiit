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
    'MemoryUnicorn'
]

import mmap
import ctypes
from typing import List, Optional

import unicorn
from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC

from fiit.machine import (
    CpuEndian, CpuBits, MemoryRegion, MemoryProtection, MemoryType, Memory
)

# ==============================================================================


class MemoryUnicorn(Memory):

    _prot_map = {
        MemoryProtection.READ: UC_PROT_READ,
        MemoryProtection.WRITE: UC_PROT_WRITE,
        MemoryProtection.EXEC: UC_PROT_EXEC,
        MemoryProtection.RW: UC_PROT_READ | UC_PROT_WRITE,
        MemoryProtection.RX: UC_PROT_READ | UC_PROT_EXEC,
        MemoryProtection.WX: UC_PROT_WRITE | UC_PROT_EXEC,
        MemoryProtection.ALL: UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC
    }

    _reverse_prot_map = {v: k for k, v in _prot_map.items()}

    def __init__(self, uc: unicorn.Uc, bits: CpuBits, endian: CpuEndian):
        Memory.__init__(self, bits, endian)
        self._uc = uc
        self._mem_regions: List[MemoryRegion] = []

    @property
    def regions(self) -> List[MemoryRegion]:
        regions = []

        # Retrieve effective mapped area in the unicorn instance.
        for begin, end, prot in self._uc.mem_regions():
            region = MemoryRegion(
                base_address=begin, size=end - begin + 1,
                protection=self._reverse_prot_map[prot]
            )

            for hard_mem_ref in self._mem_regions:
                if (hard_mem_ref.base_address == begin
                        and hard_mem_ref.end_address == end):
                    hard_mem_ref.protection = region.protection
                    region = hard_mem_ref

            regions.append(region)

        return regions

    def _create_region_host(
        self,
        base_address: int,
        size: int,
        protection: MemoryProtection,
        name: Optional[str] = None,
        memory_type: MemoryType = MemoryType.REGULAR
    ) -> MemoryRegion:
        host_mprot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
        host_mem = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE, prot=host_mprot)
        host_mem_ptr = ctypes.c_ubyte.from_buffer(host_mem)
        host_base_address = ctypes.addressof(host_mem_ptr)

        uc_prot = self._prot_map[protection]
        self._uc.mem_map_ptr(base_address, size, uc_prot, host_base_address)
        self._uc.mem_write(base_address, size * b'\x00')

        mem_region = MemoryRegion(
            base_address=base_address, size=size, name=name,
            protection=protection, type=memory_type,
            host_base_address=host_base_address, host_mem=host_mem
        )

        self._mem_regions.append(mem_region)
        return mem_region

    def create_region(
        self,
        base_address: int,
        size: int,
        protection: MemoryProtection = MemoryProtection.ALL,
        name: Optional[str] = None,
        memory_type: MemoryType = MemoryType.REGULAR
    ) -> MemoryRegion:
        region = self._create_region_host(
            base_address, size, protection, name, memory_type
        )
        return region

    def remove_region(self, base_address: int, size: int) -> None:
        region_end = base_address + size - 1
        # Retrieve effective mapped area in the unicorn instance.
        for begin, end, _ in self._uc.mem_regions():
            if begin == base_address and end == region_end:
                self._uc.mem_unmap(base_address, size)

    def write(self, address: int, data: bytes) -> int:
        self._uc.mem_write(address, data)
        return len(data)

    def read(self, address: int, size: int) -> bytes:
        return bytes(self._uc.mem_read(address, size))
