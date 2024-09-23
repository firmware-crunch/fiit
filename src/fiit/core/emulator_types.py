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

from typing import List, Union, TypedDict, Literal
from dataclasses import dataclass
import mmap


@dataclass
class MemoryRange:
    begin: int
    end: int
    name: str = None


class DictMemoryRegion(TypedDict):
    name: str
    perm: str
    base_address: int
    size: int


@dataclass
class MemoryRegion:
    name: str
    base_address: int
    size: int
    perm: str  # combination of r, w and x
    host_base_address: int = None
    host_mem_area: mmap.mmap = None

    def __post_init__(self):
        self.end_address = self.base_address + self.size - 1


class AddressSpace:
    def __init__(self, memory_regions: List[MemoryRegion]):
        self.memory_regions = memory_regions
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        try:
            mr = self.memory_regions[self._idx]
        except IndexError:
            self._idx = 0
            raise StopIteration
        self._idx += 1
        return mr


class DictMemoryMappedFile(TypedDict):
    file_path: str
    file_offset: int
    loading_size: int
    loading_address: int


@dataclass
class MemoryMappedFile:
    file_path: str
    file_offset: int
    loading_size: int
    loading_address: int


class DictMemoryMappedBlob(TypedDict):
    blob: bytes
    loading_address: int


@dataclass
class MemoryMappedBlob:
    blob: Union[bytearray, bytes]
    loading_address: int


MemoryRanges = List[MemoryRange]


@dataclass
class Architecture:
    emulator_arch_str: str
    cpu_name: str
    cpu_variant: str
    endian: Literal['big', 'little']
    mem_bit_size: int


ADDRESS_FORMAT = {
    8: '{:#04x}'.format,
    16: '{:#06x}'.format,
    32: '{:#010x}'.format,
    64: '{:#018x}'.format,
}
