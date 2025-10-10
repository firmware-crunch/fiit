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
    'MachineDevice',
    'CpuEndian',
    'CpuBits',
    'TickUnit',
    'PointerSize',
    'MemoryProtection',
    'MemoryType',
    'MemoryRegion',
    'MemoryRange',
]

import logging
import uuid
import abc
import enum
import dataclasses
import mmap
from typing import Optional, Union, Any

# ==============================================================================


# ------------------------------------------------------------------------------
# Machine


class MachineDevice(abc.ABC):

    def __init__(self, name: Optional[str] = None):
        self._dev_name = uuid.uuid4().hex if name is None else name
        self._log = logging.getLogger(f'fiit.dev@{self._dev_name}')

    @property
    def log(self) -> logging.Logger:
        return self._log

    @property
    def dev_name(self) -> str:
        return self._dev_name


# ------------------------------------------------------------------------------
# Cpu


class CpuEndian(enum.IntEnum):
    EL = (1, 'little', 'el', 'le')
    EB = (2, 'big', 'eb', 'be')

    label: str
    label_hc_lc: str
    label_lc_hc: str

    def __new__(
        cls, value: int, label: str, label_hc_lc: str, label_lc_hc: str
    ) -> 'CpuEndian':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        obj.label_hc_lc = label_hc_lc
        obj.label_lc_hc = label_lc_hc
        return obj

    @classmethod
    def from_str(cls, value: str) -> 'CpuEndian':
        for endian in cls:
            if value in [endian.label, endian.label_hc_lc, endian.label_lc_hc]:
                return endian

        raise ValueError(f'Illegal cpu endian "{value}"')

    @classmethod
    def from_any(cls, value: Any) -> 'CpuEndian':
        if isinstance(value, str):
            return cls.from_str(value)
        elif isinstance(value, cls):
            return value

        raise ValueError(f'Invalid Endian {value}')


class CpuBits(enum.IntEnum):
    BITS_8 = 8
    BITS_16 = 16
    BITS_32 = 32
    BITS_64 = 64
    BITS_128 = 128


class TickUnit(enum.IntEnum):
    INST = (1, 'instruction')
    BLOCK = (2, 'block')
    TIME_US = (3, 'us')

    label: str

    def __new__(
        cls, value: int, label: str
    ) -> 'TickUnit':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        return obj

    @classmethod
    def from_str(cls, value: str) -> 'TickUnit':
        for tick_unit in cls:
            if value == tick_unit.label:
                return tick_unit
        raise ValueError(f'Illegal contention tick unit "{value}"')


# ------------------------------------------------------------------------------
# Memory

class PointerSize(enum.IntEnum):
    SIZE_1 = 1
    SIZE_2 = 2
    SIZE_4 = 4
    SIZE_8 = 8
    SIZE_16 = 16

    bits: CpuBits

    def __new__(cls, value: int) -> 'PointerSize':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.bits = CpuBits(value * 8)
        return obj

    @classmethod
    def from_bits(cls, value: Union[int, CpuBits]) -> 'PointerSize':
        for ptr_size in cls:
            if value % 8 == 0 and value // 8 == ptr_size:
                return ptr_size
        raise ValueError(f'Illegal cpu bits "{value}"')


_MEM_PROT_READ = 1
_MEM_PROT_WRITE = 2
_MEM_PROT_EXEC = 4


class MemoryProtection(enum.IntEnum):
    READ = _MEM_PROT_READ
    WRITE = _MEM_PROT_WRITE
    EXEC = _MEM_PROT_EXEC
    RW = _MEM_PROT_READ | _MEM_PROT_WRITE
    RX = _MEM_PROT_READ | _MEM_PROT_EXEC
    WX = _MEM_PROT_WRITE | _MEM_PROT_EXEC
    ALL = _MEM_PROT_READ | _MEM_PROT_WRITE | _MEM_PROT_EXEC

    @classmethod
    def from_str(cls, value: str) -> 'MemoryProtection':
        if len(value) == 0 or len(value) > 3:
            raise ValueError(f'Illegal memory protection string "{value}"')

        protection = 0

        for char_prot in value:
            if char_prot == 'r':
                protection |= _MEM_PROT_READ
            elif char_prot == 'w':
                protection |= _MEM_PROT_WRITE
            elif char_prot == 'x':
                protection |= _MEM_PROT_EXEC
            else:
                raise ValueError(f'Illegal memory protection char "{value}"')

        return MemoryProtection(protection)


class MemoryType(enum.IntEnum):
    REGULAR = (1, 'regular')
    MMIO = (2, 'mmio')

    label: str

    def __new__(cls, value: int, label: str) -> 'MemoryType':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        return obj

    @classmethod
    def from_str(cls, value: str) -> 'MemoryType':
        for mem_region_type in cls:
            if mem_region_type.label == value:
                return mem_region_type
        raise ValueError(f'Illegal memory region type "{value}"')


@dataclasses.dataclass
class MemoryRegion:
    base_address: int
    size: int
    type: MemoryType = MemoryType.REGULAR
    name: Optional[str] = None
    protection: MemoryProtection = MemoryProtection.ALL

    host_mem: Optional[mmap.mmap] = None
    host_base_address: Optional[int] = None

    @property
    def end_address(self) -> int:
        return self.base_address + self.size - 1


@dataclasses.dataclass
class MemoryRange:
    begin: int
    end: int
    name: Optional[str] = None
