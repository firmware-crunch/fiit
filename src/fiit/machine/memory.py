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
#
# This file is a custom version of the Memory class from the Zelos project
# licensed under the GNU Affero General Public License, you can access to the
# original source code via the following web link.
#
# https://github.com/zeropointdynamics/zelos/blob/
# 506554d20656c0d4c64c4d326baec179eede211a/src/zelos/memory.py
#
################################################################################

__all__ = [
    'Memory'
]

import abc
import uuid
import struct
import os
from typing import Callable, Optional, cast, List

from .defines import (
    MemoryProtection, MemoryRegion, MemoryType, PointerSize, CpuEndian, CpuBits
)

# ==============================================================================


class Memory(abc.ABC):

    _pack_fmt_signed_little = {1: '<b', 2: '<h', 4: '<i', 8: '<q'}
    _pack_fmt_signed_big = {1: '>b', 2: '>h', 4: '>i', 8: '>q'}
    _pack_fmt_unsigned_little = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
    _pack_fmt_unsigned_big = {1: '>B', 2: '>H', 4: '>I', 8: '>Q'}
    _pack_bit_mask: List[int] = [2 ** (i * 8) - 1 for i in range(17)]

    @staticmethod
    def get_addr_fmt(
        arch_bits: int, x_prefix: bool = True
    ) -> Callable[[int], str]:
        arch_bytes = arch_bits // 8

        if x_prefix:
            return f'{{:#0{(arch_bytes * 2) + 2}x}}'.format

        return f'{{:0{arch_bytes * 2}x}}'.format

    def __init__(
        self, bits: CpuBits, endian: CpuEndian, name: Optional[str] = None
    ):
        self._bits = bits
        self._pointer_size = PointerSize.from_bits(self._bits)
        self._endian = endian
        self._name = f'mem_{uuid.uuid4().hex}' if name is None else name

        self._addr_fmt = self.get_addr_fmt(bits.value, x_prefix=False)
        self._addr_fmt_x_pre = self.get_addr_fmt(bits.value, x_prefix=True)

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    @property
    def pointer_size(self) -> PointerSize:
        return self._pointer_size

    @property
    @abc.abstractmethod
    def regions(self) -> List[MemoryRegion]:
        """ """

    @abc.abstractmethod
    def create_region(
        self,
        base_address: int,
        size: int,
        protection: MemoryProtection = MemoryProtection.ALL,
        name: Optional[str] = None,
        memory_type: MemoryType = MemoryType.REGULAR,
    ) -> MemoryRegion:
        """ Create a new memory region in the physical address space. """

    @abc.abstractmethod
    def remove_region(self, base_address: int, size: int) -> None:
        """ Remove an existing memory region in the physical address space. """

    @property
    def max_address(self) -> int:
        return self._pack_bit_mask[self._pointer_size]

    def addr_to_str(self, address: int, x_prefix: bool = True) -> str:
        if x_prefix:
            return self._addr_fmt_x_pre(address)
        return self._addr_fmt(address)

    def map_file(
        self,
        filename: str,
        file_offset: int,
        loading_address: int,
        loading_size: Optional[int] = None
    ) -> None:
        sz = os.path.getsize(filename) if loading_size is None else loading_size

        with open(filename, mode='rb') as f:
            f.seek(file_offset)
            self.write(loading_address, f.read(sz))

    # --------------------------------------------------------------------------
    # write

    @abc.abstractmethod
    def write(self, address: int, data: bytes) -> int:
        """ """

    def pack_integer(
        self,
        value: int,
        size: Optional[int] = None,
        little_endian: Optional[bool] = None,
        signed: bool = False
    ) -> bytes:
        """
        Packs an integer into bytes. Defaults to the current architecture bytes
        and endianness.
        """
        write_size = self._pointer_size if size is None else size

        is_little_endian = little_endian
        if little_endian is None:
            is_little_endian = True if self._endian == CpuEndian.EL else False

        if is_little_endian:
            if signed:
                fmt = self._pack_fmt_signed_little[write_size]
            else:
                fmt = self._pack_fmt_unsigned_little[write_size]
        else:
            if signed:
                fmt = self._pack_fmt_signed_big[write_size]
            else:
                fmt = self._pack_fmt_unsigned_big[write_size]

        masked_value = value & self._pack_bit_mask[write_size]

        if signed and value < 0:
            masked_value -= 1 << (write_size * 8)

        return struct.pack(fmt, masked_value)

    def write_int(
        self,
        addr: int,
        value: int,
        size: Optional[int] = None,
        signed: bool = False
    ) -> int:
        """
        Writes an integer value to the specified address. Can handle
        multiple sizes and representations of integers.

        Args:
            addr: Address in memory to write integer to.
            value: Integer to write into memory.
            size: Size (of bytes) to write into memory.
            signed: If true, write number as signed integer. Default false.

        Returns:
            Number of bytes written to memory.
        """
        packed = self.pack_integer(value, size=size, signed=signed)
        self.write(addr, packed)
        return len(packed)

    def write_word(self, addr: int, value: int) -> int:
        return self.write_int(addr, value, signed=False)

    # unsigned integer

    def write_uint8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=1, signed=False)

    def write_uint16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=2, signed=False)

    def write_uint32(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=4, signed=False)

    def write_uint64(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=8, signed=False)

    # signed integer

    def write_int8(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=1, signed=True)

    def write_int16(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=2, signed=True)

    def write_int32(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=4, signed=True)

    def write_int64(self, addr: int, value: int) -> int:
        return self.write_int(addr, value=value, size=8, signed=True)

    # strings

    def write_cstring(
        self, address: int, string: str, null_byte_term: bool = True
    ) -> int:
        string_bytes = string.encode('ascii')

        if null_byte_term:
            string_bytes += b'\x00'

        return self.write(address, string_bytes)

    # --------------------------------------------------------------------------
    # read

    @abc.abstractmethod
    def read(self, address: int, size: int) -> bytes:
        """ """

    def unpack_integer(
        self,
        value: bytes,
        size: Optional[int] = None,
        little_endian: Optional[bool] = None,
        signed: bool = False,
    ) -> int:
        """
        Unpacks an integer from a byte format. Defaults to the current
        architecture bytes and endianness.
        """
        read_size = self._pointer_size if size is None else size

        is_little_endian = little_endian
        if little_endian is None:
            is_little_endian = True if self._endian == CpuEndian.EL else False

        if is_little_endian:
            if signed:
                fmt = self._pack_fmt_signed_little[read_size]
            else:
                fmt = self._pack_fmt_unsigned_little[read_size]
        else:
            if signed:
                fmt = self._pack_fmt_signed_big[read_size]
            else:
                fmt = self._pack_fmt_unsigned_big[read_size]

        unpacked = struct.unpack(fmt, value)[0]
        return cast(int, unpacked)

    def read_int(
        self,
        addr: int,
        size: Optional[int] = None,
        signed: bool = False
    ) -> int:
        """
        Reads an integer value from the specified address. Can handle multiple
        sizes and representations of integers.

        Args:
            addr: Address to begin reading int from.
            size: Size (of bytes) of integer representation.
            signed: If true, interpret bytes as signed integer. Default false.

        Returns:
            Integer representation of bytes read.
        """
        size_ = size if size is not None else self._pointer_size
        value = self.read(addr, size_)
        return self.unpack_integer(value, size=size_, signed=signed)

    def read_word(self, addr: int) -> int:
        return self.read_int(addr, signed=False)

    # unsigned integer

    def read_uint8(self, addr: int) -> int:
        return self.read_int(addr, size=1, signed=False)

    def read_uint16(self, addr: int) -> int:
        return self.read_int(addr, size=2, signed=False)

    def read_uint32(self, addr: int) -> int:
        return self.read_int(addr, size=4, signed=False)

    def read_uint64(self, addr: int) -> int:
        return self.read_int(addr, size=8, signed=False)

    # signed integer

    def read_int8(self, addr: int) -> int:
        return self.read_int(addr, size=1, signed=True)

    def read_int16(self, addr: int) -> int:
        return self.read_int(addr, size=2, signed=True)

    def read_int32(self, addr: int) -> int:
        return self.read_int(addr, size=4, signed=True)

    def read_int64(self, addr: int) -> int:
        return self.read_int(addr, size=8, signed=True)

    def read_cstring(
        self, addr: int, size: Optional[int] = None
    ) -> Optional[str]:
        data = []
        string_len = 0

        while True:
            read_byte = self.read(addr + string_len, 1)

            if read_byte == b'\x00':
                break

            data.append(read_byte)
            string_len += 1

            if size is not None and string_len == size:
                break

        if len(data) > 0:
            return b''.join(data).decode('ascii')

        return None
