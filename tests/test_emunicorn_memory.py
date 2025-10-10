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

import mmap

from unicorn import unicorn_const
from unicorn import arm_const

from fiit.emunicorn import MemoryUnicorn
from fiit.machine import CpuBits, CpuEndian, MemoryProtection, MemoryType

from .fixtures import create_uc_arm_926

# ==============================================================================


# ------------------------------------------------------------------------------
# fixture

_UC_ARM_REG_MAPPING = {
    'r0': arm_const.UC_ARM_REG_R0,
    'sp':  arm_const.UC_ARM_REG_SP,
    'pc': arm_const.UC_ARM_REG_PC
}

# ------------------------------------------------------------------------------


def test_create_region():
    uc = create_uc_arm_926()
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    begin = 0x10000
    end = 0x19fff
    size = 4096*10
    mem.create_region(begin, size, MemoryProtection.READ)
    regions = list(uc.mem_regions())
    assert len(regions) == 1
    assert regions[0][0] == begin
    assert regions[0][1] == end
    assert regions[0][2] == unicorn_const.UC_PROT_READ


def test_get_regions():
    uc = create_uc_arm_926()
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    begin = 0x10000
    end = 0x19fff
    size = 4096*10
    mem.create_region(begin, size, MemoryProtection.READ, name='data0')
    regions = mem.regions
    assert len(regions) == 1
    assert regions[0].base_address == begin
    assert regions[0].end_address == end
    assert regions[0].size == size
    assert regions[0].type == MemoryType.REGULAR
    assert regions[0].name == 'data0'
    assert regions[0].protection == MemoryProtection.READ
    assert isinstance(regions[0].host_mem, mmap.mmap)
    assert isinstance(regions[0].host_base_address, int)


def test_read_region():
    uc = create_uc_arm_926()
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    begin = 0x10000
    mem.create_region(begin, 4096*10, MemoryProtection.READ)
    assert mem.read(begin, 256) == bytes(uc.mem_read(0x10000, 256))


def test_write_region():
    uc = create_uc_arm_926()
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    begin = 0x10000
    offset = 8
    tag = b'\xc0\xde\xf0\xde'
    mem.create_region(begin, 4096*10, MemoryProtection.READ)
    mem.write(begin + offset, tag)
    assert bytes(uc.mem_read(begin, offset + len(tag) + 8)) \
           == b'\x00\x00\x00\x00' \
              b'\x00\x00\x00\x00' \
              b'\xc0\xde\xf0\xde' \
              b'\x00\x00\x00\x00' \
              b'\x00\x00\x00\x00'


def test_remove_region():
    uc = create_uc_arm_926()
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    begin = 0x10000
    size = 4096*10
    mem.create_region(begin, size, MemoryProtection.READ, name='data0')
    mem.remove_region(begin, size)
    assert len(list(uc.mem_regions())) == 0
    assert len(mem.regions) == 0
