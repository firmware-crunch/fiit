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

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN,
    UC_MODE_BIG_ENDIAN)
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
    UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_FP, UC_ARM_REG_IP, UC_ARM_REG_SP,
    UC_ARM_REG_LR, UC_ARM_REG_CPSR)

from fiit.unicorn.arch_unicorn import ArchUnicorn, MemoryReader, MemoryWriter


################################################################################
# ArchUnicorn
################################################################################

def test_arch_unicorn_get_all_arch():
    assert set(ArchUnicorn.get_all_arch()) == {
        'i8086:el:16:default', 'x86:el:32:default', 'x86:el:64:default',
        'arm:el:32:default', 'arm:eb:32:default', 'arm:el:32:926',
        'arm:eb:32:926', 'arm:el:64:default', 'arm:eb:64:default',
        'mips:el:32:default', 'mips:eb:32:default', 'mips:el:64:default',
        'mips:eb:64:default', 'ppc:eb:32:default', 'ppc:eb:64:default',
        'sparc:eb:32:default', 'sparc:eb:64:default', 'm68k:eb:32:default'}


def test_arch_unicorn_get_me_bit_size():
    assert ArchUnicorn.get_mem_bit_size('arm:el:32:default') == 32
    assert ArchUnicorn.get_mem_bit_size('arm:el:64:default') == 64


def test_arch_unicorn_get_unicorn_arch_config():
    assert ArchUnicorn.get_unicorn_arch_config('arm:el:32:default') \
            == (UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)


def test_arch_unicorn_get_unicorn_pc_code():
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    assert ArchUnicorn.get_unicorn_pc_code(uc._arch) == UC_ARM_REG_PC


def test_arch_unicorn_get_arch_str_by_uc():
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
    assert ArchUnicorn.get_arch_str_by_uc(uc) == 'arm:el:32:default'


def test_arch_unicorn_get_generic_arch_str_by_uc():
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    assert ArchUnicorn.get_generic_arch_str_by_uc(uc) == 'arm:el:32'


def test_arch_unicorn_get_unicorn_registers():
    assert ArchUnicorn.get_unicorn_registers('arm:el:32:default') == {
        'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
        'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
        'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
        'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_FP,
        'r12': UC_ARM_REG_IP, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
        'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}


def test_arch_unicorn_get_endiannes_by_unicorn_mode():
    uc_little = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    uc_big = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN)
    assert ArchUnicorn.get_unicorn_endianness(uc_little._mode) == 'little'
    assert ArchUnicorn.get_unicorn_endianness(uc_big._mode) == 'big'


################################################################################
# MemoryReader
################################################################################

def uc_fixture():
    begin = 0x0
    end = 4096
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(begin, end)
    uc.mem_write(begin, b'\x01\x10\xa0\xe3\xc0\xfe\xba\xbe')
    return uc, begin, end-1


def test_register_field_get_state():
    assert int(b'11', 2) == MemoryReader.get_field(0xdeadc0de, 6, 2)


def test_memory_reader_big_8():
    uc, begin, _ = uc_fixture()
    assert 0x01 == MemoryReader(uc, 'big').read_uint8(begin)
    assert 0x01 == MemoryReader(uc, 'big').get_int_reader(8)(begin)


def test_memory_reader_big_16():
    uc, begin, _ = uc_fixture()
    assert 0x0110 == MemoryReader(uc, 'big').read_uint16(begin)
    assert 0x0110 == MemoryReader(uc, 'big').get_int_reader(16)(begin)


def test_memory_reader_big_32():
    uc, begin, _ = uc_fixture()
    assert 0x0110a0e3 == MemoryReader(uc, 'big').read_uint32(begin)
    assert 0x0110a0e3 == MemoryReader(uc, 'big').get_int_reader(32)(begin)


def test_memory_reader_big_64():
    uc, begin, _ = uc_fixture()
    assert 0x0110a0e3c0febabe == MemoryReader(uc, 'big').read_uint64(begin)
    assert 0x0110a0e3c0febabe == MemoryReader(uc, 'big').get_int_reader(64)(begin)


def test_memory_reader_little_8():
    uc, begin, _ = uc_fixture()
    assert 0x01 == MemoryReader(uc, 'little').read_uint8(begin)
    assert 0x01 == MemoryReader(uc, 'little').get_int_reader(8)(begin)


def test_memory_reader_little_16():
    uc, begin, _ = uc_fixture()
    assert 0x1001 == MemoryReader(uc, 'little').read_uint16(begin)
    assert 0x1001 == MemoryReader(uc, 'little').get_int_reader(16)(begin)


def test_memory_reader_little_32():
    uc, begin, _ = uc_fixture()
    assert 0xe3a01001 == MemoryReader(uc, 'little').read_uint32(begin)
    assert 0xe3a01001 == MemoryReader(uc, 'little').get_int_reader(32)(begin)


def test_memory_reader_little_64():
    uc, begin, _ = uc_fixture()
    assert 0xbebafec0e3a01001 == MemoryReader(uc, 'little').read_uint64(begin)
    assert 0xbebafec0e3a01001 == MemoryReader(uc, 'little').get_int_reader(64)(begin)


################################################################################
# MemoryWriter
################################################################################

def test_memory_write_set_field():
    assert int(b'1000000', 2) \
           == MemoryWriter.set_field(int(b'1001100', 2), 0, 2, 2)
    assert int(b'0001100', 2) \
           == MemoryWriter.set_field(int(b'1001100', 2), 0, 6, 1)
    assert int(b'1111100', 2) \
           == MemoryWriter.set_field(int(b'1001100', 2), 3, 4, 2)


def test_memory_write_big_8():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').write_uint8(begin, 0xdd)
    assert uc.mem_read(begin, 1) == b'\xdd'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').get_int_writer(8)(begin, 0xdd)
    assert uc.mem_read(begin, 1) == b'\xdd'


def test_memory_write_big_16():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').write_uint16(begin, 0xddaa)
    assert uc.mem_read(begin, 2) == b'\xdd\xaa'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').get_int_writer(16)(begin, 0xddaa)
    assert uc.mem_read(begin, 2) == b'\xdd\xaa'


def test_memory_write_big_32():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').write_uint32(begin, 0xddaaccff)
    assert uc.mem_read(begin, 4) == b'\xdd\xaa\xcc\xff'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').get_int_writer(32)(begin, 0xddaaccff)
    assert uc.mem_read(begin, 4) == b'\xdd\xaa\xcc\xff'


def test_memory_write_big_64():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').write_uint64(begin, 0xddaaccff01020304)
    assert uc.mem_read(begin, 8) == b'\xdd\xaa\xcc\xff\x01\x02\x03\x04'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'big').get_int_writer(64)(begin, 0xddaaccff01020304)
    assert uc.mem_read(begin, 8) == b'\xdd\xaa\xcc\xff\x01\x02\x03\x04'


def test_memory_write_little_8():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').write_uint8(begin, 0xdd)
    assert uc.mem_read(begin, 1) == b'\xdd'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').get_int_writer(8)(begin, 0xdd)
    assert uc.mem_read(begin, 1) == b'\xdd'


def test_memory_write_little_16():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').write_uint16(begin, 0xddaa)
    assert uc.mem_read(begin, 2) == b'\xaa\xdd'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').get_int_writer(16)(begin, 0xddaa)
    assert uc.mem_read(begin, 2) == b'\xaa\xdd'


def test_memory_write_little_32():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').write_uint32(begin, 0xddaaccff)
    assert uc.mem_read(begin, 4) == b'\xff\xcc\xaa\xdd'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').get_int_writer(32)(begin, 0xddaaccff)
    assert uc.mem_read(begin, 4) == b'\xff\xcc\xaa\xdd'


def test_memory_write_little_64():
    uc, begin, _ = uc_fixture()
    uc.mem_write(begin, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').write_uint64(begin, 0xddaaccff01020304)
    assert uc.mem_read(begin, 8) == b'\x04\x03\x02\x01\xff\xcc\xaa\xdd'
    uc.mem_write(begin, b'\x00\x00\x00\x00')
    MemoryWriter(uc, 'little').get_int_writer(64)(begin, 0xddaaccff01020304)
    assert uc.mem_read(begin, 8) == b'\x04\x03\x02\x01\xff\xcc\xaa\xdd'
