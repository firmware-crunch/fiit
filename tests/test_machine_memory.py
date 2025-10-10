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
import struct

import pytest

from .fixtures.blobs import BlobCcAapcs32ArmebV6HardFloatFp16Ieee
from .fixtures.fixture_utils import MinimalMemory, temp_named_bin_file

from fiit.machine import CpuBits, CpuEndian, PointerSize

# ==============================================================================


def test_name():
    name = 'ram0'
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL, name)
    assert mem.name == name
    new_name = 'rom0'
    mem.name = new_name
    assert mem.name == new_name


def test_pointer_size():
    mem = MinimalMemory(CpuBits.BITS_8, CpuEndian.EL)
    assert mem.pointer_size == PointerSize.SIZE_1
    mem = MinimalMemory(CpuBits.BITS_16, CpuEndian.EL)
    assert mem.pointer_size == PointerSize.SIZE_2
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    assert mem.pointer_size == PointerSize.SIZE_4
    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    assert mem.pointer_size == PointerSize.SIZE_8
    mem = MinimalMemory(CpuBits.BITS_128, CpuEndian.EL)
    assert mem.pointer_size == PointerSize.SIZE_16


def test_max_address():
    mem = MinimalMemory(CpuBits.BITS_8, CpuEndian.EL)
    assert mem.max_address == 0xff
    mem = MinimalMemory(CpuBits.BITS_16, CpuEndian.EL)
    assert mem.max_address == 0xffff
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    assert mem.max_address == 0xffffffff
    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    assert mem.max_address == 0xffffffffffffffff
    mem = MinimalMemory(CpuBits.BITS_128, CpuEndian.EL)
    assert mem.max_address == 0xffffffffffffffffffffffffffffffff


def test_addr_to_str():
    mem = MinimalMemory(CpuBits.BITS_8, CpuEndian.EL)
    assert mem.addr_to_str(0xab) == '0xab'
    mem = MinimalMemory(CpuBits.BITS_8, CpuEndian.EL)
    assert mem.addr_to_str(0xab, x_prefix=False) == 'ab'

    mem = MinimalMemory(CpuBits.BITS_16, CpuEndian.EL)
    assert mem.addr_to_str(0xf00d) == '0xf00d'
    mem = MinimalMemory(CpuBits.BITS_16, CpuEndian.EL)
    assert mem.addr_to_str(0xf00d, x_prefix=False) == 'f00d'

    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    assert mem.addr_to_str(0xc0dec0fe) == '0xc0dec0fe'
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    assert mem.addr_to_str(0xc0dec0fe, x_prefix=False) == 'c0dec0fe'

    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    assert mem.addr_to_str(0xc0dec0fedeadbeef) == '0xc0dec0fedeadbeef'
    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    assert mem.addr_to_str(0xc0dec0fedeadbeef, x_prefix=False) == 'c0dec0fedeadbeef'


@pytest.mark.parametrize(
    'temp_named_bin_file',
    [[BlobCcAapcs32ArmebV6HardFloatFp16Ieee.mapped_blobs[0]['blob'], '.bin']],
    indirect=['temp_named_bin_file']
)
def test_map_file(temp_named_bin_file):
    blob = BlobCcAapcs32ArmebV6HardFloatFp16Ieee.mapped_blobs[0]['blob']
    blob_size = len(blob)
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    mem_region_base = mem.regions[0].base_address
    mem.map_file(temp_named_bin_file.name, 0, mem_region_base, blob_size)
    assert mem.read(mem_region_base, blob_size) == blob


# ------------------------------------------------------------------------------
# write

def test_pack_integer():
    """
    Because `pack_integer()` allows to specify the content and the size of
    container of value, if the value greater than the container a bit mask is
    applied, but bit mask imply sign lost for signed value in two's complement,
    so this test check sign preservation for signed value.
    """
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)

    # 16 bits little -----------------------------------------------------------
    assert mem.pack_integer(0xf00dc0de, size=2, little_endian=True, signed=False) == b'\xde\xc0'
    # check the limits of a signed value
    assert mem.pack_integer(0x7fff, size=2, little_endian=True, signed=True) == b'\xff\x7f'
    assert mem.pack_integer(-0x8000, size=2, little_endian=True, signed=True) == b'\x00\x80'

    with pytest.raises(struct.error):
        mem.pack_integer(0x8000, size=2, little_endian=True, signed=True)
    with pytest.raises(struct.error):
        mem.pack_integer(-0x8001, size=2, little_endian=True, signed=True)

    # 16 bits big --------------------------------------------------------------
    assert mem.pack_integer(0xf00dc0de, size=2, little_endian=False, signed=False) == b'\xc0\xde'
    # check the limits of a signed value
    assert mem.pack_integer(0x7fff, size=2, little_endian=False, signed=True) == b'\x7f\xff'
    assert mem.pack_integer(-0x8000, size=2, little_endian=False, signed=True) == b'\x80\x00'

    with pytest.raises(struct.error):
        mem.pack_integer(0x8000, size=2, little_endian=False, signed=True)
    with pytest.raises(struct.error):
        mem.pack_integer(-0x8001, size=2, little_endian=False, signed=True)

    # 32 bits little -----------------------------------------------------------
    assert mem.pack_integer(0xf00dc0de, size=4, little_endian=True, signed=False) == b'\xde\xc0\x0d\xf0'
    # check the limits of a signed value
    assert mem.pack_integer(0x7fffffff, size=4, little_endian=True, signed=True) == b'\xff\xff\xff\x7f'
    assert mem.pack_integer(-0x80000000, size=4, little_endian=True, signed=True) == b'\x00\x00\x00\x80'

    # 32 bits big --------------------------------------------------------------
    assert mem.pack_integer(0xf00dc0de, size=4, little_endian=False, signed=False) == b'\xf0\x0d\xc0\xde'
    # check the limits of a signed value
    assert mem.pack_integer(0x7fffffff, size=4, little_endian=False, signed=True) == b'\x7f\xff\xff\xff'
    assert mem.pack_integer(-0x80000000, size=4, little_endian=False, signed=True) == b'\x80\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.pack_integer(-0x80000001, size=4, little_endian=True, signed=True)

    with pytest.raises(struct.error):
        mem.pack_integer(0x80000000, size=4, little_endian=True, signed=True)

    # default interface behaviour (here 32 bits and little endian) -------------
    assert mem.pack_integer(0xf00dc0de) == b'\xde\xc0\x0d\xf0'
    assert mem.pack_integer(-0x80000000, signed=True) == b'\x00\x00\x00\x80'


def test_write_int():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_int(region.base_address, 0xf00dc0de)
    assert mem.read(region.base_address, 8) == b'\xde\xc0\x0d\xf0\x00\x00\x00\x00'
    mem.write_int(region.base_address, 0x7fffffff, signed=True)
    assert mem.read(region.base_address, 8) == b'\xff\xff\xff\x7f\x00\x00\x00\x00'
    mem.write_int(region.base_address, -0x80000000, signed=True)
    assert mem.read(region.base_address, 8) == b'\x00\x00\x00\x80\x00\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.write_int(region.base_address, 0x80000000, signed=True)


def test_write_word():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_word(region.base_address, 0xf00dc0de)
    assert mem.read(region.base_address, 8) == b'\xde\xc0\x0d\xf0\x00\x00\x00\x00'


def test_write_uint8():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_uint8(region.base_address, 0xde)
    assert mem.read(region.base_address, 8) == b'\xde\x00\x00\x00\x00\x00\x00\x00'


def test_write_uint16():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_uint16(region.base_address, 0xc0de)
    assert mem.read(region.base_address, 8) == b'\xde\xc0\x00\x00\x00\x00\x00\x00'


def test_write_uint32():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_uint32(region.base_address, 0xf00dc0de)
    assert mem.read(region.base_address, 8) == b'\xde\xc0\x0d\xf0\x00\x00\x00\x00'


def test_write_uint64():
    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_uint64(region.base_address, 0xf00dc0debeefdead)
    assert mem.read(region.base_address, 8) == b'\xad\xde\xef\xbe\xde\xc0\x0d\xf0'


def test_write_int8():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_int8(region.base_address, 0x7f)
    assert mem.read(region.base_address, 8) == b'\x7f\x00\x00\x00\x00\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.write_int8(region.base_address, 0x80)


def test_write_int16():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_int16(region.base_address, 0x7fff)
    assert mem.read(region.base_address, 8) == b'\xff\x7f\x00\x00\x00\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.write_int16(region.base_address, 0x8000)


def test_write_int32():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_int32(region.base_address, 0x7fffffff)
    assert mem.read(region.base_address, 8) == b'\xff\xff\xff\x7f\x00\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.write_int32(region.base_address, 0x80000000)


def test_write_int64():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write_int64(region.base_address, 0x7fffffffffffffff)
    assert mem.read(region.base_address, 12) == b'\xff\xff\xff\xff\xff\xff\xff\x7f\x00\x00\x00\x00'

    with pytest.raises(struct.error):
        mem.write_int64(region.base_address, 0x8000000000000000)


def test_write_cstring_no_null_byte():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address + 8, b'\xff')
    mem.write_cstring(region.base_address, 'DEADBEEF', null_byte_term=False)
    assert mem.read(region.base_address, 9) == b'DEADBEEF\xff'


def test_write_cstring_with_null_byte():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address + 8, b'\xff')
    mem.write_cstring(region.base_address, 'DEADBEEF', null_byte_term=True)
    assert mem.read(region.base_address, 9) == b'DEADBEEF\x00'


# ------------------------------------------------------------------------------
# read
#


def test_unpack_integer():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)

    # 16 bits little -----------------------------------------------------------
    assert mem.unpack_integer(b'\xde\xc0', size=2, little_endian=True, signed=False) == 0xc0de
    # check the limits of a signed value
    assert mem.unpack_integer(b'\xff\x7f', size=2, little_endian=True, signed=True) == 0x7fff
    assert mem.unpack_integer(b'\x00\x80', size=2, little_endian=True, signed=True) == -0x8000

    # 16 bits big --------------------------------------------------------------
    assert mem.unpack_integer(b'\xc0\xde', size=2, little_endian=False, signed=False) == 0xc0de
    # check the limits of a signed value
    assert mem.unpack_integer(b'\x7f\xff', size=2, little_endian=False, signed=True) == 0x7fff
    assert mem.unpack_integer(b'\x80\x00', size=2, little_endian=False, signed=True) == -0x8000

    # 32 bits little -----------------------------------------------------------
    assert mem.unpack_integer(b'\xde\xc0\x0d\xf0', size=4, little_endian=True, signed=False) == 0xf00dc0de
    # check the limits of a signed value
    assert mem.unpack_integer(b'\xff\xff\xff\x7f', size=4, little_endian=True, signed=True) == 0x7fffffff
    assert mem.unpack_integer(b'\x00\x00\x00\x80', size=4, little_endian=True, signed=True) == -0x80000000

    # 32 bits Big --------------------------------------------------------------
    assert mem.unpack_integer(b'\xf0\x0d\xc0\xde', size=4, little_endian=False, signed=False) == 0xf00dc0de
    # check the limits of a signed value
    assert mem.unpack_integer(b'\x7f\xff\xff\xff', size=4, little_endian=False, signed=True) == 0x7fffffff
    assert mem.unpack_integer(b'\x80\x00\x00\x00', size=4, little_endian=False, signed=True) == -0x80000000

    # default interface behaviour (here 32 bits and little endian) -------------
    assert mem.unpack_integer(b'\xde\xc0\x0d\xf0') == 0xf00dc0de
    # check the limits of a signed value
    assert mem.unpack_integer(b'\x00\x00\x00\x80', signed=True) == -0x80000000
    assert mem.unpack_integer(b'\xff\xff\xff\x7f', signed=True) == 0x7fffffff


def test_read_int():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xde\xc0\x0d\xf0\x00\x00\x00\x00')
    assert mem.read_int(region.base_address) == 0xf00dc0de
    mem.write(region.base_address, b'\xff\xff\xff\x7f\x00\x00\x00\x00')
    assert mem.read_int(region.base_address, signed=True) == 0x7fffffff
    mem.write(region.base_address, b'\x00\x00\x00\x80\x00\x00\x00\x00')
    assert mem.read_int(region.base_address, signed=True) == -0x80000000


def test_read_word():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xde\xc0\x0d\xf0\x00\x00\x00\x00')
    assert mem.read_word(region.base_address) == 0xf00dc0de


def test_read_uint8():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xde\x00\x00\x00\x00\x00\x00\x00')
    assert mem.read_uint8(region.base_address) == 0xde


def test_read_uint16():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xde\xc0\x00\x00\x00\x00\x00\x00')
    assert mem.read_uint16(region.base_address) == 0xc0de


def test_read_uint32():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xde\xc0\x0d\xf0\x00\x00\x00\x00')
    assert mem.read_uint32(region.base_address) == 0xf00dc0de


def test_read_uint64():
    mem = MinimalMemory(CpuBits.BITS_64, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xad\xde\xef\xbe\xde\xc0\x0d\xf0\x00\x00\x00\x00')
    assert mem.read_uint64(region.base_address) == 0xf00dc0debeefdead


def test_read_int8():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\x7f\x00\x00\x00\x00\x00\x00\x00')
    assert mem.read_int8(region.base_address) == 0x7f
    mem.write(region.base_address, b'\x80\x00\x00\x00\x00\x00\x00\x00')
    assert mem.read_int8(region.base_address) == -0x80


def test_read_int16():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xff\x7f\x00\x00\x00\x00\x00\x00')
    assert mem.read_int16(region.base_address) == 0x7fff
    mem.write(region.base_address, b'\x00\x80\x00\x00\x00\x00\x00\x00')
    assert mem.read_int16(region.base_address) == -0x8000


def test_read_int32():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xff\xff\xff\x7f\x00\x00\x00\x00')
    assert mem.read_int32(region.base_address) == 0x7fffffff
    mem.write(region.base_address, b'\x00\x00\x00\x80\x00\x00\x00\x00')
    assert mem.read_int32(region.base_address) == -0x80000000


def test_read_int64():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    mem.write(region.base_address, b'\xff\xff\xff\xff\xff\xff\xff\x7f\x00\x00\x00\x00')
    assert mem.read_int64(region.base_address) == 0x7fffffffffffffff
    mem.write(region.base_address, b'\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00')
    assert mem.read_int64(region.base_address) == -0x8000000000000000


def test_read_cstring_no_null_byte():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]

    mem.write(region.base_address, b'DEADBEEF\xff')
    assert mem.read_cstring(region.base_address, 8) == 'DEADBEEF'


def test_read_cstring_with_null_byte():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]

    mem.write(region.base_address, b'C0DEC0FFE\x00')
    assert mem.read_cstring(region.base_address) == 'C0DEC0FFE'


def test_read_cstring_cut_before_terminator():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]

    mem.write(region.base_address, b'C0DEC0FFE\x00')
    assert mem.read_cstring(region.base_address, 4) == 'C0DE'


def test_read_cstring_no_cstring():
    mem = MinimalMemory(CpuBits.BITS_32, CpuEndian.EL)
    region = mem.regions[0]
    assert mem.read_cstring(region.base_address, 4) is None
