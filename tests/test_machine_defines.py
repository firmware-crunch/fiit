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

import logging

import pytest
from unittest.mock import patch, PropertyMock

from fiit.machine import (
    MachineDevice, CpuEndian, CpuBits, TickUnit, PointerSize, MemoryProtection,
    MemoryType, MemoryRegion
)

# ==============================================================================


# ------------------------------------------------------------------------------
# MachineDevice


def test_machine_device_named():
    class CustomDevice(MachineDevice):
        pass

    dev_name = 'custom_dev'
    custom_dev = CustomDevice(dev_name)
    assert custom_dev.dev_name == dev_name


def test_machine_device_no_name():
    class CustomDevice(MachineDevice):
        pass

    expected_id = 'd7c5428b8c094f8aa6257c2f611262b3'

    with patch('uuid.UUID.hex', new_callable=PropertyMock) as uuid_patch:
        uuid_patch.return_value = expected_id
        custom_dev = CustomDevice()

    assert custom_dev.dev_name == f'{expected_id}'


def test_machine_device_named_log(caplog):
    class CustomDevice(MachineDevice):
        pass

    dev_name = 'custom_dev'
    log_name = f'fiit.dev@{dev_name}'
    log = 'custom device log'
    caplog.set_level(logging.INFO, log_name)
    custom_dev = CustomDevice(dev_name)
    custom_dev.log.info(log)

    assert caplog.record_tuples == [(log_name, logging.INFO, log)]


def test_machine_device_no_name_log(caplog):
    class CustomDevice(MachineDevice):
        pass

    expected_id = 'd7c5428b8c094f8aa6257c2f611262b3'
    log_name = f'fiit.dev@{expected_id}'
    log = 'custom device log'
    caplog.set_level(logging.INFO, log_name)

    with patch('uuid.UUID.hex', new_callable=PropertyMock) as uuid_patch:
        uuid_patch.return_value = expected_id
        custom_dev = CustomDevice()
        custom_dev.log.info(log)

    assert caplog.record_tuples == [(log_name, logging.INFO, log)]


# ------------------------------------------------------------------------------
# CpuEndian


def test_cpu_endian_regular():
    assert CpuEndian(CpuEndian.EL) == CpuEndian.EL
    assert CpuEndian(CpuEndian.EB) == CpuEndian.EB
    assert CpuEndian(1) == CpuEndian.EL
    assert CpuEndian(2) == CpuEndian.EB


def test_cpu_endian_from_str():
    assert CpuEndian.from_str('little') == CpuEndian.EL
    assert CpuEndian.from_str('el') == CpuEndian.EL
    assert CpuEndian.from_str('le') == CpuEndian.EL
    assert CpuEndian.from_str('big') == CpuEndian.EB
    assert CpuEndian.from_str('eb') == CpuEndian.EB
    assert CpuEndian.from_str('be') == CpuEndian.EB

    with pytest.raises(ValueError) as exc_info:
        CpuEndian.from_str('junk')

    assert isinstance(exc_info.value, ValueError)


def test_cpu_endian_from_any():
    assert CpuEndian.from_any('little') == CpuEndian.EL
    assert CpuEndian.from_any('el') == CpuEndian.EL
    assert CpuEndian.from_any('le') == CpuEndian.EL
    assert CpuEndian.from_any('big') == CpuEndian.EB
    assert CpuEndian.from_any('eb') == CpuEndian.EB
    assert CpuEndian.from_any('be') == CpuEndian.EB
    assert CpuEndian.from_any(CpuEndian(CpuEndian.EL)) == CpuEndian.EL
    assert CpuEndian.from_any(CpuEndian(CpuEndian.EB)) == CpuEndian.EB

    with pytest.raises(ValueError) as exc_info:
        CpuEndian.from_any(None)

    assert isinstance(exc_info.value, ValueError)


# ------------------------------------------------------------------------------
# CpuBits


def test_cpu_bits():
    assert CpuBits.BITS_8 == 8
    assert CpuBits.BITS_16 == 16
    assert CpuBits.BITS_32 == 32
    assert CpuBits.BITS_64 == 64
    assert CpuBits.BITS_128 == 128
    assert CpuBits(8) == CpuBits.BITS_8
    assert CpuBits(16) == CpuBits.BITS_16
    assert CpuBits(32) == CpuBits.BITS_32
    assert CpuBits(64) == CpuBits.BITS_64
    assert CpuBits(128) == CpuBits.BITS_128


def test_tick_unit():
    assert TickUnit(TickUnit.INST) == TickUnit.INST
    assert TickUnit(TickUnit.BLOCK) == TickUnit.BLOCK
    assert TickUnit(TickUnit.TIME_US) == TickUnit.TIME_US
    assert TickUnit(1) == TickUnit.INST
    assert TickUnit(2) == TickUnit.BLOCK
    assert TickUnit(3) == TickUnit.TIME_US


def test_tick_unit_from_str():
    assert TickUnit.from_str('instruction') == TickUnit.INST
    assert TickUnit.from_str('block') == TickUnit.BLOCK
    assert TickUnit.from_str('us') == TickUnit.TIME_US

    with pytest.raises(ValueError) as exc_info:
        TickUnit.from_str('junk')

    assert isinstance(exc_info.value, ValueError)


# ------------------------------------------------------------------------------
# PointerSize

def test_pointer_size():
    assert PointerSize.SIZE_1 == 1
    assert PointerSize.SIZE_2 == 2
    assert PointerSize.SIZE_4 == 4
    assert PointerSize.SIZE_8 == 8
    assert PointerSize.SIZE_16 == 16
    assert PointerSize(1) == PointerSize.SIZE_1
    assert PointerSize(2) == PointerSize.SIZE_2
    assert PointerSize(4) == PointerSize.SIZE_4
    assert PointerSize(8) == PointerSize.SIZE_8
    assert PointerSize(16) == PointerSize.SIZE_16


def test_pointer_from_bits():
    assert PointerSize.from_bits(8) == PointerSize.SIZE_1
    assert PointerSize.from_bits(16) == PointerSize.SIZE_2
    assert PointerSize.from_bits(32) == PointerSize.SIZE_4
    assert PointerSize.from_bits(64) == PointerSize.SIZE_8
    assert PointerSize.from_bits(128) == PointerSize.SIZE_16
    assert PointerSize.from_bits(CpuBits.BITS_8) == PointerSize.SIZE_1
    assert PointerSize.from_bits(CpuBits.BITS_16) == PointerSize.SIZE_2
    assert PointerSize.from_bits(CpuBits.BITS_32) == PointerSize.SIZE_4
    assert PointerSize.from_bits(CpuBits.BITS_64) == PointerSize.SIZE_8
    assert PointerSize.from_bits(CpuBits.BITS_128) == PointerSize.SIZE_16

    with pytest.raises(ValueError) as exc_info:
        PointerSize.from_bits(23)


# ------------------------------------------------------------------------------
# MemoryProtection

def test_memory_protection():
    assert MemoryProtection.READ == 1
    assert MemoryProtection.WRITE == 2
    assert MemoryProtection.EXEC == 4
    assert MemoryProtection.RW == 3
    assert MemoryProtection.RX == 5
    assert MemoryProtection.WX == 6
    assert MemoryProtection.ALL == 7
    assert MemoryProtection(1) == MemoryProtection.READ
    assert MemoryProtection(2) == MemoryProtection.WRITE
    assert MemoryProtection(4) == MemoryProtection.EXEC
    assert MemoryProtection(3) == MemoryProtection.RW
    assert MemoryProtection(5) == MemoryProtection.RX
    assert MemoryProtection(6) == MemoryProtection.WX
    assert MemoryProtection(7) == MemoryProtection.ALL


def test_memory_protection_from_str():
    assert MemoryProtection.from_str('r') == MemoryProtection.READ
    assert MemoryProtection.from_str('w') == MemoryProtection.WRITE
    assert MemoryProtection.from_str('x') == MemoryProtection.EXEC
    assert MemoryProtection.from_str('rw') == MemoryProtection.RW
    assert MemoryProtection.from_str('wr') == MemoryProtection.RW
    assert MemoryProtection.from_str('rx') == MemoryProtection.RX
    assert MemoryProtection.from_str('xr') == MemoryProtection.RX
    assert MemoryProtection.from_str('wx') == MemoryProtection.WX
    assert MemoryProtection.from_str('xw') == MemoryProtection.WX
    assert MemoryProtection.from_str('rwx') == MemoryProtection.ALL

    with pytest.raises(ValueError) as exc_info:
        MemoryProtection.from_str('')

    with pytest.raises(ValueError) as exc_info:
        MemoryProtection.from_str('rwxb')

    with pytest.raises(ValueError) as exc_info:
        MemoryProtection.from_str('q')


# ------------------------------------------------------------------------------
# MemoryType

def test_memory_type():
    assert MemoryType.REGULAR == 1
    assert MemoryType.MMIO == 2
    assert MemoryType(1) == MemoryType.REGULAR
    assert MemoryType(2) == MemoryType.MMIO


def test_memory_type_from_str():
    assert MemoryType.from_str('regular') == MemoryType.REGULAR
    assert MemoryType.from_str('mmio') == MemoryType.MMIO

    with pytest.raises(ValueError) as exc_info:
        MemoryType.from_str('junk')


# ------------------------------------------------------------------------------
# MemoryRegion

def test_memory_region():
    mem_region = MemoryRegion(0x0, 4096)
    assert mem_region.end_address == 0xfff
