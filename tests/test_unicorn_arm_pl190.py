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
from unittest.mock import Mock
import pytest

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)

from fiit.unicorn.arm.pl190 import UnicornArmPl190, Pl190Exception
from fiit.core.plugin import PluginManager

from .fixtures.fixture_utils import temp_named_txt_file


OFF_VICIRQSTATUS = 0x0
OFF_VICFIQSTATUS = 0x4
OFF_VICRAWINTR = 0x8
OFF_VICINTSELECT = 0xc
OFF_VICINTENABLE = 0x10
OFF_VICINTENCLEAR = 0x14
OFF_VICSOFTINT = 0x18
OFF_VICSOFTINTCLEAR = 0x1C
OFF_VICPROTECTION = 0x20
OFF_VICVECTADDR = 0x30
OFF_VICDEFVECTADDR = 0x34

OFF_VICVECTADDR_X_BASE = 0x100
OFF_VICVECTCNTL_X_BASE = 0x200

OFF_VICITCR = 0x300
OFF_VICITIP1 = 0x304
OFF_VICITIP2 = 0x308
OFF_VICITOP1 = 0x30c
OFF_VICITOP2 = 0x310

OFF_VICPERIPHID0 = 0xfe0
OFF_VICPERIPHID1 = 0xfe4
OFF_VICPERIPHID2 = 0xfe8
OFF_VICPERIPHID3 = 0xfec
OFF_VICPCELLID0 = 0xff0
OFF_VICPCELLID1 = 0xff4
OFF_VICPCELLID2 = 0xff8
OFF_VICPCELLID3 = 0xffc

VIC_0_BASE = 0x10140000
VIC_1_BASE = 0x10200000
VIC_MAP_LEN = 0x10000


class MmioReadPrimitive:
    @staticmethod
    def _mmio_read(pl190: UnicornArmPl190, address: int) -> int:
        pl190._mem_read(pl190.uc, None, address, None, None, None)
        return struct.unpack('<I', pl190.uc.mem_read(address, 4))[0]

    @staticmethod
    def _mmio_write(pl190: UnicornArmPl190, address: int, value: int):
        pl190._mem_write(pl190.uc, None, address, None, value, None)


class BaseTestUnicornArmPl190(MmioReadPrimitive):
    def setup_method(self, test_method):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)

        self.nvicfiq_high_callback = Mock()
        self.nvicirq_high_callback = Mock()

        self.vic = UnicornArmPl190(self.uc, VIC_0_BASE)
        self.vic.reset()
        self.vic.set_nvicfiq_high_callback(self.nvicfiq_high_callback)
        self.vic.set_nvicirq_high_callback(self.nvicirq_high_callback)

    def mmio_read(self, offset: int) -> int:
        return self._mmio_read(self.vic, VIC_0_BASE + offset)

    def mmio_write(self, offset: int, value: int):
        self._mmio_write(self.vic, VIC_0_BASE + offset, value)


class TestUnicornArmPl190(BaseTestUnicornArmPl190):
    def test_fiq(self):
        int_line_nb = 8
        self.mmio_write(OFF_VICINTSELECT, 1 << int_line_nb)
        self.mmio_write(OFF_VICINTENABLE, 1 << int_line_nb)
        self.vic.set_interrupt_source(1 << int_line_nb)
        self.vic.update()

        assert self.vic.nvicfiq
        assert not self.vic.nvicirq
        self.nvicfiq_high_callback.assert_called_once()
        self.nvicirq_high_callback.assert_not_called()
        assert self.mmio_read(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read(OFF_VICFIQSTATUS) == 1 << int_line_nb

        self.mmio_write(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic.set_interrupt_source(0)
        self.vic.update()

        assert not self.vic.nvicfiq
        assert not self.vic.nvicirq
        self.nvicfiq_high_callback.assert_called_once()
        self.nvicirq_high_callback.assert_not_called()
        assert self.mmio_read(OFF_VICRAWINTR) == 0
        assert self.mmio_read(OFF_VICFIQSTATUS) == 0

    def test_non_vectored_irq(self):
        int_line_nb = 12
        vect_int_default_addr = 0x1000
        self.mmio_write(OFF_VICINTENABLE, 1 << int_line_nb)
        self.mmio_write(OFF_VICDEFVECTADDR, vect_int_default_addr)
        self.vic.set_interrupt_source(1 << int_line_nb)
        self.vic.update()

        assert self.mmio_read(OFF_VICVECTADDR) == vect_int_default_addr
        assert not self.vic.nvicfiq
        assert self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()

        assert self.mmio_read(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read(OFF_VICIRQSTATUS) == 1 << int_line_nb

        self.mmio_write(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic.set_interrupt_source(0)
        self.vic.update()

        assert self.mmio_read(OFF_VICVECTADDR) == vect_int_default_addr
        assert not self.vic.nvicfiq
        assert not self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()
        assert self.mmio_read(OFF_VICRAWINTR) == 0
        assert self.mmio_read(OFF_VICIRQSTATUS) == 0

    def test_vectored_int(self):
        int_line_nb = 14
        vect_int_handler_addr = 0x500
        vector_2 = 4
        self.mmio_write(OFF_VICVECTADDR_X_BASE + vector_2, vect_int_handler_addr)
        self.mmio_write(OFF_VICVECTCNTL_X_BASE + vector_2, 0x20 | int_line_nb)
        self.mmio_write(OFF_VICINTENABLE, 1 << int_line_nb)
        self.vic.set_interrupt_source(1 << int_line_nb)
        self.vic.update()

        assert not self.vic.nvicfiq
        assert self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()
        assert self.mmio_read(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read(OFF_VICIRQSTATUS) == 1 << int_line_nb
        assert self.mmio_read(OFF_VICVECTADDR) == 0x500

        self.mmio_write(OFF_VICVECTADDR, 0xffffffff)

        self.mmio_write(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic.set_interrupt_source(0)
        self.vic.update()

        assert not self.vic.nvicfiq
        assert not self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()
        assert self.mmio_read(OFF_VICRAWINTR) == 0
        assert self.mmio_read(OFF_VICIRQSTATUS) == 0
        assert self.mmio_read(OFF_VICVECTADDR) == 0x0

    def test_default_vectored_address(self):
        vect_int_default_addr = 0x1000
        self.mmio_write(OFF_VICDEFVECTADDR, vect_int_default_addr)
        assert self.mmio_read(OFF_VICDEFVECTADDR) == vect_int_default_addr
        assert self.mmio_read(OFF_VICVECTADDR) == vect_int_default_addr

    def test_soft_int(self):
        int_line_nb = 12
        self.mmio_write(OFF_VICINTENABLE, 1 << int_line_nb)
        self.mmio_write(OFF_VICSOFTINT, 1 << int_line_nb)
        self.vic.update()

        assert self.mmio_read(OFF_VICSOFTINT) == 1 << int_line_nb

        assert not self.vic.nvicfiq
        assert self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()
        assert self.mmio_read(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read(OFF_VICIRQSTATUS) == 1 << int_line_nb

        self.mmio_write(OFF_VICSOFTINTCLEAR, 1 << int_line_nb)
        self.vic.update()

        assert not self.vic.nvicfiq
        assert not self.vic.nvicirq
        self.nvicfiq_high_callback.assert_not_called()
        self.nvicirq_high_callback.assert_called_once()
        assert self.mmio_read(OFF_VICRAWINTR) == 0
        assert self.mmio_read(OFF_VICIRQSTATUS) == 0

    def test_write_bad_offset(self):
        with pytest.raises(Pl190Exception):
            self.mmio_write(0x2000, 0x0)

    def test_read_bad_offset(self):
        with pytest.raises(Pl190Exception):
            self.mmio_read(0x2000)

    def test_read_readonly_register(self):
        with pytest.raises(Pl190Exception):
            self.mmio_write(0xFE4, 0x0)

    def test_read_non_implemented_registers(self):
        with pytest.raises(NotImplementedError):
            self.mmio_write(OFF_VICPROTECTION, 0x0)

        with pytest.raises(NotImplementedError):
            self.mmio_read(0x300)


class BaseTestUnicornArmPl190DaisyChain(MmioReadPrimitive):
    def setup_method(self, test_method):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)

        self.vic0 = UnicornArmPl190(self.uc, VIC_0_BASE)
        self.vic0_nvicfiq_high_callback = Mock()
        self.vic0.set_nvicfiq_high_callback(self.vic0_nvicfiq_high_callback)
        self.vic0_nvicirq_high_callback = Mock()
        self.vic0.set_nvicirq_high_callback(self.vic0_nvicirq_high_callback)

        self.vic1 = UnicornArmPl190(self.uc, VIC_1_BASE, daisy_chain=self.vic0)

        self.vic1.reset()
        self.vic0.reset()

    def mmio_read_vic0(self, offset: int) -> int:
        return self._mmio_read(self.vic0, VIC_0_BASE + offset)

    def mmio_write_vic0(self, offset: int, value: int):
        self._mmio_write(self.vic0, VIC_0_BASE + offset, value)

    def mmio_read_vic1(self, offset: int) -> int:
        return self._mmio_read(self.vic1, VIC_1_BASE + offset)

    def mmio_write_vic1(self, offset: int, value: int):
        self._mmio_write(self.vic1, VIC_1_BASE + offset, value)


class TestUnicornArmPl190DaisyChain(BaseTestUnicornArmPl190DaisyChain):
    def test_fiq_from_vic_1(self):
        int_line_nb = 19
        self.mmio_write_vic1(OFF_VICINTSELECT, 1 << int_line_nb)
        self.mmio_write_vic1(OFF_VICINTENABLE, 1 << int_line_nb)
        self.vic1.set_interrupt_source(1 << int_line_nb)
        self.vic0.trigger_output_signals_callbacks()

        assert self.vic0.nvicfiq
        assert not self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_called_once()
        self.vic0_nvicirq_high_callback.assert_not_called()
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read_vic1(OFF_VICFIQSTATUS) == 1 << int_line_nb

        self.mmio_write_vic1(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic1.set_interrupt_source(0)
        self.vic0.trigger_output_signals_callbacks()

        assert not self.vic0.nvicfiq
        assert not self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_called_once()
        self.vic0_nvicirq_high_callback.assert_not_called()
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic1(OFF_VICFIQSTATUS) == 0

    def test_non_vectored_irq_from_vic_1(self):
        int_line_nb = 25
        vic0_default_vector_addr = 0x1000
        vic1_default_vector_addr = 0x2000
        self.mmio_write_vic1(OFF_VICINTENABLE, 1 << int_line_nb)
        self.mmio_write_vic1(OFF_VICDEFVECTADDR, vic1_default_vector_addr)
        self.mmio_write_vic0(OFF_VICDEFVECTADDR, vic0_default_vector_addr)
        self.vic1.set_interrupt_source(1 << int_line_nb)
        self.vic0.trigger_output_signals_callbacks()

        assert not self.vic0.nvicfiq
        assert self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_not_called()
        self.vic0_nvicirq_high_callback.assert_called_once()
        assert self.mmio_read_vic0(OFF_VICVECTADDR) == vic1_default_vector_addr
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read_vic1(OFF_VICIRQSTATUS) == 1 << int_line_nb

        self.mmio_write_vic1(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic1.set_interrupt_source(0)
        self.vic0.trigger_output_signals_callbacks()

        assert not self.vic0.nvicfiq
        assert not self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_not_called()
        self.vic0_nvicirq_high_callback.assert_called_once()
        assert self.mmio_read_vic0(OFF_VICVECTADDR) == vic0_default_vector_addr
        assert self.mmio_read_vic1(OFF_VICVECTADDR) == vic1_default_vector_addr
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic1(OFF_VICFIQSTATUS) == 0

    def test_vectored_irq_from_vic_1(self):
        int_line_nb = 14
        vic0_default_vector_addr = 0x1000
        vic1_default_vector_addr = 0x2000
        vector_2_offset = 4
        vector_2_irq_handler_address = 0x3000
        self.mmio_write_vic1(OFF_VICVECTADDR_X_BASE + vector_2_offset,
                             vector_2_irq_handler_address)
        self.mmio_write_vic1(OFF_VICVECTCNTL_X_BASE + vector_2_offset,
                             0x20 | int_line_nb)
        self.mmio_write_vic1(OFF_VICINTENABLE, 1 << int_line_nb)
        self.mmio_write_vic1(OFF_VICDEFVECTADDR, vic1_default_vector_addr)
        self.mmio_write_vic0(OFF_VICDEFVECTADDR, vic0_default_vector_addr)
        self.vic1.set_interrupt_source(1 << int_line_nb)
        self.vic0.trigger_output_signals_callbacks()

        assert not self.vic0.nvicfiq
        assert self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_not_called()
        self.vic0_nvicirq_high_callback.assert_called_once()
        assert self.mmio_read_vic0(OFF_VICVECTADDR) == vector_2_irq_handler_address
        assert self.mmio_read_vic1(OFF_VICVECTADDR) == vector_2_irq_handler_address
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 1 << int_line_nb
        assert self.mmio_read_vic1(OFF_VICIRQSTATUS) == 1 << int_line_nb

        self.mmio_write_vic1(OFF_VICINTENCLEAR, 1 << int_line_nb)
        self.vic1.set_interrupt_source(0)
        self.vic0.trigger_output_signals_callbacks()

        assert not self.vic0.nvicfiq
        assert not self.vic0.nvicirq
        self.vic0_nvicfiq_high_callback.assert_not_called()
        self.vic0_nvicirq_high_callback.assert_called_once()
        assert self.mmio_read_vic0(OFF_VICVECTADDR) == vic0_default_vector_addr
        assert self.mmio_read_vic1(OFF_VICVECTADDR) == vic1_default_vector_addr
        assert self.mmio_read_vic0(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic0(OFF_VICFIQSTATUS) == 0
        assert self.mmio_read_vic1(OFF_VICRAWINTR) == 0
        assert self.mmio_read_vic1(OFF_VICFIQSTATUS) == 0
