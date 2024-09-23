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

from typing import Callable, Optional
import logging
import struct
import mmap
import ctypes

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_MODE_BIG_ENDIAN,
    UC_PROT_READ, UC_PROT_WRITE)

from fiit.core.emulator_types import MemoryRegion


class Pl190Exception(Exception):
    pass


class UnicornArmPl190:
    @staticmethod
    def _not(x: int) -> int:
        return x ^ 0xffffffff

    MEM_MAP_SIZE = 0x10000

    # ARM DDI 0181E : 3.2 Summary of VIC registers
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
    OFF_VICITCR = 0x300

    OFF_VICVECTADDR_X_START = 0x100
    OFF_VICVECTADDR_X_END = 0x13f

    OFF_VICVECTCNTL_X_START = 0x200
    OFF_VICVECTCNTL_X_END = 0x23f

    OFF_VICPERIPHIDX_START = 0xFE0
    OFF_VICPERIPHIDX_END = 0xfff

    OFF_TEST_REG_START = 0x300
    OFF_TEST_REG_END = 0x313

    PL190_ID = {
        # ARM DDI 0181E : 3.3.14 Peripheral Identification Registers
        0xfe0: 0x90, 0xfe4: 0x11, 0xfe8: 0x04, 0xfeC: 0x00,
        # ARM DDI 0181E : 3.3.15 PrimeCell Identification Registers
        0xff0: 0x0d, 0xff4: 0xf0, 0xff8: 0x05, 0xffC: 0xb1
    }

    #  0 to 15 vectored IRQ + non vectored IRQ
    TOTAL_PRIORITY = 17

    def __init__(
        self,
        uc: Uc,
        base_address: int,
        auto_map: bool = True,
        daisy_chain: Optional['UnicornArmPl190'] = None
    ):
        self.uc = uc

        ########################################################################
        # Pl190 configurations
        ########################################################################
        self.base_address = base_address
        self._pack_str = '>I' if self.uc._mode & UC_MODE_BIG_ENDIAN else '<I'
        self._daisy_chain: Optional['UnicornArmPl190'] = daisy_chain

        ########################################################################
        # Signals
        ########################################################################
        self.vicintsource = 0
        self.nvicfiqin = False
        self.nvicirqin = False
        self.vicvectaddrin = 0

        self.vicvectaddrout = 0
        self.nvicfiq = False
        self.nvicirq = False

        self._nvicfiq_high_callback = lambda: False
        self._nvicirq_high_callback = lambda: False

        ########################################################################
        # Register internal copy
        ########################################################################
        self._vicintselect = 0
        self._vicintenable = 0
        self._vicsoftint = 0
        self._vicvectaddrX = []
        self._vicvectcntlX = []

        ########################################################################
        # Priority internal states
        ########################################################################
        self._priority = 0
        self._previous_priority = []
        self._priority_mask = []

        ########################################################################
        # Logger
        ########################################################################
        self._logger = logging.getLogger('fiit.unicorn_arm_pl190')
        self._logger.info(f'Base address at {self.base_address:#x}')

        ########################################################################
        # Initialisation
        ########################################################################
        if auto_map:
            self.mem_region = self._mem_map()

        self._init_states()

        self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_read,
                         begin=self.base_address, end=self.base_address + 0x400)

        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_write,
                         begin=self.base_address, end=self.base_address + 0x400)

    def _mem_map(self) -> MemoryRegion:
        host_mem_area = mmap.mmap(
            -1, self.MEM_MAP_SIZE, flags=mmap.MAP_PRIVATE,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        host_base_address = ctypes.addressof(
            ctypes.c_ubyte.from_buffer(host_mem_area))
        self.uc.mem_map_ptr(
            self.base_address, self.MEM_MAP_SIZE, UC_PROT_READ | UC_PROT_WRITE,
            host_base_address)
        self.uc.mem_write(self.base_address, self.MEM_MAP_SIZE * b'\x00')
        mr = MemoryRegion('PL190', self.base_address, self.MEM_MAP_SIZE, 'rw',
                          host_base_address, host_mem_area)
        return mr

    def set_nvicfiq_high_callback(self, callback: Callable):
        self._nvicfiq_high_callback = callback

    def set_nvicirq_high_callback(self, callback: Callable):
        self._nvicirq_high_callback = callback

    def _mmio_write(self, offset: int, value: int):
        self.uc.mem_write(self.base_address + offset,
                          struct.pack(self._pack_str, value))

    def reset(self):
        self._init_states()
        self.update_states()

    def reset_handler(self, uc: Uc, int_num: int, size: int):
        if int_num == 0:
            self.reset()

    def set_interrupt_source(self, vicintsource: int):
        """ Set the interrupt source input signal (vicintsource[31:0]). """
        self.vicintsource = vicintsource
        self.update_states()

    def _get_fiqstatus(self) -> int:
        return (
            (self.vicintsource | self._vicsoftint)
            & self._vicintenable & self._vicintselect
        )

    def _get_irqstatus(self) -> int:
        return (
            (self.vicintsource | self._vicsoftint)
            & self._vicintenable & self._not(self._vicintselect)
        )

    def _get_vectoraddr(self) -> int:
        irq_status = self._get_irqstatus()

        for i in range(0, self._priority):
            if irq_status & self._priority_mask[i]:
                return self._vicvectaddrX[i]

        if self.nvicirqin:
            return self.vicvectaddrin

        # Return default IRQ handler address if no pending interrupt.
        return self._vicvectaddrX[-1]

    def _init_states(self):
        self.uc.mem_write(self.base_address, 0x1000 * b'\x00')

        for offset, reset_value in self.PL190_ID.items():
            self._mmio_write(offset, reset_value)

        # Register internal copy
        self._vicintselect = 0
        self._vicintenable = 0
        self._vicsoftint = 0
        self._vicvectaddrX = [0] * self.TOTAL_PRIORITY
        self._vicvectcntlX = [0] * 16

        # Priority internal states
        self._priority = self.TOTAL_PRIORITY - 1
        self._previous_priority = [0] * self.TOTAL_PRIORITY
        self._priority_mask = [0] * self.TOTAL_PRIORITY
        self._priority_mask[-1] = 0xffffffff

    def update_states(self):
        if self._get_fiqstatus() or self.nvicfiqin:
            self.nvicfiq = True
        else:
            self.nvicfiq = False

        irq_status = self._get_irqstatus()

        if irq_status & self._priority_mask[self._priority] or self.nvicirqin:
            self.nvicirq = True
        else:
            self.nvicirq = False

        self.vicvectaddrout = self._get_vectoraddr()

        if self._daisy_chain is not None:
            if self.nvicfiq:
                self._daisy_chain.nvicfiqin = True
            else:
                self._daisy_chain.nvicfiqin = False

            if self.nvicirq:
                self._daisy_chain.nvicirqin = True
            else:
                self._daisy_chain.nvicirqin = False

            self._daisy_chain.vicvectaddrin = self.vicvectaddrout

            self._daisy_chain.update_states()

    def trigger_output_signals_callbacks(self):
        if self.nvicfiq:
            self._nvicfiq_high_callback()
        if self.nvicirq:
            self._nvicirq_high_callback()

    def update(self):
        self.update_states()
        self.trigger_output_signals_callbacks()

    def _set_vector_priority_masks(self):
        mask = 0

        for i, vicvectcntl in enumerate(self._vicvectcntlX):
            if vicvectcntl & 0x20:
                mask |= (1 << (vicvectcntl & 0x1f))

            self._priority_mask[i] = mask

    def _mem_read(self, uc: Uc, access: int, address: int, size: int,
                  value: int, data: dict):
        offset = address - self.base_address

        if offset == self.OFF_VICIRQSTATUS:
            self._mmio_write(offset, self._get_irqstatus())

        elif offset == self.OFF_VICFIQSTATUS:
            self._mmio_write(offset, self._get_fiqstatus())

        elif offset == self.OFF_VICRAWINTR:
            self._mmio_write(offset, self.vicintsource | self._vicsoftint)

        elif offset == self.OFF_VICSOFTINT:
            self._mmio_write(self.OFF_VICSOFTINT, self._vicsoftint)

        elif offset == self.OFF_VICDEFVECTADDR:
            self._mmio_write(offset, self._vicvectaddrX[-1])

        elif offset == self.OFF_VICVECTADDR:
            irq_status = self._get_irqstatus()

            for i in range(0, self._priority):
                if irq_status & self._priority_mask[i]:
                    self._previous_priority[i] = self._priority
                    self._priority = i
                    self._mmio_write(offset, self._vicvectaddrX[i])
                    self.update_states()
                    return

            if self.nvicirqin:
                self._mmio_write(offset, self.vicvectaddrin)
                return

            self._mmio_write(offset, self._vicvectaddrX[-1])

        elif ((offset in
              [self.OFF_VICINTSELECT, self.OFF_VICINTENABLE,
               self.OFF_VICPROTECTION])
              or (self.OFF_VICVECTADDR_X_START
                  <= offset < self.OFF_VICVECTADDR_X_END)
              or (self.OFF_VICVECTCNTL_X_START
                  <= offset < self.OFF_VICVECTCNTL_X_END)
              or (self.OFF_VICPERIPHIDX_START
                  <= offset < self.OFF_VICPERIPHIDX_END)):
            pass

        elif self.OFF_TEST_REG_START <= offset < self.OFF_TEST_REG_END:
            raise NotImplementedError('Feature not implemented.')

        else:
            raise Pl190Exception(f"Read bad offset")

    def _mem_write(self, uc: Uc, access: int, address: int, size: int,
                   value: int, data: dict):
        offset = address - self.base_address

        if offset == self.OFF_VICINTSELECT:
            self._vicintselect = value

        elif offset == self.OFF_VICINTENABLE:
            self._vicintenable = value

        elif offset == self.OFF_VICINTENCLEAR:
            self._vicintenable &= self._not(value)
            self._mmio_write(self.OFF_VICINTENABLE, self._vicintenable)

        elif offset == self.OFF_VICSOFTINT:
            self._vicsoftint |= value
            self._mmio_write(self.OFF_VICSOFTINT, self._vicsoftint)

        elif offset == self.OFF_VICSOFTINTCLEAR:
            self._vicsoftint &= self._not(value)
            self._mmio_write(self.OFF_VICSOFTINT, self._vicsoftint)

        elif offset == self.OFF_VICVECTADDR:
            if self._priority < self.TOTAL_PRIORITY:
                self._priority = self._previous_priority[self._priority]

        elif offset == self.OFF_VICDEFVECTADDR:
            self._vicvectaddrX[-1] = value

        elif self.OFF_VICVECTADDR_X_START <= offset < self.OFF_VICVECTADDR_X_END:
            self._vicvectaddrX[(offset - 0x100) >> 2] = value

        elif self.OFF_VICVECTCNTL_X_START <= offset < self.OFF_VICVECTCNTL_X_END:
            self._vicvectcntlX[(offset - 0x200) >> 2] = value
            self._set_vector_priority_masks()

        elif offset == self.OFF_VICITCR or offset == self.OFF_VICPROTECTION:
            raise NotImplementedError('Feature not implemented.')

        else:
            raise Pl190Exception(f"Write bad offset")

        self.update_states()
