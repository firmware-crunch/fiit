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
    'Pl190',
    'Pl190Exception',
    'Pl190IntGen',
]

import collections
import struct
from typing import Callable, Optional, Deque, List, Set

from fiit.machine import (
    CpuEndian, MemoryProtection, TickUnit, DeviceCpu, MachineDevice
)

from .arm32 import ArchArm32

# ==============================================================================


class Pl190Exception(Exception):
    pass


class Pl190(MachineDevice):
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
        cpu: ArchArm32,
        base_address: int,
        auto_map: bool = True,
        auto_plug: bool = True,
        daisy_chain: Optional['Pl190'] = None,
        dev_name: Optional[str] = None
    ) -> None:
        MachineDevice.__init__(self, dev_name)
        self.cpu = cpu
        self.mem = cpu.mem

        ########################################################################
        # Pl190 configurations
        ########################################################################
        self.base_address = base_address
        self._pack_str = '>I' if self.cpu.endian == CpuEndian.EB else '<I'
        self._daisy_chain: Optional['Pl190'] = daisy_chain

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

        self._nvicfiq_high_callback: Callable[[], None] = lambda: None
        self._nvicirq_high_callback: Callable[[], None] = lambda: None

        ########################################################################
        # Register internal copy
        ########################################################################
        self._vicintselect = 0
        self._vicintenable = 0
        self._vicsoftint = 0
        self._vicvectaddr_x: List[int] = []
        self._vicvectcntl_x: List[int] = []

        ########################################################################
        # Priority internal states
        ########################################################################
        self._priority = 0
        self._previous_priority: List[int] = []
        self._priority_mask: List[int] = []

        ########################################################################
        # Initialisation
        ########################################################################
        if auto_map and not self._mem_device_exist():
            self.log.info(
                'create peripheral memory region at dev@%s::%s (auto_map=%s)',
                self.cpu.dev_name, self.cpu.mem.addr_to_str(self.base_address),
                str(auto_map)
            )
            self._map_device()

        self.log.info(
            'peripheral base address at dev@%s::%s',
            self.cpu.dev_name, self.cpu.mem.addr_to_str(self.base_address)
        )
        self._init_states()
        end = self.base_address + 0x400
        self.cpu.hook_mem_read_range(self._mem_read, self.base_address, end)
        self.cpu.hook_mem_write_range(self._mem_write, self.base_address, end)
        self.cpu.hook_cpu_exception(self._hook_cpu_exception)

        if auto_plug:
            take_fiq_exception = getattr(cpu, 'take_fiq_exception', None)
            if take_fiq_exception is not None:
                self.log.info('connect FIQ lines to dev@%s', cpu.dev_name)
                self.set_nvicfiq_high_callback(take_fiq_exception)

            take_irq_exception = getattr(cpu, 'take_irq_exception', None)
            if take_irq_exception is not None:
                self.log.info('connect IRQ lines to dev@%s', cpu.dev_name)
                self.set_nvicirq_high_callback(take_irq_exception)

    def _map_device(self) -> None:
        self.mem_region = self.mem.create_region(
            base_address=self.base_address,
            size=self.MEM_MAP_SIZE,
            protection=MemoryProtection.RW,
            name='mmio_pl190'
        )
        self.mem.write(self.base_address, self.MEM_MAP_SIZE * b'\x00')

    def _mem_device_exist(self) -> bool:
        start = self.base_address
        end = self.base_address + Pl190.MEM_MAP_SIZE - 1

        for mr in self.cpu.mem.regions:
            if start >= mr.base_address and end <= mr.end_address:
                return True

        return False

    def set_nvicfiq_high_callback(self, callback: Callable[[], None]) -> None:
        self._nvicfiq_high_callback = callback

    def set_nvicirq_high_callback(self, callback: Callable[[], None]) -> None:
        self._nvicirq_high_callback = callback

    def _mmio_write(self, offset: int, value: int) -> None:
        self.mem.write(
            self.base_address + offset, struct.pack(self._pack_str, value)
        )

    def reset(self) -> None:
        self._init_states()
        self.update_states()

    def _hook_cpu_exception(self, _: DeviceCpu, int_num: int) -> None:
        if int_num == 0:
            self.reset()

    def set_interrupt_source(self, vicintsource: int) -> None:
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
                return self._vicvectaddr_x[i]

        if self.nvicirqin:
            return self.vicvectaddrin

        # Return default IRQ handler address if no pending interrupt.
        return self._vicvectaddr_x[-1]

    def _init_states(self) -> None:
        self.mem.write(self.base_address, 0x1000 * b'\x00')

        for offset, reset_value in self.PL190_ID.items():
            self._mmio_write(offset, reset_value)

        # Register internal copy
        self._vicintselect = 0
        self._vicintenable = 0
        self._vicsoftint = 0
        self._vicvectaddr_x = [0] * self.TOTAL_PRIORITY
        self._vicvectcntl_x = [0] * 16

        # Priority internal states
        self._priority = self.TOTAL_PRIORITY - 1
        self._previous_priority = [0] * self.TOTAL_PRIORITY
        self._priority_mask = [0] * self.TOTAL_PRIORITY
        self._priority_mask[-1] = 0xffffffff

    def update_states(self) -> None:
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

    def trigger_output_signals_callbacks(self) -> None:
        if self.nvicfiq:
            self._nvicfiq_high_callback()
        if self.nvicirq:
            self._nvicirq_high_callback()

    def update(self) -> None:
        self.update_states()
        self.trigger_output_signals_callbacks()

    def _set_vector_priority_masks(self) -> None:
        mask = 0

        for i, vicvectcntl in enumerate(self._vicvectcntl_x):
            if vicvectcntl & 0x20:
                mask |= (1 << (vicvectcntl & 0x1f))

            self._priority_mask[i] = mask

    def _mem_read(self, _: DeviceCpu, address: int, size: int) -> None:
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
            self._mmio_write(offset, self._vicvectaddr_x[-1])

        elif offset == self.OFF_VICVECTADDR:
            irq_status = self._get_irqstatus()

            for i in range(0, self._priority):
                if irq_status & self._priority_mask[i]:
                    self._previous_priority[i] = self._priority
                    self._priority = i
                    self._mmio_write(offset, self._vicvectaddr_x[i])
                    self.update_states()
                    return

            if self.nvicirqin:
                self._mmio_write(offset, self.vicvectaddrin)
                return

            self._mmio_write(offset, self._vicvectaddr_x[-1])

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
            raise NotImplementedError('feature not implemented')

        else:
            raise Pl190Exception('read bad offset')

    def _mem_write(
        self, _: DeviceCpu, address: int, size: int, value: int
    ) -> None:
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
            self._vicvectaddr_x[-1] = value

        elif self.OFF_VICVECTADDR_X_START <= offset < self.OFF_VICVECTADDR_X_END:
            self._vicvectaddr_x[(offset - 0x100) >> 2] = value

        elif self.OFF_VICVECTCNTL_X_START <= offset < self.OFF_VICVECTCNTL_X_END:
            self._vicvectcntl_x[(offset - 0x200) >> 2] = value
            self._set_vector_priority_masks()

        elif offset in [self.OFF_VICITCR, self.OFF_VICPROTECTION]:
            raise NotImplementedError('feature not implemented')

        else:
            raise Pl190Exception('write bad offset')

        self.update_states()

# ----------------------------------------------------------------------------


class Pl190IntGen(MachineDevice):

    # ARM DDI 0406C.d : B1.3.1 ARM processor modes
    # ARM DDI 0100I : A2.5.7 The mode bits
    CPSR_M_FIQ = 0b10001
    CPSR_M_IRQ = 0b10010
    CPSR_M_SVC = 0b10011

    @staticmethod
    def _check_cpu_mode(cpu: DeviceCpu, mode: int) -> bool:
        if (cpu.regs.cpsr & 0x1f) == mode:
            return True
        return False

    @staticmethod
    def _get_high_bit_offsets(value: int) -> Deque[int]:
        bits: Deque[int] = collections.deque()
        for i in range(0, 32):
            if value & (1 << i):
                bits.append(i)
        return bits

    def __init__(
        self,
        pl190: Pl190,
        int_tick_unit: TickUnit,
        int_tick_count: int,
        auto_plug: bool = True,
        dev_name: Optional[str] = None
    ):
        MachineDevice.__init__(self, dev_name)
        self.log.info('register dev@%s', pl190.dev_name)

        self._pl190 = pl190
        self._int_enabled: Set[int] = set()
        self._int_queue: Deque[int] = collections.deque()
        self._interrupt_mask: Set[int] = set()

        if auto_plug:
            self._pl190.cpu.set_contention(int_tick_unit, int_tick_count)
            self._pl190.cpu.add_contention_callback(self.gen)
            self.log.info(
                'attach cpu contention callback to dev@%s',
                self._pl190.cpu.dev_name
            )

    def is_fiq_mode(self, cpu: DeviceCpu) -> bool:
        return self._check_cpu_mode(cpu, self.CPSR_M_FIQ)

    def is_irq_mode(self, cpu: DeviceCpu) -> bool:
        return self._check_cpu_mode(cpu, self.CPSR_M_IRQ)

    def is_svc_mode(self, cpu: DeviceCpu) -> bool:
        return self._check_cpu_mode(cpu, self.CPSR_M_SVC)

    def mask_interrupt(self, int_number: int) -> None:
        self._interrupt_mask.add(int_number)

    def unmask_interrupt(self, int_number: int) -> None:
        self._interrupt_mask.remove(int_number)

    def gen(self, cpu: DeviceCpu) -> None:
        """
        Generate interrupts in round-robin and non nested fashion way,
        override this method to implement your own interrupt trigger policy.
        """
        if self.is_irq_mode(cpu) or self.is_fiq_mode(cpu):
            return

        cur_int_enabled = self._get_high_bit_offsets(self._pl190._vicintenable)

        if len(self._int_queue) == 0:
            # reload interrupts with fresh programmed interrupts
            self._int_enabled = set(cur_int_enabled)
            self._int_queue = cur_int_enabled
        else:
            # if interrupt are pending, Check if new interrupt are programmed
            for prog_int in cur_int_enabled:
                if prog_int not in self._int_queue:
                    self._int_queue.append(prog_int)
            # if interrupt are pending, Check if previous programmed interrupt
            # has been deactivated
            for queued_int in self._int_queue:
                if queued_int not in cur_int_enabled:
                    self._int_queue.remove(queued_int)

        if len(self._int_queue) == 0:
            return

        interrupt = self._int_queue.popleft()

        if interrupt in self._interrupt_mask:
            return

        self.log.debug('trigger interrupt %s', str(interrupt))
        self._pl190.set_interrupt_source(1 << interrupt)
        self._pl190.update()
