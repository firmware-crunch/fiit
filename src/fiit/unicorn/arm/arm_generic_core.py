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

from unicorn import Uc
from unicorn.unicorn_const import UC_HOOK_INTR
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_SPSR, UC_ARM_REG_PC, UC_ARM_REG_LR,
    UC_ARM_REG_CP_REG)

from ..arch_unicorn import ArchUnicorn
from fiit.core.emulator_types import ADDRESS_FORMAT


class UnicornArmGenericCore:
    # ARM DDI 0100I : A2.5 Program status registers
    OFF_CPSR_T = 5
    OFF_CPSR_F = 6
    OFF_CPSR_I = 7

    CPSR_M_FIQ = 0b10001
    CPSR_M_IRQ = 0b10010
    CPSR_M_SVC = 0b10011

    # ARM DDI 0100I : A2.6 Exceptions
    VECTOR_BASE_NORMAL = 0x0
    VECTOR_BASE_HIGH = 0xffff0000

    OFF_VECTOR_SOFT = 0x8
    OFF_VECTOR_IRQ = 0x18
    OFF_VECTOR_FIQ = 0x1c

    # ARM DDI 0100I : B3.4.1 Control register
    OFF_CP15_C1_C0_V = 13

    @staticmethod
    def _not(x: int) -> int:
        return x ^ 0xffffffff

    def __init__(
        self,
        uc: Uc,
        high_vector_support=True,
        high_vector=False
    ):
        self.uc = uc
        self.uc.hook_add(UC_HOOK_INTR, self.int_handler, begin=1, end=0)

        ########################################################################
        # Vector Configuration
        ########################################################################
        self._high_vector_support = high_vector_support
        self._high_vector = high_vector
        self.set_high_vector(self._high_vector)

        ########################################################################
        # Logger
        ########################################################################
        arch = ArchUnicorn.get_arch_str_by_uc(self.uc)
        mem_bit_size = ArchUnicorn.get_mem_bit_size(arch)
        self._addr_f = ADDRESS_FORMAT[mem_bit_size]

        self._logger = logging.getLogger('fiit.unicorn_arm_generic_core')
        self._logger.info(f'Vector table base address configured at '
                          f'{self._addr_f(self.get_vector_base_address())}')

    def _read_cp15_c1_c0(self) -> int:
        return self.uc.reg_read(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 0))

    def _write_cp15_c1_c0(self, value: int):
        self.uc.reg_write(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 0, value))

    def get_vector_base_address(self) -> int:
        if (self._high_vector_support
                and (self._read_cp15_c1_c0() & (1 << self.OFF_CP15_C1_C0_V))):
            return self.VECTOR_BASE_HIGH

        return self.VECTOR_BASE_NORMAL

    def set_high_vector(self, flag: bool):
        if self._high_vector_support:
            cp15_c1_c0 = self._read_cp15_c1_c0()

            if flag:
                cp15_c1_c0 |= 1 << self.OFF_CP15_C1_C0_V
            else:
                cp15_c1_c0 &= self._not(1 << self.OFF_CP15_C1_C0_V)

            self._write_cp15_c1_c0(cp15_c1_c0)

        self._high_vector = flag

    def int_handler(self, uc: Uc, int_num: int, size: int):
        if int_num == 2:
            self.int_soft()

    def int_soft(self):
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_SVC  # set Supervisor mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.uc.reg_write(UC_ARM_REG_CPSR, new_cpsr)
        self.uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        self.uc.reg_write(UC_ARM_REG_LR, pc)
        vector_base = self.get_vector_base_address()
        self.uc.reg_write(UC_ARM_REG_PC, vector_base + self.OFF_VECTOR_SOFT)
        self._logger.debug(f'Trigger software interrupt at {pc - 4:#x}')

    def set_fiq_mode(self):
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)

        if cpsr & (1 << self.OFF_CPSR_F):  # FIQ are not enable
            return False

        pc = self.uc.reg_read(UC_ARM_REG_PC)
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_FIQ  # set FIQ mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_F  # disable FIQ
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.uc.reg_write(UC_ARM_REG_CPSR, new_cpsr)
        self.uc.reg_write(UC_ARM_REG_LR, pc + 4)
        self.uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        vector_base = self.get_vector_base_address()
        self.uc.reg_write(UC_ARM_REG_PC, vector_base + self.OFF_VECTOR_FIQ)

        return True

    def set_irq_mode(self):
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)

        if cpsr & (1 << self.OFF_CPSR_I):  # IRQ are not enable
            return False

        pc = self.uc.reg_read(UC_ARM_REG_PC)
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_IRQ  # set IRQ mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.uc.reg_write(UC_ARM_REG_CPSR, new_cpsr)
        self.uc.reg_write(UC_ARM_REG_LR, pc + 4)
        self.uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        vector_base = self.get_vector_base_address()
        self.uc.reg_write(UC_ARM_REG_PC, vector_base + self.OFF_VECTOR_IRQ)

        return True

    def _check_cpu_mode(self, mode: int) -> bool:
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
        if (cpsr & 0x1f) == mode:
            return True
        return False

    def is_fiq_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_FIQ)

    def is_irq_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_IRQ)

    def is_svc_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_SVC)
