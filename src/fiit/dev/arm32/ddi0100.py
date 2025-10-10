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
    'ArchArm32DDI0100'
]

from typing import Optional

from fiit.machine import Cpu, DeviceCpu

from .cpu import ArchArm32

# ==============================================================================


class ArchArm32DDI0100(ArchArm32):
    """ A partial architecture layer implementation of the ARM DDI 0100I """

    ARM_SPEC = 'DDI0100'  # required by framework for cpu variant identification

    ARCH_REGISTERS = {
        ArchArm32.ARM_REGISTER_FPEXC,
        *ArchArm32.ARM_REGISTERS_GPR,
        *ArchArm32.ARM_REGISTERS_VFP_S,
        *ArchArm32.ARM_REGISTERS_VFP_D
    }

    # ARM DDI 0100I : A2.5 Program status registers
    OFF_CPSR_T = 5
    OFF_CPSR_F = 6
    OFF_CPSR_I = 7

    # ARM DDI 0100I : A2.5.7 The mode bits
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
        cpu: Cpu,
        high_vector_support: bool = True,
        high_vector: bool = False,
        vfp: bool = False,
        dev_name: Optional[str] = None
    ) -> None:
        ArchArm32.__init__(self, cpu, dev_name)
        self.cpu.regs.register_names = list(self.ARCH_REGISTERS)
        self._high_vector_support = high_vector_support
        self._high_vector = high_vector
        self.set_high_vector(self._high_vector)

        if vfp:
            self.enable_vfp()
            self.log.info('enable hard VFP')

        self.hook_cpu_exception(self._hook_cpu_exception)

        self.log.info(
            'vector table base address configured at %s',
            self.mem.addr_to_str(self.get_vector_base_address())
        )

    def _read_cp15_c1_c0(self) -> int:
        # ARM DDI 0100I B3.4 Register 1: Control registers
        # Architectural Control register is `cp15 c1 c0`
        return self.coproc.read(coproc=15, opcode_1=0, crn=1, crm=0, opcode_2=0)

    def _write_cp15_c1_c0(self, value: int) -> None:
        # ARM DDI 0100I B3.4 Register 1: Control registers
        # Architectural Control register is `cp15 c1 c0`
        self.coproc.write(
            coproc=15, opcode_1=0, crn=1, crm=0, opcode_2=0, value=value
        )

    def get_vector_base_address(self) -> int:
        if (self._high_vector_support
                and (self._read_cp15_c1_c0() & (1 << self.OFF_CP15_C1_C0_V))):
            return self.VECTOR_BASE_HIGH

        return self.VECTOR_BASE_NORMAL

    def set_high_vector(self, flag: bool) -> None:
        if self._high_vector_support:
            cp15_c1_c0 = self._read_cp15_c1_c0()

            if flag:
                cp15_c1_c0 |= 1 << self.OFF_CP15_C1_C0_V
            else:
                cp15_c1_c0 &= self._not(1 << self.OFF_CP15_C1_C0_V)

            self._write_cp15_c1_c0(cp15_c1_c0)

        self._high_vector = flag

    def enable_vfp(self) -> None:
        # ARM DDI 0100I : C2.7.3 FPEXC : EN bit
        self.regs.fpexc = 1 << 30

    def _hook_cpu_exception(self, _: DeviceCpu, int_num: int) -> None:
        if int_num == 2:
            self.take_swi_exception()

    def take_swi_exception(self) -> None:
        pc = self.regs.arch_pc
        cpsr = self.regs.cpsr
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_SVC  # set Supervisor mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.regs.cpsr = new_cpsr
        self.regs.spsr = cpsr
        self.regs.lr = pc
        vector_base = self.get_vector_base_address()
        self.regs.arch_pc = vector_base + self.OFF_VECTOR_SOFT
        self.log.debug(
            'trigger software interrupt at %s', self.mem.addr_to_str(pc - 4)
        )

    def take_fiq_exception(self) -> bool:
        cpsr = self.regs.cpsr

        if cpsr & (1 << self.OFF_CPSR_F):  # FIQ are not enable
            return False

        pc = self.regs.arch_pc
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_FIQ  # set FIQ mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_F  # disable FIQ
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.regs.cpsr = new_cpsr
        self.regs.lr = pc + 4
        self.regs.spsr = cpsr
        vector_base = self.get_vector_base_address()
        self.regs.arch_pc = vector_base + self.OFF_VECTOR_FIQ
        return True

    def take_irq_exception(self) -> bool:
        cpsr = self.regs.cpsr

        if cpsr & (1 << self.OFF_CPSR_I):  # IRQ are not enable
            return False

        pc = self.regs.arch_pc
        new_cpsr = (cpsr & 0xffffffe0) | self.CPSR_M_IRQ  # set IRQ mode
        new_cpsr &= self._not(1 << self.OFF_CPSR_T)  # Exec in ARM state
        new_cpsr |= 1 << self.OFF_CPSR_I  # disable IRQ
        self.regs.cpsr = new_cpsr
        self.regs.lr = pc + 4
        self.regs.spsr = cpsr
        vector_base = self.get_vector_base_address()
        self.regs.arch_pc = vector_base + self.OFF_VECTOR_IRQ
        return True

    def _check_cpu_mode(self, mode: int) -> bool:
        if (self.regs.cpsr & 0x1f) == mode:
            return True
        return False

    def is_fiq_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_FIQ)

    def is_irq_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_IRQ)

    def is_svc_mode(self) -> bool:
        return self._check_cpu_mode(self.CPSR_M_SVC)
