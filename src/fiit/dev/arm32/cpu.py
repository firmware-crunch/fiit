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
    'ArchArm32'
]

from typing import cast, Optional

from fiit.machine import CpuEndian, CpuBits, Cpu, DeviceCpu

from .coproc import ArchArm32Coproc

# ==============================================================================


class ArchArm32(DeviceCpu):
    """ A minimal architecture layer for ARM """

    ARCH_ID = 'arm32'
    ARCH_NAME = 'arm'
    ARCH_BITS = CpuBits.BITS_32
    ARCH_PC = 'pc'
    ARCH_SP = 'sp'

    # General Purpose Register
    ARM_REGISTERS_GPR = {
        'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
        'r11', 'r12', 'sp', 'lr', 'pc', 'cpsr', 'spsr'
    }

    ARM_REGISTER_FPEXC = 'fpexc'

    # VFP single registers
    ARM_REGISTERS_VFP_S = {
        's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10',
        's11', 's12', 's13', 's14', 's15', 's16', 's17', 's18', 's19', 's20',
        's21', 's22', 's23', 's24', 's25', 's26', 's27', 's28', 's29', 's30',
        's31',
    }

    # VFP double registers
    ARM_REGISTERS_VFP_D = {
        'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10',
        'd11', 'd12', 'd13', 'd14', 'd15', 'd16', 'd17', 'd18', 'd19', 'd20',
        'd21', 'd22', 'd23', 'd24', 'd25', 'd26', 'd27', 'd28', 'd29', 'd30',
        'd31'
    }

    # by default only expose the General Purpose Registers
    ARCH_REGISTERS = ARM_REGISTERS_GPR

    def __init__(self, cpu: Cpu, dev_name: Optional[str] = None):
        DeviceCpu.__init__(self, cpu, dev_name)
        self.cpu.regs.register_names = list(self.ARCH_REGISTERS)

    @property
    def coproc(self) -> ArchArm32Coproc:
        return cast(ArchArm32Coproc, super().coproc)

    @property
    def endian(self) -> CpuEndian:
        return CpuEndian.EB if self.regs.cpsr & (1 << 9) else CpuEndian.EL

    @property
    def thumb(self) -> bool:
        return bool(self.regs.cpsr & (1 << 5))

    @property
    def effective_pc(self) -> int:
        return self.regs.arch_pc | int(self.thumb)
