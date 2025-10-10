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
    'ARM32_REGISTER',
]

from unicorn import arm_const

# ==============================================================================


ARM32_REGISTER = {
    'r0': arm_const.UC_ARM_REG_R0,
    'r1': arm_const.UC_ARM_REG_R1,
    'r2': arm_const.UC_ARM_REG_R2,
    'r3': arm_const.UC_ARM_REG_R3,
    'r4': arm_const.UC_ARM_REG_R4,
    'r5': arm_const.UC_ARM_REG_R5,
    'r6': arm_const.UC_ARM_REG_R6,
    'r7': arm_const.UC_ARM_REG_R7,
    'r8': arm_const.UC_ARM_REG_R8,
    'r9': arm_const.UC_ARM_REG_R9,
    'r10': arm_const.UC_ARM_REG_R10,
    'r11': arm_const.UC_ARM_REG_R11,
    'r12': arm_const.UC_ARM_REG_R12,
    'sp': arm_const.UC_ARM_REG_SP,
    'lr': arm_const.UC_ARM_REG_LR,
    'pc': arm_const.UC_ARM_REG_PC,
    'cpsr': arm_const.UC_ARM_REG_CPSR,
    'spsr': arm_const.UC_ARM_REG_SPSR,
    'fpexc': arm_const. UC_ARM_REG_FPEXC,
    'fpscr': arm_const.UC_ARM_REG_FPSCR,

    # VFP single registers

    's0':  arm_const.UC_ARM_REG_S0,
    's1':  arm_const.UC_ARM_REG_S1,
    's2':  arm_const.UC_ARM_REG_S2,
    's3':  arm_const.UC_ARM_REG_S3,
    's4':  arm_const.UC_ARM_REG_S4,
    's5':  arm_const.UC_ARM_REG_S5,
    's6':  arm_const.UC_ARM_REG_S6,
    's7':  arm_const.UC_ARM_REG_S7,
    's8':  arm_const.UC_ARM_REG_S8,
    's9':  arm_const.UC_ARM_REG_S9,
    's10': arm_const.UC_ARM_REG_S10,
    's11': arm_const.UC_ARM_REG_S11,
    's12': arm_const.UC_ARM_REG_S12,
    's13': arm_const.UC_ARM_REG_S13,
    's14': arm_const.UC_ARM_REG_S14,
    's15': arm_const.UC_ARM_REG_S15,
    's16': arm_const.UC_ARM_REG_S16,
    's17': arm_const.UC_ARM_REG_S17,
    's18': arm_const.UC_ARM_REG_S18,
    's19': arm_const.UC_ARM_REG_S19,
    's20': arm_const.UC_ARM_REG_S20,
    's21': arm_const.UC_ARM_REG_S21,
    's22': arm_const.UC_ARM_REG_S22,
    's23': arm_const.UC_ARM_REG_S23,
    's24': arm_const.UC_ARM_REG_S24,
    's25': arm_const.UC_ARM_REG_S25,
    's26': arm_const.UC_ARM_REG_S26,
    's27': arm_const.UC_ARM_REG_S27,
    's28': arm_const.UC_ARM_REG_S28,
    's29': arm_const.UC_ARM_REG_S29,
    's30': arm_const.UC_ARM_REG_S30,
    's31': arm_const.UC_ARM_REG_S31,

    # VFP double registers

    'd0':  arm_const.UC_ARM_REG_D0,
    'd1':  arm_const.UC_ARM_REG_D1,
    'd2':  arm_const.UC_ARM_REG_D2,
    'd3':  arm_const.UC_ARM_REG_D3,
    'd4':  arm_const.UC_ARM_REG_D4,
    'd5':  arm_const.UC_ARM_REG_D5,
    'd6':  arm_const.UC_ARM_REG_D6,
    'd7':  arm_const.UC_ARM_REG_D7,
    'd8':  arm_const.UC_ARM_REG_D8,
    'd9':  arm_const.UC_ARM_REG_D9,
    'd10': arm_const.UC_ARM_REG_D10,
    'd11': arm_const.UC_ARM_REG_D11,
    'd12': arm_const.UC_ARM_REG_D12,
    'd13': arm_const.UC_ARM_REG_D13,
    'd14': arm_const.UC_ARM_REG_D14,
    'd15': arm_const.UC_ARM_REG_D15,
    'd16': arm_const.UC_ARM_REG_D16,
    'd17': arm_const.UC_ARM_REG_D17,
    'd18': arm_const.UC_ARM_REG_D18,
    'd19': arm_const.UC_ARM_REG_D19,
    'd20': arm_const.UC_ARM_REG_D20,
    'd21': arm_const.UC_ARM_REG_D21,
    'd22': arm_const.UC_ARM_REG_D22,
    'd23': arm_const.UC_ARM_REG_D23,
    'd24': arm_const.UC_ARM_REG_D24,
    'd25': arm_const.UC_ARM_REG_D25,
    'd26': arm_const.UC_ARM_REG_D26,
    'd27': arm_const.UC_ARM_REG_D27,
    'd28': arm_const.UC_ARM_REG_D28,
    'd29': arm_const.UC_ARM_REG_D29,
    'd30': arm_const.UC_ARM_REG_D30,
    'd31': arm_const.UC_ARM_REG_D31
}
