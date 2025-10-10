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

from unicorn import arm_const

from fiit.emunicorn import CpuRegistersUnicorn

from .fixtures import create_uc_arm_926

# ==============================================================================


# ------------------------------------------------------------------------------
# fixture

_UC_ARM_REG_MAPPING = {
    'r0': arm_const.UC_ARM_REG_R0,
    'sp':  arm_const.UC_ARM_REG_SP,
    'pc': arm_const.UC_ARM_REG_PC
}

# ------------------------------------------------------------------------------


def test_read_register_via_property():
    uc = create_uc_arm_926()
    regs = CpuRegistersUnicorn(uc, _UC_ARM_REG_MAPPING, 'pc', 'sp')
    regs.register_names = list(_UC_ARM_REG_MAPPING.keys())
    assert regs.r0 == uc.reg_read(arm_const.UC_ARM_REG_R0)


def test_read_register():
    uc = create_uc_arm_926()
    regs = CpuRegistersUnicorn(uc, _UC_ARM_REG_MAPPING, 'pc', 'sp')
    regs.register_names = list(_UC_ARM_REG_MAPPING.keys())
    assert regs.read('r0') == uc.reg_read(arm_const.UC_ARM_REG_R0)


def test_write_register_via_property():
    uc = create_uc_arm_926()
    regs = CpuRegistersUnicorn(uc, _UC_ARM_REG_MAPPING, 'pc', 'sp')
    regs.register_names = list(_UC_ARM_REG_MAPPING.keys())
    regs.r0 = 0xc0def00d
    assert uc.reg_read(arm_const.UC_ARM_REG_R0) == 0xc0def00d


def test_write_register():
    uc = create_uc_arm_926()
    regs = CpuRegistersUnicorn(uc, _UC_ARM_REG_MAPPING, 'pc', 'sp')
    regs.register_names = list(_UC_ARM_REG_MAPPING.keys())
    regs.write('r0', 0xc0def00d)
    assert uc.reg_read(arm_const.UC_ARM_REG_R0) == 0xc0def00d

