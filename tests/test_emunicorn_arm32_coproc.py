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

from fiit.emunicorn import ArchArm32CoprocUnicorn

from .fixtures import create_uc_arm_926

# ==============================================================================


def test_read_coproc():
    uc = create_uc_arm_926()
    coproc = ArchArm32CoprocUnicorn(uc)

    assert coproc.read(coproc=15, opcode_1=0, crn=1, crm=0, opcode_2=0) \
           == uc.reg_read(arm_const.UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 0))


def test_write_coproc():
    uc = create_uc_arm_926()
    coproc = ArchArm32CoprocUnicorn(uc)

    cp15_c1_c0 = coproc.read(coproc=15, opcode_1=0, crn=1, crm=0, opcode_2=0)
    cp15_c1_c0 &= (1 << 13)
    coproc.write(coproc=15, opcode_1=0, crn=1, crm=0, opcode_2=0,
                 value=cp15_c1_c0)

    assert cp15_c1_c0 == uc.reg_read(arm_const.UC_ARM_REG_CP_REG,
                                     (15, 0, 0, 1, 0, 0, 0))
