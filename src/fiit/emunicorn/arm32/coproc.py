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
    'ArchArm32CoprocUnicorn'
]

from typing import cast

from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_CP_REG

from fiit.dev.arm32 import ArchArm32Coproc

# ==============================================================================


class ArchArm32CoprocUnicorn(ArchArm32Coproc):
    def __init__(self, uc: Uc):
        self._uc = uc

    def read(
        self, coproc: int, opcode_1: int, crn: int, crm: int, opcode_2: int
    ) -> int:
        coproc_args = (coproc, 0, 0, crn, crm, opcode_1, opcode_2)
        return cast(int, self._uc.reg_read(UC_ARM_REG_CP_REG, coproc_args))

    def write(
        self, coproc: int, opcode_1: int, crn: int, crm: int, opcode_2: int,
        value: int
    ) -> None:
        coproc_args = (coproc, 0, 0, crn, crm, opcode_1, opcode_2, value)
        self._uc.reg_write(UC_ARM_REG_CP_REG, coproc_args)
