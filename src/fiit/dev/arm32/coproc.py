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
#
# This file is a custom version of the QlCprManager class from the Qiling
# project licensed under the GNU General Public License Version 2 or any later
# version, you can access to the original source code via the following web
# link.
#
# https://github.com/qilingframework/qiling/blob/
# a40690752f05044b374561689bb2a228687ccf70/qiling/arch/cpr.py
#
################################################################################

__all__ = [
    'ArchArm32Coproc'
]

import abc

# ==============================================================================


class ArchArm32Coproc(abc.ABC):
    """ ARM coprocessor registers interface """

    @abc.abstractmethod
    def read(
        self, coproc: int, opcode_1: int, crn: int, crm: int, opcode_2: int
    ) -> int:
        """Read a coprocessor register value.

        Args:
            coproc : Specifies the name of the coprocessor (0 to 15)
            opcode_1 : opcode 1 (0 to 7)
            crn : coprocessor register to access (CRn) (0 to 15)
            crm : additional coprocessor register to access (CRm) (0 to 15)
            opcode_2 : opcode 2 (0 to 7)

        Returns: value of coprocessor register
        """

    @abc.abstractmethod
    def write(
        self, coproc: int, opcode_1: int, crn: int, crm: int, opcode_2: int,
        value: int
    ) -> None:
        """Write a coprocessor register value.

        Args:
            coproc : coprocessor to access (value varies between 0 and 15)
            opcode_1 : coprocessor-specific opcode (0 to 7)
            crn : destination coprocessor register (0 to 15)
            crm : additional coprocessor register to access (CRm) (0 to 15)
            opcode_2 : coprocessor-specific opcode (0 to 7)
            value : value to write
        """
