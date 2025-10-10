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
    'CpuRegistersUnicorn'
]

from typing import Mapping, cast

import unicorn

from fiit.machine import CpuRegisters

# ==============================================================================


class CpuRegistersUnicorn(CpuRegisters):
    def __init__(
        self,
        uc: unicorn.Uc,
        register_mapping: Mapping[str, int],
        program_counter_name: str,
        stack_pointer_name: str,
    ):
        CpuRegisters.__init__(
            self,
            [],  # by default no register is exposed
            program_counter_name,
            stack_pointer_name,
            allowed_attr=['_uc', '_register_mapping']
        )

        super().__setattr__('_register_mapping', register_mapping)
        self._uc = uc

    def read(self, register: str) -> int:
        return cast(int, self._uc.reg_read(self._register_mapping[register]))

    def write(self, register: str, value: int) -> None:
        self._uc.reg_write(self._register_mapping[register], value)
