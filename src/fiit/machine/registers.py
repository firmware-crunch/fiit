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
# This file is a custom version of the QlRegisterManager class from the qiling
# project licensed under the GNU General Public License Version 2 or any later
# version, you can access to the original source via the following web link:
#
# https://github.com/qilingframework/qiling/blob/
# 0ea5fc435eefa9bf35d60996e9a8099492d73b5d/qiling/arch/register.py
#
################################################################################

__all__ = [
    'CpuRegisters'
]

import abc
from typing import Any, List, Tuple, Dict, Optional

# ==============================================================================


class CpuRegisters(abc.ABC):

    _register_names: List[str]

    def __init__(
        self,
        register_names: List[str],
        program_counter_name: str,
        stack_pointer_name: str,
        allowed_attr: Optional[List[str]] = None
    ):
        # Exotic initialisation via super().__setattr__ to avoid endless
        # recursion caused by calling self setattr/getattr upon init.
        allowed_attr_args = allowed_attr if allowed_attr is not None else []
        allowed_attr_ = [
            '_program_counter_name',
            '_stack_pointer_name',
            '_register_names',
            'register_names',
            'save',
            'restore',
            'read',
            'write',
            'arch_pc',
            'arch_sp',
            *allowed_attr_args
        ]

        super().__setattr__('_program_counter_name', program_counter_name)
        super().__setattr__('_stack_pointer_name', stack_pointer_name)
        super().__setattr__('_register_names', register_names)
        super().__setattr__('_allowed_attr', allowed_attr_)

    @property
    def register_names(self) -> Tuple[str, ...]:
        return tuple(self._register_names)

    @register_names.setter
    def register_names(self, names: List[str]) -> None:
        self._register_names.clear()
        self._register_names.extend(names)

    def __getattr__(self, name: str) -> Any:
        name = name.lower()

        if name in self._register_names:
            return self.read(name)

        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        name = name.lower()

        if name in self._register_names:
            self.write(name, value)
        elif name in self._allowed_attr:
            super().__setattr__(name, value)
        else:
            raise AttributeError(f'set attribute "{name}" is not allowed')

    def save(
        self, include_filter: Optional[List[str]] = None
    ) -> Dict[str, int]:
        registers = {}
        for name in self._register_names:
            if include_filter is None:
                registers[name] = self.read(name)
            elif include_filter is not None and name in include_filter:
                registers[name] = self.read(name)

        return registers

    def restore(self, context: dict[str, int]) -> None:
        for register, value in context.items():
            self.write(register, value)

    @abc.abstractmethod
    def read(self, register: str) -> int:
        """ """

    @abc.abstractmethod
    def write(self, register: str, value: int) -> None:
        """ """

    @property
    def arch_pc(self) -> int:
        return self.read(self._program_counter_name)

    @arch_pc.setter
    def arch_pc(self, value: int) -> None:
        self.write(self._program_counter_name, value)

    @property
    def arch_sp(self) -> int:
        return self.read(self._stack_pointer_name)

    @arch_sp.setter
    def arch_sp(self, value: int) -> None:
        self.write(self._stack_pointer_name, value)
