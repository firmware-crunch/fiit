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

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Union, Callable, ClassVar

from fiit.machine import DeviceCpu, Memory, CpuRegisters
from fiit.ctypesarch.base_types import CBaseType, FunctionSpec


class CpuContext:
    def __init__(self):
        self.pc: Optional[int] = None
        self.sp: Optional[int] = None


class FuncArg:
    def __init__(
        self,
        arg_num: int,
        value: CBaseType,
        func_spec: FunctionSpec,
        writer: Callable[[FunctionSpec, Dict[int, CBaseType]], None],
        arg_name: str = None
    ):
        self.name = arg_name
        self.arg_num = arg_num
        self.value = value
        self.func_spec = func_spec
        self._writer = writer

    def write(self):
        self._writer(self.func_spec, {self.arg_num: self.value})


class ReturnValue:
    def __init__(
        self,
        value: Union[CBaseType, None],
        func_spec: FunctionSpec,
        writer: Callable[[FunctionSpec, CBaseType], None]
    ):
        self.value = value
        self.func_spec = func_spec
        self._writer = writer

    def write(self):
        self._writer(self.func_spec, self.value)


class CallingConvention(ABC):
    NAME: ClassVar[str]

    mem: Memory
    regs: CpuRegisters

    @abstractmethod
    def __init__(self, cpu: DeviceCpu, *args, **kwargs):
        pass

    @abstractmethod
    def set_pc(self, address: int):
        pass

    @abstractmethod
    def get_return_address(self) -> int:
        pass

    @abstractmethod
    def get_cpu_context(self) -> CpuContext:
        pass

    @abstractmethod
    def get_arguments(self, spec: FunctionSpec) -> List[FuncArg]:
        pass

    @abstractmethod
    def set_arguments(
        self, spec: FunctionSpec, arg_values: Dict[int, CBaseType]
    ) -> None:
        pass

    @abstractmethod
    def get_return_value(self, spec: FunctionSpec) -> Union[ReturnValue, None]:
        pass

    @abstractmethod
    def set_return_value(self, spec: FunctionSpec, value: CBaseType):
        pass

    @abstractmethod
    def call(
        self, spec: FunctionSpec, arg_values: Dict[int, CBaseType]
    ) -> Union[CBaseType, None]:
        pass
