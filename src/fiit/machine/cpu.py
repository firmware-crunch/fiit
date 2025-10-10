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
    'DeviceCpu',
    'Cpu'
]

import uuid
import abc
import threading
from typing import Optional, ClassVar, Callable, Union, Type, Dict, List, Any

from .memory import Memory
from .registers import CpuRegisters
from .defines import TickUnit, MachineDevice, CpuEndian, CpuBits

# ==============================================================================


# arg1: DeviceCpu instance
CpuContentionCallback = Callable[[Any], None]


# arg1: DeviceCpu instance
# arg2: Program Counter value
CodeAccessCallback = Callable[[Any, int], None]


# arg1: DeviceCpu instance
# arg2: Address
CpuExceptionCallback = Callable[[Any, int], None]


# arg1: DeviceCpu instance
# arg2: Address
# arg3: Request memory size
MemoryReadAccessCallback = Callable[[Any, int, int], None]


# arg1: DeviceCpu instance
# arg2: Address
# arg3: Request memory size
# arg4: Value
MemoryWriteAccessCallback = Callable[[Any, int, int, int], None]


class Cpu(abc.ABC):
    """ A pure abstract CPU interface """

    ARCH_ID: ClassVar[str]  # Required for framework cpu identification

    ARCH_NAME: ClassVar[str]
    ARCH_BITS: ClassVar[CpuBits]
    ARCH_PC: ClassVar[str]
    ARCH_SP: ClassVar[str]

    ##############
    # backend info

    BACKEND_NAME: ClassVar[str]
    BACKEND_TYPE: ClassVar[Optional[Type[Any]]]

    @property
    @abc.abstractmethod
    def backend(self) -> Optional[Any]:
        """ """

    @classmethod
    def from_backend(
        cls, backend: Any, *args: List[Any], **kwargs: Dict[str, Any]
    ) -> 'Cpu':
        raise NotImplementedError()

    ##########
    # cpu info

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """ """

    @property
    @abc.abstractmethod
    def bits(self) -> CpuBits:
        """
        The word size, no take account of the underlying hardware data/address
        bus size.
        """

    @property
    @abc.abstractmethod
    def endian(self) -> CpuEndian:
        """ """

    @property
    @abc.abstractmethod
    def variant(self) -> Optional[Any]:
        """ cpu model variant or other cpu specific metadata info """

    ################
    # cpu components
    @property
    @abc.abstractmethod
    def regs(self) -> CpuRegisters:
        """ """

    @property
    @abc.abstractmethod
    def mem(self) -> Memory:
        """ """

    @property
    def coproc(self) -> Any:
        raise NotImplementedError()

    ###########
    # execution

    @abc.abstractmethod
    def set_contention(self, tick_unit: TickUnit, tick_count: int) -> None:
        """
        A way to periodically interrupt the execution to perform custom
        processing like IO handling, interrupt trigger and more ...
        """

    @abc.abstractmethod
    def add_contention_callback(
        self, callback: CpuContentionCallback, first: bool = False
    ) -> None:
        """ """

    @property
    @abc.abstractmethod
    def is_running(self) -> bool:
        """ """

    @abc.abstractmethod
    def start(
        self,
        begin: Optional[int] = None,
        end: Optional[int] = None,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> None:
        """ """

    ##############
    # hook context

    @property
    @abc.abstractmethod
    def hook_context(self) -> Any:
        """ """

    @hook_context.setter
    @abc.abstractmethod
    def hook_context(self, context: Any) -> Any:
        """ """

    #############
    # hook memory

    @abc.abstractmethod
    def hook_mem_read(
        self, callback: MemoryReadAccessCallback, address: int
    ) -> None:
        """ """

    @abc.abstractmethod
    def hook_mem_read_range(
        self, callback: MemoryReadAccessCallback, begin: int, end: int
    ) -> None:
        """ """

    @abc.abstractmethod
    def hook_mem_read_all(self, callback: MemoryReadAccessCallback) -> None:
        """ """

    @abc.abstractmethod
    def hook_mem_write(
        self, callback: MemoryWriteAccessCallback, address: int
    ) -> None:
        """ """

    @abc.abstractmethod
    def hook_mem_write_range(
        self, callback: MemoryWriteAccessCallback, begin: int, end: int
    ) -> None:
        """ """

    @abc.abstractmethod
    def hook_mem_write_all(self, callback: MemoryWriteAccessCallback) -> None:
        """ """

    ###########
    # hook code

    @abc.abstractmethod
    def hook_code(self, callback: CodeAccessCallback, address: int) -> None:
        """ """

    @abc.abstractmethod
    def hook_code_range(
        self, callback: CodeAccessCallback, begin: int, end: int,
    ) -> None:
        """ """

    @abc.abstractmethod
    def hook_code_all(self, callback: CodeAccessCallback) -> None:
        """ """

    ################
    # hook exception

    @abc.abstractmethod
    def hook_cpu_exception(self, callback: CpuExceptionCallback) -> None:
        """ """


# ------------------------------------------------------------------------------


class CpuFactory(abc.ABC):

    @classmethod
    @abc.abstractmethod
    def get_backend_name(cls) -> str:
        """ """

    @classmethod
    @abc.abstractmethod
    def get_backend_type(cls) -> Any:
        """ """

    @classmethod
    @abc.abstractmethod
    def class_from_arch_id(cls, arch_id: str) -> Type[Cpu]:
        """ """

    @classmethod
    @abc.abstractmethod
    def class_from_backend_instance(
        cls, backend: Any, arch_id: str
    ) -> Type[Cpu]:
        """ """

    @classmethod
    @abc.abstractmethod
    def create(cls, arch_id: str, **arch_options: int) -> Cpu:
        """ """


# ------------------------------------------------------------------------------


class DeviceCpu(MachineDevice):

    ARCH_ID: ClassVar[str]  # Required for framework device identification

    ARCH_NAME: ClassVar[str]
    ARCH_BITS: ClassVar[CpuBits]
    ARCH_PC: ClassVar[str]
    ARCH_SP: ClassVar[str]

    def __init__(self, cpu: Cpu, dev_name: Optional[str] = None):
        self._dev_name = (
            f'cpu_{uuid.uuid4().hex}' if dev_name is None else dev_name
        )
        MachineDevice.__init__(self, self._dev_name)

        self._cpu = cpu
        self._cpu.hook_context = self
        self._cpu.mem.name = f'mem_{dev_name}'

        self._program_entry_point: Optional[int] = None
        self._program_exit_point: Optional[int] = None

        self._exec_tread: Union[threading.Thread, None] = None

    def is_little_endian(self) -> bool:
        if self.endian == CpuEndian.EL:
            return True
        return False

    def is_big_endian(self) -> bool:
        return not self.is_little_endian()

    @property
    def cpu(self) -> Cpu:
        return self._cpu

    @property
    def program_entry_point(self) -> Union[int, None]:
        return self._program_entry_point

    @program_entry_point.setter
    def program_entry_point(self, address: int) -> None:
        if not self.is_running:
            self._program_entry_point = address
        else:
            raise RuntimeError("can't set program entry during execution")

    @property
    def program_exit_point(self) -> Union[int, None]:
        return self._program_exit_point

    @program_exit_point.setter
    def program_exit_point(self, address: int) -> None:
        if not self.is_running:
            self._program_exit_point = address
        else:
            raise RuntimeError("can't set program end during execution")

    def start_in_thread(
        self,
        begin: Optional[int] = None,
        end: Optional[int] = None,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> threading.Thread:
        if not self.is_running and self._exec_tread is None:
            start_kwargs = {
                'begin': begin, 'end': end, 'count': count, 'timeout': timeout
            }
            self._exec_tread = threading.Thread(
                target=self.start, daemon=True, kwargs=start_kwargs
            )
            self._exec_tread.start()
            return self._exec_tread

        raise RuntimeError("can't execute in thread cpu is running")

    def join_exec_thread(self) -> None:
        if self.is_running and self._exec_tread is not None:
            self._exec_tread.join()

    # --------------------------------------------------------------------------
    # API forward
    #

    ##############
    # backend info

    @property
    def backend_name(self) -> str:
        return self._cpu.BACKEND_NAME

    @property
    def backend_type(self) -> Optional[Any]:
        return self._cpu.BACKEND_TYPE

    @property
    def backend(self) -> Optional[Any]:
        return self._cpu.backend

    ##########
    # cpu info

    @property
    def name(self) -> str:
        return self._cpu.name

    @property
    def bits(self) -> CpuBits:
        return self._cpu.bits

    @property
    def endian(self) -> CpuEndian:
        return self._cpu.endian

    @property
    def variant(self) -> Optional[Any]:
        return self._cpu.variant

    ################
    # cpu components

    @property
    def regs(self) -> CpuRegisters:
        return self._cpu.regs

    @property
    def mem(self) -> Memory:
        return self._cpu.mem

    @property
    def coproc(self) -> Any:
        return self._cpu.coproc

    ###########
    # execution

    def set_contention(self, tick_unit: TickUnit, tick_count: int) -> None:
        self._cpu.set_contention(tick_unit, tick_count)

    def add_contention_callback(
        self, callback: CpuContentionCallback, first: bool = False
    ) -> None:
        self._cpu.add_contention_callback(callback, first)

    @property
    def is_running(self) -> bool:
        return self._cpu.is_running

    @property
    def hook_context(self) -> Any:
        return self._cpu.hook_context

    @hook_context.setter
    def hook_context(self, value: Any) -> Any:
        self._cpu.hook_context = value

    def start(
        self,
        begin: Optional[int] = None,
        end: Optional[int] = None,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> None:

        if not self._cpu.is_running:
            begin_addr = self.regs.arch_pc if begin is None else begin
            log_str = f'execute code from {self.mem.addr_to_str(begin_addr)}'

            if end is not None:
                log_str += f', end to {self.mem.addr_to_str(end)}'

            self.log.info(log_str)

        self._cpu.start(begin, end, count, timeout)

        if not self._cpu.is_running:
            self.log.info(
                'end execution at %s', self.mem.addr_to_str(self.regs.arch_pc)
            )

    #############
    # hook memory

    def hook_mem_read(
        self, callback: MemoryReadAccessCallback, address: int
    ) -> None:
        return self._cpu.hook_mem_read(callback, address)

    def hook_mem_read_range(
        self, callback: MemoryReadAccessCallback, begin: int, end: int
    ) -> None:
        return self._cpu.hook_mem_read_range(callback, begin, end)

    def hook_mem_read_all(self, callback: MemoryReadAccessCallback) -> None:
        return self._cpu.hook_mem_read_all(callback)

    def hook_mem_write(
        self, callback: MemoryWriteAccessCallback, address: int
    ) -> None:
        return self._cpu.hook_mem_write(callback, address)

    def hook_mem_write_range(
        self, callback: MemoryWriteAccessCallback, begin: int, end: int
    ) -> None:
        return self._cpu.hook_mem_write_range(callback, begin, end)

    def hook_mem_write_all(self, callback: MemoryWriteAccessCallback) -> None:
        return self._cpu.hook_mem_write_all(callback)

    ###########
    # hook code

    def hook_code(self, callback: CodeAccessCallback, address: int) -> None:
        return self._cpu.hook_code(callback, address)

    def hook_code_range(
        self,
        callback: CodeAccessCallback,
        begin: int,
        end: int
    ) -> None:
        return self._cpu.hook_code_range(callback, begin, end)

    def hook_code_all(self, callback: CodeAccessCallback) -> None:
        return self._cpu.hook_code_all(callback)

    ################
    # hook exception

    def hook_cpu_exception(self, callback: CpuExceptionCallback) -> None:
        self._cpu.hook_cpu_exception(callback)

    #
    # API forward end
    # --------------------------------------------------------------------------
