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

import functools
from typing import Any, Optional

import pytest
from unittest.mock import Mock, patch, PropertyMock

from fiit.machine import (
    CpuEndian, CpuBits, Cpu, TickUnit, DeviceCpu, Memory, CpuRegisters,
    CpuExceptionCallback, CodeAccessCallback, CpuContentionCallback,
    MemoryWriteAccessCallback, MemoryReadAccessCallback
)

from .fixtures.fixture_utils import MinimalMemory

# ==============================================================================


# ------------------------------------------------------------------------------
# fixtures

class CustomCpuBackend:
    pass


class CustomCpuRegisters(CpuRegisters):
    def __init__(self):
        CpuRegisters.__init__(
            self,
            ['pc', 'sp', 'r0'],
            'pc', 'sp',
            ['_pc', '_sp', '_r0', '_r1', '_mapping']
        )
        self._pc = 0
        self._sp = 0
        self._r0 = 0
        self._r1 = 0
        self._mapping = {
            'pc': self._pc, 'sp': self._sp, 'r0': self._r0, 'r1': self._r1
        }

    def read(self, register: str) -> int:
        if register in self._mapping and register in self._register_names:
            return self._mapping[register]
        else:
            raise ValueError('invalid register name')

    def write(self, register: str, value: int) -> None:
        if register in self._mapping and register in self._register_names:
            self._mapping[register] = value
        else:
            raise ValueError('invalid register name')


class CustomCpu(Cpu):
    BACKEND_NAME = 'world industry'
    BACKEND_TYPE = CustomCpuBackend

    ARCH_ID = 'world32'
    ARCH_NAME = 'world'
    ARCH_BITS = CpuBits.BITS_32
    ARCH_PC = 'pc'
    ARCH_SP = 'sp'

    def __init__(self, endian: str = 'el'):
        self._backend = CustomCpuBackend()
        self._endian = CpuEndian.from_str(endian)
        self._regs = CustomCpuRegisters()
        self._mem = MinimalMemory()
        self._is_running = False

    @property
    def backend(self) -> Optional[Any]:
        return self._backend

    @property
    def name(self) -> str:
        return self.ARCH_NAME

    @property
    def bits(self) -> CpuBits:
        return self.ARCH_BITS

    @property
    def endian(self) -> CpuEndian:
        return self._endian

    @property
    def variant(self) -> Optional[Any]:
        return 'CoreGen24'

    @property
    def regs(self) -> CpuRegisters:
        return self._regs

    @property
    def mem(self) -> Memory:
        return self._mem

    def set_contention(self, tick_unit: TickUnit, tick_count: int) -> None:
        pass

    def add_contention_callback(
        self, callback: CpuContentionCallback, first: bool = False
    ) -> None:
        pass

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(
        self, begin: Optional[int] = None, end: Optional[int] = None,
        count: Optional[int] = None, timeout: Optional[int] = None
    ) -> None:
        self._is_running = True

    @property
    def hook_context(self) -> Any:
        return None

    @hook_context.setter
    def hook_context(self, value) -> None:
        pass

    def hook_mem_read(
        self, callback: MemoryReadAccessCallback, address: int
    ) -> None:
        pass

    def hook_mem_read_range(
        self, callback: MemoryReadAccessCallback, begin: int, end: int
    ) -> None:
        pass

    def hook_mem_read_all(self, callback: MemoryReadAccessCallback) -> None:
        pass

    def hook_mem_write(
        self, callback: MemoryWriteAccessCallback, address: int
    ) -> None:
        pass

    def hook_mem_write_range(
        self, callback: MemoryWriteAccessCallback, begin: int, end: int
    ) -> None:
        pass

    def hook_mem_write_all(self, callback: MemoryWriteAccessCallback) -> None:
        pass

    def hook_code(self, callback: CodeAccessCallback, address: int) -> None:
        pass

    def hook_code_range(
        self, callback: CodeAccessCallback, begin: int, end: int
    ) -> None:
        pass

    def hook_code_all(self, callback: CodeAccessCallback) -> None:
        pass

    def hook_cpu_exception(self, callback: CpuExceptionCallback) -> None:
        pass


class CustomDeviceCpu(DeviceCpu):
    pass

# ------------------------------------------------------------------------------


def _assert_prop_get_called(
    patched: Any, patched_prop: str, obj: Any, prop_name: str
) -> None:
    with patch.object(patched,
                      patched_prop,
                      new_callable=PropertyMock,
                      side_effect=Mock()) as m_fun:
        getattr(obj, prop_name)
        m_fun.assert_called_once()


def _assert_prop_set_called(
    patched: Any, patched_prop: str, obj: Any, prop_name: str, value: Any
) -> None:
    patched_prop_obj = getattr(patched.__class__, patched_prop)
    wrap = functools.partial(patched_prop_obj.__set__, patched)

    with patch.object(patched.__class__,
                      patched_prop,
                      new_callable=PropertyMock,
                      wraps=wrap) as prop_mock:
        setattr(obj, prop_name, value)
        prop_mock.assert_called_once()


def _assert_called(
    patched: Any, patched_fun: str, obj: Any, fun_name: str, *args, **kwargs
) -> None:
    with patch.object(patched, patched_fun, side_effect=Mock()) as m_fun:
        getattr(obj, fun_name)(*args, **kwargs)
        m_fun.assert_called_once()


def test_device_cpu_api_forward():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')

    assert dev.cpu == cpu
    assert dev.backend_name == cpu.BACKEND_NAME
    assert dev.backend_type == cpu.BACKEND_TYPE
    _assert_prop_get_called(CustomCpu, 'backend', dev, 'backend')
    _assert_prop_get_called(CustomCpu, 'name', dev, 'name')
    _assert_prop_get_called(CustomCpu, 'bits', dev, 'bits')
    _assert_prop_get_called(CustomCpu, 'endian', dev, 'endian')
    _assert_prop_get_called(CustomCpu, 'variant', dev, 'variant')
    _assert_prop_get_called(CustomCpu, 'regs', dev, 'regs')
    _assert_prop_get_called(CustomCpu, 'mem', dev, 'mem')
    _assert_called(CustomCpu, 'set_contention', dev, 'set_contention', *[None, None])
    _assert_called(CustomCpu, 'add_contention_callback', dev, 'add_contention_callback', *[None])
    _assert_prop_get_called(CustomCpu, 'is_running', dev, 'is_running')
    _assert_prop_get_called(CustomCpu, 'hook_context', dev, 'hook_context')
    _assert_prop_set_called(cpu, 'hook_context', dev, 'hook_context', None)
    _assert_called(CustomCpu, 'start', dev, 'start', end=0xffffffff)
    _assert_called(CustomCpu, 'hook_mem_read', dev, 'hook_mem_read', *[None, None])
    _assert_called(CustomCpu, 'hook_mem_read_range', dev, 'hook_mem_read_range', *[None, None, None])
    _assert_called(CustomCpu, 'hook_mem_read_all', dev, 'hook_mem_read_all', *[None])
    _assert_called(CustomCpu, 'hook_mem_write', dev, 'hook_mem_write', *[None, None])
    _assert_called(CustomCpu, 'hook_mem_write_range', dev, 'hook_mem_write_range', *[None, None, None])
    _assert_called(CustomCpu, 'hook_mem_write_all', dev, 'hook_mem_write_all', *[None])
    _assert_called(CustomCpu, 'hook_code', dev, 'hook_code', *[None, None])
    _assert_called(CustomCpu, 'hook_code_range', dev, 'hook_code_range', *[None, None, None])
    _assert_called(CustomCpu, 'hook_code_all', dev, 'hook_code_all', *[None])
    _assert_called(CustomCpu, 'hook_cpu_exception', dev, 'hook_cpu_exception', *[None])

    with pytest.raises(NotImplementedError):
        cpr = dev.coproc

    with pytest.raises(NotImplementedError):
        backend = cpu.from_backend(None)


def test_device_cpu_endian_little():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    assert dev.is_little_endian()
    assert not dev.is_big_endian()


def test_device_cpu_endian_big():
    cpu = CustomCpu(endian='big')
    dev = CustomDeviceCpu(cpu, 'cpu0')
    assert not dev.is_little_endian()
    assert dev.is_big_endian()


def test_device_cpu_set_program_entry_point():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.program_entry_point = 0x0
    assert dev.program_entry_point == 0x0


def test_device_cpu_set_program_entry_point_error():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.start()
    with pytest.raises(RuntimeError) as exc_info:
        dev.program_entry_point = 0x0


def test_device_cpu_set_program_exit_point():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.program_exit_point = 0xffffffff
    assert dev.program_exit_point == 0xffffffff


def test_device_cpu_set_program_exit_point_error():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.start()
    with pytest.raises(RuntimeError) as exc_info:
        dev.program_exit_point = 0xffffffff


def test_device_cpu_exec_in_thread():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.start_in_thread()


def test_device_cpu_exec_in_thread_error():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.start_in_thread()

    with pytest.raises(RuntimeError) as exc_info:
        dev.start_in_thread()


def test_device_cpu_join_exec_thread():
    cpu = CustomCpu()
    dev = CustomDeviceCpu(cpu, 'cpu0')
    dev.start_in_thread()
    dev.join_exec_thread()
