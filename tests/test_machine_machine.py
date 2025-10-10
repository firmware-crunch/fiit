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

from typing import Any, Optional

import pytest

from fiit.machine import (
    Machine, Cpu, MachineDevice, DeviceCpu, TickUnit, Memory, CpuEndian,
    CpuBits, CpuRegisters, CpuExceptionCallback, CodeAccessCallback,
    CpuContentionCallback, MemoryWriteAccessCallback, MemoryReadAccessCallback
)

# ==============================================================================


# ------------------------------------------------------------------------------
# fixtures

class CustomCpu(Cpu):
    @property
    def backend(self) -> Optional[Any]:
        pass

    @property
    def name(self) -> str:
        return ''

    @property
    def bits(self) -> CpuBits:
        pass

    @property
    def endian(self) -> CpuEndian:
        pass

    @property
    def variant(self) -> Optional[Any]:
        pass

    @property
    def regs(self) -> CpuRegisters:
        pass

    @property
    def mem(self) -> Memory:
        class mem():
            name = 'ram0'
        return mem

    def set_contention(self, tick_unit: TickUnit, tick_count: int) -> None:
        pass

    def add_contention_callback(self, callback: CpuContentionCallback,
                                first: bool = False) -> None:
        pass

    @property
    def is_running(self) -> bool:
        pass

    def start(self, begin: Optional[int] = None, end: Optional[int] = None,
              count: Optional[int] = None,
              timeout: Optional[int] = None) -> None:
        pass

    @property
    def hook_context(self) -> Any:
        return None

    @hook_context.setter
    def hook_context(self, value) -> Any:
        pass

    def hook_code(self, callback: CodeAccessCallback, address: int) -> None:
        pass

    def hook_code_range(self, callback: CodeAccessCallback, begin: int,
                        end: int) -> None:
        pass

    def hook_code_all(self, callback: CodeAccessCallback) -> None:
        pass

    def hook_cpu_exception(self, callback: CpuExceptionCallback) -> None:
        pass

    def hook_mem_read(self, callback: MemoryReadAccessCallback,
                      address: int) -> None:
        pass

    def hook_mem_read_range(self, callback: MemoryReadAccessCallback,
                            begin: int, end: int) -> None:
        pass

    def hook_mem_read_all(self, callback: MemoryReadAccessCallback) -> None:
        pass

    def hook_mem_write(self, callback: MemoryWriteAccessCallback,
                       address: int) -> None:
        pass

    def hook_mem_write_range(self, callback: MemoryWriteAccessCallback,
                             begin: int, end: int) -> None:
        pass

    def hook_mem_write_all(self, callback: MemoryWriteAccessCallback) -> None:
        pass


class CustomCpuDevice(DeviceCpu):
    def __init__(self):
        DeviceCpu.__init__(self, CustomCpu(), 'cpu0')


class CustomDevice(MachineDevice):
    def __init__(self):
        MachineDevice.__init__(self, 'dev1')


# ------------------------------------------------------------------------------


def test_machine_get_devices():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())
    assert len(machine.devices) == 2
    assert machine.get_device('cpu0').dev_name == 'cpu0'
    assert machine.get_device('dev1').dev_name == 'dev1'


def test_machine_get_cpu_devices():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())
    assert len(machine.cpu_devices) == 1
    assert machine.cpu_devices[0].dev_name == 'cpu0'


def test_machine_get_device():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())
    assert machine.get_device('dev1').dev_name == 'dev1'


def test_machine_get_device_not_exist():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())

    with pytest.raises(ValueError) as exc_info:
        machine.get_device('device_not_exist')


def test_machine_get_device_cpu():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())
    assert machine.get_device_cpu('cpu0').dev_name == 'cpu0'


def test_machine_get_device_cpu_not_exist():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())

    with pytest.raises(ValueError) as exc_info:
        machine.get_device_cpu('cpu_not_exist')


def test_machine_add_device_with_same_name_error():
    machine = Machine()
    machine.add_device(CustomCpuDevice())
    machine.add_device(CustomDevice())

    class ConflictCustomDevice(MachineDevice):
        def __init__(self):
            MachineDevice.__init__(self, 'dev1')

    with pytest.raises(ValueError) as exc_info:
        machine.add_device(ConflictCustomDevice())
