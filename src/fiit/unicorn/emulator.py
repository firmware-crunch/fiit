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

from typing import List, Callable, Optional, cast, Dict, Any, Union
import logging
import threading
import mmap
import ctypes

import tabulate

import IPython
from IPython.core import magic

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_HOOK_BLOCK, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_HOOK_CODE)

from fiit.core.emulator_types import (
    MemoryRegion, AddressSpace, MemoryMappedFile, MemoryMappedBlob,
    DictMemoryRegion, DictMemoryMappedFile, DictMemoryMappedBlob, Architecture,
    ADDRESS_FORMAT)
from .arch_unicorn import ArchUnicorn
from fiit.core.shell import register_alias, EmulatorShell


EXEC_QUANTUM_UNIT_INSN = 1
EXEC_QUANTUM_UNIT_US = 2
EXEC_QUANTUM_UNIT_BLOCK = 3


class UnicornEmulator:
    def __init__(
        self,
        architecture: str,
        memory_mapping: List[DictMemoryRegion] = None,
        memory_mapped_files: List[DictMemoryMappedFile] = None,
        memory_mapped_blobs: List[DictMemoryMappedBlob] = None,
        host_memory_map=True,
        interrupt_callback: Callable = None,
        interrupt_type: int = 0,
        interrupt_tick_count: int = 0,
        entry_point: Optional[int] = None,
        end_address: Optional[int] = None
    ):
        self._logger = logging.getLogger('fiit.unicorn_emulator')

        ####################################################
        # Unicorn
        ####################################################
        self.uc = Uc(*ArchUnicorn.get_unicorn_arch_config(architecture))
        self.is_running = False
        self.entry_point = entry_point
        self.end_address = end_address

        ####################################################
        # Architecture
        ####################################################
        self.pc_code = ArchUnicorn.get_unicorn_pc_code(self.uc._arch)
        self.cpu_reg = ArchUnicorn.get_unicorn_registers(architecture)
        arch_str = ArchUnicorn.get_arch_str_by_uc(self.uc)
        cpu_name, endian, size, variant = arch_str.split(':')
        self.arch = Architecture(
            architecture, cpu_name, variant, endian, int(size))

        ####################################################
        # Interrupt
        ####################################################
        self._exec_quantum_unit = interrupt_type
        self._exec_quantum = interrupt_tick_count
        self._interrupt_callback = interrupt_callback or (lambda a, b, c: True)

        self._block_count = 0
        self._total_quantum_count = 0

        ####################################################
        # Address Space
        ####################################################
        self.host_memory_map = host_memory_map
        self.address_space = AddressSpace([])
        self.memory_mapped_blobs: List[MemoryMappedBlob] = []
        self.memory_mapped_files: List[MemoryMappedFile] = []

        if memory_mapping:
            for mm in memory_mapping:
                self.mem_map_create(**mm)

        if memory_mapped_files:
            for mmf in memory_mapped_files:
                self.mem_map_file(**mmf)

        if memory_mapped_blobs:
            for mmb in memory_mapped_blobs:
                self.mem_map_blob(**mmb)

    def _hook_block_interrupt(self, uc: Uc, address: int, size: int, data: dict):
        # Inconsistent register state during HOOK_BLOCK callback
        # https://github.com/unicorn-engine/unicorn/issues/1643
        if self._block_count == self._exec_quantum:
            self._block_count = 0
            self.uc.emu_stop()
            return
        self._block_count += 1

    def set_interrupts(
        self, interrupt_callback: Callable, exec_quantum_unit: int,
        exec_quantum: int
    ):
        self._exec_quantum_unit = exec_quantum_unit
        self._exec_quantum = exec_quantum
        self._interrupt_callback = interrupt_callback

    def start(self):
        if self.entry_point is not None and self.end_address is not None:
            self.start_at(self.entry_point, self.end_address)

    def start_at(self, begin: int, until: int):
        if self._exec_quantum_unit == EXEC_QUANTUM_UNIT_INSN:
            exec_timeout = 0
            exec_quantum = self._exec_quantum
        elif self._exec_quantum_unit == EXEC_QUANTUM_UNIT_US:
            exec_timeout = self._exec_quantum
            exec_quantum = 0
        elif self._exec_quantum_unit == EXEC_QUANTUM_UNIT_BLOCK:
            # Inconsistent register state during HOOK_BLOCK callback
            # https://github.com/unicorn-engine/unicorn/issues/1643
            exec_timeout = 0
            exec_quantum = 0
            self._block_count = 0
            self.uc.hook_add(
                UC_HOOK_BLOCK, self._hook_block_interrupt, begin=1, end=0)
        else:
            exec_timeout = 0
            exec_quantum = 0

        self._logger.info(f'Emulate from {begin:#x} to {until:#x}.')

        self.is_running = True
        begin_at = begin

        while begin_at != until:
            try:
                self.uc.emu_start(begin_at, until, exec_timeout, exec_quantum)
            except Exception as uc_error:
                self._logger.info(str(uc_error))
                self.is_running = False
                raise uc_error

            self._total_quantum_count += exec_quantum
            self._interrupt_callback(self.uc, exec_quantum,
                                     self._total_quantum_count)
            begin_at = self.uc.reg_read(self.pc_code)

        self.is_running = False
        self._logger.info('Emulation terminated')

    def stop(self):
        self.uc.emu_stop()
        self.is_running = False

    @staticmethod
    def _get_uc_protection_from_str(perm: str) -> int:
        protection = 0
        if 'r' in perm:
            protection |= UC_PROT_READ
        if 'w' in perm:
            protection |= UC_PROT_WRITE
        if 'x' in perm:
            protection |= UC_PROT_EXEC

        return protection

    def _create_mem_region(
        self, name: str, perm: str, base_address: int, size: int
    ) -> MemoryRegion:
        protection = self._get_uc_protection_from_str(perm)
        self.uc.mem_map(base_address, size, protection)
        self.uc.mem_write(base_address, size * b'\x00')
        mma = MemoryRegion(name, base_address, size, perm)
        self.address_space.memory_regions.append(mma)
        return mma

    def _create_mem_region_host(
        self, name: str, perm: str, base_address: int, size: int
    ) -> MemoryRegion:
        protection = self._get_uc_protection_from_str(perm)

        host_mem_area = mmap.mmap(
            -1, size, flags=mmap.MAP_PRIVATE,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        host_base_address = ctypes.addressof(
            ctypes.c_ubyte.from_buffer(host_mem_area))

        self.uc.mem_map_ptr(
            base_address, size, protection, host_base_address)
        self.uc.mem_write(base_address, size * b'\x00')
        mma = MemoryRegion(name, base_address, size, perm,
                           host_base_address, host_mem_area)
        self.address_space.memory_regions.append(mma)
        return mma

    def mem_map_create(
        self, name: str, perm: str, base_address: int, size: int
    ) -> MemoryRegion:
        if self.host_memory_map:
            return self._create_mem_region_host(name, perm, base_address, size)
        else:
            return self._create_mem_region(name, perm, base_address, size)

    def mem_map_blob(self, blob: bytes, loading_address):
        self.uc.mem_write(loading_address, bytes(blob))
        self.memory_mapped_blobs.append(MemoryMappedBlob(blob, loading_address))

    def mem_map_file(
        self, file_path: str, file_offset: int, loading_size: int,
        loading_address: int
    ):
        with open(file_path, mode='rb') as f:
            f.seek(file_offset)
            self.uc.mem_write(loading_address, f.read(loading_size))
        mmf = MemoryMappedFile(
            file_path, file_offset, loading_size, loading_address)
        self.memory_mapped_files.append(mmf)

    def add_hook_code(
        self, callback: Callable[['UnicornEmulator', int, int, Any], None],
        begin: int, end: int = None, user_data: Any = None
    ):
        if end is None:
            end = begin

        def _wrap_uc_hook_code(uc: Uc, address: int, size: int, data: Any):
            callback(self, address, size, user_data)

        self.uc.hook_add(UC_HOOK_CODE, _wrap_uc_hook_code, begin=begin, end=end)


@IPython.core.magic.magics_class
class UnicornEmulatorFrontend(IPython.core.magic.Magics):
    # FIXME: monitor unicorn issue statu before implement emu_stop command
    # Uc.emu_stop() doesn't work in a hook if PC is updated
    # https://github.com/unicorn-engine/unicorn/issues/1579

    def __init__(self, emu: UnicornEmulator, emu_shell: EmulatorShell):
        self.emu = emu
        self.emu_shell = emu_shell
        self.emu_tread: Union[threading.Thread, None] = None
        self._addr_f = ADDRESS_FORMAT[self.emu.arch.mem_bit_size]

        self.emu_shell.set_emulation_thread(self.emu.start)

        super(UnicornEmulatorFrontend, self).__init__(shell=emu_shell.shell)
        emu_shell.register_magics(self)
        emu_shell.register_aliases(self)

    def _mem_map_format(self, memory_mapping: AddressSpace) -> str:
        headers = ['start', 'end', 'size', 'name']
        table = [[self._addr_f(mm.base_address),
                  self._addr_f((mm.base_address + mm.size) - 1),
                  self._addr_f(mm.size),
                  mm.name]
                 for mm in memory_mapping]
        return tabulate.tabulate(table, headers, tablefmt="simple")

    @register_alias('mm')
    @IPython.core.magic.line_magic
    def memory_mapping(self, line: str):
        """Print memory mapping."""
        print(self._mem_map_format(self.emu.address_space))

    @register_alias('es')
    @IPython.core.magic.line_magic
    def emu_start(self, line: str):
        """Start emulation."""
        if not self.emu.is_running:
            self.emu_shell.start_emulation_thread()
        else:
            print('Emulator is already running.')
