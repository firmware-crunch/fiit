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
    'CpuUnicorn'
]

import logging
from typing import Optional, Callable, Any, List

import unicorn
from unicorn import unicorn_const

from fiit.machine import (
    CpuContentionCallback, TickUnit, CpuExceptionCallback, CodeAccessCallback,
    MemoryReadAccessCallback, MemoryWriteAccessCallback, CpuEndian, CpuBits, Cpu
)

from .memory import MemoryUnicorn
from .registers import CpuRegistersUnicorn

# ==============================================================================


# arg1: DeviceCpu
# arg2: Address
CodeBlockAccessCallback = Callable[[Any, int], None]


class CpuUnicorn(Cpu):
    """
    Wrapper around Unicorn cpu emulator backend

    Notes:
        - Check unicorn issue #1579 before implement stop/halt execution
          Uc.emu_stop() doesn't work in a hook if PC is updated
          https://github.com/unicorn-engine/unicorn/issues/1579
    """

    @staticmethod
    def endian_from_uc(uc: unicorn.Uc) -> CpuEndian:
        # Warning only check with big endian because little == 0
        if uc._mode & unicorn_const.UC_MODE_BIG_ENDIAN:
            return CpuEndian.EB
        return CpuEndian.EL

    @staticmethod
    def check_uc_model(uc: unicorn.Uc, model: int) -> bool:
        if uc._mode & model:
            return True
        return False

    @classmethod
    def uc_is_compatible(cls, uc: unicorn.Uc) -> bool:
        raise NotImplementedError()

    def __init__(
        self, uc: unicorn.Uc, regs: CpuRegistersUnicorn, mem: MemoryUnicorn
    ):
        Cpu.__init__(self)
        self._uc = uc
        self._regs = regs
        self._mem = mem

        self._contention_callbacks: List[CpuContentionCallback] = []
        self._contention_tick_unit: Optional[TickUnit] = None
        self._contention_tick_count: Optional[int] = None
        self._contention_block_handler: Optional[int] = None

        self._block_count = 0
        self._is_running = False
        self._hook_context = self
        self._logger = logging.getLogger(f'fiit.{self.__class__.__name__}')

    ##############
    # backend info

    BACKEND_NAME = 'unicorn'
    BACKEND_TYPE = unicorn.Uc

    @property
    def backend(self) -> unicorn.Uc:
        return self._uc

    ##########
    # cpu info

    @property
    def name(self) -> str:
        raise NotImplementedError()

    @property
    def bits(self) -> CpuBits:
        raise NotImplementedError()

    @property
    def endian(self) -> CpuEndian:
        raise NotImplementedError()

    @property
    def variant(self) -> Optional[Any]:
        raise NotImplementedError()

    ################
    # cpu components
    @property
    def regs(self) -> CpuRegistersUnicorn:
        return self._regs

    @property
    def mem(self) -> MemoryUnicorn:
        return self._mem

    ###########
    # execution

    def _hook_block_interrupt(
        self, uc: unicorn.Uc, address: int, size: int, data: Any
    ) -> None:
        # Inconsistent register state during HOOK_BLOCK callback
        # https://github.com/unicorn-engine/unicorn/issues/1643
        if self._block_count == self._contention_tick_count:
            self._block_count = 0
            self._uc.emu_stop()
            return

        self._block_count += 1

    def set_contention(self, tick_unit: TickUnit, tick_count: int) -> None:
        if self._is_running:
            raise RuntimeError("can't set contention loop, cpu is running")

        self._contention_tick_unit = tick_unit
        self._contention_tick_count = tick_count

        if (tick_unit == TickUnit.BLOCK
                and self._contention_block_handler is None):
            self._contention_block_handler = self._uc.hook_add(
                unicorn_const.UC_HOOK_BLOCK, self._hook_block_interrupt
            )
        elif (tick_unit != TickUnit.BLOCK
              and self._contention_block_handler is not None):
            self._uc.hook_del(self._contention_block_handler)
            self._contention_block_handler = None

    def add_contention_callback(
        self, callback: CpuContentionCallback, first: bool = False
    ) -> None:
        if first:
            self._contention_callbacks.insert(0, callback)
        else:
            self._contention_callbacks.append(callback)

    def _contention(self):
        for callback in self._contention_callbacks:
            callback(self._hook_context)

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(
        self,
        begin: Optional[int] = None,
        end: Optional[int] = None,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> None:

        is_nested_call = self._is_running
        uc_count = 0 if count is None else count
        uc_timeout = 0 if timeout is None else timeout
        uc_begin = self.regs.arch_pc if begin is None else begin
        uc_end = self.mem.max_address if end is None else end

        if (self._contention_tick_unit is not None
                # avoid contention count shift
                and (count is None or timeout is None)):

            if self._contention_tick_unit == TickUnit.INST:
                assert self._contention_tick_count is not None
                uc_timeout = 0
                uc_count = self._contention_tick_count
            elif self._contention_tick_unit == TickUnit.TIME_US:
                assert self._contention_tick_count is not None
                uc_timeout = self._contention_tick_count
                uc_count = 0
            elif self._contention_tick_unit == TickUnit.BLOCK:
                uc_timeout = 0
                uc_count = 0
                self._block_count = 0
            else:
                raise NotImplementedError(
                    f'interrupt tick unit not implemented: '
                    f'{str(self._contention_tick_unit)}'
                )

        try:
            if not self._is_running:
                self._is_running = True

            if is_nested_call:
                # Remove the current block in Qemu TCG cache
                # Avoid Unicorn segfault for nested emu_start() call.
                # See workaround for nested call in issue #1487
                #     Can "uc_emu_start" support nested call ?
                #     https://github.com/unicorn-engine/unicorn/issues/1487
                # TODO: Remove this workaround in future unicorn upgrade
                #     fixed in 247ffbe, "Support nested uc_emu_start calls"
                #     https://github.com/unicorn-engine/unicorn/commit/
                #     247ffbe0e8148a582f3d752f39dc4af84d472118
                pc = self.regs.arch_pc
                self._uc.ctl_remove_cache(pc, pc + 8)

            # main execution loop
            while uc_begin != uc_end:
                self._uc.emu_start(uc_begin, uc_end, uc_timeout, uc_count)

                if (self.regs.arch_pc != uc_end
                        and not is_nested_call  # avoid contention count shift
                        and self._contention_tick_unit is not None):
                    self._contention()

                uc_begin = self.regs.arch_pc

        except unicorn.unicorn.UcError as exc:
            self._logger.info('unicorn cpu error : %s', str(exc))
            raise exc

        finally:
            if not is_nested_call:
                self._is_running = False

    ##############
    # hook context

    @property
    def hook_context(self) -> Any:
        return self._hook_context

    @hook_context.setter
    def hook_context(self, context: Any) -> Any:
        self._hook_context = context

    #############
    # hook memory

    def _hook_mem_read(
        self,
        callback: MemoryReadAccessCallback,
        begin: int,
        end: int
    ) -> None:
        def _hook(
            _: unicorn.Uc, access: int, address: int, size: int, value: int,
            data: Any
        ) -> None:
            callback(self._hook_context, address, size)

        self._uc.hook_add(
            unicorn_const.UC_HOOK_MEM_READ, _hook, begin=begin, end=end
        )

    def hook_mem_read(
        self, callback: MemoryReadAccessCallback, address: int
    ) -> None:
        self._hook_mem_read(callback, address, address)

    def hook_mem_read_range(
        self, callback: MemoryReadAccessCallback, begin: int, end: int
    ) -> None:
        assert end > begin
        self._hook_mem_read(callback, begin, end)

    def hook_mem_read_all(self, callback: MemoryReadAccessCallback) -> None:
        self._hook_mem_read(callback, 1, 0)

    def _hook_mem_write(
        self,
        callback: MemoryWriteAccessCallback,
        begin: int,
        end: int
    ) -> None:
        def _hook(
            _: unicorn.Uc, access: int, address: int, size: int, value: int,
            data: Any
        ) -> None:
            callback(self._hook_context, address, size, value)

        self._uc.hook_add(
            unicorn_const.UC_HOOK_MEM_WRITE, _hook, begin=begin, end=end
        )

    def hook_mem_write(
        self, callback: MemoryWriteAccessCallback, address: int
    ) -> None:
        self._hook_mem_write(callback, address, address)

    def hook_mem_write_range(
        self, callback: MemoryWriteAccessCallback, begin: int, end: int
    ) -> None:
        assert end > begin
        self._hook_mem_write(callback, begin, end)

    def hook_mem_write_all(self, callback: MemoryWriteAccessCallback) -> None:
        self._hook_mem_write(callback, 1, 0)

    ###########
    # hook code

    def _hook_code(
        self, callback: CodeAccessCallback, begin: int, end: int
    ) -> None:
        def _hook(_: unicorn.Uc, address: int, size: int, data: Any) -> None:
            callback(self._hook_context, address)

        self._uc.hook_add(
            unicorn_const.UC_HOOK_CODE, _hook, begin=begin, end=end
        )

    def hook_code(self, callback: CodeAccessCallback, address: int) -> None:
        self._hook_code(callback, address, address)

    def hook_code_range(
        self, callback: CodeAccessCallback, begin: int, end: int
    ) -> None:
        assert end > begin
        self._hook_code(callback, begin, end)

    def hook_code_all(self, callback: CodeAccessCallback) -> None:
        self._hook_code(callback, 1, 0)

    ################
    # hook exception

    def hook_cpu_exception(
        self, callback: CpuExceptionCallback, begin: int = 1, end: int = 0
    ) -> None:
        def _hook(_: unicorn.Uc, interrupt_number: int, size: int) -> None:
            callback(self._hook_context, interrupt_number)

        self._uc.hook_add(
            unicorn_const.UC_HOOK_INTR, _hook, begin=begin, end=end
        )

    ############
    # hook block
    # specific to Qemu TCG emulation interface

    def _hook_block(
        self, callback: CodeBlockAccessCallback, begin: int, end: int
    ) -> None:
        def _hook(_: unicorn.Uc, address: int, size: int, data: Any) -> None:
            callback(self._hook_context, address)

        self._uc.hook_add(
            unicorn_const.UC_HOOK_BLOCK, _hook, begin=begin, end=end
        )

    def hook_block_all(self, callback: CodeBlockAccessCallback) -> None:
        self._hook_block(callback, 1, 0)

    def hook_block(
        self, callback: CodeBlockAccessCallback, address: int
    ) -> None:
        self._hook_block(callback, address, address)

    def hook_block_range(
        self, callback: CodeBlockAccessCallback, begin: int, end: int
    ) -> None:
        assert end > begin
        self._hook_block(callback, begin, end)
