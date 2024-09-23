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

from typing import Deque
from collections import deque
import logging

from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.unicorn_const import UC_HOOK_BLOCK, UC_HOOK_CODE

from .arm_generic_core import UnicornArmGenericCore
from .pl190 import UnicornArmPl190


class UnicornPl190RoundRobinIntGenerator:
    @staticmethod
    def _get_activated_bit_pos(value: int) -> Deque[int]:
        bits = deque()
        for i in range(0, 32):
            if value & (1 << i):
                bits.append(i)
        return bits

    def __init__(self, cpu: UnicornArmGenericCore, pl190: UnicornArmPl190):
        self._cpu = cpu
        self._pl190 = pl190
        self._int_enabled = set()
        self._int_queue = deque()

        self._before_callback = list()
        self._interrupt_mask = set()

        self._standalone_quantum_slice_count = 0
        self._exec_quantum = 0
        self._total_quantum_count = 0

        self._hook_handle_irq_producer = None

        self._logger = logging.getLogger(
            'fiit.unicorn_pl190_round_robin_int_generator')

    def interrupt_mask(self, int_number: int):
        self._interrupt_mask.add(int_number)

    def interrupt_unmask(self, int_number: int):
        self._interrupt_mask.remove(int_number)

    def add_callback_before_int_trigger(self, callback):
        self._before_callback.append(callback)

    def gen_interrupt(
        self, uc: Uc, exec_quantum:int, quantum_count: int
    ) -> bool:
        """
        Return True if an interrupt will be processed else False.
        """
        if self._cpu.is_irq_mode() or self._cpu.is_fiq_mode():
            return False

        self._total_quantum_count += exec_quantum

        for before_callback in self._before_callback:
            before_callback(self, uc, self._total_quantum_count)

        cur_int_enabled = self._get_activated_bit_pos(self._pl190._vicintenable)

        if len(self._int_queue) == 0:
            # reload interrupts with fresh programmed interrupts
            self._int_enabled = set(cur_int_enabled)
            self._int_queue = cur_int_enabled
        else:
            # if interrupt are pending, Check if new interrupt are programmed
            for prog_int in cur_int_enabled:
                if prog_int not in self._int_queue:
                    self._int_queue.append(prog_int)
            # if interrupt are pending, Check if previous programmed interrupt
            # has been deactivated
            for queued_int in self._int_queue:
                if queued_int not in cur_int_enabled:
                    self._int_queue.remove(queued_int)

        if len(self._int_queue) == 0:
            return False

        interrupt = self._int_queue.popleft()

        if interrupt in self._interrupt_mask:
            return False

        self._logger.debug(f'trigger interrupt {interrupt}')
        self._pl190.set_interrupt_source(1 << interrupt)
        self._pl190.update()
        return self._cpu.is_irq_mode() or self._cpu.is_fiq_mode()

    # Standalone interrupt generator must be review since interrupt logic in
    # hook, crash the emulator due to PC update.
    #
    # def _standalone_interrupt_generator_callback(
    #     self, uc: Uc, address: int, size: int, data: dict
    # ):
    #     if self._standalone_quantum_slice_count == self._exec_quantum:
    #         self._total_quantum_count += self._standalone_quantum_slice_count
    #         self._standalone_quantum_slice_count = 0
    #         if self.gen_interrupt(uc, address, self._total_quantum_count):
    #             return
    #     self._standalone_quantum_slice_count += 1
    #
    # def install_standalone_round_robin_loop(
    #     self, exec_quantum_unit: str, exec_quantum: int
    # ):
    #     self._exec_quantum = exec_quantum
    #     self._cpu.uc.hook_add(
    #         UC_HOOK_BLOCK if exec_quantum_unit == 'block' else UC_HOOK_CODE,
    #         self._standalone_interrupt_generator_callback)
