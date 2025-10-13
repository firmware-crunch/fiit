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

from typing import List, Tuple
import logging

from cmsis_svd.model import SVDRegister, SVDField

from fiit.machine import Memory, DeviceCpu

from .reg import get_field
from .interceptor import MonitoredMemory


class MmioLogger:
    def __init__(
        self,
        mem_bit_size: int,
        monitored_memory: MonitoredMemory,
        logger_name: str,
        log_show_field_states: bool = True,
    ):
        self._py_log = logging.getLogger(logger_name)
        self._log_show_field_states = log_show_field_states

        reg_bit_size = mem_bit_size
        self._mmio_addr_f = Memory.get_addr_fmt(reg_bit_size)
        self._mem_addr_f = Memory.get_addr_fmt(reg_bit_size)
        self._monitored_memory = monitored_memory

    def _format_mem_area_name(self, address: int) -> str:
        for mem_range in self._monitored_memory.ranges:
            if mem_range.begin <= address <= mem_range.end:
                return mem_range.name
        return '-'

    def format_read_access(self, address: int, pc: int, state: int) -> str:
        return (
            f'{self._format_mem_area_name(address)}'
            f' : access read at {self._mem_addr_f(address)}'
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}')

    def log_read_access(self, address: int, pc: int, state: int):
        self._py_log.info(self.format_read_access(address, pc, state))

    def format_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ) -> str:
        return (
            f'{self._format_mem_area_name(address)}'
            f' : access write at {self._mem_addr_f(address)}'
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}'
            f' -> {self._mmio_addr_f(new_state)}')

    def log_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ):
        self._py_log.info(self.format_write_access(address, pc, state, new_state))

    @staticmethod
    def _get_info_field_state(
        state: int, reg: SVDRegister
    ) -> List[Tuple[SVDField, int, str, str]]:
        field_states_info = []

        for field in reg.fields:
            field_state = get_field(state, field.bit_offset, field.bit_width)
            state_name = ''
            state_desc = ''

            if (isinstance(field, SVDField)
                    and field.enumerated_values is not None):
                for enum_values in field.enumerated_values:
                    for enum_val in enum_values.enumerated_values:
                        if enum_val.value == field_state:
                            state_name = enum_val.name
                            state_desc = enum_val.description

            field_states_info.append(
                (field, field_state, state_name, state_desc)
            )

        return field_states_info

    @classmethod
    def _get_info_field_states_read(cls, state: int, reg: SVDRegister) -> str:
        field_states_info = []
        state_info = cls._get_info_field_state(state, reg)

        for field, field_state, state_name, state_desc in state_info:
            field_states_info.append(
                f'{reg.parent.name or "-"}'
                f' : {reg.name or "-"} '
                f' : [{field.bit_offset}'
                f':{field.bit_offset + field.bit_width - 1}]'
                f' : {field.name or "-"} ({field.description or "-"})'
                f' : {state_name or "-"} ({state_desc or "-"})'
                f' : {field_state:#x}')

        return '\n'.join(field_states_info)

    @classmethod
    def _get_info_field_states_write(
        cls, state: int, new_state: int, reg: SVDRegister
    ) -> str:
        field_states_info = []
        state_info = cls._get_info_field_state(new_state, reg)

        for field, field_state, state_name, state_desc in state_info:
            previous_state = get_field(state, field.bit_offset, field.bit_width)

            log_value_field = (
                f'{previous_state:#x} -> {field_state:#x} (field value change)'
                if previous_state != field_state
                else f'{field_state:#x}')

            field_states_info.append(
                f'{reg.parent.name or "-"}'
                f' : {reg.name or "-"} '
                f' : [{field.bit_offset}'
                f':{field.bit_offset + field.bit_width - 1}]'
                f' : {field.name or "-"} ({field.description or "-"})'
                f' : {state_name or "-"} ({state_desc or "-"})'
                f' : {log_value_field}')

        return '\n'.join(field_states_info)

    def format_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ) -> str:
        state_info = (f'\n{self._get_info_field_states_read(state, reg)}'
                      if self._log_show_field_states else '')

        return (
            f'{reg.parent.name or "-"}'
            f' : {reg.name or "-"} '
            f' : {reg.description or "-"}'
            f' : access read at {self._mem_addr_f(address)} '
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}{state_info}')

    def log_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        self._py_log.info(self.format_svd_read_access(address, pc, state, reg))

    def format_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ) -> str:
        state_info = (
            f'\n{self._get_info_field_states_write(state, new_state, reg)}'
            if self._log_show_field_states else '')

        log_value_field = (
            f'{self._mmio_addr_f(state)} '
            f'-> {self._mmio_addr_f(new_state)}{state_info} (register value change)'
            if state != new_state else
            f'{self._mmio_addr_f(state)}')

        return (
            f'{reg.parent.name or "-"}'
            f' : {reg.name or "-"} '
            f' : {reg.description or "-"}'
            f' : access write at {self._mem_addr_f(address)} '
            f' from {self._mem_addr_f(pc)}'
            f' : {log_value_field}')

    def log_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        self._py_log.info(self.format_svd_write_access(
            address, pc, state, new_state, reg))
