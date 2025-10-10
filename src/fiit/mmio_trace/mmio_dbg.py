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

from typing import Dict

from cmsis_svd.model import SVDRegister

from fiit.dbg import Debugger, DBG_EVENT_WATCHPOINT

from .svd_helper import SvdLoader, SvdIndex
from .interceptor import MmioInterceptor, MonitoredMemory
from .logger import MmioLogger


class MmioDbg:

    def __init__(
        self,
        dbg: Debugger,
        monitored_memory: Dict,
        mmio_filters: Dict = None,
        svd_resource: str = None,
    ):
        self._dbg = dbg

        svd_dev = SvdLoader().load(svd_resource) if svd_resource else None
        svd_index = SvdIndex(svd_dev) if svd_dev else None

        self.mem_bit_size = dbg.cpu.bits.value
        self._monitored_memory = MonitoredMemory(
            self.mem_bit_size, **monitored_memory, svd_index=svd_index)

        logger_name = f'fiit.mmio_dbg.dev@{dbg.cpu.dev_name}'
        self.mmio_logger = MmioLogger(
            self.mem_bit_size, self._monitored_memory, logger_name, True)

        self.mmio_interceptor = MmioInterceptor(
            dbg.cpu,
            self._monitored_memory,
            [self._read_callback],
            [self._write_callback],
            [self._svd_read_callback],
            [self._svd_write_callback],
            mmio_filters=mmio_filters,
            svd_index=svd_index)

    def _read_callback(self, address: int, pc: int, state: int):
        out = self.mmio_logger.format_read_access(address, pc, state)
        print(f'\n\nmmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _write_callback(self, address: int, pc: int, state: int, new_state: int):
        out = self.mmio_logger.format_write_access(address, pc, state, new_state)
        print(f'\n\nmmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _svd_read_callback(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        out = self.mmio_logger.format_svd_read_access(address, pc, state, reg)
        print(f'\n\nmmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _svd_write_callback(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        out = self.mmio_logger.format_svd_write_access(address, pc, state,
                                                       new_state, reg)
        print(f'\n\nmmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})
