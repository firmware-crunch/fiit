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

from typing import Dict, Any, Optional, cast, List
import logging

from fiit.machine import DeviceCpu
from fiit.ctypesarch.base_types import DataPointerBase
from fiit.ctypesarch import CDataMemMapCache
from fiit.hooking.engine import HookingContext
from fiit.ftrace import FunctionFilterExtBase, LogFormatterExtBase


class FreeRtOsTaskCommon:
    _log: logging.log
    _px_current_tcb: DataPointerBase

    @staticmethod
    def decode_task_name(px_current_tcb: DataPointerBase) -> str:
        return (bytearray(px_current_tcb.contents.pcTaskName)
                .split(b'\x00')[0].decode('ascii'))

    def save_px_current_tcb_cdata_mapping(self, ext_ctx: Dict[str, Any]):
        cpu = cast(DeviceCpu, ext_ctx.get('cpu', None))
        if cpu is None:
            self._log.error(f'error: cpu not found in load extension context')
            return

        cdata_cache = CDataMemMapCache()
        cdata_entry = cdata_cache.find_cdata_by_name(cpu.mem, 'pxCurrentTCB')

        if cdata_entry is None:
            self._log.error('px_current_tcb cdata binding not found in cache')
            return
        else:
            px_current_tcb = cdata_entry.cdata
            self._px_current_tcb = cast(DataPointerBase, px_current_tcb)
            self._log.info(
                f'%s found in C data memory map cache, mapped at %s',
                cdata_entry.name, cpu.mem.addr_to_str(cdata_entry.address))


class FreeRTOSTaskFilterLogger(FunctionFilterExtBase, FreeRtOsTaskCommon):
    FILTER_NAME = 'freertos_task_filter'
    FILTER_CONFIG_SCHEMA = {
        FILTER_NAME: {
            'type': 'dict',
            'schema': {
                'task_names': {'type': 'list', 'schema': {'type': 'string'}}
            }
        }
    }

    def __init__(self):
        self._filtered_task_names: Optional[List[str]] = None
        self._px_current_tcb: Optional[DataPointerBase] = None
        self._log = logging.getLogger(f'{self.FILTER_NAME}')

    def filter_ext_load(self, ext_ctx: Dict[str, Any], ext_config: dict):
        self._filtered_task_names = ext_config['task_names']
        self.save_px_current_tcb_cdata_mapping(ext_ctx)

    def ext_filter(self, ctx: HookingContext):
        if self._px_current_tcb is not None and not self._px_current_tcb.is_null():
            current_task_name = self.decode_task_name(self._px_current_tcb)
            if current_task_name in self._filtered_task_names:
                return True

        return False


class FreeRTOSTaskLogFormatter(LogFormatterExtBase, FreeRtOsTaskCommon):
    FORMATTER_NAME = 'freertos_task_context_formatter'
    FORMATTER_CONFIG_SCHEMA = {FORMATTER_NAME: {'type': 'dict'}}

    def __init__(self):
        self._px_current_tcb: Optional[DataPointerBase] = None
        self._log = logging.getLogger(f'{self.FORMATTER_NAME}')

    def formatter_ext_load(self, ext_ctx: Dict[str, Any], ext_config: dict):
        self.save_px_current_tcb_cdata_mapping(ext_ctx)

    def ext_python_log(self, ctx: HookingContext, log: str) -> str:
        if self._px_current_tcb is not None and not self._px_current_tcb.is_null():
            current_task_name = self.decode_task_name(self._px_current_tcb)
            return f'task context "{current_task_name}" : {log}'
        return log
