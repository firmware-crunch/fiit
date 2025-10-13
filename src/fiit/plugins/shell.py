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
    'PluginShell'
]

from typing import Optional, Dict, Any, Union, cast, List

from fiit.dbg import Debugger
from fiit.arch_ctypes.cdata_mmap import CDataMemMapper
from fiit.mmio_trace import MmioTrace, MmioDbg
from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.shell import Shell
from fiit.shell.front import (
    MachineFrontend, DbgFrontend, CDataMemMapperFrontend, MmioDbgFrontend,
    MmioTraceVizFrontend
)

from . import (
    CTX_SHELL, CTX_REQ_MACHINE, CTX_REQ_DBG, CTX_REQ_CDATA_MMAP,
    CTX_REQ_MMIO_DBG, CTX_REQ_MMIO_TRACER
)

# ==============================================================================


class ShellPluginsContext:
    def __repr__(self):
        return '\n'.join([
             f'{name} : {type(attr)}' for name, attr in self.__dict__.items()]
         )


class PluginShell(FiitPlugin):
    NAME = 'plugin_shell'
    OPTIONAL_REQUIREMENTS = [
        CTX_REQ_MACHINE,
        CTX_REQ_DBG,
        CTX_REQ_CDATA_MMAP,
        CTX_REQ_MMIO_TRACER,
        CTX_REQ_MMIO_DBG,
    ]
    OBJECTS_PROVIDED = [CTX_SHELL]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'remote_ipykernel': {
                    'type': 'boolean', 'default': False, 'required': False
                },
                'allow_remote_connection': {
                    'type': 'boolean', 'default': False, 'required': False
                }
            }
        }
    }

    def __init__(self):
        FiitPlugin.__init__(self)
        self.shell: Optional[Shell] = None
        self.context: Union[Dict[str, Any], None] = None

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        self.shell = Shell(**plugin_config)

        machine = optional_requirements.get(CTX_REQ_MACHINE.name, None)
        if machine is not None:
            MachineFrontend(machine, self.shell)

        dbg_list = optional_requirements.get(CTX_REQ_DBG.name, None)

        if dbg_list is not None:
            dbg_list = cast(List[Debugger], dbg_list)
            DbgFrontend(dbg_list, self.shell)

        cdata_mmap_list = optional_requirements.get(CTX_REQ_CDATA_MMAP.name, None)

        if cdata_mmap_list is not None:
            cdata_mmap_list = cast(List[CDataMemMapper], cdata_mmap_list)
            CDataMemMapperFrontend(cdata_mmap_list, self.shell)

        mmio_tracer_list = optional_requirements.get(CTX_REQ_MMIO_TRACER.name, None)

        if mmio_tracer_list is not None:
            mmio_tracer_list = cast(List[MmioTrace], mmio_tracer_list)
            MmioTraceVizFrontend(mmio_tracer_list, self.shell)

        mmio_dbg_list = optional_requirements.get(CTX_REQ_MMIO_DBG.name, None)

        if mmio_dbg_list is not None:
            mmio_dbg_list = cast(List[MmioDbg], mmio_dbg_list)

            for mmio_dbg in mmio_dbg_list:
                self.shell.stream_logger_to_shell_stdout(mmio_dbg.logger_name)

            MmioDbgFrontend(mmio_dbg_list, self.shell)

        plugins_context.add(CTX_SHELL.name, self.shell)
        plugins_context.program_entry = self.plugin_program_entry
        self.context = plugins_context.context

    def plugin_program_entry(self):
        plugins_context = ShellPluginsContext()

        for name, obj in self.context.items():
            setattr(plugins_context, name, obj)

        self.shell.map_object_in_shell('plugins_context', plugins_context)
        self.shell.start_shell()
