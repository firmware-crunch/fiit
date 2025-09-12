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

from typing import Optional, cast, Dict, Any

from fiit.emu.arch_unicorn import ArchUnicorn
from fiit.emu.emulator import Emulator
from fiit.shell.front_emu import EmulatorFrontend
from fiit.shell import Shell
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import (
    CTX_SHELL, CTX_EMULATOR, CTX_EMULATOR_ADDRESS_SPACE,
    CTX_EMULATOR_ARCH, CTX_UNICORN_UC
)


class PluginEmulator(FiitPlugin):
    NAME = 'plugin_emulator'
    OPTIONAL_REQUIREMENTS = [
        CTX_SHELL.as_require()]
    OBJECTS_PROVIDED = [
        CTX_EMULATOR,
        CTX_EMULATOR_ADDRESS_SPACE,
        CTX_EMULATOR_ARCH,
        CTX_UNICORN_UC]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'schema': {
                'architecture': {
                    'type': 'string', 'allowed': ArchUnicorn.get_all_arch()},
                'memory_mapping': 'DEF_MEMORY_MAPPING',
                'memory_mapped_files': 'DEF_MEMORY_MAPPED_FILES',
                'entry_point': 'DEF_INT64',
                'end_address': 'DEF_INT64',
                'host_memory_map': {'type': 'boolean', 'default': True}
            }
        }
    }

    def __init__(self):
        self.emu: Optional[Emulator] = None

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        self.emu = Emulator(**plugin_config)

        plugins_context.add(CTX_EMULATOR.name, self.emu)
        plugins_context.add(CTX_EMULATOR_ADDRESS_SPACE.name, self.emu.address_space)
        plugins_context.add(CTX_EMULATOR_ARCH.name, self.emu.arch)
        plugins_context.add(CTX_UNICORN_UC.name, self.emu.uc)

        if shell := optional_requirements.get(CTX_SHELL.name):
            EmulatorFrontend(self.emu, cast(Shell, shell))
        else:
            plugins_context.program_entry = self.plugin_program_entry

    def plugin_program_entry(self):
        self.emu.start()
