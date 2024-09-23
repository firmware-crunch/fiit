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

from fiit.unicorn.arch_unicorn import ArchUnicorn
from fiit.unicorn.emulator import UnicornEmulator, UnicornEmulatorFrontend
from fiit.core.shell import EmulatorShell
from fiit.core.plugin import (
    FiitPlugin, FiitPluginContext, Requirement,
    PLUGIN_PRIORITY_LEVEL_BUILTIN_L1)


class PluginUnicornEmulator(FiitPlugin):
    NAME = 'plugin_unicorn_emulator'
    LOADING_PRIORITY = PLUGIN_PRIORITY_LEVEL_BUILTIN_L1
    OPTIONAL_REQUIREMENTS = [Requirement('emulator_shell', EmulatorShell)]
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
        self.emu: Optional[UnicornEmulator] = None

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        self.emu = UnicornEmulator(**plugin_config)

        plugins_context.add('unicorn_emulator', self.emu)
        plugins_context.add('emulator_address_space', self.emu.address_space)
        plugins_context.add('emulator_arch', self.emu.arch)
        plugins_context.add('unicorn_uc', self.emu.uc)

        if emu_shell := optional_requirements.get('emulator_shell'):
            UnicornEmulatorFrontend(self.emu, cast(EmulatorShell, emu_shell))
        else:
            plugins_context.program_entry = self.plugin_program_entry

    def plugin_program_entry(self):
        self.emu.start()
