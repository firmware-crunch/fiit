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

from typing import Any, Dict, cast

import unicorn

from fiit.unicorn.dbg import UnicornDbg, UnicornDbgFrontend
from fiit.core.plugin import (
    FiitPlugin, FiitPluginContext, Requirement,
    PLUGIN_PRIORITY_LEVEL_BUILTIN_L2)
from fiit.core.shell import EmulatorShell


class PluginUnicornDbg(FiitPlugin):
    NAME = 'plugin_unicorn_dbg'
    LOADING_PRIORITY = PLUGIN_PRIORITY_LEVEL_BUILTIN_L2
    REQUIREMENTS = [Requirement('unicorn_uc', unicorn.Uc)]
    OPTIONAL_REQUIREMENTS = [Requirement('emulator_shell', EmulatorShell)]
    CONFIG_SCHEMA = {NAME: {'type': 'dict'}}

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        dbg = UnicornDbg(requirements['unicorn_uc'])

        if emu_shell := optional_requirements.get('emulator_shell'):
            UnicornDbgFrontend(dbg, cast(EmulatorShell, emu_shell))

        plugins_context.add('unicorn_dbg', dbg)
