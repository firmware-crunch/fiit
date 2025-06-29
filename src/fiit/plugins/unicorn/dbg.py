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

from fiit.unicorn.dbg import UnicornDbg, UnicornDbgFrontend
import fiit.plugins.context_config as ctx_conf
from fiit.core.plugin import FiitPlugin, FiitPluginContext


class PluginUnicornDbg(FiitPlugin):
    NAME = 'plugin_unicorn_dbg'
    REQUIREMENTS = [ctx_conf.UNICORN_UC.as_require()]
    OPTIONAL_REQUIREMENTS = [ctx_conf.EMULATOR_SHELL.as_require()]
    OBJECTS_PROVIDED = [ctx_conf.UNICORN_DBG]
    CONFIG_SCHEMA = {NAME: {'type': 'dict'}}

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        dbg = UnicornDbg(requirements[ctx_conf.UNICORN_UC.name])

        if emu_shell := optional_requirements.get(ctx_conf.EMULATOR_SHELL.name):
            UnicornDbgFrontend(dbg, emu_shell)

        plugins_context.add(ctx_conf.UNICORN_DBG.name, dbg)
