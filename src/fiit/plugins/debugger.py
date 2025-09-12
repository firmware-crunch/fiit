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

from typing import Any, Dict

from fiit.dbg.debugger import Debugger
from fiit.shell.front_dbg import DbgFrontend
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import CTX_UNICORN_UC, CTX_SHELL, CTX_DBG


class PluginDebugger(FiitPlugin):
    NAME = 'plugin_debugger'
    REQUIREMENTS = [CTX_UNICORN_UC.as_require()]
    OPTIONAL_REQUIREMENTS = [CTX_SHELL.as_require()]
    OBJECTS_PROVIDED = [CTX_DBG]
    CONFIG_SCHEMA = {NAME: {'type': 'dict'}}

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        dbg = Debugger(requirements[CTX_UNICORN_UC.name])

        if shell := optional_requirements.get(CTX_SHELL.name):
            DbgFrontend(dbg, shell)

        plugins_context.add(CTX_DBG.name, dbg)
