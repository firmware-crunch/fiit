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

from typing import Optional, Dict, Any, Union

from fiit.shell import Shell
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import CTX_SHELL


class ShellPluginsContext:
    def __repr__(self):
        return '\n'.join([
             f'{name} : {type(attr)}' for name, attr in self.__dict__.items()]
         )


class PluginShell(FiitPlugin):
    NAME = 'plugin_shell'
    OBJECTS_PROVIDED = [CTX_SHELL]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'remote_ipykernel': {'type': 'boolean', 'default': False,
                                     'required': False},
                'allow_remote_connection': {'type': 'boolean', 'default': False,
                                            'required': False}
            }
        }
    }

    def __init__(self):
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
        plugins_context.add(CTX_SHELL.name, self.shell)
        plugins_context.program_entry = self.plugin_program_entry
        self.context = plugins_context.context

    def plugin_program_entry(self):
        plugins_context = ShellPluginsContext()

        for name, obj in self.context.items():
            setattr(plugins_context, name, obj)

        self.shell.map_object_in_shell('plugins_context', plugins_context)
        self.shell.start_shell()
