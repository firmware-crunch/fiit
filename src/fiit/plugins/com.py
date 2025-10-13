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

from typing import Dict, Any
from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.com import (
    ComBackend, ComBackendDataContext, COM_BACKEND_REQ_DEFAULT_PORT
)

from . import CTX_SHELL


class PluginCom(FiitPlugin):
    NAME = 'plugin_com'
    OPTIONAL_REQUIREMENTS = [CTX_SHELL.as_require()]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'allow_remote_connection': {'type': 'boolean', 'default': True,
                                            'required': False},
                'event_pub_port': {'type': 'integer', 'required': True},
                'request_port': {'type': 'integer', 'required': False,
                                 'default': COM_BACKEND_REQ_DEFAULT_PORT}
            }
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: Dict[str, Any],
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ) -> None:
        backend = ComBackend(**plugin_config)

        with ComBackendDataContext() as backend_data:
            if emulator_shell := plugins_context.get(CTX_SHELL.name):
                if emulator_shell._remote_ipykernel:
                    backend_data.jupyter_client_json_config = \
                        emulator_shell.get_remote_ipkernel_client_config()

        backend.run_backend_request_loop()
