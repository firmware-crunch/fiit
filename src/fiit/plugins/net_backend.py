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
from fiit.net import (
    NetBackend, NetBackendDataContext, NET_BACKEND_REQUEST_DEFAULT_PORT
)

from . import CTX_SHELL


class PluginNetwork(FiitPlugin):
    NAME = 'plugin_net_backend'
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
                                 'default': NET_BACKEND_REQUEST_DEFAULT_PORT}
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
        backend = NetBackend(**plugin_config)

        with NetBackendDataContext() as backend_data:
            if emulator_shell := plugins_context.get(CTX_SHELL.name):
                if emulator_shell._remote_ipykernel:
                    backend_data.jupyter_client_json_config = \
                        emulator_shell.get_remote_ipkernel_client_config()

        backend.run_backend_request_loop()
