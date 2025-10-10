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
    'PluginLogger'
]

from typing import Dict, Any

from fiit.logger import FiitLogger
from fiit.plugin import FiitPlugin, FiitPluginContext

# ==============================================================================


class PluginLogger(FiitPlugin):
    NAME = 'plugin_logger'
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'loggers_level_config': {
                    'type': 'dict',
                    'default': {},
                    'keysrules': {'type': 'string'},
                    'valuesrules': {'type': 'string', 'allowed': [
                        'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
                    },
                }
            }
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        FiitLogger.configure_loggers(**plugin_config)
