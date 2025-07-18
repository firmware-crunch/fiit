################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

from typing import Dict, Any

from fiit.core.plugin import FiitPlugin, FiitPluginContext, ContextObject


class CustomObject:
    pass



class PluginTestP8(FiitPlugin):
    NAME = 'plugin_test_p8'
    CONFIG_SCHEMA_RULE_SET_REGISTRY = (('DEF_CUSTOM_BOOL', {'type': 'boolean'}),)
    OBJECTS_PROVIDED = [ContextObject('custom_object', CustomObject)]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {'activate': 'DEF_CUSTOM_BOOL'}
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        plugins_context.add('custom_object', CustomObject())
