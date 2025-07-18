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

from fiit.core.plugin import (
    FiitPlugin, FiitPluginContext, PluginRequirement, ObjectRequirement)
from .plugin_p1 import PluginTestP1
from .plugin_p2 import PluginTestP2
from .plugin_p8 import CustomObject


class PluginTestP3(FiitPlugin):
    NAME = 'plugin_test_p3'
    REQUIREMENTS = [
        PluginRequirement('plugin_test_p1', PluginTestP1),
        ObjectRequirement('custom_object', CustomObject)]
    OPTIONAL_REQUIREMENTS = [
        PluginRequirement('plugin_test_p2', PluginTestP2)]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {'activate': {'type': 'boolean'}}
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        pass
