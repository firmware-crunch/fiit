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

import unicorn

from fiit.unicorn.arm.arm_generic_core import UnicornArmGenericCore
import fiit.plugins.context_config as conf
from fiit.core.plugin import (
    FiitPlugin, FiitPluginContext, ObjectRequirement, ContextObject)


class PluginUnicornGenericArmCore(FiitPlugin):
    NAME = 'plugin_unicorn_arm_generic_core'
    REQUIREMENTS = [
        conf.UNICORN_UC.as_require()]
    OBJECTS_PROVIDED = [
        conf.UNICORN_ARM_GENERIC_CORE]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'schema': {
                'high_vector_support': {'type': 'boolean', 'default': True},
                'high_vector': {'type': 'boolean', 'default': False},
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
        uc = requirements.get(conf.UNICORN_UC.name)
        arm_core = UnicornArmGenericCore(uc, **plugin_config)
        plugins_context.add(conf.UNICORN_ARM_GENERIC_CORE.name, arm_core)
