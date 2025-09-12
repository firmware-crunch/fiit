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

from fiit.emu.arch_arm.arm import ArchArm
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import CTX_UNICORN_UC, CTX_ARCH_ARM


class PluginArchArm(FiitPlugin):
    NAME = 'plugin_arch_arm'
    REQUIREMENTS = [
        CTX_UNICORN_UC.as_require()]
    OBJECTS_PROVIDED = [
        CTX_ARCH_ARM]
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
        uc = requirements.get(CTX_UNICORN_UC.name)
        arm_core = ArchArm(uc, **plugin_config)
        plugins_context.add(CTX_ARCH_ARM.name, arm_core)
