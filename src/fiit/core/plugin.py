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


from typing import List, Any, Callable, Type, Dict, Optional, Union, cast
import logging
import os
import inspect
from dataclasses import dataclass
from .dev_utils import pkg_object_loader, inherits_from
from .config_loader import ConfigLoader


PLUGIN_PRIORITY_LEVEL_USER_BASE = 1000
PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE = 100
PLUGIN_PRIORITY_LEVEL_BUILTIN_L0 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE
PLUGIN_PRIORITY_LEVEL_BUILTIN_L1 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 1
PLUGIN_PRIORITY_LEVEL_BUILTIN_L2 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 2
PLUGIN_PRIORITY_LEVEL_BUILTIN_L3 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 3
PLUGIN_PRIORITY_LEVEL_BUILTIN_L4 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 4
PLUGIN_PRIORITY_LEVEL_BUILTIN_L5 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 5
PLUGIN_PRIORITY_LEVEL_BUILTIN_L6 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 6
PLUGIN_PRIORITY_LEVEL_BUILTIN_L7 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 7
PLUGIN_PRIORITY_LEVEL_BUILTIN_L8 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 8
PLUGIN_PRIORITY_LEVEL_BUILTIN_L9 = PLUGIN_PRIORITY_LEVEL_BUILTIN_BASE + 9


class PluginRequirementNotFound(Exception):
    pass


class PluginRequirementInvalidType(Exception):
    pass


@dataclass
class Requirement:
    name: str
    instance_type: Type[Any]
    description: str = None


class FiitPluginContext:
    def __init__(self):
        self.context = dict()
        self.program_entry: Optional[Callable] = None

    def add(self, name: str, obj: any):
        self.context.update({name: obj})

    def get(self, name: str) -> Union[Any, None]:
        return self.context.get(name, None)

    def remove(self, name: str):
        self.context.pop(name)


class FiitPlugin:
    NAME: str
    LOADING_PRIORITY: int
    REQUIREMENTS: Optional[List[Requirement]]
    OPTIONAL_REQUIREMENTS: Optional[List[Requirement]]
    CONFIG_SCHEMA: dict
    CONFIG_SCHEMA_RULE_SET_REGISTRY: Optional[tuple]

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        raise NotImplementedError('plugin_init() not implemented.')

    def plugin_unload(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        raise NotImplementedError('plugin_unload() not implemented.')


@dataclass
class PluginStoreEntry:
    plugin_instance: FiitPlugin
    config: dict
    requirements: Dict[str, Any]
    optional_requirements: Dict[str, Any]


class PluginManager:
    def __init__(self):
        self.logger = logging.getLogger('fiit.plugin_loader')
        self.plugins_context = FiitPluginContext()
        self._plugins_store: Dict[str, PluginStoreEntry] = {}

    @staticmethod
    def is_emulator_plugin(obj: Any):
        return (
            True if inspect.isclass(obj) and inherits_from(obj, FiitPlugin)
            else False)

    @classmethod
    def _find_builtin_plugins(cls) -> List[Type[FiitPlugin]]:
        file_path = os.path.dirname(os.path.realpath(__file__))
        builtin_plugins = os.path.abspath(f'{file_path}/../')
        plugins = pkg_object_loader(
            builtin_plugins, cls.is_emulator_plugin, ['plugins'])
        return cast(List[Type[FiitPlugin]], plugins)

    @classmethod
    def _find_extra_plugins(cls, path: str) -> List[Type[FiitPlugin]]:
        plugins = pkg_object_loader(path, cls.is_emulator_plugin)
        return cast(List[Type[FiitPlugin]], plugins)

    @staticmethod
    def _sort_plugin_by_priority(
        plugins: List[Type[FiitPlugin]]
    ) -> Dict[int, List[Type[FiitPlugin]]]:
        plugin_by_priority: Dict[int, List[Type[FiitPlugin]]] = {}
        for plug in plugins:
            plugin_by_priority.setdefault(plug.LOADING_PRIORITY, [])
            plugin_by_priority[plug.LOADING_PRIORITY].append(plug)
        return plugin_by_priority

    @staticmethod
    def _get_plugin_requirements(
        plugin: Type[FiitPlugin], init_context: FiitPluginContext
    ) -> Dict[str, Any]:
        requirements = {}

        if hasattr(plugin, 'REQUIREMENTS'):
            for req in plugin.REQUIREMENTS:
                if not (req_instance := init_context.context.get(req.name)):
                    raise PluginRequirementNotFound(
                        f'Plugin requirement "{req.name}" not found during '
                        f'plugin creation for "{str(plugin)}".')
                if not isinstance(req_instance, req.instance_type):
                    raise PluginRequirementInvalidType(
                        f'Plugin requirement "{req.name}" invalid instance '
                        f'type, expected '
                        f'"{str(req.instance_type)}".')
                requirements.update({req.name: req_instance})

        return requirements

    @staticmethod
    def _get_plugin_optional_requirements(
        plugin: Type[FiitPlugin], init_context: FiitPluginContext
    ) -> Dict[str, Any]:
        optional_requirements = {}

        if hasattr(plugin, 'OPTIONAL_REQUIREMENTS'):
            for req in plugin.OPTIONAL_REQUIREMENTS:
                if req_instance := init_context.context.get(req.name):
                    if not isinstance(req_instance, req.instance_type):
                        raise PluginRequirementInvalidType(
                            f'Plugin requirement "{req.name}" invalid instance '
                            f'type, expected '
                            f'"{req.instance_type.__class__.__name__}".')
                    optional_requirements.update({req.name: req_instance})

        return optional_requirements

    def load_plugin_by_config_file(
        self, config_file: str, extra_plugin_paths: List[str] = None
    ):
        conf_schema = {'type': 'dict', 'schema': dict()}
        config_loader = ConfigLoader()
        extra_paths = []

        plugin_collect = self._find_builtin_plugins()

        if extra_plugin_paths:
            extra_paths.extend(extra_plugin_paths)

        if extra_plugin_paths_by_env := os.getenv('EXTRA_PLUGIN_PATHS', None):
            extra_paths.extend(extra_plugin_paths_by_env.split(','))

        for epp in extra_paths:
            plugin_collect.extend(self._find_extra_plugins(epp))

        plugin_by_priority = self._sort_plugin_by_priority(plugin_collect)

        for plugin in plugin_collect:
            conf_schema['schema'].update(plugin.CONFIG_SCHEMA)
            if hasattr(plugin, 'CONFIG_SCHEMA_RULE_SET_REGISTRY'):
                config_loader.validator.rules_set_registry.extend(
                    plugin.CONFIG_SCHEMA_RULE_SET_REGISTRY)

        self.logger.info(f'Loading config file "{config_file}".')
        config = config_loader.load_config(config_file, conf_schema)

        self.plugins_context.add('plugin_manager', self)

        for priority in sorted(plugin_by_priority.keys()):
            for plugin in plugin_by_priority[priority]:
                if plugin.NAME in config:
                    self.logger.info(f'Create plugin instance for '
                                     f'<{plugin.NAME}>')

                    requirements = self._get_plugin_requirements(
                        plugin, self.plugins_context)
                    optional_requirements = self._get_plugin_optional_requirements(
                        plugin, self.plugins_context)

                    plugin_instance = plugin()
                    plugin_instance.plugin_load(
                        self.plugins_context,
                        config[plugin.NAME],
                        requirements,
                        optional_requirements)

                    self._plugins_store.update({
                        plugin.NAME: PluginStoreEntry(
                            plugin_instance,
                            config[plugin.NAME],
                            requirements,
                            optional_requirements)})

                    self.plugins_context.add(plugin.NAME, plugin_instance)

    def unload_plugin(self, plugin_name: str):
        if plugin_store_entry := self._plugins_store.get(plugin_name, None):
            plugin_store_entry.plugin_instance.plugin_unload(
                self.plugins_context,
                plugin_store_entry.config,
                plugin_store_entry.requirements,
                plugin_store_entry.optional_requirements)
            self._plugins_store.pop(plugin_name)
            self.plugins_context.remove(plugin_name)
