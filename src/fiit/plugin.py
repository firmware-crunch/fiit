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

from typing import (
    List, Any, Callable, Type, Dict, Optional, Union, cast, Tuple,
    get_origin, get_args
)
import logging
import os
import inspect
from dataclasses import dataclass
import graphlib

from .dev_utils import pkg_object_loader, inherits_from
from .config_loader import ConfigLoader



class PluginRequirementNotFound(Exception):
    pass


class PluginRequirementInvalidType(Exception):
    pass


@dataclass
class PluginRequirement:
    name: str
    instance_type: Type[Any]
    description: str = None


@dataclass
class ObjectRequirement:
    name: str
    instance_type: Type[Any]
    description: str = None


@dataclass
class ContextObject:
    name: str
    instance_type: Type[Any]
    description: str = None

    def as_require(self) -> ObjectRequirement:
        return ObjectRequirement(self.name, self.instance_type, self.description)



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
    REQUIREMENTS: Optional[List[Union[PluginRequirement, ObjectRequirement]]]
    OPTIONAL_REQUIREMENTS: Optional[List[PluginRequirement]]
    OBJECTS_PROVIDED: Optional[List[ContextObject]]
    CONFIG_SCHEMA: dict
    CONFIG_SCHEMA_RULE_SET_REGISTRY: Optional[tuple]

    def __init__(self):
        self._log = logging.getLogger(f'fiit.plugin@{self.NAME}')

    @property
    def log(self) -> logging.Logger:
        return self._log

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
    def is_fiit_plugin(obj: Any):
        return (
            True if inspect.isclass(obj) and inherits_from(obj, FiitPlugin)
            else False)

    @classmethod
    def _find_builtin_plugins(cls) -> List[Type[FiitPlugin]]:
        file_path = os.path.dirname(os.path.realpath(__file__))
        builtin_plugins = os.path.abspath(f'{file_path}')
        plugins = pkg_object_loader(
            builtin_plugins, cls.is_fiit_plugin)
        return cast(List[Type[FiitPlugin]], plugins)

    @classmethod
    def _find_extra_plugins(cls, path: str) -> List[Type[FiitPlugin]]:
        plugins = pkg_object_loader(path, cls.is_fiit_plugin)
        return cast(List[Type[FiitPlugin]], plugins)

    @staticmethod
    def _get_plugin_requirements(
        plugin: Type[FiitPlugin], init_context: FiitPluginContext
    ) -> Dict[str, Any]:
        requirements = {}

        for req in getattr(plugin, 'REQUIREMENTS', []):
            req_instance = init_context.context.get(req.name)

            if not req_instance:
                raise PluginRequirementNotFound(
                    f'Plugin requirement "{req.name}" not found during '
                    f'plugin creation for "{str(plugin)}".')

            requirements.update({req.name: req_instance})

        return requirements

    @staticmethod
    def _get_plugin_optional_requirements(
        plugin: Type[FiitPlugin], init_context: FiitPluginContext
    ) -> Dict[str, Any]:
        optional_requirements = {}

        for req in getattr(plugin, 'OPTIONAL_REQUIREMENTS', []):
            req_instance = init_context.context.get(req.name, None)
            if req_instance is not None:
                optional_requirements.update({req.name: req_instance})

        return optional_requirements

    @staticmethod
    def _search_plugin_requirements(
        source_plugin: Type[FiitPlugin],
        configured_plugins: List[Type[FiitPlugin]],
        search_optional_requirements: bool
    ) -> List[Type[FiitPlugin]]:
        search = []

        requirement_attr = (
            'OPTIONAL_REQUIREMENTS' if search_optional_requirements
            else 'REQUIREMENTS')

        for require_search in getattr(source_plugin, requirement_attr, []):

            if isinstance(require_search, PluginRequirement):
                if require_search.instance_type in configured_plugins:
                    req = configured_plugins.index(require_search.instance_type)
                    search.append(configured_plugins[req])
                else:
                    if not search_optional_requirements:
                        raise PluginRequirementNotFound(
                            f'Plugin require "{require_search}" not provided by any '
                            f'configured plugin.')

            elif isinstance(require_search, ObjectRequirement):
                dependency_found = False

                for plugin in configured_plugins:
                    for provided_object in getattr(plugin, 'OBJECTS_PROVIDED', []):
                        if not isinstance(provided_object, ContextObject):
                            raise PluginRequirementInvalidType(
                                f'Invalid provided object definition '
                                f'"{provided_object}".')

                        if require_search.instance_type == provided_object.instance_type:
                            search.append(plugin)
                            dependency_found = True
                            break

                    if dependency_found:
                        break

                if not search_optional_requirements and not dependency_found:
                    raise PluginRequirementNotFound(
                        f'"{require_search.name}" object require not found in '
                        f'plugin context, required by plugin '
                        f'"{source_plugin.NAME}"')

            else:
                raise PluginRequirementInvalidType(
                    f'Invalid plugin requirement type "{require_search}".')

        return search

    def _load_plugins(self, plugin_list: Tuple[Type[FiitPlugin]], config: dict):
        for plugin in plugin_list:
            self.logger.info(f'Create plugin instance for <{plugin.NAME}>.')
            plugin_instance = plugin()

            requirements = self._get_plugin_requirements(
                plugin, self.plugins_context)

            optional_requirements = self._get_plugin_optional_requirements(
                plugin, self.plugins_context)

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

        for plugin in plugin_collect:
            conf_schema['schema'].update(plugin.CONFIG_SCHEMA)
            if hasattr(plugin, 'CONFIG_SCHEMA_RULE_SET_REGISTRY'):
                config_loader.validator.rules_set_registry.extend(
                    plugin.CONFIG_SCHEMA_RULE_SET_REGISTRY)

        self.logger.info(f'Loading config file "{config_file}".')
        config = config_loader.load_config(config_file, conf_schema)

        self.plugins_context.add('plugin_manager', self)

        config_plugins = []
        plugin_logger: Optional[Type[FiitPlugin]] = None

        for plugin in plugin_collect:
            if plugin.NAME in config:
                config_plugins.append(plugin)

                # special handling rule to load logger before any plugin
                if plugin.NAME == 'plugin_logger':
                    plugin_logger = plugin

        dependencies_graph = {}

        for plugin in config_plugins:
            reqs = self._search_plugin_requirements(plugin, config_plugins, False)
            opt_reqs = self._search_plugin_requirements(plugin, config_plugins, True)
            requirements = []
            requirements.extend(reqs)
            requirements.extend(opt_reqs)

            # special dependency creation to load logger before any plugin
            if plugin_logger is not None and plugin.NAME != 'plugin_logger':
                requirements.append(plugin_logger)

            dependencies_graph.update({plugin: set(requirements)})

        topo_sort = graphlib.TopologicalSorter(dependencies_graph).static_order()
        self._load_plugins(tuple(topo_sort), config)

    def unload_plugin(self, plugin_name: str):
        if plugin_store_entry := self._plugins_store.get(plugin_name, None):
            plugin_store_entry.plugin_instance.plugin_unload(
                self.plugins_context,
                plugin_store_entry.config,
                plugin_store_entry.requirements,
                plugin_store_entry.optional_requirements)
            self._plugins_store.pop(plugin_name)
            self.plugins_context.remove(plugin_name)
