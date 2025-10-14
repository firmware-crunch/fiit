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
    'PluginMachine'
]

import graphlib
from typing import Dict, List, Any, cast, Tuple, Callable

from fiit.config import ConfigLoader
from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.dev import FiitCpuFactory, ArchArm32, Pl190, Pl190IntGen
from fiit.machine import (
    TickUnit, MemoryProtection, Machine, MachineDevice, DeviceCpu
)

from . import CTX_MACHINE

# ==============================================================================


_SCHEMA_DEV_CPU = {
    'type': 'dict',
    'schema': {
        'cpu_backend': {
            'type': 'string',
            'required': True,
            'allowed': [
                'unicorn'
                # Add more cpu backend here...
            ],
        },
        'arch_id': {
            'type': 'string',
            'required': True,
            'allowed': [
                'arm32'
                # Add more cpu arch id here...
            ],
        },
        'options': {'type': 'dict', 'default': {}, 'required': False},
        'memory_regions': 'DEF_MEMORY_REGIONS',
        'map_files': 'DEF_LOAD_FILES',
        'program_entry_point': 'DEF_INT64',
        'program_exit_point': 'DEF_INT64_OPTIONAL',
    }
}


_SCHEMA_DEV_PL190 = {
    'type': 'dict',
    'schema': {'plug_cpu': {'type': 'string'}, 'base_address': 'DEF_INT64'}
}

_SCHEMA_DEV_PL190_INT_GEN = {
    'type': 'dict',
    'required': False,
    'schema': {
        'plug_intc': {'type': 'string'},
        'tick_unit': {
            'type': 'string', 'allowed': ['instruction', 'block', 'us']
        },
        'tick_count': 'DEF_SIZE'
    }
}


class _DevConfig:
    def __init__(
        self,
        device_type: str,
        device_name: str,
        device_config: Dict[str, Any],
        device_dependencies: List[str]
    ):
        self.device_type = device_type
        self.device_name = device_name
        self.device_config = device_config
        self.device_dependencies = device_dependencies
        self.dependencies: List[_DevConfig] = []


class PluginMachine(FiitPlugin):
    NAME = 'plugin_machine'
    OBJECTS_PROVIDED = [CTX_MACHINE]
    CONFIG_SCHEMA = {
        NAME: {'type': 'dict', 'schema': {'devices': {
            'type': 'dict',
            'keysrules': {'type': 'string'},
            'valuesrules': {
                'type': 'dict',
                'schema': {
                    'device_type': {
                        'type': 'string',
                        'allowed': ['cpu', 'pl190', 'pl190_int_gen'],
                        'required': True
                    },
                    'device_dependencies': {
                        'type': 'list',
                        'schema': {'type': 'string'},
                        'default': [],
                        'required': False,
                    },
                    'device_config': {
                        'type': 'dict',
                        'default': {},
                        'required': False,
                    }
                }
            }}}}
    }

    def __init__(self):
        FiitPlugin.__init__(self)
        self._config_loader = ConfigLoader()
        self._machine = Machine()

    @staticmethod
    def _sort_dev_by_dependencies(
        devices: List[_DevConfig]
    ) -> Tuple[_DevConfig]:
        device_dep_graph = {}

        for dev_dep_check in devices:
            device_dep_graph[dev_dep_check] = []

            for dep_name in dev_dep_check.device_dependencies:
                dep_found = False

                for dev in devices:
                    if dep_name == dev.device_name:
                        device_dep_graph[dev_dep_check].append(dev)
                        dev_dep_check.dependencies.append(dev)
                        dep_found = True
                        break

                if not dep_found:
                    raise RuntimeError(
                        f'Dependency "{dep_name}" not found for device '
                        f'"{dev_dep_check.device_name}"'
                    )

        topo_sort = graphlib.TopologicalSorter(device_dep_graph).static_order()
        return tuple([d for d in tuple(topo_sort)])

    def _parse(self, config: Dict[str, Any]) -> List[_DevConfig]:
        devices: List[_DevConfig] = []

        for dev_name, def_info in config['devices'].items():
            dev_type = cast(str, def_info['device_type'])
            dev_dep = cast(List[str], def_info['device_dependencies'])
            dev_conf = cast(Dict[str, Any], def_info['device_config'])

            if len(dev_conf) > 0:
                dev_conf_schema = self._DEV_CONFIG_SCHEMA.get(dev_type, None)

                if dev_conf_schema is None:
                    raise ValueError(
                        f'Machine device configuration not found for device '
                        f'"{dev_name}" of type "{dev_type}"'
                    )

                dev_conf_parsed = self._config_loader.parse_config(
                    dev_conf, dev_conf_schema
                )
                dev_conf = dev_conf_parsed

            conf = _DevConfig(
                device_type=dev_type,
                device_name=dev_name,
                device_config=dev_conf,
                device_dependencies=dev_dep
            )
            devices.append(conf)

        return devices

    def _create_dev_cpu(self, dev_conf: _DevConfig) -> DeviceCpu:
        name = dev_conf.device_name
        conf = dev_conf.device_config
        cpu_backend = cast(str, conf['cpu_backend'])
        arch_id = cast(str, conf['arch_id'])
        options = cast(Dict[str, Any], conf['options'])
        regions = cast(List[Dict[str, Any]], conf.get('memory_regions', []))
        map_files = cast(List[Dict[str, Any]], conf.get('map_files', []))
        cpu = FiitCpuFactory.get(cpu_backend, arch_id, name, **options)
        cpu.program_entry_point = cast(int, conf['program_entry_point'])
        cpu.program_exit_point = cast(int, conf.get('program_exit_point', None))

        for region in regions:
            cpu.mem.create_region(
                base_address=region['base_address'],
                size=region['size'],
                protection=MemoryProtection.from_str(region['perm']),
                name=region['name']
            )

        for map_file in map_files:
            cpu.mem.map_file(
                filename=map_file['filename'],
                file_offset=map_file['file_offset'],
                loading_address=map_file['loading_address'],
                loading_size=map_file.get('loading_size', None)
            )

        return cpu

    def _create_dev_pl190(self, dev_conf: _DevConfig) -> Pl190:
        name = dev_conf.device_name
        conf = dev_conf.device_config
        base_address = cast(int, conf['base_address'])
        plug_cpu = cast(str, conf['plug_cpu'])
        cpu = self._machine.get_device_cpu(plug_cpu)
        assert isinstance(cpu, ArchArm32)
        pl190 = Pl190(cpu, base_address, dev_name=name)
        return pl190

    def _create_dev_pl190_int_gen(self, dev_conf: _DevConfig) -> Pl190IntGen:
        name = dev_conf.device_name
        conf = dev_conf.device_config
        plug_intc = cast(str, conf['plug_intc'])
        tick_unit_str = cast(str, conf['tick_unit'])
        tick_unit = TickUnit.from_str(tick_unit_str)
        tick_count = cast(int, conf['tick_count'])
        pl190 = self._machine.get_device(plug_intc)
        assert isinstance(pl190, Pl190)
        pl190_int_gen = Pl190IntGen(pl190, tick_unit, tick_count, dev_name=name)
        return pl190_int_gen

    _DEV_CONFIG_SCHEMA = {
        'cpu': _SCHEMA_DEV_CPU,
        'pl190': _SCHEMA_DEV_PL190,
        'pl190_int_gen': _SCHEMA_DEV_PL190_INT_GEN
    }

    _DEV_FORGES: Dict[str, Callable[[object, _DevConfig], MachineDevice]] = {
        'cpu': _create_dev_cpu,
        'pl190': _create_dev_pl190,
        'pl190_int_gen': _create_dev_pl190_int_gen
        # add more device here...
    }

    def _get_dev_forge(
        self, dev_type: str
    ) -> Callable[[_DevConfig], MachineDevice]:
        dev_forge = self._DEV_FORGES.get(dev_type)

        if dev_forge is None:
            raise ValueError(f'machine device not supported "{dev_type}"')

        def _wrap(dev_conf: _DevConfig) -> MachineDevice:
            return dev_forge(self, dev_conf)

        return _wrap

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ) -> None:
        devices_config = self._parse(plugin_config)
        devices_config_sort = self._sort_dev_by_dependencies(devices_config)

        for dev_conf in devices_config_sort:
            dev_forge = self._get_dev_forge(dev_conf.device_type)
            dev = dev_forge(dev_conf)
            self.log.info(f'register dev@{dev.dev_name} to machine')
            self._machine.add_device(dev)

        plugins_context.add(CTX_MACHINE.name, self._machine)
        plugins_context.program_entry = self.plugin_program_entry

    def plugin_program_entry(self):
        if len(self._machine.cpu_devices) > 1:
            raise RuntimeError(
                'run machine with multiples cpu not supported, '
                'implement your own cpu contention loop to run multiples cpu'
            )
        if len(self._machine.cpu_devices) == 0:
            raise RuntimeError('cpu not found')

        cpu = self._machine.cpu_devices[0]
        cpu.start(begin=cpu.program_entry_point, end=cpu.program_exit_point)
