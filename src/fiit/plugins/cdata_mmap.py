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
    'PluginCdataMmap'
]

from typing import Dict, Any, cast, List

from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.machine import Machine
from fiit.ctypesarch import (
    configure_ctypes, CTypesTranslator, CDataMemMapper, CTYPES_TRANSLATOR_FLAVOR
)

from . import CTX_REQ_MACHINE, CTX_CDATA_MMAP

# ==============================================================================


class PluginCdataMmap(FiitPlugin):
    NAME = 'plugin_cdata_mmap'
    REQUIREMENTS = [CTX_REQ_MACHINE]
    OBJECTS_PROVIDED = [CTX_CDATA_MMAP]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'keysrules': {'type': 'string'},
            'valuesrules': {
                'type': 'dict',
                'schema': {
                    'ctypes_options': {'type': 'dict', 'default': {}},
                    'ctypes_flavor': {
                        'type': 'string',
                        'allowed': ['pycparser', 'pycparserext_gnu'],
                        'default': 'pycparser'
                    },
                    'cdata_types_files': {
                        'type': 'list',
                        'schema': {'type': 'string'}, 'default': []
                    },
                    'cdata_mapping_files': {'type': 'list', 'default': []},
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
        machine = cast(Machine, requirements[CTX_REQ_MACHINE.name])
        mappers: List[CDataMemMapper] = []

        for cpu_name, config in plugin_config.items():
            cpu = machine.get_device_cpu(cpu_name)
            arch = f'{cpu.name}:{cpu.endian.label_hc_lc}:{cpu.bits.value}'
            options = config['ctypes_options']
            flavor = CTYPES_TRANSLATOR_FLAVOR[config['ctypes_flavor']]
            ctypes_config = configure_ctypes(arch, options=options)
            ctt = CTypesTranslator(ctypes_config, flavor)

            for cdata_type_file in config['cdata_types_files']:
                extra_cdata_types = ctt.translate_from_file(cdata_type_file)
                ctt.add_cdata_type(extra_cdata_types)

            cdata_mem_mapper = CDataMemMapper(cpu.mem, ctt.get_ctypes_config())

            for cdata_map_file in config['cdata_mapping_files']:
                cdata_mem_mapper.map_cdata_from_file(cdata_map_file)

            mappers.append(cdata_mem_mapper)

        plugins_context.add(CTX_CDATA_MMAP.name, mappers)
