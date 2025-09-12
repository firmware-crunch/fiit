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

from typing import Dict, Any, cast

from fiit.emu.emu_types import Architecture, ADDRESS_FORMAT
from fiit.arch_ctypes import (
    configure_ctypes, CTypesTranslator,
    CDataMemMapper, CTYPES_TRANSLATOR_FLAVOR
)
from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.shell.front_cdata_mmap import CDataMemMapperFrontend

from . import (
    CTX_EMULATOR_ADDRESS_SPACE, CTX_EMULATOR_ARCH, CTX_SHELL,
    CTX_CDATA_MEMORY_MAPPER
)



class PluginCdataMemoryMapper(FiitPlugin):
    NAME = 'plugin_cdata_memory_mapper'
    REQUIREMENTS = [
        CTX_EMULATOR_ADDRESS_SPACE.as_require(),
        CTX_EMULATOR_ARCH.as_require()]
    OPTIONAL_REQUIREMENTS = [
        CTX_SHELL.as_require()]
    OBJECTS_PROVIDED = [
        CTX_CDATA_MEMORY_MAPPER]
    CONFIG_SCHEMA = {
        NAME: {
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

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        arch = cast(Architecture, requirements[CTX_EMULATOR_ARCH.name])
        ctypes_arch = f'{arch.cpu_name}:{arch.endian}:{arch.mem_bit_size}'
        ctypes_options = plugin_config['ctypes_options']
        ctypes_flavor = CTYPES_TRANSLATOR_FLAVOR[plugin_config['ctypes_flavor']]

        ctypes_config = configure_ctypes(ctypes_arch, options=ctypes_options)
        ctt = CTypesTranslator(ctypes_config, ctypes_flavor)

        for cdata_type_file in plugin_config['cdata_types_files']:
            extra_cdata_types = ctt.translate_from_file(cdata_type_file)
            ctt.add_cdata_type(extra_cdata_types)

        cdata_mem_mapper = CDataMemMapper(
            requirements[CTX_EMULATOR_ADDRESS_SPACE.name], ctt.get_ctypes_config())

        for cdata_map_file in plugin_config['cdata_mapping_files']:
            cdata_mem_mapper.map_cdata_from_file(cdata_map_file)

        plugins_context.add(CTX_CDATA_MEMORY_MAPPER.name, cdata_mem_mapper)

        if shell := optional_requirements.get(CTX_SHELL.name):
            CDataMemMapperFrontend(
                cdata_mem_mapper, shell, ADDRESS_FORMAT[arch.mem_bit_size])
