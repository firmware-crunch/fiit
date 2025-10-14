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

import ctypes
from dataclasses import dataclass
from typing import Dict, Union

from ..dev_utils import SingletonPattern
from ..config_loader import ConfigLoader
from ..machine import Memory

from .base_types import CBaseType, DataPointerBase, mem_sync_ctypes_factory
from .config import CTypesConfig
from .translator import CTypesTranslator


@dataclass
class CDataMemMapEntry:
    address: int
    cdata: CBaseType
    name: str


class CDataMemMapCache(metaclass=SingletonPattern):
    def __init__(self):
        self._cache_registry: Dict[Memory, Dict[str, CDataMemMapEntry]] \
            = dict()

    def add_cache_entry(self, memory: Memory):
        if memory not in self._cache_registry:
            self._cache_registry.update({memory: dict()})

    def get_cache_entry(
        self, memory: Memory
    ) -> Union[Dict[str, CDataMemMapEntry], None]:
        return self._cache_registry.get(memory, None)

    def store_cdata(
        self, memory: Memory, cdata_entry: CDataMemMapEntry
    ):
        self._cache_registry[memory].update(
            {cdata_entry.name: cdata_entry})

    def find_cdata_by_name(
        self, memory: Memory, name: str
    ) -> Union[CDataMemMapEntry, None]:
        if cache_entry := self._cache_registry.get(memory):
            return cache_entry.get(name, None)


class CDataMemMapError(Exception):
    pass


class CDataMemMapper:
    SCHEMA_MAP_FILE = {
        'type': 'list',
        'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'type': {'type': 'string'},
                'name': {'type': 'string'},
                'address': 'DEF_INT64',
            }
        }
    }

    def __init__(self, memory: Memory, ctypes_config: CTypesConfig):
        self._mem = memory
        self._cdata_mem_map_cache = CDataMemMapCache()
        self._cdata_mem_map_cache.add_cache_entry(memory)
        self._ctypes_translator = CTypesTranslator(ctypes_config)

    @property
    def mem(self) -> Memory:
        return self._mem

    def get_all_mapping(self) -> Union[Dict[str, CDataMemMapEntry], None]:
        return self._cdata_mem_map_cache.get_cache_entry(self._mem)

    def get_cdata_mapping(self, name: str) -> Union[CDataMemMapEntry, None]:
        return self._cdata_mem_map_cache.find_cdata_by_name(self._mem, name)

    def map_cdata(
        self, cdata_type_name: str, cdata_name: str, address: int
    ) -> CBaseType:

        cdata_type = self._ctypes_translator.parse_type(cdata_type_name)

        mem_region = list(filter(
            lambda m: m.base_address <= address < m.end_address,
            self._mem.regions))

        if not mem_region:
            raise CDataMemMapError(
                f'Address {address:#x} not mapped in memory "{self._mem}"')

        mem_region = mem_region[0]

        if (address + ctypes.sizeof(cdata_type)) - 1 > mem_region.end_address:
            raise CDataMemMapError(
                f'C data binding at "{address}" error, overflow memory region '
                f'{mem_region.base_address:#x}-{mem_region.end_address:#x}.')

        if mem_region.host_mem is None:
            sync_ctype = mem_sync_ctypes_factory(self._mem, address, cdata_type)
            cdata = sync_ctype()
        else:
            cdata_offset = address - mem_region.base_address
            addr_translation = mem_region.host_base_address + cdata_offset
            cdata = cdata_type.from_address(addr_translation)

        if isinstance(cdata, DataPointerBase):
            cdata.mem = self._mem

        map_entry = CDataMemMapEntry(address, cdata, cdata_name)
        self._cdata_mem_map_cache.store_cdata(self._mem, map_entry)
        return cdata

    def map_cdata_from_file(self, filename: str):
        loader = ConfigLoader()
        for cm in loader.load_config(filename, self.SCHEMA_MAP_FILE):
            self.map_cdata(cm['type'], cm['name'], cm['address'])
