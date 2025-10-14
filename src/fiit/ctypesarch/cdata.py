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
from typing import Dict, Optional

from fiit.config import ConfigLoader
from fiit.machine import Memory

from .defines import CBaseType, DataPointerBase, mem_sync_ctypes_factory
from .config import CTypesConfig
from .translator import CTypesTranslator


@dataclass
class CDataMemMapEntry:
    address: int
    cdata: CBaseType
    name: str


class CDataMemMapCache:
    def __init__(self):
        self._cache: Dict[str, CDataMemMapEntry] = {}

    def get_all(self) -> Dict[str, CDataMemMapEntry]:
        return dict(self._cache)

    def store_cdata(self, cdata_entry: CDataMemMapEntry) -> None:
        self._cache.update({cdata_entry.name: cdata_entry})

    def get_cdata_by_name(self, name: str) -> Optional[CDataMemMapEntry]:
        if cache_entry := self._cache.get(name):
            return cache_entry


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
        self._ctypes_translator = CTypesTranslator(ctypes_config)

    @property
    def mem(self) -> Memory:
        return self._mem

    def get_all_mapping(self) -> Optional[Dict[str, CDataMemMapEntry]]:
        return self._cdata_mem_map_cache.get_all()

    def get_cdata_by_name(self, name: str) -> Optional[CDataMemMapEntry]:
        return self._cdata_mem_map_cache.get_cdata_by_name(name)

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
        self._cdata_mem_map_cache.store_cdata(map_entry)
        return cdata

    def map_cdata_from_file(self, filename: str):
        loader = ConfigLoader()
        for cm in loader.load_config(filename, self.SCHEMA_MAP_FILE):
            self.map_cdata(cm['type'], cm['name'], cm['address'])
