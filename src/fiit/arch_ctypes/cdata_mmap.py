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
from typing import cast, Dict, Union

from ..dev_utils import SingletonPattern
from ..config_loader import ConfigLoader
from ..emu.emu_types import AddressSpace, MemoryRegion

from .base_types import CBaseType, DataPointerBase
from .config import CTypesConfig
from .translator import CTypesTranslator


@dataclass
class CDataMemMapEntry:
    address: int
    cdata: CBaseType
    name: str


class CDataMemMapCache(metaclass=SingletonPattern):
    def __init__(self):
        self._cache_registry: Dict[AddressSpace, Dict[str, CDataMemMapEntry]] \
            = dict()

    def add_cache_entry(self, address_space: AddressSpace):
        if address_space not in self._cache_registry:
            self._cache_registry.update({address_space: dict()})

    def get_cache_entry(
        self, address_space: AddressSpace
    ) -> Union[Dict[str, CDataMemMapEntry], None]:
        return self._cache_registry.get(address_space, None)

    def store_cdata(
        self, address_space: AddressSpace, cdata_entry: CDataMemMapEntry
    ):
        self._cache_registry[address_space].update(
            {cdata_entry.name: cdata_entry})

    def find_cdata_by_name(
        self, address_space: AddressSpace, name: str
    ) -> Union[CDataMemMapEntry, None]:
        if cache_entry := self._cache_registry.get(address_space):
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

    def __init__(self, address_space: AddressSpace, ctypes_config: CTypesConfig):
        self._address_space = address_space
        self._cdata_mem_map_cache = CDataMemMapCache()
        self._cdata_mem_map_cache.add_cache_entry(address_space)
        self._ctypes_translator = CTypesTranslator(ctypes_config)

    def get_all_mapping(self) -> Union[Dict[str, CDataMemMapEntry], None]:
        return self._cdata_mem_map_cache.get_cache_entry(self._address_space)

    def get_cdata_mapping(self, name: str) -> Union[CDataMemMapEntry, None]:
        return self._cdata_mem_map_cache.find_cdata_by_name(
            self._address_space, name)

    def map_cdata(
        self, cdata_type_name: str, cdata_name: str, address: int
    ) -> CBaseType:

        cdata_type = self._ctypes_translator.parse_type(cdata_type_name)

        mem_region = list(filter(
            lambda m: m.base_address <= address < m.end_address,
            self._address_space))

        if not mem_region:
            raise CDataMemMapError(
                f'Address {address:#x} not mapped in address space '
                f'{self._address_space}.')

        mem_region = cast(MemoryRegion, mem_region[0])

        if not mem_region.host_mem_area:
            raise CDataMemMapError(
                f'Raw memory map is not accessible for {address:#x}.')

        if (address + ctypes.sizeof(cdata_type)) - 1 > mem_region.end_address:
            raise CDataMemMapError(
                f'C data binding at "{address}" error, overflow memory region '
                f'{mem_region.base_address:#x}-{mem_region.end_address:#x}.')

        cdata = cdata_type.from_address(
            mem_region.host_base_address + (address - mem_region.base_address))

        if isinstance(cdata, DataPointerBase):
            cdata.address_space = self._address_space

        map_entry = CDataMemMapEntry(address, cdata, cdata_name)
        self._cdata_mem_map_cache.store_cdata(self._address_space, map_entry)
        return cdata

    def map_cdata_from_file(self, filename: str):
        loader = ConfigLoader()
        for cm in loader.load_config(filename, self.SCHEMA_MAP_FILE):
            self.map_cdata(cm['type'], cm['name'], cm['address'])
