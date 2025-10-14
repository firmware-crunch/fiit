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

from dataclasses import dataclass, field
from typing import Type, cast,  Any, List, Dict, Union

from ..dev_utils import SingletonPattern

from .defines import CBaseType, FACTORY_TYPE, BASIC_TYPE, EXTRA_TYPE
from .arch_arm import (
    arm_eb_32_ctype_config, arm_el_32_ctype_config, _FP_16_CODEC_DEFAULT,
    _FP_16_CODEC, Fp16
)


_CTYPE_CONFIG: Dict[str, Dict[Type[CBaseType], dict]] = {
    'arm:el:32': arm_el_32_ctype_config,
    'arm:eb:32': arm_eb_32_ctype_config
}


@dataclass
class CTypesConfig:
    basic_type: Dict[str, Type[CBaseType]] = field(init=False, default_factory=dict)
    extra_type: Dict[str, Type[CBaseType]] = field(init=False, default_factory=dict)
    factory_type: List[Type[CBaseType]] = field(init=False, default_factory=list)

    def get_all_types(self) -> Dict[str, Type[CBaseType]]:
        all_types = dict()
        all_types.update(self.basic_type)
        all_types.update(self.extra_type)
        return all_types

    def copy(self) -> 'CTypesConfig':
        new_copy = self.__class__()
        new_copy.basic_type = dict(self.basic_type)
        new_copy.extra_type = dict(self.extra_type)
        new_copy.factory_type = list(self.factory_type)
        return new_copy


class _CDataTypeCache(metaclass=SingletonPattern):
    """The C data type cache is singleton which host a cache registry where
    each registry key is a string which match a c type architecture and type
    options in the following form:
    <cpu>:<endian>:<size>+<option1>,<option2>...
    """
    def __init__(self):
        self._cache_registry: Dict[str, CTypesConfig] = dict()

    def add_cache_entry(self, arch: str, cdata_types: CTypesConfig):
        if arch not in self._cache_registry:
            self._cache_registry.update({arch: cdata_types})

    def get_cache_entry(self, arch: str) -> Union[CTypesConfig, None]:
        return self._cache_registry.get(arch, None)

    def propagate_in_scopes(self, arch: str, scopes: List[Dict[str, Any]]):
        if ctype_config := self._cache_registry.get(arch, None):
            for sc in scopes:
                for _, cdata_type in ctype_config.get_all_types().items():
                    sc[cdata_type.__name__] = cdata_type
                for cdata_type in ctype_config.factory_type:
                    sc[cdata_type.__name__] = cdata_type


def configure_ctypes(
    arch: str,
    scopes: List[Dict[str, Any]] = None,
    options: Dict[str, str] = None,
) -> CTypesConfig:
    ctypes_config = CTypesConfig()
    cdata_type_cache = _CDataTypeCache()
    options_str = list()
    _options = options if options is not None else dict()

    if arch.startswith(('arm:el:32', 'arm:eb:32')):
        if fp16_format := _options.get('fp16_format', None):
            fp_16_codec = _FP_16_CODEC[fp16_format]
        else:
            fp16_format = _FP_16_CODEC_DEFAULT.name
            fp_16_codec = _FP_16_CODEC_DEFAULT

        options_str.append(f'fp16_format={fp16_format}')

    cache_str_entry = f'{arch}' \
                      f'{"+" if len(options_str) > 0 else "" }' \
                      f'{",".join(options_str)}'

    if cache_entry := cdata_type_cache.get_cache_entry(cache_str_entry):
        if scopes:
            cdata_type_cache.propagate_in_scopes(cache_str_entry, scopes)
        return cache_entry

    for type_cat, config in _CTYPE_CONFIG[arch].items():
        for ctype, type_config in config.items():
            new_ctype = type(ctype.__name__, (ctype,), type_config)
            new_ctype = cast(Type[CBaseType], new_ctype)

            if arch.startswith(('arm:el:32', 'arm:eb:32')) and ctype is Fp16:
                new_ctype.codec = fp_16_codec
                new_ctype._codec = new_ctype.codec(new_ctype.endian)

            if type_cat == FACTORY_TYPE:
                ctypes_config.factory_type.append(new_ctype)
            elif type_cat == BASIC_TYPE:
                ctypes_config.basic_type.update({new_ctype._name_: new_ctype})
            elif type_cat == EXTRA_TYPE:
                ctypes_config.extra_type.update({new_ctype._name_: new_ctype})

    cdata_type_cache.add_cache_entry(cache_str_entry, ctypes_config)
    if scopes:
        cdata_type_cache.propagate_in_scopes(cache_str_entry, scopes)
    return ctypes_config
