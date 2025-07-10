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

import re
from typing import Dict, List, Set, Any, cast

from fiit.unicorn.mmio_tracer import (
    CodeAddress, RegisterAddress, RegisterAddressFieldsMap, SvdPeripheralName,
    SvdPeripheralRegisterTree, SvdPeripheralRegisterFieldTree, RegisterField,
    WatchMemoryRangeDict, WatchRegisterDict, WatchSvdPeripheralDict,
    WatchSvdRegisterDict, UnicornMmioTracer, UnicornMmioTracerFrontend,
    UnicornMmioDbg, UnicornMmioDbgFrontend)
from fiit.core.config_loader import normalize_hex_int64
import fiit.plugins.context_config as ctx_conf
from fiit.core.plugin import FiitPlugin, FiitPluginContext
from fiit.core.shell import Shell


class MmioFilterConfigParser:
    _pattern_svd_name = re.compile(r'^([-_a-zA-Z0-9]{1,255})$')
    _pattern_svd_names = re.compile(r'^([-_a-zA-Z0-9]{1,255},?)+$(?<!,)')
    _pattern_address = re.compile(r'^0x[0-9a-fA-F]{0,16}$')
    _pattern_bit_fields = re.compile(r'^\[([0-9]{1,2}):([0-9]{1,2})\]$')
    _extract_bit_field = re.compile(r'\[([0-9]{1,2}):([0-9]{1,2})\]')

    def __init__(
            self,
            filter_keep_from_address: List[CodeAddress] = None,
            filter_exclude_from_address: List[CodeAddress] = None,
            filter_keep: List[Any] = None,
            filter_exclude: List[Any] = None,
            filter_state_change: List[Any] = None):

        self.filter_keep_from_address = set(filter_keep_from_address or [])
        self.filter_exclude_from_address = set(filter_exclude_from_address or [])

        self.filter_keep_address: Set[RegisterAddress] = set()
        self.filter_exclude_address: Set[RegisterAddress] = set()
        self.filter_register_state_change: Set[RegisterAddress] = set()
        self.filter_field_state_change: RegisterAddressFieldsMap = {}

        self.svd_filter_peripheral_keep: Set[SvdPeripheralName] = set()
        self.svd_filter_register_keep: SvdPeripheralRegisterTree = {}
        self.svd_filter_peripheral_exclude: Set[SvdPeripheralName] = set()
        self.svd_filter_register_exclude: SvdPeripheralRegisterTree = {}
        self.svd_filter_register_state_change: SvdPeripheralRegisterTree = {}
        self.svd_filter_field_state_change: SvdPeripheralRegisterFieldTree = {}

        self._parse_sort_keep_exclude(
            filter_keep or [], self.filter_keep_address,
            self.svd_filter_peripheral_keep, self.svd_filter_register_keep)

        self._parse_sort_keep_exclude(
            filter_exclude or [], self.filter_exclude_address,
            self.svd_filter_peripheral_exclude, self.svd_filter_register_exclude)

        self._parse_sort_state_change(filter_state_change or [])

    def get_config(self):
        return self.__dict__

    def _parse_sort_keep_exclude(
            self, filter_exps: List[Any], addresses: Set[int],
            peripheral_names: Set[str], register_name: Dict[str, Set[str]]):
        for filter_exp in filter_exps:
            if type(filter_exp) == int:
                # 0xffffffc0
                addresses.add(filter_exp)
            elif type(filter_exp) == str:
                if self._pattern_address.match(filter_exp):
                    addresses.add(int(filter_exp, 16))
                elif match := self._pattern_svd_name.match(filter_exp):
                    # PERIPH1
                    peripheral_names.add(match.group())
                elif (exp := filter_exp.split('::')) and len(exp) == 2 \
                        and self._pattern_svd_name.match(exp[0]) \
                        and self._pattern_svd_names.match(exp[1]):
                    # PERIPH1::R1,R2,...
                    register_name.update({exp[0]: set(exp[1].split(','))})
                else:
                    raise ValueError(f'Invalid Filter "{filter_exp}"')
            else:
                raise ValueError(f'Invalid Filter "{str(filter_exp)}"')

    def _parse_sort_state_change(self, filter_exps: List[Any]):
        for filter_exp in filter_exps:
            if type(filter_exp) == int:
                # 0xffffffc0
                self.filter_register_state_change.add(filter_exp)
            elif type(filter_exp) == str:
                if self._pattern_address.match(filter_exp):
                    # 0xffffffc0
                    self.filter_register_state_change.add(int(filter_exp, 16))
                elif (exp := filter_exp.split('::')) and len(exp) == 2 \
                        and self._pattern_address.match(exp[0]) \
                        and self._check_bit_field_exps(exp[1]):
                    # 0xffffffc0::[0:4],[7:8]
                    address = int(exp[0], 16)
                    self.filter_field_state_change.setdefault(address, [])
                    matches = self._extract_bit_field.findall(exp[1])
                    for lsb, msb in matches:
                        self.filter_field_state_change[address].append(
                            RegisterField(int(lsb), (int(msb) - int(lsb)) + 1))
                elif (exp := filter_exp.split('::')) and len(exp) == 2 \
                        and self._pattern_svd_name.match(exp[0]) \
                        and self._pattern_svd_names.match(exp[1]):
                    # PERIPH1::R1,R2,...
                    self.svd_filter_register_state_change.update(
                        {exp[0]: set(exp[1].split(','))})
                elif (exp := filter_exp.split('::')) and len(exp) == 3 \
                        and self._pattern_svd_name.match(exp[0]) \
                        and self._pattern_svd_name.match(exp[1]) \
                        and self._pattern_svd_names.match(exp[2]):
                    # PERIH1::R1:F1,F2,...
                    self.svd_filter_field_state_change.setdefault(
                        exp[0], {})
                    self.svd_filter_field_state_change[exp[0]].setdefault(
                        exp[1], set())
                    self.svd_filter_field_state_change[exp[0]][exp[1]].update(
                        set(exp[2].split(',')))
                else:
                    raise ValueError(f'Invalid Filter "{filter_exp}"')
            else:
                raise ValueError(f'Invalid Filter "{str(filter_exp)}"')

    def _check_bit_field_exps(self, exp: str) -> bool:
        bit_field_exps = exp.split(',')
        flag = False
        if len(bit_field_exps) >= 1:
            for bit_field in bit_field_exps:
                if not self._pattern_bit_fields.match(bit_field):
                    flag = False
                    break
                else:
                    flag = True
        return flag


def normalize_monitored_memories(value: list) -> dict:
    normalized = dict()
    memory_ranges: List[WatchMemoryRangeDict] = []
    registers: List[WatchRegisterDict] = []
    svd_peripherals: List[WatchSvdPeripheralDict] = []
    svd_registers: List[WatchSvdRegisterDict] = []

    for exp in value:
        keys = set(exp.keys())
        if keys.issubset(set(WatchMemoryRangeDict.__annotations__.keys())):
            exp['begin'] = normalize_hex_int64(exp['begin'])
            exp['end'] = normalize_hex_int64(exp['end'])
            memory_ranges.append(cast(WatchMemoryRangeDict, exp))
        elif keys.issubset(set(WatchRegisterDict.__annotations__.keys())):
            exp['address'] = normalize_hex_int64(exp['address'])
            registers.append(cast(WatchRegisterDict, exp))
        elif keys.issubset(set(WatchSvdPeripheralDict.__annotations__.keys())):
            svd_peripherals.append(cast(WatchSvdPeripheralDict, exp))
        elif keys.issubset(set(WatchSvdRegisterDict.__annotations__.keys())):
            svd_registers.append(cast(WatchSvdRegisterDict, exp))
        else:
            raise ValueError(f'Invalid memory expression "{str(value)}".')

    normalized['memory_ranges'] = memory_ranges
    normalized['registers'] = registers
    normalized['svd_peripherals'] = svd_peripherals
    normalized['svd_registers'] = svd_registers
    return normalized


def normalize_mmio_filters(value: dict) -> dict:
    if 'filter_keep_from_address' in value:
        value['filter_keep_from_address'] = [
            normalize_hex_int64(addr)
            for addr in value['filter_keep_from_address']]

    if 'filter_exclude_from_address' in value:
        value['filter_exclude_from_address'] = [
            normalize_hex_int64(addr)
            for addr in value['filter_exclude_from_address']]

    return MmioFilterConfigParser(**value).get_config()


# Warning: oneof/anyof coerce design bug
# see : https://github.com/pyeve/cerberus/issues/585
# see : https://github.com/pyeve/cerberus/issues/591
plugin_mmio_rule_set_registry = (
    ('DEF_MMIO_MONITORED_MEMORIES', {
        'type': 'list',
        'coerce': normalize_monitored_memories,
        'schema': {
            'type': 'dict',
            'anyof_schema': [
                {
                    'begin': {'type': ['integer', 'string']},
                    'end': {'type': ['integer', 'string']},
                    'access': {
                        'type': 'string',
                        'allowed': ['r', 'w', 'rw'],
                        'required': False
                    },
                    'name': {'type': 'string', 'required': False}
                },
                {
                    'address': {'type': ['integer', 'string']},
                    'access': {
                        'type': 'string',
                        'allowed': ['r', 'w', 'rw'],
                        'required': False
                    }
                },
                {
                    'svd_peripheral': {'type': 'string'},
                    'access': {
                        'type': 'string',
                        'allowed': ['r', 'w', 'rw'],
                        'required': False
                    }
                },
                {
                    'svd_peripheral': {'type': 'string'},
                    'svd_register': {'type': 'string'},
                    'access': {
                        'type': 'string',
                        'allowed': ['r', 'w', 'rw'],
                        'required': False
                    }
                }

            ],
        }
    }),

    ('DEF_MMIO_FILTERS', {
        'type': 'dict',
        'coerce': normalize_mmio_filters,
        'default': dict(),
        'schema': {
            'filter_keep_from_address': {
                'type': 'list',
                'schema': {'type': ['integer', 'string']},
                'required': False
            },
            'filter_exclude_from_address': {
                'type': 'list',
                'schema': {'type': ['integer', 'string']},
                'required': False
            },
            'filter_keep': {
                'type': 'list',
                'schema': {'type': ['integer', 'string']},
                'required': False
            },
            'filter_exclude': {
                'type': 'list',
                'schema': {'type': ['integer', 'string']},
                'required': False
            },
            'filter_state_change': {
                'type': 'list',
                'schema': {'type': ['integer', 'string']},
                'required': False
            }
        }
    })

)


class PluginUnicornMmioTracer(FiitPlugin):
    NAME = 'plugin_unicorn_mmio_tracer'
    REQUIREMENTS = [
        ctx_conf.UNICORN_UC.as_require()]
    OPTIONAL_REQUIREMENTS = [
        ctx_conf.SHELL.as_require()]
    OBJECTS_PROVIDED = [
        ctx_conf.UNICORN_MMIO_TRACER]
    CONFIG_SCHEMA_RULE_SET_REGISTRY = plugin_mmio_rule_set_registry
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'monitored_memory': 'DEF_MMIO_MONITORED_MEMORIES',
                'mmio_filters': 'DEF_MMIO_FILTERS',
                'svd_resource': {'type': 'string', 'default': False},
                'log': {'type': 'boolean', 'default': False},
                'log_show_field_states': {'type': 'boolean', 'default': False},
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
        mmio_tracer = UnicornMmioTracer(
            requirements['unicorn_uc'],
            plugin_config['monitored_memory'],
            plugin_config['mmio_filters'],
            plugin_config['svd_resource'],
            plugin_config['log'],
            plugin_config['log_show_field_states'])

        if emulator_shell := optional_requirements.get('emulator_shell'):
            emulator_shell = cast(Shell, emulator_shell)
            UnicornMmioTracerFrontend(mmio_tracer, emulator_shell)

        plugins_context.add(ctx_conf.UNICORN_MMIO_TRACER.name, mmio_tracer)


class PluginUnicornMmioDbg(FiitPlugin):
    NAME = 'plugin_unicorn_mmio_dbg'
    REQUIREMENTS = [
        ctx_conf.UNICORN_DBG.as_require()]
    OPTIONAL_REQUIREMENTS = [
        ctx_conf.SHELL.as_require()]
    OBJECTS_PROVIDED = [
        ctx_conf.UNICORN_MMIO_DBG]
    CONFIG_SCHEMA_RULE_SET_REGISTRY = plugin_mmio_rule_set_registry
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'monitored_memory': 'DEF_MMIO_MONITORED_MEMORIES',
                'mmio_filters': 'DEF_MMIO_FILTERS',
                'svd_resource': {'type': 'string', 'default': False}
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
        mmio_dbg = UnicornMmioDbg(requirements[ctx_conf.UNICORN_DBG.name], **plugin_config)

        if shell := optional_requirements.get(ctx_conf.SHELL.name):
            shell = cast(Shell, shell)
            shell.stream_logger_to_shell_stdout(mmio_dbg.LOGGER_NAME)
            UnicornMmioDbgFrontend(mmio_dbg, shell)

        plugins_context.add(ctx_conf.UNICORN_MMIO_DBG.name, mmio_dbg)
