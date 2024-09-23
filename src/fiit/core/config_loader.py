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

import json
import yaml
import os
import struct
from typing import Union

import cerberus

from .emulator_types import MemoryRange
from .config_schema import RULE_SET_REGISTRY


def normalize_hex_int(value: Union[str, int]) -> int:
    if type(value) == int:  # for yaml config
        return value
    else:  # str
        return int(value, 16)


def normalize_hex_int64(value: Union[str, int]) -> int:
    value_type = type(value)
    if value_type == int:  # for yaml config
        struct.pack('Q', value)
        return value
    else:  # str
        struct.pack('Q', int(value, 16))
        return int(value, 16)


class ConfigValidator(cerberus.Validator):
    def _normalize_coerce_hex_int(self, value):
        try:
            if type(value) == int:  # for yaml config
                return value
            else:
                return int(value, 16)
        except (ValueError, TypeError) as exc:
            err_str = f'Must be an integer hexadecimal string number: ' \
                      f'{str(exc)}.'
            self._error(err_str)

    def _check_with_mem_perm(self, field, value):
        for char in value:
            if char not in ['r', 'w', 'x']:
                self._error(field, f'Invalid memory permission string, must a '
                                   f'free combination of these character '
                                   f'["r", "w", "x"]: {value}')

    def _check_with_hex_int64(self, field, value):
        try:
            if type(value) == int:  # for yaml config
                struct.pack('Q', value)
                return True
            else:
                struct.pack('Q', int(value, 16))
                return True
        except (ValueError, TypeError, struct.error) as exc:
            err_str = f'Must be a 64 bit number as hexadecimal string or ' \
                      f'integer representation: {str(exc)}.'
            self._error(err_str)

    def _normalize_coerce_hex_int64(self, value):
        try:
            return normalize_hex_int64(value)
        except (ValueError, TypeError, struct.error) as exc:
            err_str = f'Must be a 64 bit hexadecimal string number: {str(exc)}.'
            self._error(err_str)

    @staticmethod
    def _normalize_coerce_memory_ranges(value):
        return [
            MemoryRange(
                normalize_hex_int64(r['begin']),
                normalize_hex_int64(r['end']),
                r.get('name', None))
            for r in value]


class ConfigLoaderError(Exception):
    pass


class ConfigLoader:

    def __init__(self):
        self.config = {}
        self.validator = ConfigValidator()
        self.validator.rules_set_registry.extend(RULE_SET_REGISTRY)

    def load_config(
        self, config_file_path: str, schema: dict
    ) -> Union[dict, list]:
        with open(config_file_path, 'r') as f:
            _, ext = os.path.splitext(config_file_path)
            if ext == '.yaml':
                config = yaml.safe_load(f)
            elif ext == '.json':
                config = json.loads(f.read())
            else:
                raise ConfigLoaderError('Invalid configuration file extension.')

        schema_r = {'root': schema}
        config_r = {'root': config}
        is_valid = self.validator.validate(config_r, schema_r, normalize=False)

        if is_valid:
            self.config = self.validator.normalized(config_r, schema_r)['root']
        else:
            self.config = {}
            raise ConfigLoaderError(f'Config load error: '
                                    f'{self.validator.errors}')

        return self.config
