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

import os
import struct
import tempfile
import textwrap

import pytest

from fiit.emu.emu_types import MemoryRange
from fiit.config_loader import (
    ConfigLoader, ConfigLoaderError, normalize_hex_int64, normalize_hex_int)


current_path = os.path.dirname(os.path.realpath(__file__))


def test_normalize_hex_int64_as_integer():
    assert normalize_hex_int64(0x100) == 0x100


def test_normalize_hex_int64_as_string():
    assert normalize_hex_int64('0x100') == 0x100


def test_normalize_hex_int64_out_of_bound():
    with pytest.raises(struct.error):
        normalize_hex_int64(0x1ffffffffffffffff)


def test_normalize_hex_int_as_integer():
    assert normalize_hex_int(0x100) == 0x100


def test_normalize_hex_int_as_string():
    assert normalize_hex_int("0x100") == 0x100


def load_yaml_config(schema, config_str, ext='.yaml') -> dict:
    with tempfile.NamedTemporaryFile(suffix=ext) as temp:
        temp.write(textwrap.dedent(config_str).encode('utf-8'))
        temp.flush()
        return ConfigLoader().load_config(temp.name, schema)


def test_load_config_invalid_file_ext():
    with pytest.raises(ConfigLoaderError):
        load_yaml_config({}, "", '.txt')


def test_load_config_yaml_file():
    schema = {'type': 'dict', 'schema': {
                'test_conf': {'type': 'dict',
                              'schema': {'address': {'type': 'integer'}}}}}
    yaml_conf = """
    test_conf:
      address: 0xffffffff
    """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['test_conf']['address'] == 0xffffffff


def test_load_config_json_file():
    schema = {'type': 'dict', 'schema': {
                'test_conf': {'type': 'dict',
                              'schema': {'address': {'type': 'string'}}}}}
    yaml_conf = """ {"test_conf": {"address": "0xffffffff"}} """
    conf = load_yaml_config(schema, yaml_conf, '.json')
    assert conf['test_conf']['address'] == '0xffffffff'


def test_load_config_yaml_file_invalid_config():
    schema = {'type': 'dict', 'schema': {
                'test_conf': {'type': 'dict',
                              'schema': {'address': {'type': 'integer'}}}}}
    yaml_conf = """
    test_conf:
      address: "0xffffffff"
    """
    with pytest.raises(ConfigLoaderError):
        load_yaml_config(schema, yaml_conf, '.yaml')


def test_config_validator_check_with_hex_int64_value_integer():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'check_with': 'hex_int64'}}}
    yaml_conf = """ address: 0xffffffff """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == 0xffffffff


def test_config_validator_check_with_hex_int64_value_string():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'check_with': 'hex_int64'}}}
    yaml_conf = """ address: "0xffffffff" """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == "0xffffffff"


def test_config_validator_check_with_hex_int64_invalid_value():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'check_with': 'hex_int64'}}}
    yaml_conf = """ address: true """
    with pytest.raises(AttributeError):
        load_yaml_config(schema, yaml_conf, '.yaml')


def test_config_validator_normalize_hex_int64_value_int():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int64'}}}
    yaml_conf = """ address: 0xffffffff """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == 0xffffffff


def test_config_validator_normalize_hex_int64_value_string():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int64'}}}
    yaml_conf = """ address: "0xffffffff" """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == 0xffffffff


def test_config_validator_normalize_hex_int64_invalid_value():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int64'}}}
    yaml_conf = """ address: "0x1ffffffffffffffff" """
    with pytest.raises(AttributeError):
        load_yaml_config(schema, yaml_conf, '.yaml')


def test_config_validator_normalize_hex_int_value_int():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int'}}}
    yaml_conf = """ address: 0xffffffff """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == 0xffffffff


def test_config_validator_normalize_hex_int_value_string():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int'}}}
    yaml_conf = """ address: "0xffffffff" """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['address'] == 0xffffffff


def test_config_validator_normalize_hex_int_invalid_value():
    schema = {'type': 'dict', 'schema': {
                'address': {'type': ['string', 'integer'],
                            'coerce': 'hex_int'}}}
    yaml_conf = """ address: true """
    with pytest.raises(AttributeError):
        load_yaml_config(schema, yaml_conf, '.yaml')


def test_config_validator_check_with_mem_perm():
    schema = {'type': 'dict', 'schema': {
                'access': {'type': 'string',
                           'check_with': 'mem_perm'}}}
    yaml_conf = """ access: rw """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert conf['access'] == 'rw'


def test_config_validator_check_with_mem_perm_invalid():
    schema = {'type': 'dict', 'schema': {
                'access': {'type': 'string',
                           'check_with': 'mem_perm'}}}
    yaml_conf = """ access: rwq """
    with pytest.raises(ConfigLoaderError):
        load_yaml_config(schema, yaml_conf, '.yaml')


def test_config_validator_normalize_memory_ranges():
    schema = {'type': 'dict', 'schema': {'memory_ranges': 'DEF_MEMORY_RANGES'}}
    yaml_conf = """
    memory_ranges:
      - {begin: 0x0, end: "0x100", name: text}
    """
    conf = load_yaml_config(schema, yaml_conf, '.yaml')
    assert len(conf['memory_ranges']) == 1
    assert isinstance(conf['memory_ranges'][0], MemoryRange)
    assert conf['memory_ranges'][0].begin == 0x0
    assert conf['memory_ranges'][0].end == 0x100
    assert conf['memory_ranges'][0].name == 'text'
