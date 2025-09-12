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
import pytest

from fiit.plugin import (
    PluginManager, PluginRequirementNotFound, PluginRequirementInvalidType
)

from .fixtures.plugins.plugin_p1 import PluginTestP1
from .fixtures.plugins.plugin_p2 import PluginTestP2
from .fixtures.plugins.plugin_p3 import PluginTestP3
from .fixtures.plugins.plugin_p8 import PluginTestP8, CustomObject
from .fixtures.fixture_utils import temp_named_txt_file


plugin_fixture_dir = \
    f'{os.path.dirname(os.path.realpath(__file__))}/fixtures/plugins'


@pytest.mark.parametrize(
    'temp_named_txt_file',
    [["""
        plugin_test_p1:
            activate: true

        plugin_test_p2:
            activate: false

        plugin_test_p3:
            activate: false

        plugin_test_p8:
            activate: false
        """,
      '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_loader_load_plugin_by_config_file(temp_named_txt_file):
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name, [plugin_fixture_dir])
    assert pl.plugins_context.get(PluginTestP1.NAME)
    assert pl.plugins_context.get(PluginTestP2.NAME), PluginTestP2
    assert pl.plugins_context.get(PluginTestP3.NAME), PluginTestP3
    assert pl.plugins_context.get(PluginTestP8.NAME), PluginTestP8
    assert pl.plugins_context.get('custom_object'), CustomObject


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p2: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_emulator_unload_plugin(temp_named_txt_file):
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name, [plugin_fixture_dir])
    pl.unload_plugin('plugin_test_p2')
    assert pl.plugins_context.get(PluginTestP2.NAME) is None


@pytest.mark.parametrize(
    'temp_named_txt_file',
    [["""
        plugin_test_p1:
            activate: true

        plugin_test_p2:
            activate: false

        plugin_test_p3:
            activate: false

        plugin_test_p8:
            activate: false
        """,
      '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_manager_load_plugin_by_config_file_with_extra_plugin_by_env(temp_named_txt_file):
    os.environ['EXTRA_PLUGIN_PATHS'] = plugin_fixture_dir
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get(PluginTestP1.NAME)
    assert pl.plugins_context.get(PluginTestP2.NAME), PluginTestP2
    assert pl.plugins_context.get(PluginTestP3.NAME), PluginTestP3
    assert pl.plugins_context.get(PluginTestP8.NAME), PluginTestP8


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p5: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_manager_load_plugin_by_config_file_plugin_dependency_not_found(temp_named_txt_file):
    with pytest.raises(PluginRequirementNotFound):
        PluginManager().load_plugin_by_config_file(temp_named_txt_file.name,
                                                   [plugin_fixture_dir])

@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p9: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_manager_load_plugin_by_config_file_object_dependency_not_found(temp_named_txt_file):
    with pytest.raises(PluginRequirementNotFound):
        PluginManager().load_plugin_by_config_file(temp_named_txt_file.name,
                                                   [plugin_fixture_dir])


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p6: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_manager_load_plugin_by_config_file_dependency_optional_invalid_type(temp_named_txt_file):

    class OtherType:
        pass

    pl = PluginManager()
    pl.plugins_context.add('plugin_test_optional_requirement', OtherType())

    with pytest.raises(PluginRequirementInvalidType):
        pl.load_plugin_by_config_file(temp_named_txt_file.name,
                                      [plugin_fixture_dir])


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p7: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_manager_load_plugin_by_config_file_config_schema_rule_set_registry(temp_named_txt_file):
    PluginManager().load_plugin_by_config_file(temp_named_txt_file.name,
                                               [plugin_fixture_dir])


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p4: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_emulator_load_plugin_not_implemented(temp_named_txt_file):
    with pytest.raises(NotImplementedError):
        PluginManager().load_plugin_by_config_file(temp_named_txt_file.name,
                                                   [plugin_fixture_dir])


@pytest.mark.parametrize(
    'temp_named_txt_file', [['plugin_test_p1: {activate: true}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_plugin_emulator_unload_plugin_not_implemented(temp_named_txt_file):
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name, [plugin_fixture_dir])

    with pytest.raises(NotImplementedError):
        pl.unload_plugin('plugin_test_p1')
