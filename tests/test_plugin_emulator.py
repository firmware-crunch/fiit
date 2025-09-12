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

import pytest

from .fixtures.fixture_utils import temp_named_txt_file

from fiit.plugins.shell import Shell
from fiit.plugin import PluginManager


plugin_conf = """
plugin_emulator:
  architecture: "arm:el:32:default"
  memory_mapping:
    - {name: ram0, base_address: 0x00000000, size: 0x04000000, perm: rwx}
  entry_point: 0x10000
  end_address: 0x10004
  host_memory_map: True
"""


@pytest.mark.parametrize(
    'temp_named_txt_file', [[plugin_conf, '.yaml']],
    indirect=['temp_named_txt_file'])
def test_load_plugin_unicorn_emulator(temp_named_txt_file, capsys):
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get('plugin_emulator') is not None
    uc = pl.plugins_context.get('unicorn_uc')
    uc.mem_write(0x10000, b'\x00\x00\xa0\xe1')
    pl.plugins_context.program_entry()


@pytest.mark.parametrize(
    'temp_named_txt_file', [[plugin_conf, '.yaml']],
    indirect=['temp_named_txt_file'])
def test_load_plugin_unicorn_emulator_with_frontend(temp_named_txt_file, capsys):
    pl = PluginManager()
    pl.plugins_context.add('shell', Shell())
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get('plugin_emulator') is not None
    uc = pl.plugins_context.get('unicorn_uc')
    uc.mem_write(0x10000, b'\x00\x00\xa0\xe1')
