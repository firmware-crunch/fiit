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

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)

from fiit.core.plugin import PluginManager

from .fixtures.fixture_utils import temp_named_txt_file


VIC_0_BASE = 0x10140000
VIC_MAP_LEN = 0x10000


@pytest.mark.parametrize(
    'temp_named_txt_file',
    [[f'plugin_unicorn_arm_pl190: {{base_address: {VIC_0_BASE}}}', '.yaml']],
    indirect=['temp_named_txt_file'])
def test_load_plugin_unicorn_generic_arm_core(temp_named_txt_file, capsys):
    pl = PluginManager()
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(VIC_0_BASE, VIC_MAP_LEN, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    pl.plugins_context.add('unicorn_uc', uc)
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get('plugin_unicorn_arm_pl190') is not None
