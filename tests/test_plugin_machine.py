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

from typing import cast

import pytest

from .fixtures.fixture_utils import temp_named_txt_file

from fiit.machine import Machine
from fiit.plugins import CTX_MACHINE
from fiit.plugins.shell import Shell
from fiit.plugin import PluginManager

# ==============================================================================


# -----------------------------------------------------------------------------
# fixture

plugin_conf = """
plugin_machine:
    devices:
        main_cpu:
            device_type: cpu
            device_config:
                cpu_backend: unicorn
                arch_id: arm32
                options: { endian: el, vfp: True, arm_spec: DDI0100 }
                memory_regions:
                    - name: MPMC_Chip_Select_0 
                      base_address: 0x0 
                      size: 0x2000000 
                      perm: rwx
                program_entry_point: 0x10000
                program_exit_point: 0x10004

        int_ctrl:
            device_type: pl190
            device_dependencies: [ main_cpu ]
            device_config:
                plug_cpu: main_cpu
                base_address: 0x10140000

        int_gen:
            device_type: pl190_int_gen
            device_dependencies: [ int_ctrl ]
            device_config:
                plug_intc: int_ctrl
                tick_unit: instruction
                tick_count: 1000
"""

# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    'temp_named_txt_file', [[plugin_conf, '.yaml']],
    indirect=['temp_named_txt_file'])
def test_load_plugin_machine(temp_named_txt_file, capsys):
    pl = PluginManager()
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get('plugin_machine') is not None
    machine = pl.plugins_context.get(CTX_MACHINE.name)
    machine = cast(Machine, machine)
    cpu = machine.get_device_cpu('main_cpu')
    cpu.mem.write(0x10000, b'\x00\x00\xa0\xe1')
    pl.plugins_context.program_entry()


@pytest.mark.parametrize(
    'temp_named_txt_file', [[plugin_conf, '.yaml']],
    indirect=['temp_named_txt_file'])
def test_load_plugin_unicorn_emulator_with_frontend(temp_named_txt_file, capsys):
    pl = PluginManager()
    pl.plugins_context.add('shell', Shell())
    pl.load_plugin_by_config_file(temp_named_txt_file.name)
    assert pl.plugins_context.get('plugin_machine') is not None
    machine = pl.plugins_context.get(CTX_MACHINE.name)
    machine = cast(Machine, machine)
    cpu = machine.get_device_cpu('main_cpu')
    cpu.mem.write(0x10000, b'\x00\x00\xa0\xe1')
