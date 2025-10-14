#!/bin/bash

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

# IPY_TEST_SIMPLE_PROMPT=1 Force IPython to use input than readline.
IPY_TEST_SIMPLE_PROMPT=1 JUPYTER_PLATFORM_DIRS=1 pytest                        \
  --cov-report html                                                            \
  --cov="fiit"                                                                 \
  -s -v "${@}"                                                                 \
                                                                               \
test_dev_utils.py                                                              \
test_logger.py                                                                 \
test_config_loader.py                                                          \
                                                                               \
test_machine_defines.py                                                        \
test_machine_memory.py                                                         \
test_machine_registers.py                                                      \
test_machine_cpu.py                                                            \
test_machine_machine.py                                                        \
                                                                               \
test_emunicorn_registers.py                                                    \
test_emunicorn_memory.py                                                       \
test_emunicorn_cpu.py                                                          \
test_emunicorn_fix.py                                                          \
test_emunicorn_arm32_coproc.py                                                 \
test_emunicorn_arm32_cpu.py                                                    \
test_emunicorn_factory.py                                                      \
                                                                               \
test_dev_arm32.py                                                              \
test_dev_pl190.py                                                              \
test_dev_factory.py                                                            \
                                                                               \
test_dbg_dis_capstone.py                                                       \
test_dbg_uc.py                                                                 \
                                                                               \
test_ctypesarch_arch_arm32.py                                                  \
test_ctypesarch_defines.py                                                     \
test_ctypesarch_cdata.py                                                       \
test_ctypesarch_config.py                                                      \
test_ctypesarch_translator.py                                                  \
                                                                               \
test_iotrace_mmio_filter.py                                                    \
                                                                               \
test_shell_front_dbg.py                                                        \
test_shell_front_machine.py                                                    \
test_shell_shell.py                                                            \
                                                                               \
test_plugin.py                                                                 \
test_plugin_logger.py                                                          \
test_plugin_machine.py                                                         \
test_plugin_shell.py                                                           \
                                                                               \
test_hooking_cc_aapcs32.py

rm -rf .pytest_cache
