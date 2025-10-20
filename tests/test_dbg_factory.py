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

from fiit import FiitCpuFactory, FiitDbgFactory
from fiit.emunicorn import DebuggerUnicorn
from fiit.machine import DeviceCpu

import pytest

# ==============================================================================


def test_get_dbg():
    cpu = FiitCpuFactory.get('unicorn', 'arm32', endian='le')
    dbg = FiitDbgFactory.get(cpu)
    assert isinstance(dbg, DebuggerUnicorn)


def test_get_dbg_invalid_cpu():
    class UnsupportedCpu:
        cpu = None

    with pytest.raises(ValueError):
        dbg = FiitDbgFactory.get(UnsupportedCpu())


def test_get_dbg_cpu_not_supported():
    class UnsupportedCpu:
        class mem:
            name = 'ram0'
        regs = None

    cpu = DeviceCpu(UnsupportedCpu)

    with pytest.raises(ValueError):
        dbg = FiitDbgFactory.get(cpu)


