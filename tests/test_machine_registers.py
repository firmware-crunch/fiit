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

from fiit.machine import CpuRegisters

# ==============================================================================


# ------------------------------------------------------------------------------
# fixture


class CustomCpuRegisters(CpuRegisters):
    def __init__(self):
        CpuRegisters.__init__(
            self,
            ['pc', 'sp', 'r0'],
            'pc', 'sp',
            ['_pc', '_sp', '_r0', '_r1', '_mapping']
        )
        self._pc = 0
        self._sp = 0
        self._r0 = 0
        self._r1 = 0
        self._mapping = {
            'pc': self._pc, 'sp': self._sp, 'r0': self._r0, 'r1': self._r1
        }

    def read(self, register: str) -> int:
        if register in self._mapping and register in self._register_names:
            return self._mapping[register]
        else:
            raise ValueError('invalid register name')

    def write(self, register: str, value: int) -> None:
        if register in self._mapping and register in self._register_names:
            self._mapping[register] = value
        else:
            raise ValueError('invalid register name')


# ------------------------------------------------------------------------------

def test_get_invalid_register():
    regs = CustomCpuRegisters()

    with pytest.raises(AttributeError) as exc_info:
        assert regs.r1 == 500


def test_set_invalid_register():
    regs = CustomCpuRegisters()

    with pytest.raises(AttributeError) as exc_info:
        regs.r1 = 0xdeadbeef


def test_get_register_names():
    assert set(CustomCpuRegisters().register_names) == {'pc', 'sp', 'r0'}


def test_set_register_names():
    regs = CustomCpuRegisters()

    regs.register_names = ['pc', 'sp', 'r0', 'r1']

    assert set(regs.register_names) == {'pc', 'sp', 'r0', 'r1'}
    assert regs.r1 == 0

    regs.r1 = 0xff

    assert regs.r1 == 0xff


def test_save():
    regs = CustomCpuRegisters()
    regs.pc = 10
    regs.sp = 20
    regs.r0 = 30
    assert regs.save() == {'pc': 10, 'sp': 20, 'r0': 30}


def test_save_with_filter():
    regs = CustomCpuRegisters()
    regs.pc = 10
    regs.sp = 20
    regs.r0 = 30
    assert regs.save(include_filter=['sp', 'r0']) == {'sp': 20, 'r0': 30}


def test_restore():
    regs = CustomCpuRegisters()
    regs.pc = 10
    regs.sp = 20
    regs.r0 = 30
    context = regs.save()

    assert context == {'pc': 10, 'sp': 20, 'r0': 30}

    context['pc'] = 100
    context['sp'] = 110
    context['r0'] = 120
    regs.restore(context)

    assert regs.pc == 100
    assert regs.sp == 110
    assert regs.r0 == 120


def test_set_arch_pc():
    regs = CustomCpuRegisters()
    regs.arch_pc = 10
    assert regs.arch_pc == 10


def test_set_arch_sp():
    regs = CustomCpuRegisters()
    regs.arch_sp = 50
    assert regs.arch_sp == 50
