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

import unicorn
from unicorn import unicorn_const

from fiit.machine import CpuBits, CpuEndian
from fiit.emunicorn import (
    ArchArm32Unicorn, ArchArm32CoprocUnicorn, CpuRegistersUnicorn, MemoryUnicorn
)

from .fixtures import create_uc_arm, create_uc_arm_926, create_uc_arm_1176


# ==============================================================================


def test_get_model_from_uc():
    uc = create_uc_arm_926()
    assert ArchArm32Unicorn.get_model_from_uc(uc) == '926'
    uc = create_uc_arm_1176()
    assert ArchArm32Unicorn.get_model_from_uc(uc) == '1176'
    uc = create_uc_arm()
    assert ArchArm32Unicorn.get_model_from_uc(uc) is None


def test_uc_is_compatible_true():
    uc = create_uc_arm_926()
    assert ArchArm32Unicorn.uc_is_compatible(uc)


def test_uc_is_compatible_false():
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_MCLASS
    )

    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    assert not ArchArm32Unicorn.uc_is_compatible(uc)


def test_create_uc_little_endian():
    uc = ArchArm32Unicorn._create_uc(endian=CpuEndian.EL, model='926')
    assert isinstance(uc, unicorn.Uc)


def test_create_uc_big_endian():
    uc = ArchArm32Unicorn._create_uc(endian=CpuEndian.EB, model='926')
    assert isinstance(uc, unicorn.Uc)


def test_create_instance():
    cpu = ArchArm32Unicorn(endian=CpuEndian.EL, model='926')
    assert cpu.name == 'arm'
    assert cpu.bits == CpuBits.BITS_32
    assert cpu.endian == CpuEndian.EL
    assert cpu.variant == '926'
    assert isinstance(cpu.mem, MemoryUnicorn)
    assert isinstance(cpu.regs, CpuRegistersUnicorn)
    assert isinstance(cpu.coproc, ArchArm32CoprocUnicorn)


def test_from_backend():
    uc = create_uc_arm_926()
    cpu = ArchArm32Unicorn.from_backend(uc)
    assert cpu.name == 'arm'
    assert cpu.bits == CpuBits.BITS_32
    assert cpu.endian == CpuEndian.EL
    assert cpu.variant == '926'
    assert isinstance(cpu.mem, MemoryUnicorn)
    assert isinstance(cpu.regs, CpuRegistersUnicorn)
    assert isinstance(cpu.coproc, ArchArm32CoprocUnicorn)
