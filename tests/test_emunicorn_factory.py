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

import unicorn

from fiit.machine import CpuEndian, CpuBits
from fiit.emunicorn import (
    CpuFactoryUnicorn, ArchArm32Unicorn, ArchArm32CoprocUnicorn,
    CpuRegistersUnicorn, MemoryUnicorn
)

from .fixtures import create_uc_arm_926, create_uc_arm_cortex

# ==============================================================================


def test_get_backend_name():
    assert CpuFactoryUnicorn.get_backend_name() == 'unicorn'


def test_get_backend_type():
    assert CpuFactoryUnicorn.get_backend_type() == unicorn.Uc


def test_class_from_arch_id():
    cpu_class = CpuFactoryUnicorn.class_from_arch_id('arm32')
    assert cpu_class == ArchArm32Unicorn


def test_class_from_arch_id_error():
    with pytest.raises(ValueError) as exc_info:
        cpu_class = CpuFactoryUnicorn.class_from_arch_id('legend')


def test_class_from_backend_instance():
    uc = create_uc_arm_926()
    cpu_class = CpuFactoryUnicorn.class_from_backend_instance(uc, 'arm32')
    assert cpu_class == ArchArm32Unicorn


def test_class_from_backend_instance_without_arch_id():
    uc = create_uc_arm_926()
    cpu_class = CpuFactoryUnicorn.class_from_backend_instance(uc, '')
    assert cpu_class == ArchArm32Unicorn


def test_class_from_backend_instance_error():
    uc = create_uc_arm_cortex()

    with pytest.raises(ValueError) as exc_info:
        cpu_class = CpuFactoryUnicorn.class_from_backend_instance(uc, 'arm32')


def test_create():
    cpu = CpuFactoryUnicorn.create('arm32', endian=CpuEndian.EB, model='926')
    assert cpu.name == 'arm'
    assert cpu.bits == CpuBits.BITS_32
    assert cpu.endian == CpuEndian.EB
    assert cpu.variant == '926'
    assert isinstance(cpu.mem, MemoryUnicorn)
    assert isinstance(cpu.regs, CpuRegistersUnicorn)
    assert isinstance(cpu.coproc, ArchArm32CoprocUnicorn)


def test_create_invalid_arch():
    with pytest.raises(ValueError) as exc_info:
        cpu = CpuFactoryUnicorn.create('legend')
