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

import pytest

from fiit.dev import FiitCpuFactory, ArchArm32, ArchArm32DDI0100
from fiit.machine import CpuEndian, CpuBits
from fiit.emunicorn import CpuFactoryUnicorn


# ==============================================================================


def test_get_cpu_factory_by_backend_name():
    factory = FiitCpuFactory._get_cpu_factory('unicorn')
    assert CpuFactoryUnicorn == factory


def test_get_cpu_factory_by_backend_instance():
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_ARM926
    )
    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    factory = FiitCpuFactory._get_cpu_factory(uc)
    assert CpuFactoryUnicorn == factory


def test_get_cpu_factory_not_exist():
    with pytest.raises(ValueError) as exc_info:
        FiitCpuFactory._get_cpu_factory('legend')


def test_get_cpu_device_class_arm():
    cpu_class = FiitCpuFactory._get_cpu_device_class('arm32')
    assert ArchArm32 == cpu_class


def test_get_cpu_device_class_invalid():
    with pytest.raises(ValueError) as exc_info:
        FiitCpuFactory._get_cpu_device_class('legend')


_FACTORY_KWARGS_ARM = {
    'endian': 'el',
    'dev_name': 'cpu0',
    'model': '926',
    'vfp': True,
    'thumb': True,
}


def test_extract_init_args():
    extracted = FiitCpuFactory._extract_init_args(
        ArchArm32DDI0100, _FACTORY_KWARGS_ARM, [('cpu', 0)]
    )
    assert extracted == {'vfp': True, 'dev_name': 'cpu0'}


def test_extract_init_args_missing():
    with pytest.raises(ValueError) as exc_info:
        FiitCpuFactory._extract_init_args(ArchArm32DDI0100, _FACTORY_KWARGS_ARM)


def test_select_arm_variant_base():
    cpu_class = FiitCpuFactory._select_arm32_variant('unicorn', {})
    assert ArchArm32 == cpu_class


def test_select_arm_variant_ddi0100_by_spec():
    cpu_class = FiitCpuFactory._select_arm32_variant(
        'unicorn', {'arm_spec': 'DDI0100'}
    )
    assert ArchArm32DDI0100 == cpu_class


def test_select_arm_variant_ddi0100_by_model():
    cpu_class = FiitCpuFactory._select_arm32_variant(
        'unicorn', {'model': '926'}
    )
    assert ArchArm32DDI0100 == cpu_class


def test_get_unicorn_cpu_by_name():
    cpu = FiitCpuFactory.get(
        'unicorn', 'arm32', 'cpu0', endian='el', arm_spec='DDI0100'
    )
    assert isinstance(cpu, ArchArm32DDI0100)
    assert isinstance(cpu.backend, unicorn.Uc)
    assert cpu.backend_name == 'unicorn'
    assert cpu.backend_type == unicorn.Uc
    assert cpu.endian == CpuEndian.EL
    assert cpu.bits == CpuBits.BITS_32


def test_get_unicorn_cpu_by_backend_instance():
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_ARM926
    )

    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)

    cpu = FiitCpuFactory.get(
        uc, 'arm32', 'cpu0', endian='el', arm_spec='DDI0100'
    )
    assert isinstance(cpu, ArchArm32DDI0100)
    assert isinstance(cpu.backend, unicorn.Uc)
    assert cpu.backend == uc
    assert cpu.backend_name == 'unicorn'
    assert cpu.backend_type == unicorn.Uc
    assert cpu.endian == CpuEndian.EL
    assert cpu.bits == CpuBits.BITS_32

