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

from fiit import FiitCpuFactory
from fiit.machine import DeviceCpu, CpuEndian
from fiit.arch_ctypes.base_types import Struct, Float, Double, UnsignedInt, Char
from fiit.arch_ctypes.arch_arm import Fp16
from fiit.arch_ctypes import configure_ctypes
from fiit.hooking_engine.cc.aapcs32 import CallingConventionARM

from .fixtures.cc.cc_tester import BasePyTestCallingConvention
from .fixtures.cpu_utils import Blob2Cpu
from .fixtures.blobs import (
    BlobCcAapcs32ArmelV6SoftFloatFp16Ieee,
    BlobCcAapcs32ArmebV6SoftFloatFp16Ieee,
    BlobCcAapcs32ArmelV6HardFloatFp16Ieee,
    BlobCcAapcs32ArmebV6HardFloatFp16Ieee,
    BlobArmEl32IncLoop
)

# ==============================================================================


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_fp16_aggregate_valid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Fp16), ('c', Fp16), ('d', Fp16)]

    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    assert Fp16 == CallingConventionARM(emu)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_char_aggregate_invalid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Char), ('b', Char), ('c', Char), ('d', Char)]

    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    assert not CallingConventionARM(emu)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_fp_aggregate_invalid_size():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Fp16), ('c', Fp16), ('d', Fp16),
                    ('e', Fp16)]

    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    assert not CallingConventionARM(emu)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_heterogeneous_aggregate_invalid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Float)]

    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    assert not CallingConventionARM(emu)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_aggregates_with_nested_heterogeneous_aggregates_with_homogenous_sub_base_type():
    configure_ctypes('arm:el:32', [globals()])

    class FloatStructA(Struct):
        _fields_ = [('a', Double), ('b', Double)]

    class FloatStructB(Struct):
        _fields_ = [('c', Double), ('d', Double)]

    class WrapL1(Struct):
        _fields_ = [('b', FloatStructB)]

    class WrapL2(Struct):
        _fields_ = [('a', FloatStructA), ('wrap_l1', WrapL1)]

    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    assert Double == CallingConventionARM(emu)._is_aggregate_vfp_cprc(WrapL2)


def test_cc_arm_alloc_vfp_regs_invalid_vfp_cprc_type():
    emu = FiitCpuFactory.get('unicorn', 'arm32', endian=CpuEndian.EL)
    with pytest.raises(ValueError, match='VFP alloc fail due to unsupported type'):
        CallingConventionARM(emu)._alloc_vfp_regs(UnsignedInt, 1)


def test_cc_arm_set_pc():
    class Tester:
        def __init__(self):
            self.counter = 0
            self.break_address = 0xc
            self.patch_address = 0x14

        def hook(self, cpu: DeviceCpu, address: int):
            self.counter += 1
            assert self.break_address == self.break_address
            CallingConventionARM(cpu).set_pc(self.patch_address)
            assert cpu.mem.read(cpu.regs.arch_pc, 4) == b'\x01\x10\xa0\xe3'

    tester = Tester()
    machine_wrap = Blob2Cpu(BlobArmEl32IncLoop)
    machine_wrap.cpu.hook_code(tester.hook, tester.break_address)
    machine_wrap.start()
    assert tester.counter == 1


def test_cc_arm_get_cpu_context():
    class Tester:
        def __init__(self):
            self.counter = 0

        def hook(self, cpu: DeviceCpu, address: int):
            self.counter += 1
            assert address == 0
            ctx = CallingConventionARM(cpu).get_cpu_context()
            assert ctx.pc == 0
            assert ctx.sp == 0

    tester = Tester()
    machine_wrap = Blob2Cpu(BlobArmEl32IncLoop)
    machine_wrap.cpu.hook_code(tester.hook, 0)
    machine_wrap.start()
    assert tester.counter == 1


@pytest.mark.parametrize(
    'cc,torture_blob', [
        [CallingConventionARM, BlobCcAapcs32ArmelV6SoftFloatFp16Ieee],
        [CallingConventionARM, BlobCcAapcs32ArmelV6HardFloatFp16Ieee],
        [CallingConventionARM, BlobCcAapcs32ArmebV6SoftFloatFp16Ieee],
        [CallingConventionARM, BlobCcAapcs32ArmebV6HardFloatFp16Ieee]
    ]
)
class TestCallingConventionARM(BasePyTestCallingConvention):
    pass
