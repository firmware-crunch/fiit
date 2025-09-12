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
##################################################################################

import pytest

from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.unicorn_const import UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN

from fiit.arch_ctypes.base_types import (
    Struct, Float, Double, UnsignedInt, Char
)
from fiit.arch_ctypes.arch_arm import Fp16
from fiit.arch_ctypes import configure_ctypes
from fiit.hooking_engine.cc_aapcs32 import CallingConventionARM

from .fixtures.cc.cc_tester import BasePyTestCallingConvention
from .fixtures.unicorn_utils import BinBlob2Emulator, CodeBreakpoint
from .fixtures.blobs import (
    BlobCcAapcs32ArmelV6SoftFloatFp16Ieee, BlobCcAapcs32ArmebV6SoftFloatFp16Ieee,
    BlobCcAapcs32ArmelV6HardFloatFp16Ieee, BlobCcAapcs32ArmebV6HardFloatFp16Ieee,
    BlobArmEl32IncLoop)


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_fp16_aggregate_valid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Fp16), ('c', Fp16), ('d', Fp16)]

    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    assert Fp16 == CallingConventionARM(uc)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_char_aggregate_invalid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Char), ('b', Char), ('c', Char), ('d', Char)]

    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    assert not CallingConventionARM(uc)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_homogenous_fp_aggregate_invalid_size():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Fp16), ('c', Fp16), ('d', Fp16),
                    ('e', Fp16)]

    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    assert not CallingConventionARM(uc)._is_aggregate_vfp_cprc(Aggr)


def test_cc_arm_is_aggregate_vfp_cprc_heterogeneous_aggregate_invalid_candidate():
    configure_ctypes('arm:el:32', [globals()])

    class Aggr(Struct):
        _fields_ = [('a', Fp16), ('b', Float)]

    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    assert not CallingConventionARM(uc)._is_aggregate_vfp_cprc(Aggr)


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

    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    assert Double == CallingConventionARM(uc)._is_aggregate_vfp_cprc(WrapL2)


def test_cc_arm_alloc_vfp_regs_invalid_vfp_cprc_type():
    uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    with pytest.raises(ValueError,
                       match='VFP alloc fail due to unsupported type'):
        CallingConventionARM(uc)._alloc_vfp_regs(UnsignedInt, 1)


def test_cc_arm_set_pc():
    break_address = 0xc
    patch_address = 0x14

    def hook(uc: Uc, address: int):
        assert break_address == break_address
        CallingConventionARM(uc).set_pc(patch_address)
        assert uc.mem_read(uc.reg_read(UC_ARM_REG_PC), 4) == b"\x01\x10\xa0\xe3"

    emu = BinBlob2Emulator(BlobArmEl32IncLoop)
    cb = CodeBreakpoint(emu.uc, hook, [break_address])
    emu.start()
    assert cb.break_count == 1


def test_cc_arm_get_cpu_context():
    def hook(uc: Uc, address: int):
        assert address == 0
        ctx = CallingConventionARM(uc).get_cpu_context()
        assert ctx.pc == 0
        assert ctx.sp == 0

    emu = BinBlob2Emulator(BlobArmEl32IncLoop)
    cb = CodeBreakpoint(emu.uc, hook, [0])
    emu.start()
    assert cb.break_count == 1


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
