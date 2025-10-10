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

import tempfile

import pytest

import unicorn
from unicorn import arm_const

from fiit.emunicorn import CpuUnicorn, CpuRegistersUnicorn, MemoryUnicorn
from fiit.machine import TickUnit, CpuEndian, CpuBits

from .fixtures import MetaBinBlob
from .fixtures.blobs import BlobArmEl32MultiBlock, BlobArmEl32InvalidInsn
from .fixtures import create_uc_arm_926, create_uc_arm_1176

# ==============================================================================


# ------------------------------------------------------------------------------
# fixture

_UC_ARM_REG_MAPPING = {
    'r1': arm_const.UC_ARM_REG_R1,
    'r0': arm_const.UC_ARM_REG_R0,
    'sp':  arm_const.UC_ARM_REG_SP,
    'pc': arm_const.UC_ARM_REG_PC
}


def create_cpu() -> CpuUnicorn:
    uc = create_uc_arm_926()
    regs = CpuRegistersUnicorn(uc, _UC_ARM_REG_MAPPING, 'pc', 'sp')
    regs.register_names = list(_UC_ARM_REG_MAPPING.keys())
    mem = MemoryUnicorn(uc, CpuBits.BITS_32, CpuEndian.EL)
    cpu = CpuUnicorn(uc, regs, mem)
    return cpu


def blob_2_cpu(bin_blob: MetaBinBlob, cpu: CpuUnicorn) -> None:
    for mm in bin_blob.mem_map:
        cpu.mem.create_region(mm['base_address'], mm['size'])

    for blob_part in bin_blob.mapped_blobs:
        cpu.mem.write(blob_part['loading_address'], blob_part['blob'])


# ------------------------------------------------------------------------------


def test_endian_from_uc():
    uc_little = unicorn.Uc(
        unicorn.unicorn_const.UC_ARCH_ARM,
        unicorn.unicorn_const.UC_MODE_ARM
        | unicorn.unicorn_const.UC_MODE_LITTLE_ENDIAN
    )
    uc_big = unicorn.Uc(
        unicorn.unicorn_const.UC_ARCH_ARM,
        unicorn.unicorn_const.UC_MODE_ARM
        | unicorn.unicorn_const.UC_MODE_BIG_ENDIAN
    )
    assert CpuUnicorn.endian_from_uc(uc_little) == CpuEndian.EL
    assert CpuUnicorn.endian_from_uc(uc_big) == CpuEndian.EB


def test_check_uc_model():
    uc = create_uc_arm_1176()
    assert CpuUnicorn.check_uc_model(
        uc, unicorn.unicorn_const.UC_MODE_ARM1176
    )
    assert not CpuUnicorn.check_uc_model(
        uc, unicorn.unicorn_const.UC_MODE_ARM926
    )

    uc = create_uc_arm_926()
    assert CpuUnicorn.check_uc_model(
        uc, unicorn.unicorn_const.UC_MODE_ARM926
    )
    assert not CpuUnicorn.check_uc_model(
        uc, unicorn.unicorn_const.UC_MODE_ARM1176
    )


def test_uc_is_compatible():
    with pytest.raises(NotImplementedError) as exc_info:
        CpuUnicorn.uc_is_compatible(create_uc_arm_926())


def test_property_get_backend():
    assert isinstance(create_cpu().backend, unicorn.Uc)


def test_property_get_name():
    with pytest.raises(NotImplementedError) as exc_info:
        name = create_cpu().name


def test_property_get_bits():
    with pytest.raises(NotImplementedError) as exc_info:
        bits = create_cpu().bits


def test_property_get_endian():
    with pytest.raises(NotImplementedError) as exc_info:
        endian = create_cpu().endian


def test_property_get_variant():
    with pytest.raises(NotImplementedError) as exc_info:
        variant = create_cpu().variant


def test_remove_block_based_contention():
    emu = create_cpu()
    blob_2_cpu(BlobArmEl32MultiBlock, emu)
    assert isinstance(emu, CpuUnicorn)
    emu.set_contention(TickUnit.BLOCK, 1)
    emu.set_contention(TickUnit.INST, 1)


def test_set_contention_error():
    def another_contention_callback(self, cpu: CpuUnicorn) -> None:
        pass

    def contention_callback(cpu: CpuUnicorn) -> None:
        with pytest.raises(RuntimeError) as exc_info:
            cpu.set_contention(TickUnit.INST, 1)
            cpu.add_contention_callback(another_contention_callback)

    emu = create_cpu()
    blob_2_cpu(BlobArmEl32MultiBlock, emu)
    assert isinstance(emu, CpuUnicorn)
    emu.set_contention(TickUnit.INST, 1)
    emu.add_contention_callback(contention_callback)
    emu.start(BlobArmEl32MultiBlock.emu_start, BlobArmEl32MultiBlock.emu_end)


def test_start_with_invalid_tick_contention():
    emu = create_cpu()
    blob_2_cpu(BlobArmEl32MultiBlock, emu)
    assert isinstance(emu, CpuUnicorn)
    emu.set_contention(0x96, 1)

    with pytest.raises(NotImplementedError) as exc_info:
        emu.start()


class TestContentionLoop:
    def int_tester_callback(self, cpu: CpuUnicorn) -> None:
        assert cpu.is_running
        assert self.values[self.count][0] == cpu.regs.arch_pc
        assert self.values[self.count][1] == cpu.regs.r0
        assert self.values[self.count][2] == cpu.regs.r1
        self.count += 1

    def _test(
        self, bin_blob: MetaBinBlob, int_tick_unit: TickUnit,
        int_tick_count: int
    ):
        emu = create_cpu()
        blob_2_cpu(bin_blob, emu)
        assert isinstance(emu, CpuUnicorn)
        emu.set_contention(int_tick_unit, int_tick_count)
        emu.add_contention_callback(self.int_tester_callback)
        self.count = 0
        emu.start(bin_blob.emu_start, bin_blob.emu_end)

    def test_int_type_block_one_at_time(self):
        self.values = [
            [0x10, 1, 1], [0x20, 2, 2], [0x30, 3, 3], [0x40, 4, 4], [0x50, 5, 5]
        ]
        self._test(BlobArmEl32MultiBlock, TickUnit.BLOCK, 1)

    def test_int_type_block_two_at_time(self):
        self.values = [[0x20, 2, 2], [0x40, 4, 4], [0x50, 5, 5]]
        self._test(BlobArmEl32MultiBlock, TickUnit.BLOCK, 2)

    def test_int_type_insn_one_at_time(self):
        self.values = [
            [0x4, 0x1, 0x0], [0x8, 0x1, 0x1], [0xc, 0x1, 0x1], [0x10, 0x1, 0x1],
            [0x14, 0x2, 0x1], [0x18, 0x2, 0x2], [0x1c, 0x2, 0x2], [0x20, 0x2, 0x2],
            [0x24, 0x3, 0x2], [0x28, 0x3, 0x3], [0x2c, 0x3, 0x3], [0x30, 0x3, 0x3],
            [0x34, 0x4, 0x3], [0x38, 0x4, 0x4], [0x3c, 0x4, 0x4], [0x40, 0x4, 0x4],
            [0x44, 0x5, 0x4], [0x48, 0x5, 0x5], [0x4c, 0x5, 0x5], [0x50, 0x5, 0x5],
            [0x54, 0x5, 0x5]
        ]
        self._test(BlobArmEl32MultiBlock, TickUnit.INST, 1)

    def test_int_type_insn_two_at_time(self):
        self.values = [
            [0x8, 0x1, 0x1], [0x10, 0x1, 0x1], [0x18, 0x2, 0x2], [0x20, 0x2, 0x2],
            [0x28, 0x3, 0x3], [0x30, 0x3, 0x3], [0x38, 0x4, 0x4], [0x40, 0x4, 0x4],
            [0x48, 0x5, 0x5], [0x50, 0x5, 0x5], [0x54, 0x5, 0x5]
        ]
        self._test(BlobArmEl32MultiBlock, TickUnit.INST, 2)


def test_int_type_time():
    blob = BlobArmEl32MultiBlock
    emu = create_cpu()
    blob_2_cpu(blob, emu)
    assert isinstance(emu, CpuUnicorn)
    emu.set_contention(TickUnit.TIME_US, 1)
    emu.start(blob.emu_start, blob.emu_end)

    assert emu.regs.arch_pc == 0x50
    assert emu.regs.r0 == 0x5
    assert emu.regs.r1 == 0x5


def test_no_int():
    blob = BlobArmEl32MultiBlock
    emu = create_cpu()
    blob_2_cpu(blob, emu)
    assert isinstance(emu, CpuUnicorn)
    emu.start(blob.emu_start, blob.emu_end)

    assert emu.regs.arch_pc == 0x50
    assert emu.regs.r0 == 0x5
    assert emu.regs.r1 == 0x5


def test_emulator_error():
    blob = BlobArmEl32InvalidInsn
    emu = create_cpu()
    blob_2_cpu(blob, emu)
    assert isinstance(emu, CpuUnicorn)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        emu.start(blob.emu_start, blob.emu_end)

    assert exc_info.value.errno == unicorn.unicorn_const.UC_ERR_INSN_INVALID


def test_memory_mapped_file():
    blob = BlobArmEl32MultiBlock.mapped_blobs[0]
    blob_len = len(blob['blob'])

    with tempfile.NamedTemporaryFile() as temp:
        temp.write(blob['blob'])
        temp.flush()
        emu = create_cpu()
        blob_2_cpu(BlobArmEl32MultiBlock, emu)
        assert isinstance(emu, CpuUnicorn)
        emu.mem.map_file(temp.name, 0x0, blob['loading_address'], blob_len)
        emu.start(BlobArmEl32MultiBlock.emu_start, BlobArmEl32MultiBlock.emu_end)

        assert emu.regs.arch_pc == 0x50
        assert emu.regs.r0 == 0x5
        assert emu.regs.r1 == 0x5
        assert emu.mem.read(0x0, blob_len) == blob['blob']
