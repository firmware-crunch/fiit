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

from typing import Type
import tempfile

import pytest

import unicorn
from unicorn.unicorn_const import UC_ERR_INSN_INVALID

from fiit.emu.emulator import (
    Emulator,
    EXEC_QUANTUM_UNIT_BLOCK, EXEC_QUANTUM_UNIT_INSN, EXEC_QUANTUM_UNIT_US
)

from .fixtures.blobs.meta_bin_blob import MetaBinBlob
from .fixtures.blobs import BlobArmEl32MultiBlock, BlobArmEl32InvalidInsn


class TestInterrupt:
    def int_tester_callback(
        self, uc: unicorn.Uc, _: int, __: int
    ) -> bool:
        address = self.emu.uc.reg_read(self.emu.pc_code)
        assert self.emu.is_running
        assert self.values[self.count][0] == address
        assert self.values[self.count][0] == uc.reg_read(self.emu.cpu_reg['pc'])
        assert self.values[self.count][1] == uc.reg_read(self.emu.cpu_reg['r0'])
        assert self.values[self.count][2] == uc.reg_read(self.emu.cpu_reg['r1'])
        self.count += 1
        return True

    def _test(
        self, bin_blob: Type[MetaBinBlob], int_type: int, int_tick_count: int
    ):
        self.emu = Emulator(
            bin_blob.arch_unicorn,
            bin_blob.mem_map,
            memory_mapped_blobs=bin_blob.mapped_blobs,
            interrupt_callback=self.int_tester_callback,
            interrupt_type=int_type,
            interrupt_tick_count=int_tick_count)

        self.count = 0
        self.emu.start_at(bin_blob.emu_start, bin_blob.emu_end)
        self.emu.stop()

    def _test_by_set_interrupt(
        self, bin_blob: Type[MetaBinBlob], int_type: int, int_tick_count: int
    ):
        self.emu = Emulator(
            bin_blob.arch_unicorn,
            bin_blob.mem_map,
            memory_mapped_blobs=bin_blob.mapped_blobs)

        self.emu.set_interrupts(
            self.int_tester_callback, int_type, int_tick_count)

        self.count = 0
        self.emu.start_at(bin_blob.emu_start, bin_blob.emu_end)
        self.emu.stop()

    def test_int_type_block_one_at_time(self):
        self.values = [
            [0x10, 1, 1], [0x20, 2, 2], [0x30, 3, 3], [0x40, 4, 4], [0x50, 5, 5]]
        self._test(BlobArmEl32MultiBlock, EXEC_QUANTUM_UNIT_BLOCK, 1)

    def test_int_type_block_two_at_time(self):
        self.values = [[0x20, 2, 2], [0x40, 4, 4], [0x50, 5, 5]]
        self._test(BlobArmEl32MultiBlock, EXEC_QUANTUM_UNIT_BLOCK, 2)

    def test_int_type_insn_one_at_time(self):
        self.values = [
            [0x4, 0x1, 0x0], [0x8, 0x1, 0x1], [0xc, 0x1, 0x1], [0x10, 0x1, 0x1],
            [0x14, 0x2, 0x1], [0x18, 0x2, 0x2], [0x1c, 0x2, 0x2], [0x20, 0x2, 0x2],
            [0x24, 0x3, 0x2], [0x28, 0x3, 0x3], [0x2c, 0x3, 0x3], [0x30, 0x3, 0x3],
            [0x34, 0x4, 0x3], [0x38, 0x4, 0x4], [0x3c, 0x4, 0x4], [0x40, 0x4, 0x4],
            [0x44, 0x5, 0x4], [0x48, 0x5, 0x5], [0x4c, 0x5, 0x5], [0x50, 0x5, 0x5],
            [0x54, 0x5, 0x5]]
        self._test(BlobArmEl32MultiBlock, EXEC_QUANTUM_UNIT_INSN, 1)

    def test_int_type_insn_two_at_time(self):
        self.values = [
            [0x8, 0x1, 0x1], [0x10, 0x1, 0x1], [0x18, 0x2, 0x2], [0x20, 0x2, 0x2],
            [0x28, 0x3, 0x3], [0x30, 0x3, 0x3], [0x38, 0x4, 0x4], [0x40, 0x4, 0x4],
            [0x48, 0x5, 0x5], [0x50, 0x5, 0x5], [0x54, 0x5, 0x5]]
        self._test(BlobArmEl32MultiBlock, EXEC_QUANTUM_UNIT_INSN, 2)

    def test_set_interrupt(self):
        self.values = [[0x20, 2, 2], [0x40, 4, 4], [0x50, 5, 5]]
        self._test_by_set_interrupt(
            BlobArmEl32MultiBlock, EXEC_QUANTUM_UNIT_BLOCK, 2)


def test_int_type_time():
    emu = Emulator(
        BlobArmEl32MultiBlock.arch_unicorn,
        BlobArmEl32MultiBlock.mem_map,
        memory_mapped_blobs=BlobArmEl32MultiBlock.mapped_blobs,
        interrupt_callback=lambda a, b, c: None,
        interrupt_type=EXEC_QUANTUM_UNIT_US,
        interrupt_tick_count=1)

    emu.start_at(BlobArmEl32MultiBlock.emu_start, BlobArmEl32MultiBlock.emu_end)
    assert emu.uc.reg_read(emu.cpu_reg['pc']) == 0x50
    assert emu.uc.reg_read(emu.cpu_reg['r0']) == 0x5
    assert emu.uc.reg_read(emu.cpu_reg['r1']) == 0x5


def test_no_int():
    emu = Emulator(
        BlobArmEl32MultiBlock.arch_unicorn,
        BlobArmEl32MultiBlock.mem_map,
        memory_mapped_blobs=BlobArmEl32MultiBlock.mapped_blobs)

    emu.start_at(BlobArmEl32MultiBlock.emu_start, BlobArmEl32MultiBlock.emu_end)
    assert emu.uc.reg_read(emu.cpu_reg['pc']) == 0x50
    assert emu.uc.reg_read(emu.cpu_reg['r0']) == 0x5
    assert emu.uc.reg_read(emu.cpu_reg['r1']) == 0x5


def test_uc_error():
    emu = Emulator(
        BlobArmEl32InvalidInsn.arch_unicorn,
        BlobArmEl32InvalidInsn.mem_map,
        memory_mapped_blobs=BlobArmEl32InvalidInsn.mapped_blobs)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        emu.start_at(BlobArmEl32InvalidInsn.emu_start,
                     BlobArmEl32InvalidInsn.emu_end)

    assert exc_info.value.errno == UC_ERR_INSN_INVALID


def test_no_host_memory_map():
    emu = Emulator(
        BlobArmEl32MultiBlock.arch_unicorn,
        BlobArmEl32MultiBlock.mem_map,
        memory_mapped_blobs=BlobArmEl32MultiBlock.mapped_blobs,
        host_memory_map=False)
    emu.start_at(BlobArmEl32MultiBlock.emu_start, BlobArmEl32MultiBlock.emu_end)
    assert emu.uc.reg_read(emu.cpu_reg['pc']) == 0x50
    assert emu.uc.reg_read(emu.cpu_reg['r0']) == 0x5
    assert emu.uc.reg_read(emu.cpu_reg['r1']) == 0x5


def test_memory_mapped_file():
    blob = BlobArmEl32MultiBlock.mapped_blobs[0]
    blob_len = len(blob['blob'])

    with tempfile.NamedTemporaryFile() as temp:
        temp.write(blob['blob'])
        temp.flush()
        emu = Emulator(
            BlobArmEl32MultiBlock.arch_unicorn,
            BlobArmEl32MultiBlock.mem_map,
            memory_mapped_files=[{
                'file_path': temp.name,
                'file_offset': 0x0,
                'loading_size': blob_len,
                'loading_address': blob['loading_address']
            }])
        emu.start_at(BlobArmEl32MultiBlock.emu_start,
                     BlobArmEl32MultiBlock.emu_end)
        emu.stop()
        assert emu.uc.reg_read(emu.cpu_reg['pc']) == 0x50
        assert emu.uc.reg_read(emu.cpu_reg['r0']) == 0x5
        assert emu.uc.reg_read(emu.cpu_reg['r1']) == 0x5
        assert emu.uc.mem_read(0x0, blob_len) == blob['blob']
