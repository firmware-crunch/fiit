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

from typing import cast

from fiit.machine import DeviceCpu
from fiit.dev.arm32 import ArchArm32DDI0100

from .fixtures.cpu_utils import Blob2Cpu
from .fixtures.blobs import (
    BlobArmEl32MinimalInt,
    BlobArmEl32MinimalIntHighV,
    BlobArmEl32SoftInt
)

# ==============================================================================


class TestIrq:
    BIN_BLOB = BlobArmEl32MinimalInt  # ARM926 blob
    INT_TRIGGER_ADDRESS = 0x94
    CORE_IRQ_ADDRESS = 0x58
    EXPECTED_TRACE = [
        0x0, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40, 0x44, 0x70,
        0x74, 0x78, 0x7c, 0x48, 0x80, 0x84, 0x88, 0x8c, 0x4c, 0x90, 0x18, 0x50,
        0x54, 0x58, 0x5c, 0x94, 0x98,
    ]

    def setup_method(self, test_method):
        self.emu = Blob2Cpu(
            self.BIN_BLOB,
            'unicorn',
            arm_spec='DDI0100',
            high_vector_support=True,
            high_vector=False,
        )
        self.emu.cpu.hook_code_all(self.code_callback)
        self.records = []
        self.trigger_flag = False

    def code_callback(self, cpu: DeviceCpu, address: int):
        cpu = cast(ArchArm32DDI0100, cpu)

        if not self.trigger_flag and address == self.INT_TRIGGER_ADDRESS:
            self.trigger_flag = True
            assert not cpu.is_irq_mode()
            cpu.take_irq_exception()

        elif address == self.CORE_IRQ_ADDRESS:
            assert cpu.is_irq_mode()
            cpu.take_irq_exception()
            self.records.append(address)

        else:
            self.records.append(address)

    def test_irq(self):
        self.emu.start()
        assert self.records == self.EXPECTED_TRACE


class TestFiq:
    BIN_BLOB = BlobArmEl32MinimalInt  # ARM926 blob
    INT_TRIGGER_ADDRESS = 0x94
    CORE_FIQ_ADDRESS = 0x68
    EXPECTED_TRACE = [
        0x0, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40, 0x44, 0x70,
        0x74, 0x78, 0x7c, 0x48, 0x80, 0x84, 0x88, 0x8c, 0x4c, 0x90, 0x1c, 0x60,
        0x64, 0x68, 0x6c, 0x94, 0x98
    ]

    def setup_method(self, test_method):
        self.emu = Blob2Cpu(
            self.BIN_BLOB,
            machine='unicorn',
            arm_spec='DDI0100',
            high_vector_support=True,
            high_vector=False
        )
        self.emu.cpu.hook_code_all(self.code_callback)
        self.records = []
        self.trigger_flag = False

    def code_callback(self, cpu: DeviceCpu, address: int):
        cpu = cast(ArchArm32DDI0100, cpu)

        if not self.trigger_flag and address == self.INT_TRIGGER_ADDRESS:
            self.trigger_flag = True
            assert not cpu.is_fiq_mode()
            cpu.take_fiq_exception()

        elif address == self.CORE_FIQ_ADDRESS:
            assert cpu.is_fiq_mode()
            cpu.take_fiq_exception()
            self.records.append(address)

        else:
            self.records.append(address)

    def test_fiq(self):
        self.emu.start()
        assert self.records == self.EXPECTED_TRACE


class TestIrqHighV:
    BIN_BLOB = BlobArmEl32MinimalIntHighV  # ARM926 blob
    INT_TRIGGER_ADDRESS = 0xffff0094
    CORE_IRQ_ADDRESS = 0xffff0058
    EXPECTED_TRACE = [
        0xffff0000, 0xffff0020, 0xffff0024, 0xffff0028, 0xffff002c, 0xffff0030,
        0xffff0034, 0xffff0038, 0xffff003c, 0xffff0040, 0xffff0044, 0xffff0070,
        0xffff0074, 0xffff0078, 0xffff007c, 0xffff0048, 0xffff0080, 0xffff0084,
        0xffff0088, 0xffff008c, 0xffff004c, 0xffff0090, 0xffff0018, 0xffff0050,
        0xffff0054, 0xffff0058, 0xffff005c, 0xffff0094, 0xffff0098
    ]

    def setup_method(self, test_method):
        self.emu = Blob2Cpu(
            self.BIN_BLOB,
            machine='unicorn',
            arm_spec='DDI0100',
            high_vector_support=True,
            high_vector=True
        )
        self.emu.cpu.hook_code_all(self.code_callback)
        self.records = []
        self.trigger_flag = False

    def code_callback(self, cpu: DeviceCpu, address: int):
        cpu = cast(ArchArm32DDI0100, cpu)

        if not self.trigger_flag and address == self.INT_TRIGGER_ADDRESS:
            self.trigger_flag = True
            assert not cpu.is_irq_mode()
            cpu.take_irq_exception()

        elif address == self.CORE_IRQ_ADDRESS:
            assert cpu.is_irq_mode()
            cpu.take_irq_exception()
            self.records.append(address)

        else:
            self.records.append(address)

    def test_irq_high_vector(self):
        self.emu.start()
        assert self.records == self.EXPECTED_TRACE


class TestSoftInt:
    BIN_BLOB = BlobArmEl32SoftInt  # ARM926 blob
    CORE_SWI_ADDRESS = 0x44
    EXPECTED_TRACE = [
        0x0, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x48, 0x4c, 0x8, 0x3c,
        0x40, 0x44, 0x50,
    ]

    def setup_method(self, test_method):
        self.emu = Blob2Cpu(
            self.BIN_BLOB,
            machine='unicorn',
            arm_spec='DDI0100',
            high_vector_support=True,
            high_vector=False
        )
        self.emu.cpu.hook_code_all(self.code_callback)
        self.records = []

    def code_callback(self, cpu: DeviceCpu, address: int):
        cpu = cast(ArchArm32DDI0100, cpu)

        if address == self.CORE_SWI_ADDRESS:
            assert cpu.is_svc_mode()
        elif address == 0x50:
            assert not cpu.is_svc_mode()

        self.records.append(address)

    def test_soft_int(self):
        self.emu.start()
        assert self.records == self.EXPECTED_TRACE
