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

from typing import Optional, Callable, List

import unicorn
from unicorn.unicorn_const import (
    UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM, UC_ARCH_ARM64, UC_MODE_ARM926,
    UC_MODE_ARM1176,
    UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE)
from unicorn.arm_const import UC_ARM_REG_FPEXC

from .blobs.meta_bin_blob import MetaBinBlob


class BinBlob2Emulator:
    ARCH = {
        'arm:el:32:default': (
            UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN),
        'arm:el:32:926': (
            UC_ARCH_ARM,
            UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM926),
        'arm:eb:32:926': (
            UC_ARCH_ARM,
            UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_BIG_ENDIAN | UC_MODE_ARM926),
        'arm:el:32:1176': (
            UC_ARCH_ARM,
            UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM1176),
        'arm:eb:32:1176': (
            UC_ARCH_ARM,
            UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_BIG_ENDIAN | UC_MODE_ARM1176),
        'arm:eb:32:default': (
            UC_ARCH_ARM,
            UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_BIG_ENDIAN),
        'arm:el:64:default': (
            UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    }

    def __init__(
        self, bin_blob: MetaBinBlob, arch_extra: Optional[dict] = None
    ):
        self.bin_blob = bin_blob
        self.uc = unicorn.Uc(*self.ARCH[bin_blob.arch_unicorn])

        for mm in bin_blob.mem_map:
            self.uc.mem_map(mm['base_address'], mm['size'],
                            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        for load_blob in bin_blob.mapped_blobs:
            self.uc.mem_write(load_blob['loading_address'], load_blob['blob'])

        if (bin_blob.arch_unicorn.startswith(('arm:el:32', 'arm:eb:32'))
                and arch_extra
                and arch_extra.get('cpu_float_flag') == 'FLOAT_HARD'):
            self.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
            print('[i] Configuring UC for ARM hard float code.')

    def start(self):
        self.uc.emu_start(self.bin_blob.emu_start, self.bin_blob.emu_end)


class InstructionTracer:
    def __init__(self, uc: unicorn.Uc):
        self.records = []
        uc.hook_add(UC_HOOK_CODE, self.tracer, begin=1, end=0)

    def tracer(self, uc: unicorn.Uc, address: int, size: int, data: dict):
        self.records.append(address)


class CodeBreakpoint:
    def __init__(
        self, uc: unicorn.Uc, code_tracer_callback: Callable,
        code_tracer_breaks: List[int]
    ):
        self.break_count = 0
        self.code_tracer_breaks = code_tracer_breaks
        self._code_tracer_callback = code_tracer_callback
        uc.hook_add(UC_HOOK_CODE, self.tracer, begin=1, end=0)

    def tracer(self, uc: unicorn.Uc, address: int, size: int, data: dict):
        if address in self.code_tracer_breaks:
            self.break_count += 1
            self._code_tracer_callback(uc, address)
