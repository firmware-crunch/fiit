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

__all__ = [
    'blob_2_cpu'
]

from typing import (
    Callable,
    Optional,
    List
)

from fiit import FiitCpuFactory
from fiit.machine import (
    DeviceCpu,
    CpuBits,
    CpuEndian
)

from .blobs.meta_bin_blob import MetaBinBlob

# ------------------------------------------------------------------------------


def blob_2_cpu(bin_blob: MetaBinBlob, cpu: DeviceCpu) -> None:
    for mm in bin_blob.mem_map:
        cpu.mem.create_region(mm['base_address'], mm['size'])

    for blob_part in bin_blob.mapped_blobs:
        cpu.mem.write(blob_part['loading_address'], blob_part['blob'])


def packed_arch_2_kwargs(packed_arch_str: str) -> dict:
    """
    convert this arch string style 'arm:el:32:v5te' to this:
    {
        'name': 'arm',
        'endian': CpuEndian,
        'bits': CpuBits,
        'variant': 'v5te'
    }

    """
    arch_kwargs = {}
    unpacked = packed_arch_str.split(':')
    cpu_name, _cpu_endian, _cpu_bits, cpu_variant = unpacked
    arch_kwargs['name'] = cpu_name
    arch_kwargs['endian'] = CpuEndian.from_str(_cpu_endian)
    arch_kwargs['bits'] = CpuBits(int(_cpu_bits))
    arch_kwargs['variant'] = cpu_variant
    return arch_kwargs


class Blob2Cpu:
    def __init__(
        self,
        blob: MetaBinBlob,
        cpu_backend: str = 'unicorn',
        cpu_name: Optional[str] = None,
        **arch_options: int
    ):
        self.bin_blob = blob
        machine_kwargs = dict(dev_name=cpu_name)
        arch_info = packed_arch_2_kwargs(blob.arch_unicorn)

        if (blob.arch_info.get('tag_cpu_name', '').startswith('ARM1176')
                and blob.arch_info.get('cpu_float_flag', '') == 'FLOAT_HARD'):
            machine_kwargs['arm_spec'] = 'DDI0100'

        if arch_info['name'] == 'arm' and arch_info['bits'] == 32:
            machine_kwargs['arch_id'] = 'arm32'
            machine_kwargs['endian'] = arch_info['endian']
            if arch_info['variant'] != 'default':
                machine_kwargs['model'] = arch_info['variant']
        else:
            raise NotImplementedError('architecture not implemented')

        machine_kwargs.update(arch_options)
        self.cpu = FiitCpuFactory.get(cpu_backend, **machine_kwargs)
        blob_2_cpu(self.bin_blob, self.cpu)

        if (blob.arch_info.get('tag_cpu_name', '').startswith('ARM1176')
                and blob.arch_info.get('cpu_float_flag', '') == 'FLOAT_HARD'):
            self.cpu.regs.fpexc = (1 << 30)

    def start(self):
        self.cpu.start(self.bin_blob.emu_start, self.bin_blob.emu_end)


class InstructionTracer:
    def __init__(self, cpu: DeviceCpu):
        self.records = []
        cpu.hook_code_all(self.tracer)

    def tracer(self, _: DeviceCpu, address: int):
        self.records.append(address)


class CodeBreakpoint:
    def __init__(
        self, cpu: DeviceCpu, code_tracer_callback: Callable,
        code_tracer_breaks: List[int]
    ):
        self.break_count = 0
        self.code_tracer_breaks = code_tracer_breaks
        self._code_tracer_callback = code_tracer_callback
        cpu.hook_code_all(self.tracer)

    def tracer(self, cpu: DeviceCpu, address: int):
        if address in self.code_tracer_breaks:
            self.break_count += 1
            self._code_tracer_callback(cpu, address)
