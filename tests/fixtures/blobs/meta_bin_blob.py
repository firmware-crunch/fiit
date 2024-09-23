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

from typing import List, Any, Union
from dataclasses import dataclass, field
import sys
import textwrap
import pprint
import copy
import subprocess

from elftools.elf.elffile import ELFFile
import elftools.dwarf
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import set_global_machine_arch


################################################################################
# ARM CONSTANTS
################################################################################
EF_ARM_ABI_FLOAT_HARD = 0x00000400
EF_ARM_ABI_FLOAT_SOFT = 0x00000200

TAG_CPU_ARCH_VALUES = {
    # from addenda32
    0: 'Pre-v4', 1: 'v4', 2: 'v4T', 3: 'v5T', 4: 'v5TE', 5: 'v5TEJ', 6: 'v6',
    7: 'v6KZ', 8: 'v6T2', 9: 'v6K', 10: 'v7', 11: 'v6-M', 12: 'v6S-M',
    13: 'v7E-M', 14: 'v8-A', 15: 'v8-R', 16: 'v8-M.baseline',
    17: 'v8-M.mainline', 18: 'v8.1-A', 19: 'v8.2-A', 20: 'v8.3-A',
    21: 'v8.1-M.mainline', 22: 'v9-A'
}

TAG_FP_ARCH_VALUES = {
    0: 'NO_FP_HARDWARE', 1: 'VFPv1', 2: 'VFPv2', 3: 'VFPv3',
    4: 'VFPv3_no_retro', 5: 'VFPv4', 6: 'VFPv4_no_retro', 7: 'VFPv8-A',
    8: 'VFPv8-A_no_retro',
}

TAG_ABI_FP_16BIT_FORMAT_VALUES = {
    0: 'NO_FP_16',
    1: 'IEEE754',
    2: 'alternative',
}

################################################################################
# ARM CONSTANTS END
################################################################################


LICENCE_GPL_V3_STR = \
"""################################################################################
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

"""


def _to_class_name(text: str) -> str:
    if len(text) == 0:
        return text
    s = text.replace('_', ' ')
    return ''.join(i.capitalize() for i in s.split())


@dataclass
class _BinBlob:
    blob: bytes

    def __repr__(self) -> str:
        render = ''.join(['\\x{:02x}'.format(b) for b in self.blob])
        return f"b'{render}'"


@dataclass
class MetaBinBlob:
    arch_unicorn: str
    arch_info: dict
    compiler: str
    producer: str
    emu_start: int
    emu_end: int
    mem_map: [List[dict]]
    disassembly: str = field(default_factory=str)
    mapped_blobs: List[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, meta: dict) -> Any:
        return cls(**meta)

    def to_file(self, filename: str, meta_name: str):
        to_dict = copy.deepcopy(self.__dict__)

        for bl in to_dict['mapped_blobs']:
            bl['blob'] = _BinBlob(bl['blob'])

        format_src = textwrap.indent(
            pprint.pformat(to_dict, sort_dicts=False, width=78), '  ')

        with open(filename, 'w') as f:
            f.write(
                f'{LICENCE_GPL_V3_STR}'
                f'from ..meta_bin_blob import MetaBinBlob\n\n'
                f'meta_blob_{meta_name} = \\\n{format_src}\n\n'
                f'Blob{_to_class_name(meta_name)} = '
                f'MetaBinBlob.from_dict(meta_blob_{meta_name})\n\n')


class Elf2MetaBinBlob:
    PERM_R = 2
    PERM_W = 4
    PERM_X = 8

    MEM_MAP_AREA_NAME_PRE = '__mem_map_area_'
    MEM_MAP_AREA_ORG_PRE = '__mem_map_start_'
    MEM_MAP_AREA_SIZE_PRE = '__mem_map_size_'

    SYM_EMU_START = 'emu_start'
    SYM_EMU_END = 'emu_end'

    OBJDUMP_BIN_MAP = {
        'ARM': 'arm-none-eabi-objdump',
        'AArch64': 'aarch64-linux-gnu-objdump'
    }

    CPU_NAME_UNICORN_MAPPING = {
        'ARM926EJ-S': '926',
        'ARM1176JZF-S': '1176',
    }

    def __init__(self, elf_file_path: str):
        self.elf_file_path = elf_file_path
        self.elffile = ELFFile.load_from_path(elf_file_path)
        self.symbols = self.get_elf_symbols()

    def get_elf_symbols(self) -> List[elftools.elf.sections.Symbol]:
        coll = []
        for sym_table in filter(lambda s: isinstance(s, SymbolTableSection),
                                self.elffile.iter_sections()):
            coll = [sym for sym in sym_table.iter_symbols()]
        return coll

    def _get_symbol(self, sym_name) -> elftools.elf.sections.Symbol:
        if (ret := list(filter(lambda s: s.name == sym_name, self.symbols))) == 0:
            raise RuntimeError(f'Symbol "{sym_name}" not found.')
        return ret[0]

    def _get_dwarf_sym(self, sym_name: str)\
            -> Union[elftools.dwarf.die.AttributeValue, None]:
        set_global_machine_arch(self.elffile.get_machine_arch())
        for CU in self.elffile.get_dwarf_info().iter_CUs():
            for DIE in CU.iter_DIEs():
                for attr in DIE.attributes.values():
                    if attr.name == sym_name:
                        return attr

    def _arm_attribut_tag_filter(self, tag_name: str) \
            -> Union[None, elftools.elf.sections.ARMAttribute]:
        arm_attr = self.elffile.get_section_by_name('.ARM.attributes')
        tags_it = arm_attr.subsections[0].subsubsections[0].iter_attributes()
        return (
            tag[0]
            if (tag := list(filter(lambda t: t.tag == tag_name, tags_it)))
            else None)

    def _collect_memory_map(self) -> List[dict]:
        """
        Expected symbol format:
        __mem_map_area_<memory mapped area name> = <perm>
        __mem_map_start_<memory mapped area name> = <base address>
        __mem_map_size_<memory mapped area name> = <size>
        """
        mem_map = []

        for mm_area in filter(
                lambda s: s.name.startswith(self.MEM_MAP_AREA_NAME_PRE),
                self.symbols):
            perm = ''
            if mm_area.entry.st_value & self.PERM_R:
                perm += 'r'
            if mm_area.entry.st_value & self.PERM_W:
                perm += 'w'
            if mm_area.entry.st_value & self.PERM_X:
                perm += 'x'

            name = mm_area.name.split(self.MEM_MAP_AREA_NAME_PRE)[1]
            base_address = self._get_symbol(
                f'{self.MEM_MAP_AREA_ORG_PRE}{name}').entry.st_value
            size = self._get_symbol(
                f'{self.MEM_MAP_AREA_SIZE_PRE}{name}').entry.st_value

            mem_map.append({
                'name': name,
                'perm': perm,
                'base_address': base_address,
                'size': size})

        return mem_map

    def _collect_disassembly(self) -> str:
        machine_arch = self.elffile.get_machine_arch()
        if not (objdump_bin := self.OBJDUMP_BIN_MAP.get(machine_arch, None)):
            raise RuntimeError(f'objdump not found for arch {machine_arch}.')

        p = subprocess.Popen(f'{objdump_bin} -d -S {self.elf_file_path}',
                             stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        p.wait()
        return output.decode('utf-8').replace('\t', '  ')

    def _collect_firmware_arch_unicorn(self) -> str:
        endian = 'el' if self.elffile.little_endian else 'eb'
        machine_arch = self.elffile.get_machine_arch()

        if machine_arch == 'ARM':
            elf_cpu_name = self._arm_attribut_tag_filter('TAG_CPU_NAME').value
            name = self.CPU_NAME_UNICORN_MAPPING.get(elf_cpu_name, 'default')
            arch = f'arm:{endian}:32:{name}'
        elif machine_arch == 'AArch64':
            arch = f'arm:{endian}:64:default'
        else:
            raise NotImplementedError(f'Arch not handled {machine_arch}.')

        return arch

    def _collect_blobs_load(self) -> List[dict]:
        return [{'loading_address': segment.header.p_paddr,
                 'blob': segment.data()}
                for segment in filter(lambda s: s.header.p_type == 'PT_LOAD',
                                      self.elffile.iter_segments())]

    def _collect_compiler(self) -> str:
        if comment_sec := self.elffile.get_section_by_name('.comment'):
            return comment_sec.data().decode('ascii')

    def _collect_producer(self) -> str:
        if producer := self._get_dwarf_sym('DW_AT_producer'):
            return producer.value.decode('ascii')

    def _collect_arch_info(self) -> dict:
        arch_info = {}
        machine_arch = self.elffile.get_machine_arch()

        if machine_arch == 'ARM':
            float_flag = ('FLOAT_HARD'
                          if self.elffile.header.e_flags & EF_ARM_ABI_FLOAT_HARD
                          else 'FLOAT_SOFT')
            arch_info.update({'cpu_float_flag': float_flag})

            cpu_arch = self._arm_attribut_tag_filter('TAG_CPU_ARCH')
            arch_info.update({'tag_cpu_arch': TAG_CPU_ARCH_VALUES[cpu_arch.value]})

            cpu_name = self._arm_attribut_tag_filter('TAG_CPU_NAME')
            arch_info.update({'tag_cpu_name': cpu_name.value})

            fp_arch = self._arm_attribut_tag_filter('TAG_FP_ARCH')
            fp_arch = TAG_FP_ARCH_VALUES[fp_arch.value] if fp_arch else None
            arch_info.update({'tag_fp_arch': fp_arch})

            abi_fp_16 = self._arm_attribut_tag_filter('TAG_ABI_FP_16BIT_FORMAT')
            abi_fp_16 = TAG_ABI_FP_16BIT_FORMAT_VALUES.get(abi_fp_16.value, None)
            arch_info.update({'tag_abi_fp_16bit_format': abi_fp_16})

        return arch_info

    def conv(self, meta_name: str):
        mbb = MetaBinBlob(
            arch_unicorn=self._collect_firmware_arch_unicorn(),
            emu_start=self._get_symbol(self.SYM_EMU_START).entry.st_value,
            emu_end=self._get_symbol(self.SYM_EMU_END).entry.st_value,
            mem_map=self._collect_memory_map(),
            compiler=self._collect_compiler(),
            producer=self._collect_producer(),
            arch_info=self._collect_arch_info(),
            disassembly=self._collect_disassembly(),
            mapped_blobs=self._collect_blobs_load())
        mbb.to_file(f'{meta_name}.py', meta_name)


if __name__ == '__main__':
    """
    script argument 1: ELF file path
    script argument 2: meta binary blob name use for python file naming
                       and python objects generation naming
    """
    Elf2MetaBinBlob(sys.argv[1]).conv(sys.argv[2])
