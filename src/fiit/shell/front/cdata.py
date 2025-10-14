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
    'CDataMemMapperFrontend'
]

from typing import Union, Dict, List

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from fiit.ctypesarch import CDataMemMapper, CDataMemMapEntry
from fiit.shell import register_alias, Shell

# ==============================================================================


class ShellCDataMemMapper:
    def __init__(self, cdata_mem_mapper: CDataMemMapper):
        self._cdata_mmap = cdata_mem_mapper

    def __getattr__(self, name: str):
        if cdata_entry := self._cdata_mmap.get_cdata_mapping(name):
            return cdata_entry.cdata
        else:
            raise AttributeError(f'{name} attribute not found.')

    def __repr__(self):
        cdata_entries = self._cdata_mmap.get_all_mapping()

        cdata_by_addr: Dict[int, List[CDataMemMapEntry]] = {}
        for _, cdata_entry in cdata_entries.items():
            cdata_by_addr.setdefault(cdata_entry.address, list())
            cdata_by_addr[cdata_entry.address].append(cdata_entry)

        buffer = list()
        for addr in sorted(cdata_by_addr):
            for entry in cdata_by_addr[addr]:
                buffer.append(
                    f'{self._cdata_mmap.mem.addr_to_str(entry.address)} '
                    f': {entry.name} : {str(entry.cdata.__class__._name_)}'
                )

        return '\n'.join(buffer)


@IPython.core.magic.magics_class
class CDataMemMapperFrontend(IPython.core.magic.Magics):
    def __init__(
        self, cdata_mmap_list: List[CDataMemMapper], shell: Shell
    ):
        super(CDataMemMapperFrontend, self).__init__(shell=shell.shell)
        self._cdata_mmap_list = cdata_mmap_list
        self.shell = shell
        shell.register_magics(self)
        shell.register_aliases(self)

        for cdata_mmap in self._cdata_mmap_list:
            shell_cdata_mapper = ShellCDataMemMapper(cdata_mmap)
            shell_name = f'cdata_{cdata_mmap.mem.name}'
            shell.map_object_in_shell(shell_name, shell_cdata_mapper)

    def _get_cdata_mmap(self, mem_name: str) -> Union[CDataMemMapper]:
        for cdata_mmap in self._cdata_mmap_list:
            if cdata_mmap.mem.name == mem_name:
                return cdata_mmap

    @magic_arguments()
    @argument('mem_name', type=str, help='')
    @argument('cdata_type', type=str, help='')
    @argument('cdata_name', type=str, help='')
    @argument('address', help='')
    @register_alias('bc')
    @IPython.core.magic.line_magic
    def map_cdata(self, line: str):
        args = parse_argstring(self.map_cdata, line)
        if isinstance(args.address, str):
            address = int(args.address, 16)
        else:
            address = args.address

        cdata_mmap = self._get_cdata_mmap(args.mem_name)

        if cdata_mmap is None:
            print(f'cdata mapper not found for memory name "{args.mem_name}"')
        else:
            cdata_mmap.map_cdata(args.ctype_name, args.cdata_name, address)
