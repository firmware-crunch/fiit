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

from typing import Dict, List

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from fiit.arch_ctypes import CDataMemMapper, CDataMemMapEntry
from fiit.shell import register_alias, Shell



class ShellCDataMemMapper:
    def __init__(self, cdata_mem_mapper: CDataMemMapper, address_formatter):
        self._cdata_mem_mapper = cdata_mem_mapper
        self._address_formatter = address_formatter

    def __getattr__(self, name: str):
        if cdata_entry := self._cdata_mem_mapper.get_cdata_mapping(name):
            return cdata_entry.cdata
        else:
            raise AttributeError(f'{name} attribute not found.')

    def __repr__(self):
        cdata_entries = self._cdata_mem_mapper.get_all_mapping()

        cdata_by_addr: Dict[int, List[CDataMemMapEntry]] = {}
        for _, cdata_entry in cdata_entries.items():
            cdata_by_addr.setdefault(cdata_entry.address, list())
            cdata_by_addr[cdata_entry.address].append(cdata_entry)

        buffer = list()
        for addr in sorted(cdata_by_addr):
            for entry in cdata_by_addr[addr]:
                buffer.append(f'{self._address_formatter(entry.address)} '
                              f': {entry.name} '
                              f': {str(entry.cdata.__class__._name_)}')

        return '\n'.join(buffer)



@IPython.core.magic.magics_class
class CDataMemMapperFrontend(IPython.core.magic.Magics):
    def __init__(
        self, cdata_mem_mapper: CDataMemMapper, shell: Shell,
        address_formatter
    ):
        super(CDataMemMapperFrontend, self).__init__(shell=shell.shell)
        self.cdata_memory_mapper = cdata_mem_mapper
        self.shell = shell
        shell.register_magics(self)
        shell.register_aliases(self)
        shell_cdata_mapper = ShellCDataMemMapper(
            cdata_mem_mapper, address_formatter)
        shell.map_object_in_shell('cdata_mapping', shell_cdata_mapper)

    @magic_arguments()
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

        self.cdata_memory_mapper.map_cdata(
            args.ctype_name, args.cdata_name, address)
