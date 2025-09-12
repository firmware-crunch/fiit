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

from fiit.emu.emu_types import MemoryRegion, AddressSpace


def test_address_space_iteration():
    address_space = AddressSpace([
        MemoryRegion('a1', 0x0, 4096, 'rwx'),
        MemoryRegion('a2', 0x200, 8192, 'r')
    ])

    for idx, mem in enumerate(address_space):
        if idx == 0:
            assert mem.name == 'a1'
            assert mem.base_address == 0x0
            assert mem.size == 4096
            assert mem.perm == 'rwx'
        elif idx == 1:
            assert mem.name == 'a2'
            assert mem.base_address == 0x200
            assert mem.size == 8192
            assert mem.perm == 'r'

        assert idx < 2
