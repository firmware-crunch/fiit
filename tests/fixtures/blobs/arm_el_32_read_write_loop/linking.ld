################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

PERM_R = 2;
PERM_W = 4;
PERM_X = 8;


MEMORY
{
    rom (rx) :  ORIGIN = 0x0, LENGTH = 4096
}


SECTIONS
{
    .text : {
        main.o (__main__)
        #*(.text*)
    } > rom
}


__mem_map_area_rom = PERM_R | PERM_X;
__mem_map_start_rom = ORIGIN(rom);
__mem_map_size_rom = LENGTH(rom);
