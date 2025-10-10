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

from .cc_base import CallingConvention
from .cc_aapcs32 import CallingConventionARM


CC = {
    ('arm', 'arm:el:32', 'arm:eb:32'): CallingConventionARM,
}


def get_calling_convention_by_arch(arch: str) -> Type[CallingConvention]:
    for cc_arch_names, cc in CC.items():
        if arch in cc_arch_names:
            return cc
    raise ValueError(f'calling convention not found for arch "{arch}"')


def get_calling_convention_by_name(cc_name: str) -> Type[CallingConvention]:
    return list(filter(lambda cc: cc.NAME == cc_name, CC.values()))[0]

