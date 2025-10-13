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
    'get_calling_convention_by_arch',
    'get_calling_convention_by_name',
    'CallingConvention',
    'ReturnValue',
    'FuncArg',
    'CpuRegisters',
    'CallingConventionARM'
]

from typing import Type

from .aapcs32 import CallingConventionARM
from .cc import (
    CallingConvention, ReturnValue, FuncArg, CpuContext, CpuRegisters
)


CC = {
    ('arm', 'arm:el:32', 'arm:eb:32'): CallingConventionARM,
}


def get_calling_convention_by_arch(arch: str) -> Type[CallingConvention]:
    for cc_arch_names, calling_convention in CC.items():
        if arch in cc_arch_names:
            return calling_convention
    raise ValueError(f'calling convention not found for arch "{arch}"')


def get_calling_convention_by_name(cc_name: str) -> Type[CallingConvention]:
    for calling_convention in CC.values():
        if calling_convention.NAME == cc_name:
            return calling_convention

    raise ValueError(f'calling convention name not found for "{cc_name}"')
