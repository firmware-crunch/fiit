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
    'CpuFactoryUnicorn'
]

from typing import cast, Any, Type, Tuple

import unicorn

from fiit.machine import CpuFactory, Cpu

from .cpu import CpuUnicorn
from .arm32 import ArchArm32Unicorn

# ==============================================================================


class CpuFactoryUnicorn(CpuFactory):

    _ARCH: Tuple[Type[CpuUnicorn], ...] = (
        ArchArm32Unicorn,
        # Add more arch here...
    )

    @classmethod
    def get_backend_name(cls) -> str:
        return 'unicorn'

    @classmethod
    def get_backend_type(cls) -> Any:
        return unicorn.Uc

    @classmethod
    def class_from_arch_id(cls, arch_id: str) -> Type[Cpu]:
        for arch_class in cls._ARCH:
            if arch_class.ARCH_ID == arch_id:
                return arch_class

        raise ValueError(f'ARCH_ID for "{arch_id}" not found')

    @classmethod
    def class_from_backend_instance(
        cls, backend: Any, arch_id: str
    ) -> Type[Cpu]:
        for arch_class in cls._ARCH:
            if (arch_class.ARCH_ID == arch_id
                    and arch_class.uc_is_compatible(backend)):
                return arch_class

        for arch_class in cls._ARCH:  # skip arch_id for direct binding
            if arch_class.uc_is_compatible(backend):
                return arch_class

        raise ValueError(f'Compatible CpuUnicorn not found for Uc "{backend}"')

    @classmethod
    def create(cls, arch_id: str, **arch_options: int) -> Cpu:
        for arch_class in cls._ARCH:
            if arch_class.ARCH_ID == arch_id:
                arch_class = cast(Type[Any], arch_class)
                cpu_instance = arch_class(**arch_options)
                cpu_instance = cast(CpuUnicorn, cpu_instance)
                return cpu_instance

        raise ValueError(f'ARCH_ID for "{arch_id}" not found')
