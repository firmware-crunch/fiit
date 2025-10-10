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
    'ArchArm32Unicorn'
]

from typing import Optional, Dict, Union, Any, List, cast

import unicorn
from unicorn import unicorn_const

from fiit.machine import CpuEndian, CpuBits

from ..cpu import CpuUnicorn
from ..memory import MemoryUnicorn
from ..registers import CpuRegistersUnicorn

from .coproc import ArchArm32CoprocUnicorn
from .const import ARM32_REGISTER

# ==============================================================================


class ArchArm32Unicorn(CpuUnicorn):

    ARCH_ID = 'arm32'

    ARCH_NAME = 'arm'
    ARCH_BITS = CpuBits.BITS_32
    ARCH_PC = 'pc'
    ARCH_SP = 'sp'

    _UNICORN_CPU_MODELS: Dict[str, int] = {
        '926': unicorn_const.UC_MODE_ARM926,
        '946': unicorn_const.UC_MODE_ARM946,
        '1176': unicorn_const.UC_MODE_ARM1176,
        # Add more model here ...
    }

    def __init__(
        self,
        endian: Union[CpuEndian, str],
        model: Optional[str] = None,
        thumb: bool = True,
        uc: Optional[unicorn.Uc] = None
    ):
        self._model = model
        self._endian = CpuEndian.from_any(endian)

        if uc is None:
            _uc = self._create_uc(self._endian, model, thumb)
        else:
            assert self.uc_is_compatible(uc)
            _uc = uc

        mem = MemoryUnicorn(_uc, self.ARCH_BITS, self._endian)
        regs = self._get_registers(_uc)
        CpuUnicorn.__init__(self, _uc, regs, mem)
        self._coproc = ArchArm32CoprocUnicorn(self._uc)

    ##########
    # cpu info

    @property
    def name(self) -> str:
        return self.ARCH_NAME

    @property
    def bits(self) -> CpuBits:
        return self.ARCH_BITS

    @property
    def endian(self) -> CpuEndian:
        return self._endian

    @property
    def variant(self) -> Optional[Any]:
        return self._model

    @property
    def coproc(self) -> ArchArm32CoprocUnicorn:
        return self._coproc

    @classmethod
    def _get_registers(cls, uc: unicorn.Uc) -> CpuRegistersUnicorn:
        regs_map = {**ARM32_REGISTER}
        regs = CpuRegistersUnicorn(uc, regs_map, cls.ARCH_PC, cls.ARCH_SP)
        return regs

    @classmethod
    def _create_uc(
        cls, endian: CpuEndian, model: Optional[str] = None, thumb: bool = True
    ) -> unicorn.Uc:
        """
        This method is a custom version of the QlArchARM.uc() method from the
        Qiling project licensed under the GNU General Public License Version 2
        or any later version, you can access to the original source code via the
        following web link.

        https://github.com/qilingframework/qiling/blob/
        a40690752f05044b374561689bb2a228687ccf70/qiling/arch/arm.py#L35
        """
        unicorn_mode = unicorn_const.UC_MODE_ARM

        if endian == CpuEndian.EL:
            unicorn_mode |= unicorn_const.UC_MODE_LITTLE_ENDIAN
        else:
            unicorn_mode |= unicorn_const.UC_MODE_BIG_ENDIAN

        if thumb:
            unicorn_mode |= unicorn_const.UC_MODE_THUMB

        if model is not None:
            uc_model = cls._UNICORN_CPU_MODELS.get(model, None)

            if uc_model is not None:
                unicorn_mode |= uc_model

        uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)

        return uc

    @classmethod
    def uc_is_compatible(cls, uc: unicorn.Uc) -> bool:
        """ """
        if (uc._arch & unicorn_const.UC_ARCH_ARM
                and not uc._mode & unicorn_const.UC_MODE_MCLASS):
            return True
        return False

    @classmethod
    def get_model_from_uc(cls, uc: unicorn.Uc) -> Optional[str]:
        for model_name, model_const in cls._UNICORN_CPU_MODELS.items():
            if uc._mode & model_const:
                return model_name

        return None

    @classmethod
    def from_backend(
        cls, backend: Any, *args: List[Any], **kwargs: Dict[str, Any]
    ) -> 'ArchArm32Unicorn':
        backend = cast(unicorn.Uc, backend)
        endian = cls.endian_from_uc(backend)
        model = cls.get_model_from_uc(backend)
        return cls(endian, model, uc=backend)
