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
    'create_uc_arm',
    'create_uc_arm_926',
    'create_uc_arm_1176',
    'create_uc_arm_cortex'
]

import unicorn
from unicorn import unicorn_const


# ------------------------------------------------------------------------------

def create_uc_arm() -> unicorn.Uc:
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN | unicorn_const.UC_MODE_THUMB
    )
    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    return uc


def create_uc_arm_926() -> unicorn.Uc:
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_ARM926
    )
    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    return uc


def create_uc_arm_1176() -> unicorn.Uc:
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_ARM1176
    )
    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    return uc


def create_uc_arm_cortex() -> unicorn.Uc:
    unicorn_mode = (
        unicorn_const.UC_MODE_LITTLE_ENDIAN
        | unicorn_const.UC_MODE_THUMB
        | unicorn_const.UC_MODE_MCLASS
    )
    uc = unicorn.Uc(unicorn_const.UC_ARCH_ARM, unicorn_mode)
    return uc

