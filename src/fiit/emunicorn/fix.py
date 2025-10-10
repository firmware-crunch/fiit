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
    'unicorn_fix_issue_972'
]

from typing import Union, Any

import unicorn
from unicorn.unicorn_const import UC_HOOK_CODE

# ==============================================================================


def _hook_code_fix_issue_972(
    _: unicorn.Uc, __: int, ___: int, ____: Any
) -> None:
    """ """


_handler_hook_code_fix_issue_972: Union[int, None] = None


def unicorn_fix_issue_972(uc: unicorn.Uc) -> None:
    """
    Dirty workaround to get correct PC value in memory access hook.
    This brings a big overhead, since each instruction is hooked.
    See design bug, not solved in unicorn 2:

    - Fix issue with some memory hooks and PC register
      https://github.com/unicorn-engine/unicorn/pull/1257

    - ARM - Wrong PC in data hook
      https://github.com/unicorn-engine/unicorn/issues/972
    """
    global _handler_hook_code_fix_issue_972

    uc_callbacks = [e[0] for e in uc._callbacks.values()]

    if (_hook_code_fix_issue_972 not in uc_callbacks
            and _handler_hook_code_fix_issue_972 is None):

        _handler_hook_code_fix_issue_972 = uc.hook_add(
            UC_HOOK_CODE, _hook_code_fix_issue_972, 0, 1
        )
