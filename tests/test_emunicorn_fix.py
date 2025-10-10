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


from fiit.emunicorn import unicorn_fix_issue_972

from .fixtures import create_uc_arm_926

# ==============================================================================


def test_unicorn_fix_issue_972():
    uc = create_uc_arm_926()
    unicorn_fix_issue_972(uc)
    assert len(uc._callbacks) == 1
    unicorn_fix_issue_972(uc)
    assert len(uc._callbacks) == 1
