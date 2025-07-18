#!/bin/bash

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

# IPY_TEST_SIMPLE_PROMPT=1 Force IPython to use input than readline.
IPY_TEST_SIMPLE_PROMPT=1 JUPYTER_PLATFORM_DIRS=1 pytest \
  --cov-report html \
  --cov="fiit.core" \
  --cov="fiit.unicorn" \
  --cov="fiit.plugins" \
  -s -v "${@}"

rm -rf .pytest_cache
