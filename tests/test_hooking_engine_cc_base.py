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

import pytest

from fiit.arch_ctypes.base_types import UnsignedInt, FunctionSpec
from fiit.hooking_engine.cc_base import (
    CallingConvention, CpuContext, FuncArg, ReturnValue
)


def test_set_pc_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().set_pc(0xff)


def test_get_return_address_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().get_return_address()


def test_get_cpu_context_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().get_cpu_context()


def test_get_argument_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().get_arguments(FunctionSpec('foo'))


def test_set_argument_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().set_arguments(FunctionSpec('foo'),
                                          {0: UnsignedInt(1)})


def test_get_return_value_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().get_return_value(None)


def test_set_return_value_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().set_return_value(
            FunctionSpec('test'), UnsignedInt(1))


def test_call_not_implemented():
    with pytest.raises(NotImplementedError):
        CallingConvention().call(FunctionSpec('test'), {0: UnsignedInt(1)})


def test_only_code_coverage():
    CpuContext()
    FuncArg(0, UnsignedInt(1), FunctionSpec(), lambda *args: None).write()
    ReturnValue(UnsignedInt(0), FunctionSpec(), lambda *args: None).write()
