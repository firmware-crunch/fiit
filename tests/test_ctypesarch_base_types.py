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

from typing import Tuple, Type
import ctypes
import copy

import pytest

from .fixtures.fixture_utils import minimal_memory, minimal_memory_host

from fiit.ctypesarch import configure_ctypes
from fiit.ctypesarch.base_types import (
    array_eq,
    CBaseType,
    DataPointerBase,
    CodePointerBase, FunctionSpec,
    UnsignedChar, UnsignedInt, UnsignedLongLong, UnsignedShort,
    Float, FloatCodecBase,
    Enum, Struct
)


# Array utility


def test_ctypes_array_eq_true():
    configure_ctypes('arm:el:32', [globals()])
    array_1 = UnsignedInt * 2
    array_2 = UnsignedInt * 2
    assert array_eq(
        array_1(UnsignedInt(1), UnsignedInt(2)),
        array_2(UnsignedInt(1), UnsignedInt(2)))


def test_ctypes_array_eq_true_nested_array():
    configure_ctypes('arm:el:32', [globals()])
    base_array = UnsignedInt * 2
    array_1 = base_array * 2
    array_2 = base_array * 2
    assert array_eq(
        array_1(base_array(UnsignedInt(1), UnsignedInt(2)),
                base_array(UnsignedInt(3), UnsignedInt(4))),
        array_2(base_array(UnsignedInt(1), UnsignedInt(2)),
                base_array(UnsignedInt(3), UnsignedInt(4))))


def test_ctypes_array_eq_false_nested_array():
    configure_ctypes('arm:el:32', [globals()])
    base_array = UnsignedInt * 2
    array_1 = base_array * 2
    array_2 = base_array * 2
    assert not array_eq(
        array_1(base_array(UnsignedInt(1), UnsignedInt(2)),
                base_array(UnsignedInt(3), UnsignedInt(4))),
        array_2(base_array(UnsignedInt(1), UnsignedInt(2)),
                base_array(UnsignedInt(8), UnsignedInt(4))))


def test_ctypes_array_eq_false_different_values():
    configure_ctypes('arm:el:32', [globals()])
    array_1 = UnsignedInt * 2
    array_2 = UnsignedInt * 2
    assert not array_eq(array_1(UnsignedInt(1), UnsignedInt(2)),
                        array_2(UnsignedInt(2), UnsignedInt(2)))


def test_ctypes_array_eq_false_different_length():
    configure_ctypes('arm:el:32', [globals()])
    array_1 = UnsignedInt * 2
    array_2 = UnsignedInt * 1
    assert not array_eq(
        array_1(UnsignedInt(1), UnsignedInt(2)), array_2(UnsignedInt(1)))


# CBaseType


def test_ctypes_cbase_type_init():
    assert isinstance(CBaseType(), ctypes.Structure)


def test_ctypes_cbase_type_get_raw():
    class CustomType(CBaseType):
        _fields_ = [('f1', ctypes.c_uint32.__ctype_be__)]

    ct = CustomType()
    ct.f1 = 0x01020304
    assert ct._raw_ == b'\x01\x02\x03\x04'


def test_ctypes_cbase_type_set_raw():
    class CustomType(CBaseType):
        _fields_ = [('f1', ctypes.c_uint32.__ctype_be__)]

    ct = CustomType()
    ct._raw_ = b'\x05\x06\x07\x08'
    assert ct.f1 == 0x05060708


def test_ctypes_cbase_type_get_align():
    class CustomType(CBaseType):
        _align_ = 4
        _fields_ = [('f1', ctypes.c_uint32.__ctype_be__)]

    ct = CustomType()
    assert ct.get_align() == 4


# IntegralType

def test_ctypes_integral_type_init_with_value_check_value():
    configure_ctypes('arm:el:32', [globals()])
    value_to_test = 0x01020304
    x = UnsignedInt(value_to_test)
    assert x.value == value_to_test


def test_ctypes_integral_type_init_with_value_check_raw_():
    configure_ctypes('arm:el:32', [globals()])
    x = UnsignedInt(0x01020304)
    assert x._raw_ == b'\x04\x03\x02\x01'


def test_ctypes_integral_type_eq_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert UnsignedInt(7) == UnsignedInt(7)


def test_ctypes_integral_type_eq_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert UnsignedInt(7) == UnsignedInt(12)


def test_ctypes_integral_type_ne_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert UnsignedInt(7) != UnsignedInt(7)


def test_ctypes_integral_type_ne_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert UnsignedInt(7) != UnsignedInt(12)


# FloatType


def test_ctypes_float_type_init_with_value_check_value():
    configure_ctypes('arm:el:32', [globals()])
    value_to_test = 0.9375
    x = Float(value_to_test)
    assert x.value == value_to_test


def test_ctypes_float_type_init_with_value_check_raw():
    configure_ctypes('arm:el:32', [globals()])
    x = Float(0.9375)
    assert x._raw_ == b'\x00\x00\x70\x3f'


def test_ctypes_float_type_eq_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert Float(0.9375) == Float(0.9375)


def test_ctypes_float_type_eq_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert Float(0.9375) == Float(0.75)


def test_ctypes_float_type_ne_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert Float(0.9375) != Float(0.9375)


def test_ctypes_float_type_ne_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert Float(0.9375) != Float(0.75)


# FloatCodecBase

def test_float_codec_base_not_implemented():
    with pytest.raises(NotImplementedError):
        FloatCodecBase().set_endian('<')
    with pytest.raises(NotImplementedError):
        FloatCodecBase.decode(b'\xff')
    with pytest.raises(NotImplementedError):
        FloatCodecBase.encode(1)



# DataPointerBase

def test_ctypes_new_data_pointer_type():
    configure_ctypes('arm:el:32', [globals()])
    new_ptr_type = DataPointerBase.new_type(UnsignedInt)
    assert issubclass(new_ptr_type, DataPointerBase)
    assert new_ptr_type.type == UnsignedInt


def test_ctypes_new_data_pointer_instance():
    configure_ctypes('arm:el:32', [globals()])
    new_ptr_instance = DataPointerBase.new(UnsignedInt(0x01020304))
    assert isinstance(new_ptr_instance, DataPointerBase)
    assert new_ptr_instance.type == UnsignedInt


def test_ctypes_data_pointer_contents_check():
    configure_ctypes('arm:el:32', [globals()])
    test_value = 0x01020304
    assert (DataPointerBase.new(UnsignedInt(test_value)).contents.value
            == test_value)


def test_ctypes_data_pointer_raw_contents_check():
    configure_ctypes('arm:el:32', [globals()])
    assert (DataPointerBase.new(UnsignedInt(0x01020304)).raw_contents
            == b'\x04\x03\x02\x01')


def test_ctypes_data_pointer_null():
    configure_ctypes('arm:el:32', [globals()])
    assert DataPointerBase.new(UnsignedInt(0x01020304)).is_null()


def test_ctypes_data_pointer_fail_de_referencing():
    configure_ctypes('arm:el:32', [globals()])
    new_ptr_type = DataPointerBase.new_type(UnsignedInt)
    new_ptr = new_ptr_type(488)

    with pytest.raises(ValueError):
        assert new_ptr.contents


def test_ctypes_data_pointer_host_mapped_de_referencing(minimal_memory_host):
    mem = minimal_memory_host
    mem_region = mem.regions[0]
    raw_value_1 = b'\x04\x03\x02\x01'
    raw_value_offset_1 = 0x50
    raw_value_2 = b'\x08\x07\x06\x05'
    raw_value_offset_2 = 0x58

    mem_region.host_mem.seek(raw_value_offset_1)
    mem_region.host_mem.write(raw_value_1)
    mem_region.host_mem.seek(raw_value_offset_2)
    mem_region.host_mem.write(raw_value_2)

    configure_ctypes('arm:el:32', [globals()])
    int_var = UnsignedInt.from_address(
        mem_region.host_base_address+raw_value_offset_1)
    int_var_ptr = DataPointerBase.new(
        int_var, mem_region.base_address + raw_value_offset_1, mem)

    assert int_var.value == 0x01020304
    assert int_var_ptr.contents.value == 0x01020304
    assert not int_var_ptr.is_null()

    int_var_ptr.target_address = mem_region.base_address + raw_value_offset_2

    assert int_var_ptr.contents.value == 0x05060708
    assert not int_var_ptr.is_null()

    int_var_ptr.target_address = mem_region.base_address + mem_region.size * 2

    with pytest.raises(ValueError):
        assert int_var_ptr.contents.value


def test_ctypes_data_pointer_eq_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert (DataPointerBase.new(UnsignedInt(0x01020304), 0x4)
            == DataPointerBase.new(UnsignedInt(0x01020304), 0x4))


def test_ctypes_data_pointer_eq_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert (DataPointerBase.new(UnsignedInt(0x01020304), 0x4)
                == DataPointerBase.new(UnsignedInt(0x01020304), 0x20))


def test_ctypes_data_pointer_ne_value_equal():
    configure_ctypes('arm:el:32', [globals()])
    with pytest.raises(AssertionError):
        assert (DataPointerBase.new(UnsignedInt(0x01020304), 0x4)
                != DataPointerBase.new(UnsignedInt(0x01020304), 0x4))


def test_ctypes_data_pointer_ne_value_not_equal():
    configure_ctypes('arm:el:32', [globals()])
    assert (DataPointerBase.new(UnsignedInt(0x01020304), 0x4)
            != DataPointerBase.new(UnsignedInt(0x01020304), 0x20))


# CodePointerBase

def test_ctypes_new_code_pointer_type():
    configure_ctypes('arm:el:32', [globals()])
    spec = FunctionSpec()
    new_ptr_type = CodePointerBase.new_type(spec)
    assert issubclass(new_ptr_type, CodePointerBase)
    assert new_ptr_type._function_ == spec


def test_ctypes_new_code_pointer_instance():
    configure_ctypes('arm:el:32', [globals()])
    spec = FunctionSpec()
    new_ptr = CodePointerBase.new_type(spec)()
    assert isinstance(new_ptr, CodePointerBase)


# Enum

def test_ctypes_new_enum():
    configure_ctypes('arm:el:32', [globals()])
    new_enum = Enum()
    new_enum._val_id_ = ((5, 'ORANGE'), (30, 'BLUE'))
    assert new_enum.get_identifier(30) == 'BLUE'


# Struct


def test_ctypes_struct_get_align_with_fund_types():
    configure_ctypes('arm:el:32', [globals()])

    class TestStruct(Struct):
        _fields_ = [
            ('x1', UnsignedChar), ('x2', UnsignedInt), ('x3', UnsignedLongLong)]

    assert TestStruct.get_align() == UnsignedLongLong.get_align()


def test_ctypes_struct_get_align_with_fund_types_and_nested_structs():
    configure_ctypes('arm:el:32', [globals()])

    class StructL3(Struct):
        _fields_ = [('x1', UnsignedLongLong)]

    class StructL2(Struct):
        _fields_ = [('x1', StructL3)]

    class TestStruct(Struct):
        _fields_ = [('x1', UnsignedChar), ('x2', UnsignedInt), ('x3', StructL2)]

    assert TestStruct.get_align() == UnsignedLongLong.get_align()


def test_ctypes_struct_get_align_with_fund_types_and_array():
    configure_ctypes('arm:el:32', [globals()])

    class TestStruct(Struct):
        _fields_ = [
            ('x1', UnsignedChar), ('x2', UnsignedShort), ('x3', UnsignedInt*8)]

    assert TestStruct.get_align() == UnsignedInt.get_align()


def test_ctypes_struct_init_from_dict():
    configure_ctypes('arm:el:32', [globals()])

    class StructL3(Struct):
        _fields_ = [('x1', UnsignedLongLong)]

    class StructL2(Struct):
        _fields_ = [('x1', StructL3), ('x2', UnsignedShort)]

    class TestStruct(Struct):
        _fields_ = [('x1', StructL2),
                    ('x2', UnsignedInt),
                    ('x3', UnsignedChar*4),
                    ('x4', DataPointerBase.new_type(UnsignedInt)),
                    ('x5', StructL3 * 2),
                    ('x6', DataPointerBase.new_type(UnsignedInt) * 2)]

    s_inst = TestStruct.init_from_dict({
        'x1': {'x1': {'x1': 0x0102030405060708}, 'x2': 0x090A},
        'x2': 0x0B0C0D0E,
        'x3': [*b'\x0F\x10\x11\x12'],
        'x4': 0x4,
        'x5': [{'x1': 0x131415161718191A}, {'x1': 0x1B1C1D1E1F202122}],
        'x6': [0x5, 0x6]
    })

    assert isinstance(s_inst, TestStruct)
    assert isinstance(s_inst.x1, StructL2)
    assert isinstance(s_inst.x1.x1, StructL3)
    assert isinstance(s_inst.x1.x1.x1, UnsignedLongLong)
    assert s_inst.x1.x1.x1.value == 0x0102030405060708
    assert isinstance(s_inst.x1.x2, UnsignedShort)
    assert s_inst.x1.x2.value == 0x090A
    assert isinstance(s_inst.x2, UnsignedInt)
    assert s_inst.x2.value == 0x0B0C0D0E
    assert isinstance(s_inst.x3, ctypes.Array)
    assert s_inst.x3._type_ == UnsignedChar
    assert isinstance(s_inst.x4, DataPointerBase)
    assert s_inst.x4.target_address == 0x4
    assert isinstance(s_inst.x5, ctypes.Array)
    assert s_inst.x5._type_ == StructL3
    assert s_inst.x5[0].x1.value == 0x131415161718191A
    assert s_inst.x5[1].x1.value == 0x1B1C1D1E1F202122
    assert isinstance(s_inst.x6, ctypes.Array)
    assert issubclass(s_inst.x6._type_, DataPointerBase)
    assert s_inst.x6[0].target_address == 0x5
    assert s_inst.x6[1].target_address == 0x6


def test_ctypes_struct_init_from_dict_invalid_type():
    class TestStruct(Struct):
        _fields_ = [('x1', ctypes.c_int)]

    with pytest.raises(NotImplementedError):
        TestStruct.init_from_dict({'x1': 1})


def get_fixture_nested_dict_with_heterogen_type_armel() \
        -> Tuple[Type[Struct], dict]:
    configure_ctypes('arm:el:32', [globals()])

    class StructL3(Struct):
        _fields_ = [('x1', UnsignedLongLong)]

    class StructL2(Struct):
        _fields_ = [('x1', StructL3), ('x2', UnsignedShort)]

    class TestStruct(Struct):
        _fields_ = [('x1', StructL2),
                    ('x2', UnsignedInt),
                    ('x3', UnsignedChar*4),
                    ('x4', DataPointerBase.new_type(UnsignedInt)),
                    ('x5', StructL3 * 2),
                    ('x6', DataPointerBase.new_type(UnsignedInt) * 2)]

    test_struct_instance_as_dict = {
        'x1': {'x1': {'x1': 0x0102030405060708}, 'x2': 0x090A},
        'x2': 0x0B0C0D0E,
        'x3': [*b'\x0F\x10\x11\x12'],
        'x4': 0x4,
        'x5': [{'x1': 0x131415161718191A}, {'x1': 0x1B1C1D1E1F202122}],
        'x6': [0x5, 0x6]
    }

    return TestStruct, test_struct_instance_as_dict


def test_ctypes_struct_eq_values_equal():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct)
    assert s_inst_1 == s_inst_2


def test_ctypes_struct_eq_values_not_equal_nested_struct_value():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    py_struct_2 = copy.deepcopy(py_struct)
    py_struct_2['x1']['x1']['x1'] = 0x0102030405060709
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct_2)
    with pytest.raises(AssertionError):
        assert s_inst_1 == s_inst_2


def test_ctypes_struct_eq_values_not_equal_array_value():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    py_struct_2 = copy.deepcopy(py_struct)
    py_struct_2['x3'] = [*b'\x0F\x10\x14\x12']
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct_2)
    with pytest.raises(AssertionError):
        assert s_inst_1 == s_inst_2


def test_ctypes_struct_ne_values_equal():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct)
    with pytest.raises(AssertionError):
        assert s_inst_1 != s_inst_2


def test_ctypes_struct_ne_values_not_equal_nested_struct_value():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    py_struct_2 = copy.deepcopy(py_struct)
    py_struct_2['x1']['x1']['x1'] = 0x0102030405060709
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct_2)
    assert s_inst_1 != s_inst_2


def test_ctypes_struct_ne_values_not_equal_array_value():
    TestStruct, py_struct = get_fixture_nested_dict_with_heterogen_type_armel()
    py_struct_2 = copy.deepcopy(py_struct)
    py_struct_2['x3'] = [*b'\x0F\x10\x14\x12']
    s_inst_1 = TestStruct.init_from_dict(py_struct)
    s_inst_2 = TestStruct.init_from_dict(py_struct_2)
    assert s_inst_1 != s_inst_2
