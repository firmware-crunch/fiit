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

import ctypes

import pytest

from .fixtures.fixture_utils import temp_named_txt_file

from fiit.arch_ctypes import (
    configure_ctypes, CTypesConfig,
    CTypesTranslator, CTypesTranslatorError, PYCPARSEREXT_GNU)
from fiit.arch_ctypes.base_types import (
    DataPointerBase,
    CodePointerBase, ArgSpec, FunctionSpec,
    UnsignedInt,
    Enum, Struct)


def test_ctypes_translator_get_ctypes_config():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    assert isinstance(ctt.get_ctypes_config(), CTypesConfig)


def test_ctypes_translator_get_type_by_name():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    assert ctt.get_type_by_name('unsigned int') == UnsignedInt


def test_ctypes_translator_parse_type_numeric_type():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    unsigned_int_type = ctt.parse_type('  unsigned  int  ')
    assert unsigned_int_type == UnsignedInt


def test_ctypes_translator_parse_type_pointer_type():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    unsigned_int_pointer_type = ctt.parse_type('  unsigned  int  * ')
    assert issubclass(unsigned_int_pointer_type, DataPointerBase)


def test_ctypes_translator_parse_type_custom():
    basic_types = configure_ctypes('arm:el:32', [globals()])

    class CustomType(UnsignedInt):
        _name_ = 'CustomType'

    ctt = CTypesTranslator(basic_types)
    ctt.add_cdata_type({CustomType._name_: CustomType})
    assert ctt.parse_type(' CustomType ') == CustomType


def test_ctypes_translator_translate_aggregate_type():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        """
        void func(void){}

        struct CustomAggregateType
        {
            unsigned int f1;
            unsigned char buffer [10];
            struct CustomAggregateType *next;
        };
        """)
    custom = extra_type['struct CustomAggregateType']
    custom_instance = custom()

    # Types checks
    assert issubclass(custom, Struct)
    assert ctypes.sizeof(custom) == 20
    assert custom._fields_[0][1] == UnsignedInt
    assert issubclass(custom._fields_[1][1], ctypes.Array)
    assert issubclass(custom._fields_[2][1], DataPointerBase)

    # Instance checks
    assert ctypes.sizeof(custom) == 20
    assert isinstance(custom_instance.f1, UnsignedInt)
    assert isinstance(custom_instance.buffer, ctypes.Array)
    assert isinstance(custom_instance.next, DataPointerBase)


def test_ctypes_translator_translate_typedef():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        """
        typedef unsigned int size_t;
        """)
    size_t = extra_type['size_t']
    assert issubclass(size_t, UnsignedInt)


def test_ctypes_translator_translate_custom_type():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    # ctt.add_cdata_type({'custom': UnsignedInt})
    extra_type = ctt.translate_from_source(
        """
        typedef unsigned int custom;
        typedef custom opaque;
        """)
    assert issubclass(extra_type['custom'], UnsignedInt)
    assert issubclass(extra_type['opaque'], UnsignedInt)


def test_ctypes_translator_translate_const_decl_with_operator_plus():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[2+2];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 4


def test_ctypes_translator_translate_const_decl_with_operator_minus():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[12-4];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 8


def test_ctypes_translator_translate_const_decl_with_operator_multiply():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[6*2];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 12


def test_ctypes_translator_translate_const_decl_with_operator_divider():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[8/2];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 4


def test_ctypes_translator_translate_const_decl_with_operator_shift_left():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[2<<1];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 4


def test_ctypes_translator_translate_const_decl_with_operator_shift_right():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[8>>1];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 4


def test_ctypes_translator_translate_const_decl_with_operator_sizeof():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "struct test_struct {unsigned char array[sizeof(unsigned int)];};")
    assert ctypes.sizeof(extra_type['struct test_struct']) == 4


def test_ctypes_translator_translate_function_pointer():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source("typedef void (*p1)(unsigned int);")
    assert issubclass(extra_type['p1'], CodePointerBase)
    assert extra_type['p1']._function_.name == 'p1'
    assert extra_type['p1']._function_.return_value_type is None
    assert len(extra_type['p1']._function_.arguments) == 1
    assert issubclass(extra_type['p1']._function_.arguments[0].type, UnsignedInt)


def test_ctypes_translator_translate_enum():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "enum color { red, green = 20, blue };")
    assert issubclass(extra_type['color'], Enum)
    assert extra_type['color'](0).get_identifier(20) == 'green'


def test_ctypes_translator_translate_union():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_source(
        "union ip { unsigned char ipv4[4]; unsigned char ipv6[128];};")
    assert issubclass(extra_type['ip'], ctypes.Union)
    assert ctypes.sizeof(extra_type['ip']) == 128


@pytest.mark.parametrize(
    'temp_named_txt_file', [['typedef unsigned int size_t;', '.c']],
    indirect=['temp_named_txt_file'])
def test_ctypes_translator_translate_typedef_from_file(temp_named_txt_file):
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    extra_type = ctt.translate_from_file(temp_named_txt_file.name)
    size_t = extra_type['size_t']
    assert issubclass(size_t, UnsignedInt)


def test_ctypes_translator_parse_function_prototype():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_spec = ctt.parse_function_prototype(
        'unsigned int foo(unsigned int a);')
    assert func_spec.name == 'foo'
    assert func_spec.return_value_type == UnsignedInt
    assert len(func_spec.arguments) == 1
    assert isinstance(func_spec.arguments[0], ArgSpec)
    assert func_spec.arguments[0].name == 'a'
    assert func_spec.arguments[0].type == UnsignedInt


def test_ctypes_translator_parse_function_prototype_with_no_return_value():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_spec = ctt.parse_function_prototype(
        'void foo(unsigned int a);')
    assert func_spec.name == 'foo'
    assert func_spec.return_value_type is None
    assert len(func_spec.arguments) == 1
    assert isinstance(func_spec.arguments[0], ArgSpec)
    assert func_spec.arguments[0].name == 'a'
    assert func_spec.arguments[0].type == UnsignedInt


def test_ctypes_translator_parse_function_prototype_with_variadic_arg():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_spec = ctt.parse_function_prototype(
        'void foo(unsigned int a, ...);')
    assert func_spec.is_variadic
    assert len(func_spec.arguments) == 1


def test_ctypes_translator_parse_function_prototype_with_array_argument():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_spec = ctt.parse_function_prototype(
        'void foo(unsigned int a[]);')
    assert func_spec.name == 'foo'
    assert func_spec.return_value_type is None
    assert len(func_spec.arguments) == 1
    assert isinstance(func_spec.arguments[0], ArgSpec)
    assert func_spec.arguments[0].name == 'a'
    assert issubclass(func_spec.arguments[0].type, DataPointerBase)
    assert func_spec.arguments[0].type.type == UnsignedInt


def test_ctypes_translator_parse_function_prototype_with_no_argument():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_spec = ctt.parse_function_prototype(
        'void foo();')
    assert func_spec.name == 'foo'
    assert func_spec.return_value_type is None
    assert func_spec.arguments is None


def test_ctypes_translator_parse_function_prototype_invalid_prototype():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    with pytest.raises(CTypesTranslatorError):
        ctt.parse_function_prototype(
            'unsigned int foo(unsigned int a); struct MyStruct {int a;};')


def test_ctypes_translator_decl_to_type_type_not_handle():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    with pytest.raises(CTypesTranslatorError):
        ctt._decl_to_type(1, {})


def test_ctypes_translator_parse_function_prototype_gnu_flavor():
    ctypes_config = configure_ctypes('arm:el:32', [globals()])
    ctt = CTypesTranslator(ctypes_config, PYCPARSEREXT_GNU)
    func_spec = ctt.parse_function_prototype(
        ' __attribute__((__noreturn__)) extern void loader(unsigned int x);')
    assert func_spec.name == 'loader'
    assert func_spec.return_value_type is None
    assert func_spec.arguments is not None
    assert issubclass(func_spec.arguments[0].type, UnsignedInt)


def test_ctypes_translator_parse_function_prototypes():
    ctt = CTypesTranslator(configure_ctypes('arm:el:32', [globals()]))
    func_specs = ctt.parse_function_prototypes(
        """
        void foo(unsigned int a);
        unsigned int bar(void);
        """)
    assert len(func_specs) == 2

    for spec in func_specs:
        assert isinstance(spec, FunctionSpec)

    assert func_specs[0].name == 'foo'
    assert func_specs[0].return_value_type is None
    assert func_specs[0].arguments[0].name == 'a'
    assert func_specs[0].arguments[0].type == UnsignedInt

    assert func_specs[1].name == 'bar'
    assert func_specs[1].return_value_type == UnsignedInt
    assert func_specs[1].arguments is None
