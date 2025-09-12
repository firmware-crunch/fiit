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
from dataclasses import dataclass, field
from typing import (
    Type, cast,  Any, Literal, List, Dict, Union, Tuple, Optional)

from ..emu.emu_types import AddressSpace, MemoryRegion


################################################################################
# ctypes.array utility
################################################################################

def array_eq(array_1: ctypes.Array, array_2: ctypes.Array) -> bool:
    if array_1._length_ != array_2._length_:
        return False

    for idx, item_array_1 in enumerate(array_1):
        if isinstance(item_array_1, ctypes.Array):
            if not array_eq(item_array_1, array_2[idx]):
                return False
        else:
            if item_array_1 != array_2[idx]:
                return False

    return True


################################################################################
# C Base Type Container
################################################################################

class CBaseType(ctypes.Structure):
    _name_: str
    _align_: int

    def __init__(self):
        ctypes.Structure.__init__(self)

    @property
    def _raw_(self) -> bytes:
        return ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))

    @_raw_.setter
    def _raw_(self, raw_value: bytes):
        size = ctypes.sizeof(self)
        buffer = (ctypes.c_ubyte * size)()
        buffer[:size] = raw_value
        ctypes.memmove(ctypes.addressof(self), ctypes.addressof(buffer), size)

    @classmethod
    def get_align(cls) -> int:
        return cls._align_


################################################################################
#  Type categorisation
################################################################################

class FundBaseType(CBaseType):
    """ Fundamental C base type """
    pass


################################################################################
# Pointer for variable and function
################################################################################


class DataPointerBase(FundBaseType):
    type: CBaseType

    @classmethod
    def new_type(cls, ctype: Type[CBaseType]) -> Type['DataPointerBase']:
        ptr_t = type(f'{ctype.__name__}DataPointer', (cls,),
                     dict(_name_=f'{ctype._name_}*', type=ctype))
        return cast(Type['DataPointerBase'], ptr_t)

    @classmethod
    def new(
        cls,
        ctypes_instance: CBaseType,
        target_address: int = 0,
        address_space: AddressSpace = None
    ) -> 'DataPointerBase':
        new_ptr = cls.new_type(type(ctypes_instance))(target_address, address_space)
        new_ptr.target_backed_address = ctypes.addressof(ctypes_instance)
        return new_ptr

    def __init__(
        self, target_address: int = 0, address_space: AddressSpace = None
    ):
        FundBaseType.__init__(self)
        # target_address is the ctypes container of the pointer value
        self.target_address = target_address
        self.target_backed_address: Optional[int] = None
        self.address_space: Union[AddressSpace, None] = address_space

    def is_null(self) -> bool:
        if self.target_address == 0:
            return True
        return False

    @property
    def contents(self) -> Any:
        if self.address_space is not None:
            mem_region = list(filter(
                lambda m: m.base_address <= self.target_address < m.end_address,
                self.address_space))

            if not mem_region:
                raise ValueError(f'Target address {self.target_address:#x} not '
                                 f'found in address space.')

            mem_region = cast(MemoryRegion, mem_region[0])

            #  Address translation to host memory map
            mapping_target_backed_address = \
                mem_region.host_base_address \
                + (self.target_address - mem_region.base_address)

            return self.type.from_address(mapping_target_backed_address)

        elif self.target_backed_address:  # for non host mapped C data type
            return self.type.from_address(self.target_backed_address)

        raise ValueError('Pointer not backed by any address space')

    @property
    def raw_contents(self) -> bytes:
        return ctypes.string_at(self.target_backed_address,
                                ctypes.sizeof(self.type))

    def __eq__(self, other: Any) -> bool:
        if self.target_address != other.target_address:
            return False
        return True

    def __ne__(self, other: Any) -> bool:
        if self.target_address == other.target_address:
            return False
        return True


@dataclass
class ArgSpec:
    type: Type[CBaseType]
    name: str = None

    def __post_init__(self):
        self.size = ctypes.sizeof(self.type)
        self.align = self.type.get_align()
        self.word_size = 0


@dataclass
class FunctionSpec:
    name: str = field(default=None)
    return_value_type: Type[CBaseType] = field(default=None)
    arguments: List[ArgSpec] = field(default_factory=list)
    cc: Any = field(default=None)
    address: int = field(default=None)
    is_variadic: bool = False

    def __post_init__(self):
        self._name_ = self.name


class CodePointerBase(FundBaseType):
    _function_: FunctionSpec

    @classmethod
    def new_type(cls, function: FunctionSpec) -> Type['CodePointerBase']:
        name = function.name if function.name is not None else '<anonymous>'
        ptr_t = type(f'{name}CodePointer', (cls, FundBaseType),
                     dict(_name_=name, _function_=function))
        return cast(Type['CodePointerBase'], ptr_t)

    def __init__(self, target_address: int = 0):
        FundBaseType.__init__(self)
        # target_address is the ctypes container of the pointer value
        self.target_address = target_address


################################################################################
# Void type (the famous)
################################################################################

class Void(CBaseType):
    _name_ = 'void'
    _align_ = None


################################################################################
# Integer type
################################################################################

class IntegralType(FundBaseType):
    def __init__(self, value: int = None):
        FundBaseType.__init__(self)
        if value:
            self.value = value

    def __eq__(self, other: Any) -> bool:
        if self.value != other.value:
            return False
        return True

    def __ne__(self, other: Any) -> bool:
        if self.value == other.value:
            return False
        return True


class Enum(IntegralType):
    _val_id_: Tuple[Tuple[int, str]]

    def get_identifier(self, value: int) -> Union[str, None]:
        for enum_value, identifier in self._val_id_:
            if enum_value == value:
                return identifier


# char

class Char(IntegralType):
    _name_ = 'char'


# char (unsigned)

class SignedChar(IntegralType):
    _name_ = 'signed char'


class UnsignedChar(IntegralType):
    _name_ = 'unsigned char'


# short

class Short(IntegralType):
    _name_ = 'short'


class ShortInt(IntegralType):
    _name_ = 'short int'


class SignedShort(IntegralType):
    _name_ = 'signed short'


class SignedShortInt(IntegralType):
    _name_ = 'signed short int'


# short (unsigned)

class UnsignedShort(IntegralType):
    _name_ = 'unsigned short'


class UnsignedShortInt(IntegralType):
    _name_ = 'unsigned short int'


# int

class Int(IntegralType):
    _name_ = 'int'


class Signed(IntegralType):
    _name_ = 'signed'


class SignedInt(IntegralType):
    _name_ = 'signed int'


class Unsigned(IntegralType):
    _name_ = 'unsigned'


class UnsignedInt(IntegralType):
    _name_ = 'unsigned int'


# long

class Long(IntegralType):
    _name_ = 'long'


class LongInt(IntegralType):
    _name_ = 'long int'


class SignedLong(IntegralType):
    _name_ = 'Signed long'


class SignedLongInt(IntegralType):
    _name_ = 'signed long int'


# long (unsigned)

class UnsignedLong(IntegralType):
    _name_ = 'unsigned long'


class UnsignedLongInt(IntegralType):
    _name_ = 'unsigned long int'


class LongUnsignedInt(IntegralType):
    _name_ = 'long unsigned int'


# long long

class LongLong(IntegralType):
    _name_ = 'long long'


class LongLongInt(IntegralType):
    _name_ = 'long long int'


class SignedLongLong(IntegralType):
    _name_ = 'signed long long'


class SignedLongLongInt(IntegralType):
    _name_ = 'signed long long int'


# long long (unsigned)

class UnsignedLongLong(IntegralType):
    _name_ = 'unsigned long long'


class UnsignedLongLongInt(IntegralType):
    _name_ = 'unsigned long long int'


# bool (C99)


class _Bool(IntegralType):
    _name_ = '_Bool'


# Other loose extra type

class Bool(IntegralType):
    _name_ = 'bool'


class Int16T(IntegralType):
    _name_ = 'int16_t'


class Uint16T(IntegralType):
    _name_ = 'uint16_t'


################################################################################
# Float type
################################################################################

class FloatType(FundBaseType):
    def __init__(self, value: float = None):
        FundBaseType.__init__(self)
        if value:
            setattr(self, 'value', value)

    def __eq__(self, other: Any) -> bool:
        if self.value != other.value:
            return False
        return True

    def __ne__(self, other: Any) -> bool:
        if self.value == other.value:
            return False
        return True


class Float(FloatType):
    _name_ = 'float'


class Double(FloatType):
    _name_ = 'double'


class FloatCodecBase:
    def set_endian(self, endian_code: Literal['<', '>']):
        raise NotImplementedError('Fixme')

    @classmethod
    def decode(cls, raw: bytes) -> Any:
        raise NotImplementedError('Fixme')

    @classmethod
    def encode(cls, value: Any) -> bytes:
        raise NotImplementedError('Fixme')


################################################################################
# Aggregate type
################################################################################

class Struct(CBaseType):
    @classmethod
    def get_align(cls) -> int:
        align = 0
        for _, f_type in cls._fields_:
            if issubclass(f_type, FundBaseType):
                f_type = cast(FundBaseType, f_type)
                if f_type._align_ > align:
                    align = f_type.get_align()
            elif issubclass(f_type, ctypes.Array):
                f_type = cast(ctypes.Array, f_type)
                al = f_type._type_.get_align()
                if al > align:
                    align = al
            elif issubclass(f_type, Struct):
                f_type = cast(Struct, f_type)
                al = f_type.get_align()
                if al > align:
                    align = al
        return align

    @classmethod
    def init_from_dict(cls, values: Dict[str, Any]) -> CBaseType:
        struct_inst = cls()
        for f_name, f_value in values.items():
            for struct_f_name, struct_f_type in cls._fields_:
                if struct_f_name == f_name:
                    struct_member = getattr(struct_inst, struct_f_name)
                    if issubclass(struct_f_type, IntegralType) \
                            or issubclass(struct_f_type, FloatType):
                        struct_member.value = f_value
                    elif issubclass(struct_f_type, Struct):
                        struct_f_type = cast(Struct, struct_f_type)
                        struct_member._raw_ = struct_f_type.init_from_dict(
                            f_value)._raw_
                    elif issubclass(struct_f_type, DataPointerBase):
                        struct_member.target_address = f_value
                    elif issubclass(struct_f_type, ctypes.Array):
                        struct_f_type = cast(ctypes.Array, struct_f_type)
                        if(issubclass(struct_f_type._type_, IntegralType)
                                or issubclass(struct_f_type._type_, FloatType)):
                            for idx, slot in enumerate(struct_member):
                                slot.value = f_value[idx]
                        elif issubclass(struct_f_type._type_, Struct):
                            for idx, slot in enumerate(struct_member):
                                slot._raw_ = struct_f_type._type_.\
                                    init_from_dict(f_value[idx])._raw_
                        elif issubclass(struct_f_type._type_, DataPointerBase):
                            for idx, slot in enumerate(struct_member):
                                slot.target_address = f_value[idx]
                    else:
                        raise NotImplementedError(
                            'Struct member type init not implemented')
        return struct_inst

    def __eq__(self, other: Any) -> bool:
        for field_name, _ in self._fields_:
            member_1 = getattr(self, field_name)
            member_2 = getattr(other, field_name)
            if isinstance(member_1, ctypes.Array):
                if not array_eq(member_1, member_2):
                    return False
            elif isinstance(member_1, Struct):
                if not member_1.__eq__(member_2):
                    return False
            else:
                if member_1 != member_2:
                    return False
        return True

    def __ne__(self, other: Any) -> bool:
        for field_name, _ in self._fields_:
            member_1 = getattr(self, field_name)
            member_2 = getattr(other, field_name)
            if isinstance(member_1, ctypes.Array):
                if not array_eq(member_1, member_2):
                    return True
            elif isinstance(member_1, Struct):
                if not member_1.__ne__(member_2):
                    return True
            else:
                if member_1 != member_2:
                    return True
        return False


################################################################################
# C type configuration
################################################################################

FACTORY_TYPE = 'factory_type'
BASIC_TYPE = 'basic_type'
EXTRA_TYPE = 'extra_type'
