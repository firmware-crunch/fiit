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

from typing import Callable, Dict, Optional, Any, Type
import copy

from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_LR

from fiit.hooking_engine.cc_base import CallingConvention
from fiit.arch_ctypes.config import configure_ctypes
from fiit.arch_ctypes.translator import CTypesTranslator
from fiit.arch_ctypes.base_types import (
    DataPointerBase,
    CBaseType, FundBaseType, IntegralType, FloatType,
    ArgSpec, FunctionSpec, Struct)

from ..blobs.meta_bin_blob import MetaBinBlob
from ..unicorn_utils import BinBlob2Emulator, CodeBreakpoint
from ..cc.source_code_analyzer import MetaFunc


class CallingConventionBaseTester:
    def __init__(
        self, cc: Type[CallingConvention], meta_fw: MetaBinBlob
    ):
        self.cc = cc
        self.meta_fw = meta_fw
        self.meta_src = meta_fw.extra['cc_test_data']
        self.emu: Optional[BinBlob2Emulator] = None
        self.cp: Optional[CodeBreakpoint] = None

        # test states
        self._func_addr: Optional[int] = None
        self._tested_func_spec: Optional[FunctionSpec] = None
        self._expected_arg_values: Optional[Dict[int, CBaseType]] = None
        self._mutated_arg_values: Optional[Dict[int, CBaseType]] = None
        self._expected_return_value: Optional[CBaseType] = None
        self._cc_kwargs: Optional[dict] = None

        self._cc_return_value_test_ret_addr: Optional[int] = None

        self._cc_call_test_wrapper: Optional[Callable] = None
        self._cc_call_test_wrapper_ret_addr: Optional[int] = None
        self._collect_func_arg_value: Optional[list] = None
        self._collect_func_return_value = None
        self._collect_stack_canary: Optional[int] = None

    def _meta_func_filter(self, name: str) -> MetaFunc:
        return list(filter(lambda f: f.name == name, self.meta_src.func))[0]

    @staticmethod
    def _meta_func_arg_name_index(func: MetaFunc, name: str) -> int:
        return list(filter(lambda a: a[1][0] == name, func.arguments.items()))[0]

    @classmethod
    def _mutate_value(cls, value: CBaseType):
        if isinstance(value, IntegralType):
            value.value += 1
        elif isinstance(value, FloatType):
            value.value += 1
        elif isinstance(value, DataPointerBase):
            value.target_address += 4
        elif isinstance(value, Struct):
            for member_name, _ in value._fields_:
                cls._mutate_value(getattr(value, member_name))
        else:
            raise NotImplementedError(
                'Value mutation not implemented for this type')

    @classmethod
    def _mutate_argument_values(cls, arg_values) -> Dict[int, Any]:
        mutated_arg_values = copy.deepcopy(arg_values)
        for arg_idx, arg_value in mutated_arg_values.items():
            cls._mutate_value(arg_value)
        return mutated_arg_values

    @staticmethod
    def _create_typed_value(c_type: Type[CBaseType], value: Any) -> CBaseType:
        if issubclass(c_type, FundBaseType):
            return c_type(value)
        elif issubclass(c_type, Struct):
            return c_type.init_from_dict(value)
        elif issubclass(c_type, DataPointerBase):
            ptr = c_type()
            ptr.target_address = value
            return ptr
        else:
            raise NotImplementedError('Type value init not implemented')

    def run_test(self):
        print(f'\n[i] Calling convention testing with '
              f'"{self.meta_fw.arch_unicorn}" firmware.\n[i] compiler: '
              f'{self.meta_fw.compiler}\n[i] producer: {self.meta_fw.producer}')

        for func in self.meta_src.func:
            if func.name in self.meta_src.skip_test_func:
                continue

            # configure C parser
            ctypes_options = {}
            if (self.meta_fw.arch_unicorn.startswith(('arm:el:32', 'arm:eb:32'))
                    # and self.meta_fw.arch_extra
                    and (fp16_format := self.meta_fw.arch_info.get(
                        'tag_abi_fp_16bit_format', None))):
                ctypes_options.update({'fp16_format': fp16_format})

            arch, endian, size, _ = self.meta_fw.arch_unicorn.split(':')
            ctypes_arch = f'{arch}:{endian}:{size}'
            ctypes_config = configure_ctypes(
                ctypes_arch, [globals()], ctypes_options)
            cparser = CTypesTranslator(ctypes_config)
            extra_type = cparser.translate_from_source(self.meta_src.cpp_source)
            cparser.add_cdata_type(extra_type)

            func_spec = FunctionSpec(func.name)
            func_spec.address = func.address
            func_spec.return_value_type = (
                cparser.parse_type(func.return_value_type)
                if func.return_value_type else None)

            if func.return_value:
                ret_value = self._create_typed_value(
                    func_spec.return_value_type, func.return_value)
            else:
                ret_value = None

            call_args = {}
            if func.call_arg_values:
                for arg_idx, arg in func.arguments.items():
                    arg_type = cparser.parse_type(arg[1])
                    arg_instance = self._create_typed_value(
                        arg_type, func.call_arg_values[arg_idx])
                    call_args.update({arg_idx: arg_instance})
                    func_spec.arguments.append(ArgSpec(arg_type, arg[0]))

            # prepare calling convention
            cc_kwargs = {}
            if (self.meta_fw.arch_unicorn.startswith(('arm:el:32', 'arm:eb:32'))
                    and (f_float := self.meta_fw.arch_info.get('cpu_float_flag'))):
                if f_float == 'FLOAT_HARD':
                    cc_kwargs.update({'hard_fp': True})

            # Prepare Emulator
            self.emu = BinBlob2Emulator(self.meta_fw, self.meta_fw.arch_info)
            self.cp = CodeBreakpoint(self.emu.uc, self.test, [func.address])

            # run test
            self._func_addr = func.address
            self._tested_func_spec = func_spec
            self._expected_return_value = ret_value
            self._expected_arg_values = call_args
            self._cc_kwargs = cc_kwargs

            self.test_hook_before_emu(cparser)
            self.emu.start()
            self.test_hook_after_emu()

    def test_hook_before_emu(self, cparser: CTypesTranslator):
        pass

    def test_hook_after_emu(self):
        pass

    def test(self, uc: Uc, address: int):
        raise NotImplementedError('Test not implemented.')


class CallingConventionGetArgumentsTester(CallingConventionBaseTester):
    def test_hook_after_emu(self):
        assert self.cp.break_count == 1

    def test(self, uc: Uc, address: int):
        print(f'-> testing "{self._tested_func_spec.name}()"', end='')
        cc = self.cc(uc, **self._cc_kwargs)
        collect_value = cc.get_arguments(self._tested_func_spec)

        assert len(collect_value) == len(self._expected_arg_values)
        for arg_idx, func_arg in enumerate(collect_value):
            assert isinstance(func_arg.value,
                              type(self._expected_arg_values[arg_idx]))
            assert (func_arg.value._name_
                    == self._expected_arg_values[arg_idx]._name_)
            assert (func_arg.value
                    == self._expected_arg_values[arg_idx])

        print('    [PASSED]')


class CallingConventionSetArgumentsTester(CallingConventionBaseTester):
    def test_hook_after_emu(self):
        assert self.cp.break_count == 1

    def test(self, uc: Uc, address: int):
        print(f'-> testing "{self._tested_func_spec.name}()"', end='')
        mutated_arg_values = self._mutate_argument_values(
            self._expected_arg_values)
        cc = self.cc(uc, **self._cc_kwargs)
        cc.set_arguments(self._tested_func_spec, mutated_arg_values)
        collect_value = cc.get_arguments(self._tested_func_spec)
        assert len(collect_value) == len(mutated_arg_values)
        for arg_idx, func_arg in enumerate(collect_value):
            assert isinstance(func_arg.value, type(mutated_arg_values[arg_idx]))
            assert func_arg.value._name_ == mutated_arg_values[arg_idx]._name_
            assert func_arg.value == mutated_arg_values[arg_idx]

        print('    [PASSED]')


class CallingConventionGetReturnValue(CallingConventionBaseTester):
    def test_hook_after_emu(self):
        assert self.cp.break_count == 2

    def test(self, uc: Uc, address: int):
        if address == self._func_addr and self.cp.break_count == 1:
            self.cp.code_tracer_breaks.append(uc.reg_read(UC_ARM_REG_LR))
            cc = self.cc(uc, **self._cc_kwargs)
            self._cc_return_value_test_ret_addr = cc.get_return_address()
        elif(address == self._cc_return_value_test_ret_addr
             and self.cp.break_count == 2):
            print(f'-> testing "{self._tested_func_spec.name}()"', end='')
            cc = self.cc(uc, **self._cc_kwargs)
            ret = cc.get_return_value(self._tested_func_spec)
            if self._tested_func_spec.return_value_type is not None:
                assert ret.value == self._expected_return_value
            else:
                assert ret is None
            print('    [PASSED]')


class CallingConventionSetReturnValue(CallingConventionBaseTester):
    def test_hook_after_emu(self):
        assert self.cp.break_count == 2

    def test(self, uc: Uc, address: int):
        if address == self._func_addr and self.cp.break_count == 1:
            self.cp.code_tracer_breaks.append(uc.reg_read(UC_ARM_REG_LR))
            cc = self.cc(uc, **self._cc_kwargs)
            self._cc_return_value_test_ret_addr = cc.get_return_address()
        elif(address == self._cc_return_value_test_ret_addr
             and self.cp.break_count == 2):
            print(f'-> testing "{self._tested_func_spec.name}()"', end='')
            mutated_return_value = copy.deepcopy(self._expected_return_value)
            if mutated_return_value is not None:
                self._mutate_value(mutated_return_value)

            cc = self.cc(uc, **self._cc_kwargs)
            cc.set_return_value(self._tested_func_spec, mutated_return_value)
            ret = cc.get_return_value(self._tested_func_spec)
            if self._tested_func_spec.return_value_type is not None:
                assert ret.value == mutated_return_value
            else:
                assert ret is None
            print('    [PASSED]')


class CallingConventionCall(CallingConventionBaseTester):
    """
    To test function calling convention call method the tester use the
    `cc_call_test_wrapper` function which must be called in the main
    function of the emulated code.

    The `cc_call_test_wrapper` interface must be architecture agnostic. It will
    be expected that this interface set a know stack canary defined through the
    `cc_call_test_stack_canary` symbol, then offer a NOP section place labeled
    with the `cc_call_test_call_site` symbol and then return the stack canary
    which can be tested for stack integrity.

    The tester break at `cc_call_test_call_site`, call a function through the
    tested calling convention object, then collect the function arguments, the
    return value and the stack canary return by `cc_call_test_wrapper` and
    check all the collected values after emulation stop. The stack canary
    check take sense since the majority of the calling convention can write
    argument on the stack according parameter numbers and size.
    """
    def test_hook_before_emu(self, cparser: CTypesTranslator):
        cc_call_test_wrapper = FunctionSpec(
            self.meta_src.cc_call_test_info.cc_call_test_wrapper.name,
            cparser.get_type_by_name(self.meta_src.cc_call_test_info
                                     .cc_call_test_wrapper.return_value_type),
            address=self.meta_src.cc_call_test_info.cc_call_test_wrapper.address)

        mutated_arg_values = self._mutate_argument_values(
            self._expected_arg_values)

        # set test specific states
        self._mutated_arg_values = mutated_arg_values
        self._cc_call_test_wrapper = cc_call_test_wrapper
        self._cc_call_test_wrapper_ret_addr = None
        self._collect_func_arg_value = None
        self._collect_func_return_value = None
        self._collect_stack_canary = None
        self.cp.code_tracer_breaks = [
            self.meta_src.cc_call_test_info.cc_call_test_call_site,
            self._tested_func_spec.address,
            cc_call_test_wrapper.address
        ]

    def test_hook_after_emu(self):
        assert (len(self._collect_func_arg_value)
                == len(self._mutated_arg_values))
        for arg_idx, func_arg in enumerate(self._collect_func_arg_value):
            assert isinstance(func_arg.value,
                              type(self._mutated_arg_values[arg_idx]))
            assert (func_arg.value._name_
                    == self._mutated_arg_values[arg_idx]._name_)
            assert func_arg.value == self._mutated_arg_values[arg_idx]

        assert self._collect_func_return_value == self._expected_return_value

        assert (self._collect_stack_canary.value.value
                == self.meta_src.cc_call_test_info.cc_call_test_stack_canary)

        assert self.cp.break_count == 4

    def test(self, uc: Uc, address: int):
        if(address == self._cc_call_test_wrapper.address
                and self.cp.break_count == 1):
            self._cc_call_test_wrapper_ret_addr = \
                self.cc(uc, **self._cc_kwargs).get_return_address()
            self.cp.code_tracer_breaks.append(
                self._cc_call_test_wrapper_ret_addr)

        elif(address == self.meta_src.cc_call_test_info.cc_call_test_call_site
                and self.cp.break_count == 2):
            print(f'-> testing "{self._tested_func_spec.name}()"', end='')
            cc = self.cc(uc, **self._cc_kwargs)
            self._collect_func_return_value = cc.call(self._tested_func_spec,
                                                      self._mutated_arg_values)
            print('    [PASSED]')

        elif(address == self._tested_func_spec.address
             and self.cp.break_count == 3):
            cc = self.cc(uc, **self._cc_kwargs)
            self._collect_func_arg_value = cc.get_arguments(
                self._tested_func_spec)

        elif(address == self._cc_call_test_wrapper_ret_addr
             and self.cp.break_count == 4):
            cc = self.cc(uc, **self._cc_kwargs)
            self._collect_stack_canary = cc.get_return_value(
                self._cc_call_test_wrapper)
            self.cp.code_tracer_breaks = []


class BasePyTestCallingConvention:
    @staticmethod
    def test_cc_get_arguments(
        cc: Type[CallingConvention], torture_blob: MetaBinBlob
    ):
        CallingConventionGetArgumentsTester(cc, torture_blob).run_test()

    @staticmethod
    def test_cc_set_arguments(cc: Type[CallingConvention], torture_blob):
        CallingConventionSetArgumentsTester(cc, torture_blob).run_test()

    @staticmethod
    def test_cc_get_return_value(cc: Type[CallingConvention], torture_blob):
        CallingConventionGetReturnValue(cc, torture_blob).run_test()

    @staticmethod
    def test_cc_set_return_value(cc: Type[CallingConvention], torture_blob):
        CallingConventionSetReturnValue(cc, torture_blob).run_test()

    @staticmethod
    def test_cc_call(cc: Type[CallingConvention], torture_blob):
        CallingConventionCall(cc, torture_blob).run_test()
