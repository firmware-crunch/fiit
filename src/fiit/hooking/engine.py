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

import logging
import inspect
from typing import cast,  Any, Optional, Literal, List, Dict, Union, Callable

from fiit.machine import DeviceCpu
from fiit.emunicorn import CpuUnicorn
from fiit.config_loader import ConfigLoader
from fiit.dev_utils import pkg_module_object_loader
from fiit.ctypesarch import configure_ctypes, CTypesTranslator, PYCPARSER
from fiit.ctypesarch.defines import FunctionSpec, ArgSpec

from .cc import get_calling_convention_by_arch, get_calling_convention_by_name
from .defines import (
    FuncHookMeta, HookingContext, FUNC_HOOK_META_TAG, HookHandler,
    InterceptorPreHookConfig, InterceptorPostHookConfig, InterceptorHookEntry,
    HookingEngineException
)


class HookingEngine:

    SCHEMA_FUNC_FILE = {
        'type': 'list',
        'required': True,
        'schema': {
            'type': 'dict',
            'schema': {
                # Unic function name identifier.
                'tag': {'type': 'string', 'required': False},
                # (Optional) Address of the function in physical memory.
                # The value of this field can be delayed at runtime.
                'address': 'DEF_INT64',
                # (Optional) C prototype ended with a semicolon.
                'c_prototype': {'type': 'string', 'required': False},
                # (Optional) ABI use for this function.
                'ABI': {'type': 'string', 'required': False},
                # (Optional) Extra data pass to hook.
                'data': {'type': 'dict', 'required': False},
            }
        }
    }

    def __init__(
        self,
        cpu: DeviceCpu,
        ctypes_options: Dict['str', 'str'] = None,
        ctypes_flavor: int = PYCPARSER,
        default_cc_options: Dict['str', Any] = None,
        context_user_data: Dict['str', Any] = None,
    ):
        self.cpu = cpu
        arch_str = (f'{self.cpu.ARCH_NAME}'
                    f':{self.cpu.endian.label_hc_lc}'
                    f':{self.cpu.bits.value}')

        ########################################################################
        # Calling convention
        ########################################################################
        self._default_cc = get_calling_convention_by_arch(arch_str)
        self._default_cc_options = (default_cc_options if default_cc_options
                                    else dict())
        self._default_cc_ctypes_options = ctypes_options

        ########################################################################
        # C Data Types
        ########################################################################
        ctypes_config = configure_ctypes(arch_str, ctypes_options)
        self._cparser = CTypesTranslator(ctypes_config, flavor=ctypes_flavor)

        ########################################################################
        # Functions Specification
        ########################################################################
        self.func_spec: List[FunctionSpec] = list()

        ########################################################################
        #  Interceptor Internal
        ########################################################################
        self._config_loader = ConfigLoader()
        self._targets: Dict[int, InterceptorHookEntry] = dict()
        self._targets_return: Dict[int, List[InterceptorHookEntry]] = dict()

        if isinstance(self.cpu.cpu, CpuUnicorn):
            cpu_uc = cast(CpuUnicorn, self.cpu.cpu)
            cpu_uc.hook_block_all(self._block_interceptor)
        else:
            raise HookingEngineException(
                f'Hooking in machine backend "{self.cpu.backend_name}" '
                f'not yet implement')

        logger_name = f'fiit.hooking_engine.dev@{cpu.dev_name}'
        self._log = logging.getLogger(logger_name)
        self._context_user_data = (context_user_data if context_user_data
                                   else dict())

    def add_user_data(self, data: Dict['str', Any]):
        self._context_user_data.update(data)

    def register_cdata_types_file(self, cdata_types_file: str):
        cdata_types = self._cparser.translate_from_file(cdata_types_file)
        self._cparser.add_cdata_type(cdata_types)
        self._log.info(f'{len(cdata_types)} C data types collected.')

    def _create_function_spec(self, function: str,
                              return_value_type: Optional[str] = None,
                              argument_types: Optional[List[str]] = None,
                              calling_convention: Optional[str] = None,
                              address: Optional[int] = None) -> FunctionSpec:
        if return_value_type:
            return_ctype = self._cparser.parse_type(return_value_type)
        else:
            return_ctype = None

        if argument_types:
            func_arg_ctypes = [
                ArgSpec(self._cparser.parse_type(a)) for a in argument_types]
        else:
            func_arg_ctypes = []

        if calling_convention:
            cc = get_calling_convention_by_name(calling_convention)(self.cpu)
        else:
            cc = self._default_cc(
                self.cpu, self._default_cc_ctypes_options,
                **self._default_cc_options)

        return FunctionSpec(function, return_ctype, func_arg_ctypes, cc, address)

    def register_function_spec(self, function: str,
                               return_value_type: Optional[str] = None,
                               argument_types: Optional[List[str]] = None,
                               address: Optional[int] = None,
                               calling_convention: Optional[str] = None):
        spec = self._create_function_spec(
            function, return_value_type, argument_types, calling_convention,
            address)
        self.func_spec.append(spec)

    def get_spec_by_address(self, address: int) -> Union[FunctionSpec, None]:
        spec = list(filter(lambda s: s.address == address, self.func_spec))
        return spec[0] if spec else None

    def get_spec_by_name(self, func_name: str) -> Union[FunctionSpec, None]:
        spec = list(filter(lambda s: s.name == func_name, self.func_spec))
        return spec[0] if spec else None

    def register_function_file(self, spec_file: str):
        data = self._config_loader.load_config(spec_file, self.SCHEMA_FUNC_FILE)

        c_prototypes_def = '\n'.join([
            f'{c_proto};' for e in data
            if (c_proto := e.get('c_prototype', None))])

        # Parse all function prototypes at the same time in one pass.
        # Parsing one prototype is exponential in time when the number of
        # prototype growth.
        func_specs = self._cparser.parse_function_prototypes(c_prototypes_def)

        for idx, entry in enumerate(data):
            if entry.get('c_prototype', None):
                spec = func_specs.pop(0)
            else:
                spec = FunctionSpec()

            if entry_tag := entry.get('tag', None):
                spec.name = entry_tag
            elif spec.name is None:
                spec.name = '<unknown>'

            spec.data = entry.get('data', None)
            spec.address = entry.get('address', None)

            if abi := entry.get('ABI'):
                spec.cc = abi
            else:
                spec.cc = self._default_cc(
                    self.cpu, self._default_cc_ctypes_options,
                    **self._default_cc_options)

            self.func_spec.append(spec)

    def bind_address_to_spec(self, name: str, address: int):
        spec = list(filter(lambda s: s.name == name, self.func_spec))[0]
        spec.address = address

    def register_hook_meta(self, hook_meta: FuncHookMeta):
        if(type(hook_meta.target) == int
                and (spec := self.get_spec_by_address(hook_meta.target))):
            pass
        elif(type(hook_meta.target) == str
             and (spec := self.get_spec_by_name(hook_meta.target))):
            if not spec.address:
                raise ValueError(f'Function spec for "{hook_meta.target}" '
                                 f'not mapped at any memory location.')
        elif type(hook_meta.target) == int:
            spec = self._create_function_spec(
                hook_meta.function_name
                or f'<unknown function@{hook_meta.target}>',
                hook_meta.return_value_type, hook_meta.argument_types,
                hook_meta.calling_convention, hook_meta.target)
        else:
            raise ValueError(f'Function spec not found for {hook_meta.target}.')

        i_entry = self._targets.setdefault(cast(int, spec.address),
                                           InterceptorHookEntry(spec))

        if hook_meta.hook_type == 'pre':
            i_entry.pre_hooks.append(
                InterceptorPreHookConfig(
                    hook_meta.function, hook_meta.active, hook_meta.cc_get_args)
            )

        elif hook_meta.hook_type == 'post':
            i_entry.post_hooks.append(
                InterceptorPostHookConfig(
                    hook_meta.function,
                    hook_meta.active,
                    hook_meta.cc_get_ret_val))

        elif hook_meta.hook_type == 'replace':
            i_entry.replace_hook = InterceptorPreHookConfig(
                hook_meta.function, hook_meta.active, hook_meta.cc_get_args
            )

        else:
            raise ValueError(f'Invalid hook type "{hook_meta.hook_type}".')

    def _get_interceptor_entry(
        self, target: Union[str, int]
    ) -> InterceptorHookEntry:
        if isinstance(target, int):
            if not (i_entry := self._targets.get(target)):
                raise ValueError(f'No hook configured at "{target:#x}".')
        elif isinstance(target, str):
            ret = list(filter(lambda t: t.func_spec.name == target,
                              self._targets.values()))
            if not ret:
                raise ValueError(f'No hook configured for function "{target}".')

            i_entry = ret[0]
        else:
            raise ValueError(f'Invalid target type "{target}".')

        return i_entry

    def _active_hook(
        self,
        target: Union[str, int],
        hook_type: Literal['pre', 'post', 'replace', 'all'],
        active: bool
    ):
        hook_entry = self._get_interceptor_entry(target)

        if hook_type == 'pre' and hook_entry.pre_hooks:
            for ph in hook_entry.pre_hooks:
                ph.active = active
        elif hook_type == 'post' and hook_entry.post_hooks:
            for ph in hook_entry.post_hooks:
                ph.active = active
        elif hook_type == 'replace' and hook_entry.replace_hook:
            hook_entry.replace_hook.active = active
        elif hook_type == 'all':
            if hook_entry.pre_hooks:
                for ph in hook_entry.pre_hooks:
                    ph.active = active
            if hook_entry.post_hooks:
                for ph in hook_entry.post_hooks:
                    ph.active = active
            if hook_entry.replace_hook:
                hook_entry.replace_hook.active = active

    def deactivate_hook(self, target: Union[str, int],
                        hook_type: Literal['pre', 'post', 'replace', 'all']):
        self._active_hook(target, hook_type, False)

    def activate_hook(self, target: Union[str, int],
                      hook_type: Literal['pre', 'post', 'replace', 'all']):
        self._active_hook(target, hook_type, True)

    @staticmethod
    def _is_hook_function(func: Callable[..., None]) -> bool:
        if (hasattr(func, FUNC_HOOK_META_TAG) and
                isinstance(getattr(func, FUNC_HOOK_META_TAG), FuncHookMeta)):
            return True
        return False

    def register_hook(self, hook: Callable[..., None]):
        if not self._is_hook_function(hook):
            raise ValueError(f'Invalid hook function use pre_hook()/'
                             f'post_hook()/replace_hook() as decorator.')
        self.register_hook_meta(getattr(hook, FUNC_HOOK_META_TAG))

    def register_hook_handler(self, hook_handler: HookHandler):
        if not isinstance(hook_handler, HookHandler):
            raise ValueError(f'HookHandler subclass instance expected for '
                             f'{str(hook_handler)}.')

        if hasattr(hook_handler, '_FUNC_SPEC_'):
            for spec in getattr(hook_handler, '_FUNC_SPEC_'):
                self.register_function_spec(*spec)

        for hook_meta in hook_handler._hook_meta:
            self.register_hook_meta(hook_meta)

    def register_hook_functions_from_file(self, file: str):
        for hook in pkg_module_object_loader(file, self._is_hook_function):
            self.register_hook(hook)

    def register_hook_handler_from_file(self, file: str):
        for hh in pkg_module_object_loader(file, inspect.isclass):
            if issubclass(hh, HookHandler):
                self.register_hook_handler(hh())

    def _block_interceptor(self, _: DeviceCpu, address: int):
        if target := self._targets.get(address):
            cc = target.func_spec.cc
            return_address = cc.get_return_address()

            tr = self._targets_return.setdefault(return_address, list())
            tr.append(target)

            for ph in filter(lambda h: h.active, target.pre_hooks):
                # very time-consuming, checked by profiling
                # cpu_context = cc.get_cpu_context()
                ctx = HookingContext(
                    self, return_address, self.cpu, self._log, None,
                    target.func_spec, self._context_user_data)

                if ph.cc_get_arguments:
                    f_args = cc.get_arguments(target.func_spec)
                else:
                    f_args = list()
                ph.hook_handler(ctx, *f_args)

            if target.replace_hook and target.replace_hook.active:
                ctx = HookingContext(self, return_address, self.cpu,
                                     self._log, cc.get_cpu_context(),
                                     target.func_spec, self._context_user_data)

                if target.replace_hook.cc_get_arguments:
                    f_args = cc.get_arguments(target.func_spec)
                else:
                    f_args = list()

                return_value = target.replace_hook.hook_handler(ctx, *f_args)

                if target.func_spec.return_value_type and return_value:
                    cc.set_return_value(target.func_spec, return_value)

                cc.set_pc(return_address)

        elif return_stack := self._targets_return.get(address):
            target = return_stack.pop()

            for ph in filter(lambda h: h.active, target.post_hooks):
                # very time-consuming, checked by profiling
                # cpu_context = cc.get_cpu_context()
                ctx = HookingContext(
                    self, address, self.cpu, self._log, None,
                    target.func_spec, self._context_user_data)

                return_value = None
                if ph.cc_get_return_value:
                    return_value = target.func_spec.cc.get_return_value(
                        target.func_spec)

                if ((ph_return_value := ph.hook_handler(ctx, return_value))
                        and target.func_spec.return_value_type):
                    target.func_spec.cc.set_return_value(
                        target.func_spec, ph_return_value)
