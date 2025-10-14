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
from dataclasses import dataclass, field
from typing import Any, Optional, Literal, List, Union, Callable

from fiit.machine import DeviceCpu
from fiit.ctypesarch.base_types import FunctionSpec

from .cc import CpuContext


@dataclass
class FuncHookMeta:
    hook_type: Literal['replace', 'pre', 'post']
    function: Callable[..., Any]
    target: Union[int, str]
    function_name: Optional[str] = None
    return_value_type: Optional[str] = None
    argument_types: Optional[List[str]] = None
    calling_convention: Optional[str] = None
    cc_get_args: bool = True
    cc_get_ret_val: bool = True
    active: bool = True


FUNC_HOOK_META_TAG = '__FUNC_HOOK_META__'


def pre_hook(*args, **kwargs) -> Callable[..., Any]:
    def wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
        setattr(func, FUNC_HOOK_META_TAG,
                FuncHookMeta('pre',  func, *args, **kwargs))
        return func
    return wrapper


def post_hook(*args, **kwargs) -> Callable[..., Any]:
    def wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
        setattr(func, FUNC_HOOK_META_TAG,
                FuncHookMeta('post',  func, *args, **kwargs))
        return func
    return wrapper


def replace_hook(*args, **kwargs) -> Callable[..., Any]:
    def wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
        setattr(func, FUNC_HOOK_META_TAG,
                FuncHookMeta('replace',  func, *args, **kwargs))
        return func
    return wrapper


class HookHandler:
    _hook_meta: List[FuncHookMeta]

    def __new__(cls, *args, **kwargs) -> Any:
        instance = super().__new__(cls, *args, **kwargs)
        setattr(instance, '_hook_meta', list())
        for _, met in inspect.getmembers(instance, predicate=inspect.ismethod):
            if (hasattr(met, FUNC_HOOK_META_TAG) and
                    isinstance(getattr(met, FUNC_HOOK_META_TAG), FuncHookMeta)):
                hook_meta = getattr(met, FUNC_HOOK_META_TAG)
                hook_meta.function = met
                getattr(instance, '_hook_meta').append(hook_meta)
        return instance


@dataclass
class InterceptorPreHookConfig:
    hook_handler: Callable[..., Any]
    active: bool
    cc_get_arguments: bool


@dataclass
class InterceptorPostHookConfig:
    hook_handler: Callable[..., Any]
    active: bool
    cc_get_return_value: bool


@dataclass
class InterceptorHookEntry:
    func_spec: FunctionSpec
    pre_hooks: List[InterceptorPreHookConfig] = field(default_factory=list)
    post_hooks: List[InterceptorPostHookConfig] = field(default_factory=list)
    replace_hook: InterceptorPreHookConfig = None


@dataclass
class HookingContext:
    interceptor_engine: Any
    return_address: int
    cpu: DeviceCpu
    log: logging.Logger
    cpu_context: CpuContext
    func_spec: FunctionSpec
    user_data: Any = None


class HookingEngineException(Exception):
    pass
