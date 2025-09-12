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

import inspect
import os
from typing import Any, Dict, List, cast

from ..dev_utils import pkg_object_loader, inherits_from
from ..hooking_engine.engine import HookingContext



class FunctionFilterExtBase:
    FILTER_NAME: str
    FILTER_CONFIG_SCHEMA: dict

    def filter_ext_load(self, ext_ctx: Dict[str, Any], ext_config: dict):
        raise NotImplementedError('fixme')

    def ext_filter(self, ctx: HookingContext) -> bool:
        raise NotImplementedError('fixme')


def predicate_is_func_trace_ext(obj: any) -> bool:
    return (True if (inspect.isclass(obj)
                     and inherits_from(obj, FunctionFilterExtBase))
            else False)


class FilterExt:
    pass


class FunctionRuntimeFilter:
    FILTER_LAMBDA_WRAPPER = 'lambda self, ctx: '
    FILTER_EXP_INCLUDE_RET_ADDR = \
        '(ctx.return_address in self._filter_include_return_address)'
    FILTER_EXP_EXCLUDE_RET_ADDR = \
        '(ctx.return_address not in self._filter_exclude_return_address)'
    FILTER_EXP_EXT = '(self.filter_ext.{filter_ext_func}(ctx))'

    def __init__(
        self,
        filter_include_return_address: List[int] = None,
        filter_exclude_return_address: List[int] = None,
        filter_extensions: Dict[str, Dict[str, Any]] = None,
        data: Dict[str, Any] = None
    ):
        self._filter_include_return_address = filter_include_return_address
        self._filter_exclude_return_address = filter_exclude_return_address

        runtime_filter = []

        if filter_include_return_address:
            runtime_filter.append(self.FILTER_EXP_INCLUDE_RET_ADDR)

        if filter_exclude_return_address:
            runtime_filter.append(self.FILTER_EXP_EXCLUDE_RET_ADDR)

        if filter_extensions:
            ext_path = os.path.abspath(
                f'{os.path.dirname(os.path.realpath(__file__))}'
                f'/function_tracer_ext')
            filter_ext_load = pkg_object_loader(ext_path,
                                                predicate_is_func_trace_ext)
            filter_ext_load = cast(List[FunctionFilterExtBase], filter_ext_load)
            filter_ext_load = {c.FILTER_NAME: c for c in filter_ext_load}

            self.filter_ext = FilterExt()

            for ext_name, ext_conf in filter_extensions.items():
                filter_ext_class = filter_ext_load[ext_name]
                filter_ext_inst = cast(FunctionFilterExtBase, filter_ext_class())
                filter_ext_inst.filter_ext_load(data, ext_conf)
                setattr(self.filter_ext, filter_ext_inst.FILTER_NAME,
                        filter_ext_inst.ext_filter)
                filter_ext_exp = self.FILTER_EXP_EXT.format(
                    filter_ext_func=filter_ext_inst.FILTER_NAME)
                runtime_filter.append(filter_ext_exp)

        if not runtime_filter:
            self._runtime_filter_predicate = eval(
                f'{self.FILTER_LAMBDA_WRAPPER} {"True"}')
        else:
            self._runtime_filter_predicate = eval(
                f'{self.FILTER_LAMBDA_WRAPPER} {" and ".join(runtime_filter)}')

    def predicate(self, ctx: HookingContext) -> bool:
        return self._runtime_filter_predicate(self, ctx)
