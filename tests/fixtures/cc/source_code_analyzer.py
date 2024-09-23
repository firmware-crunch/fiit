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

import sys
import textwrap
import copy
import pprint
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, cast

import pycparser
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def _to_class_name(text: str) -> str:
    if len(text) == 0:
        return text
    s = text.replace('_', ' ')
    return ''.join(i.capitalize() for i in s.split())


@dataclass
class MetaFunc:
    address: int
    size: int
    name: str
    return_value_type: str = field(default=None)
    return_value: Any = field(default=None)
    arguments: Dict[int, Tuple[str, str]] = field(default_factory=dict)
    call_arg_values: Dict[int, Any] = field(default_factory=dict)


class CCCallTestInfo:
    SYM_STACK_CANARY = 'cc_call_test_stack_canary'
    SYM_CALL_SITE = 'cc_call_test_call_site'
    SYM_WRAPPER = 'cc_call_test_wrapper'

    cc_call_test_wrapper: MetaFunc = field(init=False)
    cc_call_test_stack_canary: int = field(init=False)
    cc_call_test_call_site: int = field(init=False)

    def to_dict(self) -> dict:
        to_dict = copy.deepcopy(self.__dict__)
        if to_dict['cc_call_test_wrapper']:
            to_dict['cc_call_test_wrapper'] = \
                to_dict['cc_call_test_wrapper'].__dict__
        return to_dict

    @classmethod
    def from_dict(cls, meta: dict) -> Any:
        call_test_info = cls()
        call_test_info.__dict__ = copy.deepcopy(meta)
        if meta['cc_call_test_wrapper']:
            call_test_info.cc_call_test_wrapper = \
                MetaFunc(**meta['cc_call_test_wrapper'])
        return call_test_info


@dataclass
class MetaSourceCode:
    cc_call_test_info: CCCallTestInfo = field(default_factory=CCCallTestInfo)
    skip_test_func: List[str] = field(default_factory=list)  # function to not test
    func: List[MetaFunc] = field(default_factory=list)
    cpp_source: str = field(default_factory=str)

    def get_func(self, func_name: str) -> MetaFunc:
        return cast(MetaFunc, list(filter(lambda f: f.name == func_name,
                                          self.func))[0])

    @classmethod
    def from_dict(cls, meta: dict) -> Any:
        meta_src = cls()
        meta_src.__dict__ = copy.deepcopy(meta)
        meta_src.func = [MetaFunc(**f) for f in meta['func']]
        meta_src.cc_call_test_info = CCCallTestInfo.from_dict(
            meta['cc_call_test_info'])
        return meta_src

    def to_dict(self) -> dict:
        meta_fw = copy.deepcopy(self.__dict__)
        meta_fw['func'] = [f.__dict__ for f in self.func]
        meta_fw['cc_call_test_info'] = meta_fw['cc_call_test_info'].to_dict()
        return meta_fw


class SourceCodeAnalyzer:
    GCC_BIN_MAP = {
        'ARM': 'arm-none-eabi-gcc',
    }

    def __init__(self,
                 firmware_elf: str,
                 source_file: str,
                 gcc_preprocess_extra_args: str,
                 source_file_main: str):
        self.source_file = source_file
        self.gcc_preprocess_extra_args = gcc_preprocess_extra_args
        self.source_file_main = source_file_main
        self.meta_src = MetaSourceCode()

        # Elf parser
        self.elf_file = ELFFile.load_from_path(firmware_elf)

        # C parser
        self.scope_stack = [dict()]

        arch = self.elf_file.get_machine_arch()

        if arch == 'ARM':
            self.scope_stack.append({'__fp16': True})

        self._patch_pycparser()
        if self.gcc_preprocess_extra_args:
            extra_args = ['-E', self.gcc_preprocess_extra_args]
        else:
            extra_args = ['-E']

        self.cpp = pycparser.preprocess_file(
            source_file, self.GCC_BIN_MAP[arch], extra_args)
        self.ast = pycparser.c_parser.CParser().parse(
            self.cpp, scope_stack=self.scope_stack)

    @staticmethod
    def _patch_pycparser():
        """
        Pycparser parser patch to accept scope_stack

        Code modified from:
        https://github.com/angr/angr/blob/master/angr/sim_type.py
        """
        def parse(self, text, filename='', debuglevel=0, scope_stack=None):
            self.clex.filename = filename
            self.clex.reset_lineno()
            self._scope_stack = scope_stack if scope_stack else [dict()]
            self._last_yielded_token = None
            return self.cparser.parse(
                input=text,
                lexer=self.clex,
                debug=debuglevel)
        setattr(pycparser.CParser, 'parse', parse)

    def _collect_firmware_source(self):
        self.meta_src.cpp_source = self.cpp

    def _sym_filter(self, name: str):
        sym_table = list(filter(lambda s: isinstance(s, SymbolTableSection),
                         self.elf_file.iter_sections()))[0]
        return list(filter(lambda e: e.name == name,
                           sym_table.iter_symbols()))[0]

    @classmethod
    def _decl_to_type(cls, decl: Any):
        if isinstance(decl, pycparser.c_ast.TypeDecl):
            return cls._decl_to_type(decl.type)
        elif isinstance(decl, pycparser.c_ast.IdentifierType):
            name = ' '.join(decl.names)
            if name == 'void':
                return None
            return ' '.join(decl.names)
        elif isinstance(decl, pycparser.c_ast.PtrDecl):
            return f'{cls._decl_to_type(decl.type)}*'
        elif isinstance(decl, pycparser.c_ast.Struct):
            return f'struct {decl.name}'

        raise NotImplementedError(f'C type declaration not handled.')

    @staticmethod
    def _ast_const_to_pytype(const_value: pycparser.c_ast.Constant) -> Any:
        if const_value.type == 'char':
            conv_value = ord(const_value.value[1:-1])
        elif const_value.type == 'int':
            if const_value.value[:2] == '0x':
                conv_value = int(const_value.value, 16)
            else:
                conv_value = int(const_value.value)
        elif const_value.type == 'double':
            conv_value = float(const_value.value)
        else:
            raise NotImplementedError('Constant type mapping not handled')
        return conv_value

    @classmethod
    def _compound_literals_struct_to_dict(
            cls, init_list: pycparser.c_ast.InitList) -> dict:
        struct = {}
        for init_item in init_list.exprs:
            if not isinstance(init_item, pycparser.c_ast.NamedInitializer):
                raise ValueError('Compound literals init style not handled')
            if isinstance(init_item.expr, pycparser.c_ast.Constant):
                struct.update(
                    {init_item.name[0].name: cls._ast_const_to_pytype(
                        init_item.expr)})
            elif isinstance(init_item.expr, pycparser.c_ast.InitList):
                struct.update({init_item.name[0].name:
                                   cls._compound_literals_struct_to_dict(
                                       init_item.expr)})
            else:
                raise NotImplementedError('Fixme')
        return struct

    def _collect_cc_call_test_data(self):
        try:
            stack_canary = self._sym_filter(
                self.meta_src.cc_call_test_info.SYM_STACK_CANARY).entry.st_value
            call_site = self._sym_filter(
                self.meta_src.cc_call_test_info.SYM_CALL_SITE).entry.st_value
            call_site_wrapper = self._sym_filter(
                self.meta_src.cc_call_test_info.SYM_WRAPPER).entry.st_value
        except IndexError:
            return

        wrapper = MetaFunc(
            call_site_wrapper, 0, self.meta_src.cc_call_test_info.SYM_WRAPPER,
            return_value_type='unsigned int', return_value=stack_canary,)
        self.meta_src.cc_call_test_info.cc_call_test_stack_canary = stack_canary
        self.meta_src.cc_call_test_info.cc_call_test_call_site = call_site
        self.meta_src.cc_call_test_info.cc_call_test_wrapper = wrapper

    def _collect_func_def_args(self, fun_def: pycparser.c_ast.FuncDef) -> dict:
        params = {}
        for arg_idx, func_arg in enumerate(fun_def.decl.type.args):
            type_name = self._decl_to_type(func_arg.type)
            if type_name:
                params.update({arg_idx: (func_arg.name, type_name)})
        return params

    def _collect_func_call_arg_values(self, fun_call: pycparser.c_ast.FuncCall)\
            -> dict:
        call_params = {}
        for arg_idx, arg in enumerate(fun_call.args):
            if isinstance(arg, pycparser.c_ast.Constant):
                value = {arg_idx: self._ast_const_to_pytype(arg)}
            elif (isinstance(arg, pycparser.c_ast.CompoundLiteral)
                  and isinstance(arg.type.type, pycparser.c_ast.TypeDecl)
                  and isinstance(arg.type.type.type, pycparser.c_ast.Struct)
                  and isinstance(arg.init, pycparser.c_ast.InitList)):
                value = {arg_idx: self._compound_literals_struct_to_dict(arg.init)}
            elif (isinstance(arg, pycparser.c_ast.Cast)
                  and isinstance(arg.expr, pycparser.c_ast.Constant)):
                value = {arg_idx: self._ast_const_to_pytype(arg.expr)}
            else:
                raise ValueError(f'C call argument value not handled.')
            call_params.update(value)
        return call_params

    def _collect_func_return_value(self, func_def: pycparser.c_ast.FuncDef)\
            -> Any:
        for ast_item in func_def.body:
            if isinstance(ast_item, pycparser.c_ast.Return):
                it = ast_item.expr
                if isinstance(it, pycparser.c_ast.Constant):
                    return self._ast_const_to_pytype(it)
                elif (isinstance(it, pycparser.c_ast.Cast)
                      and isinstance(it.expr, pycparser.c_ast.Constant)):
                    return self._ast_const_to_pytype(it.expr)
                elif (isinstance(it, pycparser.c_ast.CompoundLiteral)
                      and isinstance(it.type.type, pycparser.c_ast.TypeDecl)
                      and isinstance(it.type.type.type, pycparser.c_ast.Struct)
                      and isinstance(it.init, pycparser.c_ast.InitList)):
                    return self._compound_literals_struct_to_dict(
                        ast_item.expr.init)

    def _get_func(self) -> List[Tuple[str, int, int]]:
        coll = []
        for sym_table in filter(lambda s: isinstance(s, SymbolTableSection),
                                self.elf_file.iter_sections()):
            for sym in filter(lambda e: e.entry.st_info.type == 'STT_FUNC',
                              sym_table.iter_symbols()):
                if sym.entry.st_info.type == 'STT_FUNC':
                    coll.append((sym.name, sym.entry.st_value, sym.entry.st_size))
        return sorted(coll, key=lambda func: func[1])

    def _collect_function_info(self):
        for func in self._get_func():
            meta_fun = MetaFunc(func[1], func[2], func[0])

            # collect function function arguments
            for ast_item in self.ast.ext:
                if(isinstance(ast_item, pycparser.c_ast.FuncDef)
                        and ast_item.decl.name == func[0]):
                    meta_fun.return_value_type = self._decl_to_type(
                        ast_item.decl.type.type)
                    meta_fun.arguments.update(self._collect_func_def_args(
                        ast_item))
                    meta_fun.return_value = self._collect_func_return_value(
                        ast_item)

            # collect function argument values for a single call
            for ast_item in self.ast.ext:
                if(isinstance(ast_item, pycparser.c_ast.FuncDef)
                        and ast_item.decl.name == self.source_file_main
                        and ast_item.body.block_items is not None):
                    for block_item in ast_item.body.block_items:
                        if (isinstance(block_item, pycparser.c_ast.FuncCall)
                                and block_item.name.name == func[0]):
                            if block_item.args is not None:
                                meta_fun.call_arg_values.update(
                                    self._collect_func_call_arg_values(
                                        block_item))

                            break  # break after first call found
            self.meta_src.func.append(meta_fun)

    def _collect_func_name_test_exclude(self):
        self.meta_src.skip_test_func.extend([
            self.source_file_main,
            self.meta_src.cc_call_test_info.SYM_WRAPPER])

    def src_info_collect(self) -> MetaSourceCode:
        self._collect_firmware_source()
        self._collect_function_info()
        self._collect_cc_call_test_data()
        self._collect_func_name_test_exclude()
        return self.meta_src


def extend_bin_blob_data(
    meta_src_code: MetaSourceCode, filename: str, meta_name: str
):
    format_src = textwrap.indent(
        pprint.pformat(meta_src_code.to_dict(), sort_dicts=False, width=78),
        '  ')
    with open(filename, 'a') as f:
        f.write(
            f'\n'
            f'from ...cc.source_code_analyzer import MetaSourceCode\n\n'
            f'meta_source_code_{meta_name} = \\\n{format_src}\n\n'
            f'MetaSourceCode{_to_class_name(meta_name)} = '
            f'MetaSourceCode.from_dict(meta_source_code_{meta_name})\n\n'
            f'Blob{_to_class_name(meta_name)}.extra.update('
            f'{{"cc_test_data": MetaSourceCode{_to_class_name(meta_name)}}})')


if __name__ == "__main__":
    """
    script argument 1: ELF file path.
    script argument 2: C source file to analyze.
    script argument 3: C preprocessor defines pass to gcc preprocessing step.
    script argument 4: C symbol name of the program entry point.
    script argument 5: Meta source code name use for python file naming
                       and python objects generation naming
    """
    fw_collector = SourceCodeAnalyzer(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    m = fw_collector.src_info_collect()
    extend_bin_blob_data(m, f'{sys.argv[5]}.py', sys.argv[5])
