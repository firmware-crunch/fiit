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
import pdb
import textwrap
import ctypes
from typing import Type, cast,  Any, List, Dict, Union

import pycparser
import pycparser.ply
import pycparserext.ext_c_parser
import pycparserext

from .config import CTypesConfig
from .ctypes_base import (
    CBaseType, DataPointerBase, CodePointerBase, Enum,
    FunctionSpec, ArgSpec, Void, Struct)


class _SearchTypeDeclName(pycparser.c_ast.NodeVisitor):
    def __init__(self):
        self.declname = None

    def visit_TypeDecl(self, node):
        self.declname = node.declname


PYCPARSER = 1
PYCPARSEREXT_GNU = 2

CTYPES_TRANSLATOR_FLAVOR: Dict[str, int] = {
    'pycparser': PYCPARSER,
    'pycparserext_gnu': PYCPARSEREXT_GNU
}


class CTypesTranslatorError(Exception):
    pass


class CTypesTranslator:
    def __init__(self, ctypes_config: CTypesConfig, flavor: int = PYCPARSER):
        ########################################################################
        # C parser
        ########################################################################
        self._flavor = flavor
        if flavor == PYCPARSEREXT_GNU:
            self._ctypes_parser = self._create_type_parser_pycparserext_gnu()
            self._parser = pycparserext.ext_c_parser.GnuCParser
        else:
            self._patch_pycparser()
            self._ctypes_parser = self._create_type_parser()
            self._parser = pycparser.c_parser.CParser

        ########################################################################
        # C parser data type
        ########################################################################
        self._ctypes_config = ctypes_config.copy()

        self._data_pointer = list(filter(
            lambda ft: issubclass(ft, DataPointerBase),
            self._ctypes_config.factory_type))[0]

        self._code_pointer = list(filter(
            lambda ft: issubclass(ft, CodePointerBase),
            self._ctypes_config.factory_type))[0]

        self._enum = list(filter(
            lambda ft: issubclass(ft, Enum),
            self._ctypes_config.factory_type))[0]

    @staticmethod
    def _patch_pycparser():
        """
        Pycparser parser patch to accept scope_stack

        Code modified from:
        https://github.com/angr/angr/blob/master/angr/sim_type.py
        """
        def parse(self, text, filename='', debuglevel=0,
                  initial_type_symbols: dict = None):
            self.clex.filename = filename
            self.clex.reset_lineno()

            self._scope_stack = [dict() if initial_type_symbols is None
                                 else {t: True for t in initial_type_symbols}]

            self._last_yielded_token = None
            return self.cparser.parse(
                input=text,
                lexer=self.clex,
                debug=debuglevel)
        setattr(pycparser.CParser, 'parse', parse)

    @staticmethod
    def _create_type_parser() -> pycparser.CParser:
        """
        Code modified from:
        https://github.com/angr/angr/blob/master/angr/sim_type.py
        """
        logger = logging.getLogger(name=f'{__name__}yacc')
        logger.setLevel(logging.ERROR)
        ctype_parser = pycparser.CParser()
        ctype_parser.cparser = pycparser.ply.yacc.yacc(
                module=ctype_parser, start='parameter_declaration',
                debug=False, optimize=False, errorlog=logger)
        return ctype_parser

    @staticmethod
    def _create_type_parser_pycparserext_gnu() -> pycparserext.ext_c_parser.GnuCParser:
        """
        Code modified from:
        https://github.com/angr/angr/blob/master/angr/sim_type.py
        """
        logger = logging.getLogger(name=f'{__name__}yacc')
        logger.setLevel(logging.ERROR)
        ctype_parser = pycparserext.ext_c_parser.GnuCParser()
        ctype_parser.cparser = pycparser.ply.yacc.yacc(
                module=ctype_parser, start='parameter_declaration',
                debug=False, optimize=False, errorlog=logger)
        return ctype_parser

    def _build_scope_stack(self) -> List[str]:
        return list(set(list(self._ctypes_config.extra_type.keys())))

    def get_ctypes_config(self) -> CTypesConfig:
        return self._ctypes_config

    def get_type_by_name(self, name: str) -> Type[CBaseType]:
        return self._ctypes_config.get_all_types()[name]

    def add_cdata_type(self, cdata_types: Dict[str, Type[CBaseType]]):
        for name, cdata in cdata_types.items():
            self._ctypes_config.extra_type.update({name: cdata})

    def translate_from_file(self, filename: str) -> Dict[str, Type[CBaseType]]:
        cpp = pycparser.preprocess_file(filename)
        return self.translate_from_source(cpp)

    def translate_from_source(self, text: str) -> Dict[str, Type[CBaseType]]:
        extra_type: Dict[str, Type[CBaseType]] = dict()
        # var_def: Dict[str, Type[CBaseType]] = dict()

        ast = self._parser().parse(
            textwrap.dedent(text),
            initial_type_symbols=self._build_scope_stack())

        for ast_node in ast.ext:
            if isinstance(ast_node, pycparser.c_ast.Decl):
                ty = self._decl_to_type(ast_node.type, extra_type)
            #     if ast_node.name is not None:
            #         var_def[ast_node.name] = ty
            if isinstance(ast_node, pycparser.c_ast.Typedef):
                if ast_node.name is not None:
                    extra_type[ast_node.name] = self._decl_to_type(
                        ast_node.type, extra_type)

        return extra_type

    def _parse_const(self, const, extra_types=None) -> int:
        if isinstance(const, pycparser.c_ast.Constant):
            value = const.value.replace('u', '')
            return int(value, base=0)
        elif isinstance(const, pycparser.c_ast.BinaryOp):
            if const.op == '+':
                return self._parse_const(const.children()[0][1], extra_types) \
                    + self._parse_const(const.children()[1][1], extra_types)
            if const.op == '-':
                return self._parse_const(const.children()[0][1], extra_types) \
                    - self._parse_const(const.children()[1][1], extra_types)
            if const.op == '*':
                return self._parse_const(const.children()[0][1], extra_types) \
                    * self._parse_const(const.children()[1][1], extra_types)
            if const.op == '/':
                return self._parse_const(const.children()[0][1], extra_types) \
                    // self._parse_const(const.children()[1][1], extra_types)
            if const.op == '<<':
                return self._parse_const(const.children()[0][1], extra_types) \
                    << self._parse_const(const.children()[1][1], extra_types)
            if const.op == '>>':
                return self._parse_const(const.children()[0][1], extra_types) \
                    >> self._parse_const(const.children()[1][1], extra_types)

            raise ValueError(f'Binary op {const.op}')

        elif isinstance(const, pycparser.c_ast.UnaryOp):
            if const.op == 'sizeof':
                return ctypes.sizeof(
                    self._decl_to_type(const.expr.type, extra_types=extra_types))
            else:
                raise ValueError(f'Unary op {const.op}')

        elif isinstance(const, pycparser.c_ast.Cast):
            return self._parse_const(const.expr, extra_types)

        else:
            raise ValueError(const)

    def _decl_func_to_type(
        self, decl: Any, extra_types: Dict[str, Type[CBaseType]]
    ) -> FunctionSpec:
        func_args_specs = None
        is_variadic = False

        if decl.args:
            func_args_specs = list()
            for func_arg in decl.args.params:
                if isinstance(func_arg, pycparser.c_ast.EllipsisParam):
                    is_variadic = True
                elif isinstance(func_arg, pycparser.c_ast.ID):
                    raise NotImplementedError('fixme')
                elif (isinstance(func_arg.type, pycparser.c_ast.ArrayDecl)
                      and func_arg.type.dim is None):
                    # C99 at 6.7.5.3 Function declarators (including prototypes)
                    array_type = self._decl_to_type(func_arg.type.type, extra_types)
                    ptr_adjust = self._data_pointer.new_type(array_type)
                    func_args_specs.append(ArgSpec(ptr_adjust, func_arg.name))
                else:
                    arg_type = self._decl_to_type(func_arg.type, extra_types)

                    if issubclass(arg_type, Void):
                        func_args_specs = None
                    else:
                        func_args_specs.append(ArgSpec(arg_type,func_arg.name))

        ret_type = self._decl_to_type(decl.type, extra_types)
        if issubclass(ret_type, Void):
            ret_type = None

        stdl = _SearchTypeDeclName()
        stdl.visit(decl.type)

        return FunctionSpec(
            name=stdl.declname,
            return_value_type=ret_type,
            arguments=func_args_specs,
            is_variadic=is_variadic)

    def _decl_ptr_to_type(
        self, decl: pycparser.c_ast.PtrDecl,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[CBaseType]:

        ptr_type = self._decl_to_type(decl.type, extra_types)

        if ((isinstance(decl.type, pycparser.c_ast.FuncDecl)
                or isinstance(decl.type, pycparserext.ext_c_parser.FuncDeclExt))
                or isinstance(ptr_type, FunctionSpec)):
            return self._code_pointer.new_type(ptr_type)
        else:
            return self._data_pointer.new_type(ptr_type)

    def _decl_struct_to_type(
        self, decl: pycparser.c_ast.Struct,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[CBaseType]:
        struct_t = None
        fields = None

        if decl.name is not None:
            struct_t = extra_types.get(f'struct {decl.name}', None)

        if struct_t is None:
            name = (f'struct <unknown>' if decl.name is None
                    else f'struct {decl.name}')
            struct_t = type(f'{decl.name}Struct', (Struct,), dict(_name_=name))

            if decl.name is not None and name not in extra_types:
                extra_types.update({name: struct_t})

        if decl.decls is not None:
            fields = [(f.name, self._decl_to_type(f.type, extra_types))
                      for f in decl.decls]

        if not hasattr(struct_t, '_fields_') and fields is not None:
            try:
                struct_t._fields_ = fields
            except AttributeError as exc:
                struct_name = decl.name if decl.name else '<unknown>'
                print(f'[WARNING] struct {struct_name}: {exc}')

        return struct_t

    def _decl_union_to_type(
        self, decl: pycparser.c_ast.Union,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[CBaseType]:
        union_t = None
        fields = None

        if decl.name is not None:
            union_t = extra_types.get(decl.name, None)

        if union_t is None:
            name = (f'union <unknown>' if decl.name is None
                    else f'union {decl.name}')
            union_t = type(f'{decl.name}Union', (ctypes.Union,),
                           dict(_name_=name))

            if decl.name is not None and decl.name not in extra_types:
                extra_types.update({decl.name: union_t})

        if decl.decls is not None:
            fields = [(f.name, self._decl_to_type(f.type, extra_types))
                      for f in decl.decls]

        if not hasattr(union_t, '_fields_') and fields is not None:
            try:
                union_t._fields_ = fields
            except Exception as exc:
                union_name = decl.name if decl.name else '<unknown>'
                print(f'[WARNING] Union {union_name}: {exc}')

        def get_align() -> int:
            return 0

        setattr(union_t, get_align.__name__, get_align)
        return union_t

    def _decl_array_to_type(
        self, decl: pycparser.c_ast.ArrayDecl,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[ctypes.Array]:
        if decl.dim is None:
            raise CTypesTranslatorError('Array with not size')

        array_type = self._decl_to_type(decl.type, extra_types)
        size = self._parse_const(decl.dim, extra_types=extra_types)
        ctype_array = array_type * size

        stdl = _SearchTypeDeclName()
        stdl.visit(decl.type)

        if stdl.declname is None:
            raise NotImplementedError('Array name not found.')

        # if isinstance(decl.type, pycparser.c_ast.PtrDecl):
        #     array_name = decl.type.type.declname
        # elif isinstance(decl.type, pycparser.c_ast.TypeDecl):
        #     array_name = decl.type.declname
        # else:
        #     raise NotImplementedError('Array name not found.')

        setattr(ctype_array, '_name_', stdl.declname)

        def get_align() -> int:
            return 0

        setattr(ctype_array, get_align.__name__, get_align)
        return cast(Type[ctypes.Array], ctype_array)

    def _decl_identifier_to_type(
        self, decl: pycparser.c_ast.IdentifierType,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[CBaseType]:
        name = ' '.join(decl.names)

        if cdata_type := self._ctypes_config.get_all_types().get(name, None):
            return cdata_type
        elif cdata_type := extra_types.get(name, None):
            return cdata_type

        raise CTypesTranslatorError(f'C data type not found "{name}".')

    def _decl_enum_to_type(
        self, decl: pycparser.c_ast.Enum,
        extra_types: Dict[str, Type[CBaseType]]
    ) -> Type[CBaseType]:
        val_id = ()

        if decl.values:
            val_id = tuple(
                (self._parse_const(entry.value), entry.name)
                if isinstance(entry.value, pycparser.c_ast.Constant)
                else (None, entry.name)
                for entry in decl.values
            )

        enum = type(
            f'{decl.name}Enum', (self._enum,),
            dict(_name_=f'Enum {decl.name}' if decl.name else None,
                 _val_id_=val_id))

        if decl.name is not None and decl.name not in extra_types:
            extra_types.update({decl.name: enum})

        return cast(Type[CBaseType], enum)

    def _decl_to_type(
        self, decl: Any, extra_types: Dict[str, Type[CBaseType]]
    ) -> Union[Type[CBaseType], Type[ctypes.Array], FunctionSpec]:
        if isinstance(decl, pycparser.c_ast.TypeDecl):
            return self._decl_to_type(decl.type, extra_types)
        elif isinstance(decl, pycparser.c_ast.PtrDecl):
            return self._decl_ptr_to_type(decl, extra_types)
        elif isinstance(decl, pycparser.c_ast.Struct):
            return self._decl_struct_to_type(decl, extra_types)
        elif isinstance(decl, pycparser.c_ast.ArrayDecl):
            return self._decl_array_to_type(decl, extra_types)
        elif isinstance(decl, pycparser.c_ast.IdentifierType):
            return self._decl_identifier_to_type(decl, extra_types)
        elif isinstance(decl, pycparser.c_ast.Union):
            return self._decl_union_to_type(decl, extra_types)
        elif isinstance(decl, pycparser.c_ast.Enum):
            return self._decl_enum_to_type(decl, extra_types)
        elif (isinstance(decl, pycparser.c_ast.FuncDecl)
                or isinstance(decl, pycparserext.ext_c_parser.FuncDeclExt)):
            return self._decl_func_to_type(decl, extra_types)

        raise CTypesTranslatorError('C AST node type not handled.')

    def parse_type(self, string_type: str) -> Type[CBaseType]:
        node = self._ctypes_parser.parse(
            text=string_type, initial_type_symbols=self._build_scope_stack())
        return self._decl_to_type(node.type, self._ctypes_config.get_all_types())

    def parse_function_prototype(self, prototype: str) -> FunctionSpec:
        tree = self._parser().parse(
            prototype, initial_type_symbols=self._build_scope_stack())

        if (len(tree.ext) != 1
                or not isinstance(tree.ext[0], pycparser.c_ast.Decl)
                or not (isinstance(tree.ext[0].type, pycparser.c_ast.FuncDecl)
                        or isinstance(tree.ext[0].type,
                                      pycparserext.ext_c_parser.FuncDeclExt))):
            raise CTypesTranslatorError(
                f'Invalid C function prototype "{prototype}".')

        func_spec = self._decl_to_type(tree.ext[0].type,
                                       self._ctypes_config.get_all_types())
        return func_spec

    def parse_function_prototypes(self, text: str) -> List[FunctionSpec]:
        tree = self._parser().parse(
            text, initial_type_symbols=self._build_scope_stack())

        collect = list()

        for node in tree.ext:
            if (isinstance(node, pycparser.c_ast.Decl)
                and (isinstance(node.type, pycparser.c_ast.FuncDecl)
                     or isinstance(node.type, pycparserext.ext_c_parser.FuncDeclExt))):
                func_spec = self._decl_to_type(node.type,
                                               self._ctypes_config.get_all_types())
                collect.append(func_spec)

        return collect
