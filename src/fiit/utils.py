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

from typing import Any, List, Callable, Type
import os
import importlib.util
import inspect
import pathlib
import sys


# FIXME: Dirty inheritance check to remove
def inherits_from(obj: Any, parent: Type[Any]) -> bool:
    if inspect.isclass(obj):
        if parent.__name__ in [c.__name__ for c in inspect.getmro(obj)[1:]]:
            return True
    return False


def pkg_module_object_loader(
    file: str, predicate: Callable[[Any], bool]
) -> List[Any]:
    collect: List[Type[Any]] = []
    path = pathlib.Path(file).absolute()
    parent_parent = path.parent.parent.as_posix()
    package_name = path.parent.name

    if parent_parent not in sys.path:
        sys.path.insert(0, parent_parent)
        top_mod = importlib.import_module(package_name)
        # Very important to reload since previous import updates sys.modules
        # and a module of same name can hide the new imported module.
        importlib.reload(top_mod)
        sys.path.remove(parent_parent)
    else:
        top_mod = importlib.import_module(package_name)
        importlib.reload(top_mod)

    mod = importlib.import_module(f'{package_name}.{path.stem}')

    for item in dir(mod):
        attr = getattr(mod, item)
        if predicate(attr):
            collect.append(attr)

    return collect


def pkg_object_loader(
    package_path: str,
    predicate: Callable[[Any], bool],
    sub_dir_filter: List[str] = None
) -> List[Type[Any]]:
    collect: List[Type[Any]] = []
    __sub_dir_filter = None
    abs_pkg_path = os.path.abspath(package_path)
    top_pkg_path = os.path.abspath(f'{abs_pkg_path}/../')
    package_name = os.path.basename(abs_pkg_path)

    if top_pkg_path not in sys.path:
        sys.path.insert(0, top_pkg_path)
        top_mod = importlib.import_module(package_name)
        # Very important to reload since previous import updates sys.modules
        # and a module of same name can hide the new imported module.
        importlib.reload(top_mod)
        sys.path.remove(top_pkg_path)
    else:
        top_mod = importlib.import_module(package_name)
        importlib.reload(top_mod)

    for py_file in pathlib.Path(abs_pkg_path).rglob('*.py'):
        module_path = py_file.parent.as_posix()

        if sub_dir_filter is not None:
            if __sub_dir_filter is None:
                __sub_dir_filter = [f'{abs_pkg_path}/{p}' for p in sub_dir_filter]
            if not module_path.startswith(tuple(__sub_dir_filter)):
                continue

        py_module_part = module_path.replace(abs_pkg_path, '')\
                                    .replace(os.sep, '.')[1:]

        to_import = (f'{package_name}'
                     f'{"." + py_module_part if py_module_part else ""}'
                     f'.{py_file.stem}')

        mod = importlib.import_module(to_import)

        for item in dir(mod):
            attr = getattr(mod, item)
            if predicate(attr):
                collect.append(attr)

    return collect


class SingletonPattern(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = \
                super(SingletonPattern, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
