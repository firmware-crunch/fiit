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

from typing import Any
import textwrap
import tempfile
import inspect

from fiit.core.dev_utils import inherits_from, pkg_module_object_loader


def test_inherits_from():
    class Foo:
        pass

    class Bar(Foo):
        pass

    assert inherits_from(Bar, Foo)


def test_inherits_from_not():
    class Foo:
        pass

    assert not inherits_from(Foo, Foo)


def test_import_object_from_py_file():
    source = (
        """
        class A:
            pass

        class FooClass(str):
            pass

        def foo():
            pass

        def bar():
            pass

        setattr(foo, '__TAG__', 0xaabbccdd)
        """
    )

    def predicate_subclass_str(obj: Any):
        if inspect.isclass(obj) and issubclass(obj, str):
            return True
        return False

    def predicate_tagged_func(obj: Any):
        if inspect.isfunction(obj) and hasattr(obj, '__TAG__') \
                and obj.__TAG__ == 0xaabbccdd:
            return True
        return False

    with tempfile.NamedTemporaryFile(suffix='.py') as temp:
        temp.write(textwrap.dedent(source).encode('utf-8'))
        temp.flush()
        objects = pkg_module_object_loader(temp.name, predicate_subclass_str)
        assert len(objects) == 1
        assert objects[0].__name__ == 'FooClass'

        objects = pkg_module_object_loader(temp.name, predicate_tagged_func)
        assert len(objects) == 1
        assert objects[0].__name__ == 'foo'
        assert objects[0].__TAG__ == 0xaabbccdd
