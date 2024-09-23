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

from unittest.mock import patch
from io import StringIO

# Force IPython to use input than readline. Must be called before import.
# import os
# os.environ['IPY_TEST_SIMPLE_PROMPT'] = '1'
import IPython
from IPython.core import magic
from IPython.core.magic_arguments import argument, magic_arguments

from .fixtures.fixture_utils import get_file_content

from fiit.core.shell import register_alias, CustomShell


@IPython.core.magic.magics_class
class PartialShell(IPython.core.magic.Magics):
    def __init__(self):
        self.shell = CustomShell()
        self.shell.initialize_shell('test-shell >>> ')
        super(PartialShell, self).__init__(self.shell)
        self.shell.register_magics(self)
        self.shell.register_aliases(self)

        self.shell.map_object_in_shell('object_map_before_start_shell', 4)

    @magic_arguments()
    @argument('cmd_arg1', help='command argument 1')
    @register_alias('tc')
    @IPython.core.magic.line_magic
    def test_cmd(self, line: str):
        """This is the doc of the test command.

        Another stuff about this command.
        """
        print('\nTest Function Call')

    @IPython.core.magic.line_magic
    def map_object_at_runtime(self, line: str):
        self.shell.map_object_in_shell('map_object_at_runtime', 10)
        print('\nMapping shell object.')

    @IPython.core.magic.line_magic
    def check_shell_objects(self, line: str):
        assert self.shell.shell.user_ns['object_map_before_start_shell'] == 4
        assert self.shell.shell.user_ns['map_object_at_runtime'] == 10
        print('\nShell object check ok.')


def test_custom_shell(capsys):
    shell = PartialShell()

    with patch('sys.stdin', StringIO('%help\n'
                                     '%test_cmd\n'
                                     '%map_object_at_runtime\n'
                                     '%shell_objects\n'
                                     '%check_shell_objects\n'
                                     'quit\n')):
        shell.shell.start_shell('Wellcome to the test shell')

    assert (capsys.readouterr().out ==
            get_file_content('outputs/shell_test_session.txt'))
