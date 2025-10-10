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

from typing import Dict, Callable, Any, Optional
import inspect
import threading
import logging
import sys

from tabulate import tabulate

import IPython
from IPython.core.magic import Magics
from IPython.terminal.embed import InteractiveShellEmbed
from IPython.terminal.prompts import Prompts, Token

from ipykernel.iostream import OutStream
from ipykernel.ipkernel import IPythonKernel

import background_zmq_ipython
from background_zmq_ipython import IPythonBackgroundKernelWrapper


class OurOutStream:
    """
    Stream proxy: redirect output of all thread to ipython kernel
    """
    def __init__(self, process_stream, session, socket, name):
        self._process_stream = process_stream
        self._global_stream = OutStream(session, socket, name)

    def __getattr__(self, name):
        return getattr(self._global_stream, name)


setattr(background_zmq_ipython.kernel, 'OurOutStream', OurOutStream)


def _get_zmq_ipython_shell(
    wrapper: IPythonBackgroundKernelWrapper
) -> IPythonKernel:
    """
    Workaround to extract shell from a IPythonBackgroundKernelWrapper thread.
    """
    while True:
        wrapper.thread.join(0.1)
        if wrapper._kernel is not None:
            if wrapper._kernel.shell is not None:
                return wrapper._kernel.shell


def register_alias(alias_name: str) -> Any:
    def wrap(func: Callable) -> Any:
        func.__IPYTHON_ALIAS__ = alias_name
        return func
    return wrap


class ShellLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        record.name = record.name.split('.', 1)[1]
        return True


@IPython.core.magic.magics_class
class Shell(IPython.core.magic.Magics):
    SHELL_TOKEN = 'fiit >>> '
    LOGIN_BANNER = ''
    BLANK_LINE = ['___BLANK___', '', '']

    def __init__(self, shell=None, remote_ipykernel: bool = False,
                 allow_remote_connection: bool = False, **kwargs):
        super(Shell, self).__init__(shell=shell, **kwargs)
        self.local_ns: Dict[str, Callable] = {}
        self.magic_class_instances: Any = [self]
        self.shell: Optional[InteractiveShellEmbed] = None
        self._is_running = False
        self.shell_object_refs = dict()
        self._remote_ipykernel: bool = remote_ipykernel
        self._allow_remote_connection: bool = allow_remote_connection
        self._remote_ipykernel_wrapper: \
            Optional[IPythonBackgroundKernelWrapper] = None
        self._shell_stream: Optional[logging.StreamHandler] = None

        # Prompt lock and events
        self._prompt_is_unlocked = threading.Event()
        self._prompt_is_unlocked.set()
        self._prompt_is_lock = threading.Event()
        self._prompt_is_lock.clear()

        self.initialize_shell(self.SHELL_TOKEN)

    def stream_logger_to_shell_stdout(self, logger_name: str):
        logging.getLogger(logger_name).addHandler(self._shell_stream)

    def get_remote_ipkernel_client_config(self) -> str:
        with open(self._remote_ipykernel_wrapper.connection_filename) as f:
            return f.read()

    def register_magics(self, inst: Any) -> None:
        self.magic_class_instances.append(inst)
        self.shell.register_magics(inst)

    def register_aliases(self, inst: Any) -> None:
        for name, obj in inspect.getmembers(inst, inspect.ismethod):
            if hasattr(obj, '__IPYTHON_ALIAS__'):
                self.shell.magics_manager.register_alias(
                    obj.__IPYTHON_ALIAS__, obj.__name__)

    def initialize_shell(self, shell_token: str):
        self.local_ns = {}  # 'q': self.shell.exiter,

        class PromptShell(Prompts):
            def in_prompt_tokens(self, cli=None):
                return [(Token.Prompt,  shell_token)]

        if self.shell is None and not self._remote_ipykernel:
            self.shell = InteractiveShellEmbed(banner1="", exit_msg="")
        elif self.shell is None and self._remote_ipykernel:
            self._remote_ipykernel_wrapper = IPythonBackgroundKernelWrapper(
                connection_filename='./ipykernel_client_conf.json',
                connection_fn_with_pid=False, redirect_stdio=True,
                banner=self.LOGIN_BANNER,
                allow_remote_connections=self._allow_remote_connection)
            self._remote_ipykernel_wrapper.start()
            self.shell = _get_zmq_ipython_shell(self._remote_ipykernel_wrapper)

        self.shell.events.register('post_execute', self._post_execute_hook_lock)

        self.shell.prompts = PromptShell(self.shell)
        self.register_magics(self)
        self.register_aliases(self)

        self._shell_stream = logging.StreamHandler(sys.stdout)
        self._shell_stream.addFilter(ShellLogFilter())
        self._shell_stream.setFormatter(logging.Formatter('%(name)s: %(message)s'))

    def start_shell(self, msg: str = None):
        if self.shell is not None:
            if msg is not None:
                print(msg)
            self._is_running = True
            if self._remote_ipykernel:
                self.shell.user_ns.update(self.local_ns)
                self._remote_ipykernel_wrapper.thread.join()
            else:
                self.shell.mainloop(local_ns=self.local_ns)
            self._is_running = False

    def _post_execute_hook_lock(self):
        self._prompt_is_unlocked.wait()

    def wait_for_prompt_suspend(self):
        self._prompt_is_lock.wait()

    def suspend(self) -> None:
        self._prompt_is_unlocked.clear()
        self._prompt_is_lock.set()

    def resume(self) -> None:
        self._prompt_is_unlocked.set()
        self._prompt_is_lock.clear()

    def map_object_in_shell(self, name: str, obj: Any):
        if self._is_running:
            self.shell.user_ns.update({name: obj})
        else:
            self.local_ns.update({name: obj})
        self.shell_object_refs.update({name: obj})

    @register_alias('h')
    @IPython.core.magic.line_magic
    def help(self, line: str):
        """Print this help"""
        ipy_magics = self.shell.magics_manager.lsmagic()
        cmd_table = [
            ['-'*7, '-'*5, '-'*12],
            self.BLANK_LINE,
            [f'%{self.help.__name__}',
             f'%{self.help.__IPYTHON_ALIAS__}',
             self.help.__doc__],
            self.BLANK_LINE,
            [f'%{self.shell_objects.__name__}',
             f'%{self.shell_objects.__IPYTHON_ALIAS__}',
             self.shell_objects.__doc__],
            self.BLANK_LINE]

        for magic_inst in self.magic_class_instances:
            for cmd, cmd_func in ipy_magics['line'].items():
                if cmd in ['config', 'help', 'shell_objects']:
                    continue

                if hasattr(magic_inst, cmd):
                    doc = cmd_func.__doc__ or ''
                    if doc.startswith('::\n\n'):
                        doc = doc.replace('::\n\n', '', 1)

                    alias = '-'
                    if hasattr(ipy_magics['line'][cmd], '__IPYTHON_ALIAS__'):
                        alias = f'%{ipy_magics["line"][cmd].__IPYTHON_ALIAS__}'
                    cmd_table.append([f'%{cmd}', alias, doc])
                    cmd_table.append(self.BLANK_LINE)

        tab = tabulate(cmd_table, ['command', 'alias', 'description'],
                       tablefmt='plain')

        tab = '\n'.join([('' if li.startswith('___BLANK___') else li)
                         for li in tab.split('\n')])

        tab = f'{"":<4}' + f'\n{"":<4}'.join(tab.split("\n"))
        print(f'\n\n{tab}\n\n{"":<4}For a more detailed command description, '
              f'type %<cmd>? (example %mem_map?)\n')

    @register_alias('so')
    @IPython.core.magic.line_magic
    def shell_objects(self, line: str):
        """
        Shell objects register via `Shell.map_object_in_shell` interface.
        """
        print('')
        for name, obj in self.shell_object_refs.items():
            print(f'{name} : {type(obj)}')
