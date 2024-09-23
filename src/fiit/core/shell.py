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


from typing import Dict, Callable, Any, Optional, Union
import inspect
import threading
import logging
import sys

from tabulate import tabulate

import IPython
from IPython.core.magic import Magics, magics_class
from IPython.terminal.embed import InteractiveShellEmbed
from IPython.terminal.prompts import Prompts, Token

from ipykernel.iostream import OutStream

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


def register_alias(alias_name):
    def wrap(func):
        func.__IPYTHON_ALIAS__ = alias_name
        return func
    return wrap


@magics_class
class CustomShell(IPython.core.magic.Magics):
    LOGIN_BANNER = '    >>> fiit remote ipykernel <<<\n'
    BLANK_LINE = ['___BLANK___', '', '']

    def __init__(self, shell=None, remote_ipykernel: bool = False,
                 allow_remote_connection: bool = False, **kwargs):
        super(CustomShell, self).__init__(shell=shell, **kwargs)
        self.local_ns: Dict[str, Callable] = {}
        self.magic_class_instances: Any = [self]
        self.shell: Optional[InteractiveShellEmbed] = None
        self._is_running = False
        self.shell_object_refs = dict()
        self._remote_ipykernel: bool = remote_ipykernel
        self._allow_remote_connection: bool = allow_remote_connection
        self._remote_ipykernel_wrapper: \
            Optional[IPythonBackgroundKernelWrapper] = None

    def get_remote_ipkernel_client_config(self) -> str:
        with open(self._remote_ipykernel_wrapper.connection_filename) as f:
            return f.read()

    def register_magics(self, inst):
        self.magic_class_instances.append(inst)
        self.shell.register_magics(inst)

    def register_aliases(self, inst):
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
            self._remote_ipykernel_wrapper.thread.join(0.5)
            self.shell = self._remote_ipykernel_wrapper._kernel.shell

        self.shell.prompts = PromptShell(self.shell)
        self.register_magics(self)
        self.register_aliases(self)

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
        Shell objects register via `CustomShell.map_object_in_shell` interface.
        """
        print('')
        for name, obj in self.shell_object_refs.items():
            print(f'{name} : {type(obj)}')


class EmulatorShellLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        record.name = record.name.split('.', 1)[1]
        return True


class EmulatorShell(CustomShell):
    ROOT_LOGGER = 'fiit'

    def __init__(self, remote_ipykernel: bool = False,
                 allow_remote_connection: bool = False):
        super().__init__(
            remote_ipykernel=remote_ipykernel,
            allow_remote_connection=allow_remote_connection
        )
        ########################################################################
        # Shell config
        ########################################################################
        self.initialize_shell('fiit >>> ')
        # self.shell.register_magics(self)
        # self.shell.register_aliases(self)

        ########################################################################
        # Emulation thread and locks
        ########################################################################
        self._emu_tread: Union[threading.Thread, None] = None
        self._lock_user_interact = threading.Lock()
        self._lock_emu_exec = threading.Lock()

        self._emulation_func: Union[Callable, None] = None
        self._emulation_func_args = tuple()
        self._emulation_func_kwargs = dict()

        self.shell.events.register(
             'post_execute', self._wait_for_user_interact)

        ########################################################################
        # Logs redirection to shell output
        ########################################################################
        self._shell_stream = logging.StreamHandler(sys.stdout)
        self._shell_log_filter = EmulatorShellLogFilter()
        self._shell_stream.addFilter(self._shell_log_filter)
        self._shell_stream.setFormatter(logging.Formatter('%(name)s: %(message)s'))

    def stream_logger_to_shell_stdout(self, logger_name: str):
        logging.getLogger(logger_name).addHandler(self._shell_stream)

    def set_emulation_thread(
        self, emulation_func: Callable = None, args: tuple = None,
        kwargs: dict = None
    ):
        self._emulation_func = emulation_func
        self._emulation_func_args = args if args else tuple()
        self._emulation_func_kwargs = kwargs if args else dict()

    def start_emulation_thread(self):
        if self._emulation_func is not None and self._emu_tread is None:
            self._lock_user_interact.acquire(blocking=True)
            self._emu_tread = threading.Thread(
                target=self._emulation_func,
                args=self._emulation_func_args,
                kwargs=self._emulation_func_kwargs,
                daemon=True)
            self._emu_tread.start()
            threading.Thread(target=self._emulation_join, daemon=True).start()

    def emulation_thread_is_running(self) -> bool:
        return (
            True if self._emu_tread is not None and self._emu_tread.is_alive()
            else False)

    def _emulation_join(self):
        if self._emu_tread.is_alive():
            self._emu_tread.join()

        self._emu_tread = None
        self._lock_user_interact.release()

    def _wait_for_user_interact(self):
        if self._lock_user_interact.locked():
            self._lock_user_interact.acquire(blocking=True)
            self._lock_user_interact.release()

    def resume_user_interact(self):
        """ Use in emulation event handler to prompt a shell. This function
        block until resume_emu_exec will be called.
        """
        self._lock_emu_exec.acquire(blocking=True)
        self._lock_user_interact.release()

        self._lock_emu_exec.acquire(blocking=True)
        self._lock_emu_exec.release()

    def resume_emu_exec(self):
        """ Use in shell command to block the shell prompt. """
        self._lock_user_interact.acquire(blocking=True)
        self._lock_emu_exec.release()
