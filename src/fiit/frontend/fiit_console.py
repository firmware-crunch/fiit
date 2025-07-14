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

import uuid
import dataclasses
import tempfile
import signal
import sys
import os
from typing import Optional
import asyncio

import zmq

from prompt_toolkit.application import get_app_or_none

from jupyter_console.ptshell import ZMQTerminalInteractiveShell, ask_yes_no
from jupyter_console.app import ZMQTerminalIPythonApp
from jupyter_client.consoleapp import JupyterConsoleApp

from fiit.plugins.backend import BACKEND_REQ_GET_BACKEND_DATA, BackendRequest


class RemoteKernelSync(Exception):
    pass


class SynchronizedZmqTerminal(ZMQTerminalInteractiveShell):
    """
    Extend the ZMQTerminalInteractiveShell
    """
    include_other_output = True

    ECHO_FILTER = ['%emu_start', '%es', '%step', '%s', '%cont', '%c']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # cache
        self._iopub_msg_cache: Optional[dict] = None

        # Warning: asyncio.Event must be initialized in the event loop
        self._is_running_cell: Optional[asyncio.Event] = None
        self._interact_lock: Optional[asyncio.Event] = None
        self._is_interact_loop_stopped: Optional[asyncio.Event] = None

        self._full_echo = os.getenv('FULL_ECHO', False)
        self._other_is_running_cell_with_echo = False
        self._other_is_running_cell = False

    def init_kernel_info(self):
        """ Subclassed to print stdout/stderr stream if kernel is busy. """
        self.client.hb_channel.unpause()
        msg_id = self.client.kernel_info()
        iopub_socket = self.client.iopub_channel.socket
        shell_socket = self.client.shell_channel.socket
        socket_poller = zmq.Poller()
        socket_poller.register(iopub_socket, zmq.POLLIN)
        socket_poller.register(shell_socket, zmq.POLLIN)

        while True:
            socks = dict(socket_poller.poll())

            if socks.get(shell_socket) == zmq.POLLIN:
                reply = self.client.get_shell_msg()
                if reply['parent_header'].get('msg_id') == msg_id:
                    self.kernel_info = reply['content']
                    return

            elif socks.get(iopub_socket) == zmq.POLLIN:
                msg = self.client.iopub_channel.get_msg()
                if msg['header']['msg_type'] == 'stream':
                    if msg['content']['name'] == "stdout":
                        print(msg['content']['text'], end='', flush=True)
                    elif msg['content']['name'] == 'stderr':
                        print(msg['content']['text'], end='', flush=True)

    def _init_events(self):
        self._is_running_cell = asyncio.Event()
        self._is_interact_loop_stopped = asyncio.Event()
        self._interact_lock = asyncio.Event()
        self._is_running_cell.clear()
        self._is_interact_loop_stopped.clear()
        self._interact_lock.clear()

    @property
    def interact_loop_is_locked(self) -> bool:
        return self._is_interact_loop_stopped.is_set()

    @property
    def cell_is_running(self) -> bool:
        return self._is_running_cell.is_set()

    async def lock_interact_loop(self):
        if not self.interact_loop_is_locked and not self.cell_is_running:
            app = get_app_or_none()
            if not app.is_done and app.is_running:
                self._interact_lock.clear()
                app.exit(exception=RemoteKernelSync('kernel sync'))
                await self._is_interact_loop_stopped.wait()

    def unlock_interact_loop(self):
        if self.interact_loop_is_locked:
            self._interact_lock.set()

    async def interact(self, loop=None, display_banner=None):
        """ Override to allow prompt freezing via `RemoteKernelSync`. """
        while self.keep_running:
            print('\n', end='')

            try:
                code = await self.prompt_for_code()
            except EOFError:
                if (not self.confirm_exit
                        or ask_yes_no('Do you really want to exit ([y]/n)?',
                                      'y', 'n')):
                    self.ask_exit()
            except RemoteKernelSync:
                # Can fix ghost side effects of asynchronous prompt not yet exited
                # await asyncio.sleep(0.1)
                self._is_interact_loop_stopped.set()
                await self._interact_lock.wait()
                self._is_interact_loop_stopped.clear()

            else:
                if code:
                    self._is_running_cell.set()
                    self.run_cell(code, store_history=True)
                    self._is_running_cell.clear()

    async def handle_external_iopub(self, loop=None):
        """
        Override to fix inefficient and slow manual polling in parent method,
        and allow post jupyter message render with asynchronous capability in
        same event loop (for exemple for asynchronous event sync).
        """
        self._init_events()
        poller = zmq.asyncio.Poller()
        poller.register(self.client.iopub_channel.socket, zmq.POLLIN)

        while self.keep_running:
            events = dict(await poller.poll(0.5))

            if self.client.iopub_channel.socket in events:
                self.handle_iopub()
                await self._post_jupyter_message_render(self._iopub_msg_cache)

    async def _post_jupyter_message_render(self, msg: dict) -> None:
        msg = self._iopub_msg_cache
        msg_type = msg['header']['msg_type']

        if (msg_type == 'execute_input'
                and self._other_is_running_cell_with_echo):
            await self.lock_interact_loop()
            content = self._iopub_msg_cache['content']
            ec = content.get('execution_count',
                             self.execution_count - 1)

            if self._pending_clearoutput:
                print("\r", end="")
                sys.stdout.flush()
                sys.stdout.flush()
                self._pending_clearoutput = False

            sys.stdout.write(f'Remote In [{ec}]: {content["code"]}\n')
            sys.stdout.flush()

        elif not self._other_is_running_cell_with_echo:
            self.unlock_interact_loop()

    def _include_output(self, msg: dict) -> bool:
        self._set_terminal_states(msg)
        msg_type = msg['header']['msg_type']

        if self._other_is_running_cell_with_echo and msg_type == 'execute_input':
            return False  # input render from handle_iopub() is bugged for other
        elif self._other_is_running_cell and not self._other_is_running_cell_with_echo:
            return False  # no render for other cell running without echo

        return super().include_output(msg)

    def _msg_cache_wrapper(self, msg: dict) -> bool:
        ret = self._include_output(msg)
        self._iopub_msg_cache = msg
        return ret

    def include_output(self, msg: dict) -> bool:
        """
        `Include_output()` is the best place to capture iopub message since this
        method is called just after read message on the channel iopub channel
        in `handle_iopub()`.
        """
        return self._msg_cache_wrapper(msg)

    def _set_terminal_states(self, msg: dict) -> None:
        """
        Warning:
        This methods set the states only for this terminal layer before
        `handle_iopub()` set states, so `ZMQTerminalInteractiveShell` states
        are the past states (t-1), minus the `execution_count` counter which is
        synchronized before this method call.
        """
        msg_type = msg['header']['msg_type']
        from_here = self.from_here(msg)

        if (self.include_other_output
                and not from_here
                and self._execution_state == 'busy'
                and msg_type == 'execute_input'
                and (self._full_echo or msg['content']['code'] in self.ECHO_FILTER)):
            self._other_is_running_cell_with_echo = True
        elif (self.include_other_output
              and not from_here
              and self._execution_state == 'busy'
              and msg_type == 'status'
              and msg['content']['execution_state'] == 'idle'
              and (self._full_echo or self._other_is_running_cell_with_echo)):
            self._other_is_running_cell_with_echo = False

        if (self.include_other_output
                and not from_here
                and self._execution_state == 'busy'
                and msg_type == 'execute_input'):
            self._other_is_running_cell = True
        elif (self.include_other_output
              and not from_here
              and self._execution_state == 'busy'
              and msg_type == 'status'
              and msg['content']['execution_state'] == 'idle'):
            self._other_is_running_cell = False


class SynchronizedTerminalApp(ZMQTerminalIPythonApp):
    classes = [SynchronizedZmqTerminal] + JupyterConsoleApp.classes

    def init_shell(self):
        JupyterConsoleApp.initialize(self)
        # relay sigint to kernel
        signal.signal(signal.SIGINT, self.handle_sigint)
        self.shell = SynchronizedZmqTerminal.instance(
            parent=self,
            manager=self.kernel_manager,
            client=self.kernel_client,
            confirm_exit=self.confirm_exit,
        )
        self.shell.own_kernel = not self.existing


fiit_console = SynchronizedTerminalApp.launch_instance


def fiit_console_from_backend(backend_ip: str, backend_port: str) -> None:
    zmq_context = zmq.Context()
    sock = zmq_context.socket(zmq.REQ)
    sock.connect(f'tcp://{backend_ip}:{backend_port}')
    req = BackendRequest(method=BACKEND_REQ_GET_BACKEND_DATA, id=uuid.uuid1().hex)
    sock.send_json(dataclasses.asdict(req))
    res = sock.recv_json()
    sock.close()

    if res.get('error') is not None:
        print(f'error: {res["error"]["message"]}')
        sys.exit(1)

    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    f.write(res['result']['jupyter_client_json_config'])
    f.close()
    print(f'[i] Jupyter console configuration file dropped to "{f.name}".')
    SynchronizedTerminalApp.launch_instance(['--existing', f.name])
