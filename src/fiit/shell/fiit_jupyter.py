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

from jupyter_console.utils import run_sync
from jupyter_console.ptshell import ZMQTerminalInteractiveShell, ask_yes_no
from jupyter_console.app import ZMQTerminalIPythonApp
from jupyter_client.consoleapp import JupyterConsoleApp

from ..net.messages import BACKEND_REQ_GET_BACKEND_DATA
from ..net import NET_BACKEND_REQUEST_DEFAULT_PORT, BackendRequest


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

        # Warning: asyncio sync primitives must be initialized in the event loop
        self._iopub_channel_lock: Optional[asyncio.Lock] = None
        self._interact_lock: Optional[asyncio.Event] = None
        self._is_interact_loop_stopped: Optional[asyncio.Event] = None

        self._full_echo = os.getenv('FULL_ECHO', False)
        self._other_is_running_cell_with_echo = False

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
                self._custom_iopub_msg_renderer(msg)

    def _init_events(self):
        self._iopub_channel_lock = asyncio.Lock()
        self._is_interact_loop_stopped = asyncio.Event()
        self._interact_lock = asyncio.Event()
        self._is_interact_loop_stopped.clear()
        self._interact_lock.clear()

    async def lock_interact_loop(self):
        if not self._is_interact_loop_stopped.is_set():
            app = get_app_or_none()
            if not app.is_done and app.is_running:
                self._interact_lock.clear()
                app.exit(exception=RemoteKernelSync('kernel sync'))
                await self._is_interact_loop_stopped.wait()

    def unlock_interact_loop(self):
        if self._is_interact_loop_stopped.is_set():
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
                    async with self._iopub_channel_lock:
                        self.run_cell(code, store_history=True)

    async def handle_external_iopub(self, loop=None):
        """
        Override to: fix inefficient and slow manual iopub channel polling in
        parent method, provides exclusive access to the iopub channel to avoid
        conflict with running cell from here, and call a custom Jupyter
        external message processing method.
        """
        self._init_events()
        poller = zmq.asyncio.Poller()
        poller.register(self.client.iopub_channel.socket, zmq.POLLIN)

        while self.keep_running:
            events = dict(await poller.poll(0.5))

            if (not self._iopub_channel_lock.locked()
                    and self.client.iopub_channel.socket in events):
                async with self._iopub_channel_lock:
                    await self._external_iopub_custom_processing()

    def include_output(self, msg: dict) -> bool:
        # Disable handling of external message by the parent class.
        return super().include_output(msg) if self.from_here(msg) else False

    async def _external_iopub_custom_processing(self):
        while run_sync(self.client.iopub_channel.msg_ready)():
            sub_msg = run_sync(self.client.iopub_channel.get_msg)()
            self._set_terminal_states(sub_msg)

            if self._other_is_running_cell_with_echo:
                await self.lock_interact_loop()
                self._custom_iopub_msg_renderer(sub_msg)
            elif (not self._other_is_running_cell_with_echo
                  and self._is_interact_loop_stopped.is_set()):
                self.unlock_interact_loop()

    def _set_terminal_states(self, msg: dict) -> None:
        msg_type = msg['header']['msg_type']
        from_here = self.from_here(msg)

        previous_status = self._execution_state

        if msg_type == 'execute_input':
            self.execution_count = int(msg['content']['execution_count']) + 1

        if msg_type == 'status':
            self._execution_state = msg['content']['execution_state']

        if (self.include_other_output
                and not from_here
                and self._execution_state == 'busy'
                and msg_type == 'execute_input'
                and (self._full_echo or msg['content']['code'] in self.ECHO_FILTER)):
            self._other_is_running_cell_with_echo = True
        elif (self.include_other_output
              and not from_here
              and previous_status == 'busy'
              and msg_type == 'status'
              and self._execution_state == 'idle'
              and (self._full_echo or self._other_is_running_cell_with_echo)):
            self._other_is_running_cell_with_echo = False

    def _custom_iopub_msg_renderer(self, msg: dict) -> None:
        msg_type = msg['header']['msg_type']

        if msg_type == 'stream':
            self._stream_msg_renderer(msg)
        elif msg_type == 'execute_result':
            self._execute_result_msg_renderer(msg)
        elif msg_type == 'display_data':
            self._display_data_msg_renderer(msg)
        elif msg_type == 'execute_input':
            self._execute_input_msg_renderer(msg)
        elif msg_type == 'clear_output':
            self._clear_output_msg_renderer(msg)

    def _stream_msg_renderer(self, msg: dict) -> None:
        if msg['content']['name'] == 'stdout':
            if self._pending_clearoutput:
                print('\r', end='', flush=True)
                self._pending_clearoutput = False
            print(msg['content']['text'], end='', flush=True)
        elif msg['content']['name'] == 'stderr':
            if self._pending_clearoutput:
                print('\r', file=sys.stderr, end='', flush=True)
                self._pending_clearoutput = False
            print(msg['content']['text'], file=sys.stderr, end='', flush=True)

    def _execute_input_msg_renderer(self, msg: dict) -> None:
        if not self.from_here(msg):
            ec = msg['content'].get('execution_count', self.execution_count - 1)
            print(f'Remote In [{ec}]: {msg["content"]["code"]}\n', flush=True)

    def _execute_result_msg_renderer(self, msg: dict) -> None:
        if self._pending_clearoutput:
            print("\r", end="")
            self._pending_clearoutput = False

        self.execution_count = int(msg["content"]["execution_count"])

        if not self.from_here(msg):
            sys.stdout.write(self.other_output_prefix)

        format_dict = msg["content"]["data"]
        self.handle_rich_data(format_dict)

        if 'text/plain' not in format_dict:
            return

        print(format_dict['text/plain'])

    def _display_data_msg_renderer(self, msg: dict) -> None:
        data = msg['content']['data']
        handled = self.handle_rich_data(data)
        if not handled:
            if not self.from_here(msg):
                sys.stdout.write(self.other_output_prefix)
            # if it was an image, we handled it by now
            if 'text/plain' in data:
                print(data['text/plain'])

    def _clear_output_msg_renderer(self, msg: dict) -> None:
        if msg['content']['wait']:
            self._pending_clearoutput = True
        else:
            print('\r', end='')


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


fiit_jupyter = SynchronizedTerminalApp.launch_instance


def fiit_jupyter_from_backend(
    backend_ip: str,
    backend_port: str=f'{NET_BACKEND_REQUEST_DEFAULT_PORT}'
) -> None:
    zmq_context = zmq.Context()
    sock = zmq_context.socket(zmq.REQ)
    print(f'tcp://{backend_ip}:{backend_port}')
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
