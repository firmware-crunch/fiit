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

from typing import Dict, Any, Optional, Union, TypedDict, Callable, cast, Type
from types import TracebackType
import dataclasses
import socket
import threading
import signal
import atexit
import json
import traceback

import zmq
import cerberus

from fiit.core.shell import Shell
import fiit.plugins.context_config as ctx_conf
from fiit.core.plugin import FiitPlugin, FiitPluginContext, ObjectRequirement


################################################################################
# Backend Data Structures
################################################################################

@dataclasses.dataclass
class EventQueueInfo:
    ip: Optional[str] = None
    port: Optional[int] = None


@dataclasses.dataclass
class BackendData:
    event_queue_info: EventQueueInfo = dataclasses.field(default_factory=EventQueueInfo)
    jupiter_client_json_config: Optional[str] = None


class ThreadSafeSingleton(type):
    _lock = threading.Lock()
    _instances: Dict[type, Any] = {}

    def __call__(cls, *args, **kwargs) -> Any:
        if cls not in cls._instances:
            with cls._lock:
                if cls not in cls._instances:
                    cls._instances[cls] = super(
                        ThreadSafeSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class BackendDataWrapper(metaclass=ThreadSafeSingleton):
    def __init__(self) -> None:
        self.access_lock = threading.Lock()
        self.data = BackendData()


class BackendDataContext:
    def __init__(self) -> None:
        self._backend_data_wrapper = BackendDataWrapper()

    def __enter__(self) -> BackendData:
        self._backend_data_wrapper.access_lock.acquire(blocking=True)
        return self._backend_data_wrapper.data

    def __exit__(
        self,
        exc_type: Union[Type[BaseException], None],
        exc_val: Union[TracebackType, None],
        exc_tb: Union[TracebackType, None],
    ) -> None:
        self._backend_data_wrapper.access_lock.release()


################################################################################
# Backend Messages Definitions
################################################################################


class EventMsg(TypedDict):
    event_topic: str
    event_type: str
    event_data: Dict['str', Any]


JSON_RPC_VER = '2.0'

backend_request_schema = {
    'jsonrpc': {'type': 'string', 'required': True, 'allowed': [JSON_RPC_VER]},
    'id': {'type': ['integer', 'string'], 'required': True, 'nullable': True},
    'method': {'type': 'string', 'required': True},
    'params': {'type': ['dict', 'list'], 'required': False}
}


@dataclasses.dataclass
class BackendRequest:
    method: str
    id: Union[int, str, None] = None
    params: Optional[Union[dict, list]] = dataclasses.field(default_factory=dict)
    jsonrpc: str = JSON_RPC_VER


class BackendResponse(TypedDict):
    jsonrpc: str    # 2.0
    id: Union[int, str, None]
    result: Any


class BackendErrorObject(TypedDict):
    code: int
    message: str
    data: dict


class BackendErrorResponse(TypedDict):
    jsonrpc: str    # 2.0
    id: Union[int, str, None]
    error: BackendErrorObject


BACKEND_ERR_PARSE = {
    'code': -32700, 'message': 'Parse Error', 'data': {
        'description': 'An error occurred on the server while parsing the JSON'
                       ' text.'
    }
}

BACKEND_ERR_INVALID_REQ = {
    'code': -32600, 'message': 'Invalid Request', 'data': {
        'description': 'The JSON sent is not a valid Request object.'
    }
}

BACKEND_ERR_METHOD_NOT_FOUND = {
    'code': -32601, 'message': 'Method not found', 'data': {
        'description': 'The method does not exist / is not available.'
    }
}

BACKEND_ERR_INTERNAL = {
    'code': -32601, 'message': 'Internal Error', 'data': {
        'description': 'Internal JSON-RPC error', 'stack_trace': None
    }
}


BACKEND_REQ_GET_BACKEND_DATA = 'get_backend_data'


_ZMQ_INPROC_INTERNAL_BACKEND_COM = 'internal_backend_com'

_INTERNAL_REQ_KILL = 'kill'
_INTERNAL_REQ_PUB_EVENT = 'pub_event'


################################################################################
# Backend Internal Clients
################################################################################


class BackendInternalClient:
    def __init__(self, zmq_context: zmq.Context) -> None:
        self._zmq_context = zmq_context
        self._pair_client = self._zmq_context.socket(zmq.PAIR)
        self._pair_client.connect(f'inproc://{_ZMQ_INPROC_INTERNAL_BACKEND_COM}')

        atexit.register(self._close_resources)
        signal.signal(signal.SIGTERM, self._exit_handler)
        signal.signal(signal.SIGINT, self._exit_handler)

    def _close_resources(self) -> None:
        self._pair_client.close()

    def _exit_handler(self, signum: int, frame: Any) -> None:
        self._close_resources()

    def pub_event(
        self, event_topic: str, event_type: str, event_data: dict
    ) -> None:
        event = EventMsg(event_topic=event_topic, event_type=event_type,
                         event_data=event_data)
        req = BackendRequest(method=_INTERNAL_REQ_PUB_EVENT, params=dict(event))
        self._pair_client.send_json(dataclasses.asdict(req))


################################################################################
# Backend Core
################################################################################


class Backend:
    _backend_req_validator = cerberus.Validator(backend_request_schema)

    def __init__(
        self, request_port: int, event_pub_port: int,
        allow_remote_connection: bool
    ) -> None:
        ###################################################
        # Backend Communication Infrastructure
        ###################################################
        self._backend_tread = threading.Thread(
            target=self._backend_request_loop,
            daemon=True)

        if allow_remote_connection:
            machine_ip = socket.gethostbyname(socket.gethostname())
        else:
            machine_ip = '127.0.0.1'

        self.zmq_context = zmq.Context()

        self._backend_socket = self.zmq_context.socket(zmq.REP)
        self._backend_socket.bind(f'tcp://{machine_ip}:{request_port}')
        self._backend_is_running = True

        self._event_pub_socket = self.zmq_context.socket(zmq.PUB)
        self._event_pub_socket.bind(f'tcp://{machine_ip}:{event_pub_port}')

        self._internal_com_socket = self.zmq_context.socket(zmq.PAIR)
        self._internal_com_socket.bind(f'inproc://{_ZMQ_INPROC_INTERNAL_BACKEND_COM}')

        self._socket_poller = zmq.Poller()
        self._socket_poller.register(self._backend_socket, zmq.POLLIN)
        self._socket_poller.register(self._internal_com_socket, zmq.POLLIN)

        ###################################################
        # Backend Request Tables
        ###################################################
        self._req_table: Dict[str, Callable[[BackendRequest], None]] = {
            BACKEND_REQ_GET_BACKEND_DATA: self._request_get_backend_data,
        }

        self._internal_req_table: Dict[str, Callable[[BackendRequest], None]] = {
            _INTERNAL_REQ_KILL: self._internal_request_kill,
            _INTERNAL_REQ_PUB_EVENT: self._internal_request_pub_event
        }

        ###################################################
        # Backend Resources Management
        ###################################################
        atexit.register(self._close_resources)
        signal.signal(signal.SIGTERM, self._exit_handler)
        signal.signal(signal.SIGINT, self._exit_handler)

        ###################################################
        # Backend Objects
        ###################################################
        with BackendDataContext() as backend_data:
            backend_data.event_queue_info.ip = machine_ip
            backend_data.event_queue_info.port = event_pub_port

    def _close_resources(self) -> None:
        pair_client = self.zmq_context.socket(zmq.PAIR)
        pair_client.connect(f'inproc://{_ZMQ_INPROC_INTERNAL_BACKEND_COM}')
        notif = BackendRequest(method=_INTERNAL_REQ_KILL)
        pair_client.send_json(dataclasses.asdict(notif))
        pair_client.close()

        if self._backend_tread.is_alive():
            self._backend_tread.join()

    def _exit_handler(self, signum: int, frame: Any) -> None:
        self._close_resources()

    def _internal_request_kill(self, req: BackendRequest) -> None:
        self._backend_is_running = False

    def _internal_request_pub_event(self, req: BackendRequest) -> None:
        self._event_pub_socket.send_string(
            cast(EventMsg, req.params)['event_topic'], flags=zmq.SNDMORE)
        self._event_pub_socket.send_json(req.params)

    @staticmethod
    def _backend_response(
        zmq_socket: zmq.Socket, request_id: Union[int, None], result: Any
    ) -> None:
        res = BackendResponse(jsonrpc=JSON_RPC_VER, id=request_id, result=result)
        zmq_socket.send_json(res)

    @staticmethod
    def _backend_error_response(
        zmq_socket: zmq.Socket, request_id: Union[int, None], code: int,
        message: str, data: dict
    ) -> None:
        err = BackendErrorObject(code=code, message=message, data=data)
        res = BackendErrorResponse(jsonrpc=JSON_RPC_VER, id=request_id, error=err)
        zmq_socket.send_json(res)

    def _request_get_backend_data(self, req: BackendRequest) -> None:
        with BackendDataContext() as backend_data:
            data = dataclasses.asdict(backend_data)
            self._backend_response(self._backend_socket, req.id, data)

    @classmethod
    def _backend_process_request(
        cls,
        sock: zmq.Socket,
        request_table: Dict[str, Callable[[BackendRequest], None]]
    ) -> None:
        try:
            raw_req = sock.recv_json()
        except json.JSONDecodeError:
            cls._backend_error_response(sock, None, **BACKEND_ERR_PARSE)
            return

        if not cls._backend_req_validator.validate(raw_req):
            cls._backend_error_response(sock, None, **BACKEND_ERR_INVALID_REQ)
            return

        req = BackendRequest(**raw_req)

        if req.method not in request_table:
            cls._backend_error_response(sock, None, **BACKEND_ERR_METHOD_NOT_FOUND)
            return

        try:
            request_table[req.method](req)
        except Exception:
            err = dict(BACKEND_ERR_INTERNAL)
            err['data']['stack_trace'] = traceback.format_exc()
            cls._backend_error_response(sock, None, **err)

    def _backend_request_loop(self) -> None:
        while self._backend_is_running:
            socks = dict(self._socket_poller.poll())

            if socks.get(self._backend_socket) == zmq.POLLIN:
                self._backend_process_request(
                    self._backend_socket, self._req_table)
            elif socks.get(self._internal_com_socket) == zmq.POLLIN:
                self._backend_process_request(
                    self._internal_com_socket, self._internal_req_table)

        self._backend_socket.close()
        self._event_pub_socket.close()
        self._internal_com_socket.close()

    def run_backend_request_loop(self) -> None:
        self._backend_tread.start()


################################################################################
# Backend Plugin
################################################################################


class PluginBackend(FiitPlugin):
    NAME = 'plugin_backend'
    OPTIONAL_REQUIREMENTS = [
        ctx_conf.SHELL.as_require()]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'allow_remote_connection': {'type': 'boolean', 'default': True,
                                            'required': False},
                'request_port': {'type': 'integer', 'required': True},
                'event_pub_port': {'type': 'integer', 'required': True},
            }
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: Dict[str, Any],
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ) -> None:
        backend = Backend(**plugin_config)

        with BackendDataContext() as backend_data:
            if emulator_shell := plugins_context.get(ctx_conf.SHELL.name):
                if emulator_shell._remote_ipykernel:
                    backend_data.jupiter_client_json_config = \
                        emulator_shell.get_remote_ipkernel_client_config()

        backend.run_backend_request_loop()
