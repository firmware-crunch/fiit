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

from typing import Dict, Any, Optional, Union, TypedDict
import dataclasses


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

