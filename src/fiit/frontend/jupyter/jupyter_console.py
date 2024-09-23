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

import sys
import uuid
import os
import dataclasses
import tempfile

import zmq

from fiit.plugins.backend import BACKEND_REQ_GET_BACKEND_DATA, BackendRequest


def jupyter_console(backend_ip: str, backend_port: str) -> None:
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
    f.write(res['result']['jupiter_client_json_config'])
    f.close()
    print(f'[i] Jupyter console configuration file dropped to "{f.name}".')
    os.execvp('jupyter', ['jupyter', 'console', '--existing', f.name])


