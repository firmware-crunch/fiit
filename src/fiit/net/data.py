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

from typing import Dict, Any, Optional, Union, Type
from types import TracebackType
import dataclasses
import threading



@dataclasses.dataclass
class EventQueueInfo:
    ip: Optional[str] = None
    port: Optional[int] = None


@dataclasses.dataclass
class BackendData:
    event_queue_info: EventQueueInfo = dataclasses.field(default_factory=EventQueueInfo)
    jupyter_client_json_config: Optional[str] = None


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


class NetBackendDataContext:
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
