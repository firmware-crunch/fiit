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

__all__ = [
    'Machine'
]

from typing import List

from .cpu import DeviceCpu
from .defines import MachineDevice

# ==============================================================================


class Machine:

    def __init__(self) -> None:
        self._devices: List[MachineDevice] = []

    @property
    def devices(self) -> List[MachineDevice]:
        return self._devices

    @property
    def cpu_devices(self) -> List[DeviceCpu]:
        return [dev for dev in self._devices if isinstance(dev, DeviceCpu)]

    def get_device(self, name: str) -> MachineDevice:
        for dev in self._devices:
            if dev.dev_name == name:
                return dev

        raise ValueError(f'machine device "{name}" not found')

    def get_device_cpu(self, name: str) -> DeviceCpu:
        for dev in self._devices:
            if isinstance(dev, DeviceCpu) and dev.dev_name == name:
                return dev

        raise ValueError(f'device cpu "{name}" not found')

    def add_device(self, device: MachineDevice) -> None:
        for dev in self._devices:
            if dev.dev_name == device.dev_name:
                raise ValueError(
                    f"can't add device '{device.dev_name}', name already exist"
                    f" with MachineDevice id '{id(dev)}'"
                )

        self._devices.append(device)
