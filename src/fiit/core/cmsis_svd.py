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

from typing import Dict, Set, Optional

from cmsis_svd.parser import SVDParser
from cmsis_svd.model import SVDDevice, SVDPeripheral, SVDRegister


class SvdLoader:
    def __init__(self):
        self.device: Optional[SVDDevice] = None

    def load(self, cmsis_svd_filename: str) -> SVDDevice:
        self.device = SVDParser.for_xml_file(cmsis_svd_filename).get_device()
        return self.device


class SvdIndex:
    def __init__(self, cmsis_svd_device_root: SVDDevice):
        self._dev = cmsis_svd_device_root
        self._address_map_svd_reg = self.map_address_to_register(self._dev)
        self._name_map_register_address = self.map_name_to_register_address(self._dev)

    @staticmethod
    def map_address_to_register(device: SVDDevice) -> Dict[int, SVDRegister]:
        index: Dict[int, SVDRegister] = {}
        for peripheral in device.get_peripherals():
            for register in peripheral.get_registers():
                index.update({
                    peripheral.base_address+register.address_offset: register})
        return index

    @staticmethod
    def map_name_to_register_address(
        device: SVDDevice
    ) -> Dict[str, Dict[str, int]]:
        index: Dict[str, Dict[str, int]] = dict()
        for peripheral in device.get_peripherals():
            index.update({peripheral.name: dict()})
            for register in peripheral.get_registers():
                index[peripheral.name].update({
                    register.name:
                        peripheral.base_address+register.address_offset
                })
        return index

    def get_all_peripheral_register_address(self, peripheral: str) -> Set[int]:
        return set(self._name_map_register_address[peripheral].values())

    def get_all_register_address(self) -> Set[int]:
        return set(self._address_map_svd_reg.keys())

    def get_address_index(self) -> Dict[int, SVDRegister]:
        return dict(self._address_map_svd_reg)

    def get_register_address(self, peripheral: str, register: str) -> int:
        return self._name_map_register_address[peripheral][register]

    def get_svd_register(self, peripheral: str, register: str) -> SVDRegister:
        return self._address_map_svd_reg[
            self._name_map_register_address[peripheral][register]]

    def get_svd_peripheral(self, peripheral: str) -> SVDPeripheral:
        try:
            return list(filter(lambda p: p.name == peripheral,
                               self._dev.get_peripherals()))[0]
        except IndexError:
            raise ValueError(f'SVD peripheral "{peripheral}" not found.')

    def get_register_count(self) -> int:
        return len(self._address_map_svd_reg)
