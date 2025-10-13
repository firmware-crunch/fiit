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

from typing import Dict, List, Set, Union

from cmsis_svd.model import SVDRegister

from .svd import SvdIndex
from .reg import get_field


class RegisterField:
    def __init__(self, bit_offset: int, bit_width: int):
        self.bit_offset = bit_offset
        self.bit_width = bit_width


CodeAddress = int
RegisterAddress = int

RegisterAddressFieldsMap = Dict[RegisterAddress, List[RegisterField]]

SvdPeripheralName = str
SvdRegisterName = str
SvdFieldName = str

SvdPeripheralRegisterTree = Dict[SvdPeripheralName, Set[SvdRegisterName]]
SvdPeripheralRegisterFieldTree = Dict[
    SvdPeripheralName, Dict[SvdRegisterName, Set[SvdFieldName]]]


class MmioFilter:
    # Numeric Filter expression
    exp_keep_addr_from = '(f in self._filter_keep_from_address)'

    exp_exclude_addr_from = '(f not in self._filter_exclude_from_address)'

    exp_keep_addr = '(a in self._filter_keep_address)'

    exp_exclude_addr = '(a not in self._filter_exclude_address)'

    exp_state_change = \
        '((c != n) ' \
        ' if a in self._filter_register_state_change ' \
        ' else True)'

    exp_field_change = \
        '(self._check_fields_change(c, n, fields)' \
        ' if (fields := self._filter_field_state_change.get(a)) ' \
        ' else True)'

    # SVD Filter Expression
    exp_svd_state_change = \
        '((c != n) ' \
        'if a in self._svd_filter_register_state_change ' \
        'else True)'

    exp_svd_field_change = \
        '(self._check_fields_change(c, n, fields) ' \
        ' if (fields := self._svd_filter_field_state_change.get(a)) ' \
        ' else True)'

    exp_check_svd_register_exist = \
        '(svd_register ' \
        'if (svd_register := self._svd_address_index.get(a)) ' \
        'else False)'

    def __init__(
            self,
            filter_keep_from_address: Set[CodeAddress] = None,
            filter_exclude_from_address: Set[CodeAddress] = None,

            filter_keep_address: Set[RegisterAddress] = None,
            filter_exclude_address: Set[RegisterAddress] = None,
            filter_register_state_change: Set[RegisterAddress] = None,
            filter_field_state_change: RegisterAddressFieldsMap = None,

            svd_filter_peripheral_keep: Set[SvdPeripheralName] = None,
            svd_filter_register_keep: SvdPeripheralRegisterTree = None,
            svd_filter_peripheral_exclude: Set[SvdPeripheralName] = None,
            svd_filter_register_exclude: SvdPeripheralRegisterTree = None,
            svd_filter_register_state_change: SvdPeripheralRegisterTree = None,
            svd_filter_field_state_change: SvdPeripheralRegisterFieldTree = None,

            svd_index: SvdIndex = None,
    ):
        ##########################################
        # Numeric Filters
        ##########################################
        self._filter_keep_from_address = set(filter_keep_from_address or [])
        self._filter_exclude_from_address = set(filter_exclude_from_address or [])
        self._filter_keep_address = set(filter_keep_address or [])
        self._filter_exclude_address = set(filter_exclude_address or [])
        self._filter_register_state_change = set(filter_register_state_change or [])
        self._filter_field_state_change = filter_field_state_change or {}

        self._read_predicate = None
        self._write_predicate = None

        self.build_numeric_filter()

        ##########################################
        # SVD Filters
        ##########################################
        self.svd_filter_peripheral_keep = svd_filter_peripheral_keep
        self.svd_filter_register_keep = svd_filter_register_keep
        self.svd_filter_peripheral_exclude = svd_filter_peripheral_exclude
        self.svd_filter_register_exclude = svd_filter_register_exclude
        self.svd_filter_register_state_change = svd_filter_register_state_change
        self.svd_filter_field_state_change = svd_filter_field_state_change
        self.svd_index = svd_index
        self._svd_read_predicate = None
        self._svd_write_predicate = None

        if self.svd_index:
            self._svd_address_index = self.svd_index.get_address_index()
            self._svd_filter_register_state_change: Set[int] = set()
            self._svd_filter_field_state_change: RegisterAddressFieldsMap = dict()
            self.build_svd_filters()

    def build_numeric_filter(self):
        r_filters, w_filters = [], []

        if self._filter_keep_from_address:
            r_filters.append(self.exp_keep_addr_from)
            w_filters.append(self.exp_keep_addr_from)
        if self._filter_exclude_from_address:
            r_filters.append(self.exp_exclude_addr_from)
            w_filters.append(self.exp_exclude_addr_from)
        if self._filter_keep_address:
            r_filters.append(self.exp_keep_addr)
            w_filters.append(self.exp_keep_addr)
        if self._filter_exclude_address:
            r_filters.append(self.exp_exclude_addr)
            w_filters.append(self.exp_exclude_addr)
        if self._filter_register_state_change:
            w_filters.append(self.exp_state_change)
        if self._filter_field_state_change:
            w_filters.append(self.exp_field_change)
        if r_filters:
            self._read_predicate = eval(f'lambda self, a, f, c: '
                                        f'{" and ".join(r_filters)}')
        else:
            self._read_predicate = eval(f'lambda self, a, f, c: True')

        if w_filters:
            self._write_predicate = eval(f'lambda self, a, f, c, n: '
                                         f'{" and ".join(w_filters)}')
        else:
            self._write_predicate = eval(f'lambda self, a, f, c, n: True')

    def build_svd_filters(self):
        if not self.svd_index or self.svd_index.get_register_count() == 0:
            self._svd_read_predicate = None
            self._svd_write_predicate = None
            return

        self._svd_address_index = self.svd_index.get_address_index()
        self._svd_filter_register_state_change = set()
        self._svd_filter_field_state_change = dict()

        svd_r_filter, svd_w_filter = list(), list()
        keep_addr, exclude_addr = set(), set()

        if self.svd_filter_peripheral_keep:
            for periph in self.svd_filter_peripheral_keep:
                keep_addr.update(
                    self.svd_index.get_all_peripheral_register_address(periph))

        if self.svd_filter_register_keep:
            for periph, regs in self.svd_filter_register_keep.items():
                for reg in regs:
                    keep_addr.add(self.svd_index.get_register_address(periph, reg))

        if keep_addr:
            for address in list(self._svd_address_index.keys()):
                if address not in keep_addr:
                    del self._svd_address_index[address]

        if self.svd_filter_peripheral_exclude:
            for periph in self.svd_filter_peripheral_exclude:
                exclude_addr.update(
                    self.svd_index.get_all_peripheral_register_address(periph))

        if self.svd_filter_register_exclude:
            for periph, regs in self.svd_filter_register_exclude.items():
                for reg in regs:
                    exclude_addr.add(
                        self.svd_index.get_register_address(periph, reg))

        if exclude_addr:
            for address in list(self._svd_address_index.keys()):
                if address in exclude_addr:
                    del self._svd_address_index[address]

        if self.svd_filter_register_state_change:
            svd_w_filter.append(self.exp_svd_state_change)
            for periph, regs in self.svd_filter_register_state_change.items():
                for reg in regs:
                    addr = self.svd_index.get_register_address(periph, reg)
                    self._svd_filter_register_state_change.add(addr)

        if self.svd_filter_field_state_change:
            svd_w_filter.append(self.exp_svd_field_change)
            for periph, regs_dict in self.svd_filter_field_state_change.items():
                for reg, fields in regs_dict.items():
                    svd_register = self.svd_index.get_svd_register(periph, reg)
                    self._svd_filter_field_state_change.setdefault(
                        svd_register.parent.base_address
                        + svd_register.address_offset, [])
                    for field in fields:
                        addr = svd_register.parent.base_address \
                               + svd_register.address_offset
                        svd_field = list(filter(lambda f: f.name == field,
                                                svd_register.fields))[0]
                        self._svd_filter_field_state_change[addr].append(svd_field)

        if self._filter_keep_from_address:
            svd_w_filter.append(self.exp_keep_addr_from)
            svd_r_filter.append(self.exp_keep_addr_from)

        if self._filter_exclude_from_address:
            svd_w_filter.append(self.exp_exclude_addr_from)
            svd_r_filter.append(self.exp_exclude_addr_from)

        svd_r_filter.append(self.exp_check_svd_register_exist)
        svd_w_filter.append(self.exp_check_svd_register_exist)

        self._svd_read_predicate = eval(f'lambda self, a, f, c: '
                                        f'{" and ".join(svd_r_filter)}')
        self._svd_write_predicate = eval(f'lambda self, a, f, c, n: '
                                         f'{" and ".join(svd_w_filter)}')

    def build_filters(self):
        self.build_numeric_filter()
        self.build_svd_filters()

    @staticmethod
    def _check_fields_change(
            current_state: int, new_state: int,
            svd_fields: Union[Set[RegisterField], Set[SVDRegister]]) -> bool:
        for field in svd_fields:
            if get_field(current_state, field.bit_offset, field.bit_width) \
                    != get_field(new_state, field.bit_offset, field.bit_width):
                return True
        return False

    def read_predicate(self, address: int, from_address: int,
                       current_state: int) -> bool:
        return self._read_predicate(self, address, from_address, current_state)

    def write_predicate(self, address: int, from_address: int,
                        current_state: int, new_state: int) -> bool:
        return self._write_predicate(
            self, address, from_address, current_state, new_state)

    def svd_read_predicate(self, address: int, from_address: int,
                           current_state: int) -> Union[SVDRegister, None]:
        return self._svd_read_predicate(
                self, address, from_address, current_state)

    def svd_write_predicate(self, address: int, from_address: int,
                            current_state: int, new_state: int
                            ) -> Union[SVDRegister, bool]:
        return self._svd_write_predicate(
                self, address, from_address, current_state, new_state)

    def svd_filter_is_active(self) -> bool:
        if (self._svd_read_predicate is not None
                and self._svd_write_predicate is not None):
            return True
        else:
            return False

    def exclude_from_address_add(self, addresses: List[int]):
        self._filter_exclude_from_address.update(addresses)
