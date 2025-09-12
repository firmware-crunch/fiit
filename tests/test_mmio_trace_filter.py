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

from fiit.mmio_trace.svd_helper import SvdLoader, SvdIndex
from fiit.mmio_trace.filter import MmioFilter, RegisterField


def test_keep_from_address():
    mmio_filter = MmioFilter(filter_keep_from_address={0xffff00f0})
    assert not mmio_filter.svd_filter_is_active()
    assert not mmio_filter.read_predicate(0x10000000, 0xffff0000, 0x50)
    assert not mmio_filter.read_predicate(0x10000000, 0xffff00f8, 0x50)
    assert mmio_filter.read_predicate(0x10000000, 0xffff00f0, 0x50)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff0000, 0x50, 0x60)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff00f8, 0x50, 0x60)
    assert mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x50, 0x60)


def test_exclude_from_address():
    mmio_filter = MmioFilter(filter_exclude_from_address={0xffff00f0})
    assert not mmio_filter.svd_filter_is_active()
    assert mmio_filter.read_predicate(0x10000000, 0xffff0000, 0x50)
    assert mmio_filter.read_predicate(0x10000000, 0xffff00f8, 0x50)
    assert not mmio_filter.read_predicate(0x10000000, 0xffff00f0, 0x50)
    assert mmio_filter.write_predicate(0x10000000, 0xffff0000, 0x50, 0x60)
    assert mmio_filter.write_predicate(0x10000000, 0xffff00f8, 0x50, 0x60)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x50, 0x60)


def test_keep_address():
    mmio_filter = MmioFilter(filter_keep_address={0x10000000})
    assert not mmio_filter.svd_filter_is_active()
    assert mmio_filter.read_predicate(0x10000000, 0xffff00f8, 0x50)
    assert not mmio_filter.read_predicate(0x10000008, 0xffff00f0, 0x50)
    assert not mmio_filter.read_predicate(0xffffffc, 0xffff00f0, 0x50)
    assert mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x50, 0x60)
    assert not mmio_filter.write_predicate(0x10000008, 0xffff00f8, 0x50, 0x60)
    assert not mmio_filter.write_predicate(0xffffffc, 0xffff00f8, 0x50, 0x60)


def test_exclude_address():
    mmio_filter = MmioFilter(filter_exclude_address={0x10000000})
    assert not mmio_filter.svd_filter_is_active()
    assert not mmio_filter.read_predicate(0x10000000, 0xffff00f8, 0x50)
    assert mmio_filter.read_predicate(0x10000008, 0xffff00f0, 0x50)
    assert mmio_filter.read_predicate(0xffffffc, 0xffff00f0, 0x50)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x50, 0x60)
    assert mmio_filter.write_predicate(0x10000008, 0xffff00f8, 0x50, 0x60)
    assert mmio_filter.write_predicate(0xffffffc, 0xffff00f8, 0x50, 0x60)


def test_register_state_change():
    mmio_filter = MmioFilter(filter_register_state_change={0x10000000})
    assert not mmio_filter.svd_filter_is_active()
    assert mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x50, 0x55)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0x55, 0x55)


def test_register_field_change():
    field_filter = {0x10000000: [RegisterField(6, 2)]}
    mmio_filter = MmioFilter(filter_field_state_change=field_filter)
    assert not mmio_filter.svd_filter_is_active()
    assert mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0xc0, 0x80)
    assert not mmio_filter.write_predicate(0x10000000, 0xffff00f0, 0xc0, 0xc0)


def test_svd_filter_peripheral_keep():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_peripheral_keep={'UART4'},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x4004C004, 0xffff00f4, 0x0, 0x1)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_read_predicate(0x4004C004, 0xffff00f4, 0x0)
    assert not svd_reg


def test_svd_filter_peripheral_exclude():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_peripheral_exclude={'UART4'},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert not svd_reg

    svd_reg = mmio_filter.svd_write_predicate(0x4004C004, 0xffff00f4, 0x0, 0x1)
    assert svd_reg
    assert svd_reg.name == 'CFG'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x4004C004

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x4004C004, 0xffff00f4, 0x0)
    assert svd_reg
    assert svd_reg.name == 'CFG'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x4004C004


def test_svd_filter_register_keep():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_register_keep={'UART4': {'DR'}},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x40048004, 0xffff00f4, 0x0, 0x1)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_read_predicate(0x40048004, 0xffff00f4, 0x0)
    assert not svd_reg


def test_svd_filter_register_exclude():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_register_exclude={'UART4': {'DR'}},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert not svd_reg

    svd_reg = mmio_filter.svd_write_predicate(0x40048004, 0xffff00f4, 0x0, 0x1)
    assert svd_reg is not None
    assert svd_reg.name == 'ECR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048004

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x40048004, 0xffff00f4, 0x0)
    assert svd_reg
    assert svd_reg.name == 'ECR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048004


def test_svd_filter_register_state_change():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_register_state_change={'UART4': {'DR'}},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x0)
    assert not svd_reg


def test_svd_filter_field_state_change():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(svd_filter_field_state_change={
                                'UART4': {'DR': {'DATA'}}},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x100)
    assert not svd_reg


def test_svd_filter_keep_from_address():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(filter_keep_from_address:={0xffff00f0},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x40048004, 0xffff00f4, 0x0, 0x100)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_read_predicate(0x40048004, 0xffff00f4, 0x0)
    assert not svd_reg


def test_svd_filter_exclude_from_address():
    dev = SvdLoader().load('./fixtures/cmsis-svd/Toshiba_M367.svd')
    mmio_filter = MmioFilter(filter_exclude_from_address={0xffff00f4},
                             svd_index=SvdIndex(dev))
    assert mmio_filter.svd_filter_is_active()

    svd_reg = mmio_filter.svd_write_predicate(0x40048000, 0xffff00f0, 0x0, 0x41)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_write_predicate(0x40048004, 0xffff00f4, 0x0, 0x100)
    assert not svd_reg

    svd_reg = mmio_filter.svd_read_predicate(0x40048000, 0xffff00f0, 0x0)
    assert svd_reg
    assert svd_reg.name == 'DR'
    assert svd_reg.parent.base_address + svd_reg.address_offset == 0x40048000

    svd_reg = mmio_filter.svd_read_predicate(0x40048004, 0xffff00f4, 0x0)
    assert not svd_reg
