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

from dataclasses import dataclass
from typing import Dict, List, Union, Optional

from cmsis_svd.model import SVDRegister

from fiit.machine import DeviceCpu

from .svd import SvdIndex, SvdLoader
from .interceptor import MonitoredMemory
from .logger import MmioLogger
from .interceptor import MmioInterceptor


@dataclass
class MmioAccessCount:
    address: int
    svd: Optional[SVDRegister] = None
    read: int = 0
    write: int = 0
    change: int = 0


class MmioTraceAccessCount:
    def __init__(self):
        self._raw_counter: Dict[int, MmioAccessCount] = dict()
        self._svd_counter: Dict[str, Dict[str, MmioAccessCount]] = dict()

    def inc_raw_counter_read(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).read += 1

    def inc_raw_counter_write(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).write += 1

    def inc_raw_counter_change(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).change += 1

    def _get_svd_counter(self, reg: SVDRegister) -> MmioAccessCount:
        periph = self._svd_counter.setdefault(reg.parent.name, dict())
        counter = MmioAccessCount(
            reg.parent.base_address+reg.address_offset, svd=reg)
        return periph.setdefault(reg.name, counter)

    def inc_svd_counter_read(self, reg: SVDRegister):
        self._get_svd_counter(reg).read += 1

    def inc_svd_counter_write(self, reg: SVDRegister):
        self._get_svd_counter(reg).write += 1

    def inc_svd_counter_change(self, reg: SVDRegister):
        self._get_svd_counter(reg).change += 1

    def reg_count(self):
        count = len(self._raw_counter)
        for periph_name in self._svd_counter:
            count += len(self._svd_counter[periph_name])
        return count

    def periph_count(self) -> int:
        return len(self._svd_counter)

    def get_all_registers(self) -> List[Union[int, SVDRegister]]:
        all_reg = list()

        for periph_name in self._svd_counter:
            for reg_name in self._svd_counter[periph_name]:
                all_reg.append(self._svd_counter[periph_name][reg_name].svd)

        all_reg += list(self._raw_counter.keys())
        return all_reg

    def get_all_peripherals(self) -> List[str]:
        return list(self._svd_counter.keys())

    def get_all_counters(self):
        all_counter: List[MmioAccessCount] = list()

        for periph_name in self._svd_counter:
            for reg_name in self._svd_counter[periph_name]:
                all_counter.append(self._svd_counter[periph_name][reg_name])

        all_counter.extend(list(self._raw_counter.values()))
        return all_counter


@dataclass
class MmioReadRecord:
    address: int
    pc: int
    state: int
    svd: Optional[SVDRegister] = None


@dataclass
class MmioWriteRecord:
    address: int
    pc: int
    state: int
    new_state: int
    svd: Optional[SVDRegister] = None


class MmioDataTrace:
    """ """
    def __init__(self):
        self.access_count = MmioTraceAccessCount()
        self.access_timeline: List[Union[MmioReadRecord, MmioWriteRecord]] = list()

    def record_read_access(self, address: int, pc: int, state: int):
        self.access_count.inc_raw_counter_read(address)
        self.access_timeline.append(MmioReadRecord(address, pc, state))

    def record_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ):
        if state != new_state:
            self.access_count.inc_raw_counter_change(address)
        else:
            self.access_count.inc_raw_counter_write(address)

        self.access_timeline.append(
            MmioWriteRecord(address, pc, state, new_state))

    def record_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        self.access_count.inc_svd_counter_read(reg)
        self.access_timeline.append(MmioReadRecord(address, pc, state, reg))

    def record_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        if state != new_state:
            self.access_count.inc_svd_counter_change(reg)
        else:
            self.access_count.inc_svd_counter_write(reg)

        self.access_timeline.append(
            MmioWriteRecord(address, pc, state, new_state, reg))

    def mmio_access_count(self) -> int:
        return len(self.access_timeline)

    def mmio_access_locations_data(self):
        locations = dict()

        for record in self.access_timeline:
            # This key is used to identify location access because different
            # MMIO register can be accessed from the same code address.
            key = f'{record.pc:#x}:{record.address:#x}'

            if key in locations:
                continue

            access_from = record.pc
            mmio_addr = record.address
            svd_name = (f'{record.svd.parent.name}:{record.svd.name}'
                        if record.svd is not None else None)
            access_type = 'w' if isinstance(record, MmioWriteRecord) else 'r'

            locations.update(
                {key: [access_from, mmio_addr, svd_name, access_type]})

        loc = list(locations.values())
        loc =  sorted(loc, key=lambda access_loc_info: access_loc_info[1])
        return loc

    def mmio_access_locations(self):
        return {record.pc for record in self.access_timeline}

    def mmio_access_registers(self):
        registers = {}
        for record in self.access_timeline:
            if record.address not in registers:
                svd_name = (f'{record.svd.parent.name}:{record.svd.name}'
                            if record.svd is not None else None)
                registers.update({record.address: (record.address, svd_name)})
        registers = list(registers.values())
        registers = sorted(registers, key=lambda r: r[0])
        return registers


class MmioTracer:

    def __init__(
        self,
        cpu: DeviceCpu,
        monitored_memory: Dict,
        mmio_filters: Dict = None,
        svd_resource: str = None,
        trace_data: bool = True,
        log: bool = False,
        log_show_field_states: bool = True
    ):
        self.cpu = cpu

        ########################################################################
        # SVD Data
        ########################################################################
        svd_dev = SvdLoader().load(svd_resource) if svd_resource else None
        svd_index = SvdIndex(svd_dev) if svd_dev else None

        ########################################################################
        # Monitored Memory
        ########################################################################
        self.mem_bit_size = cpu.bits.value
        self._monitored_memory = MonitoredMemory(
            self.mem_bit_size, **monitored_memory, svd_index=svd_index)

        ########################################################################
        # Logging
        ########################################################################
        logger_name = f'fiit.mmio_trace.dev@{cpu.dev_name}'
        mmio_logger = MmioLogger(
            self.mem_bit_size, self._monitored_memory, logger_name,
            log_show_field_states)

        ########################################################################
        # Data Trace
        ########################################################################
        self.mmio_data_trace = MmioDataTrace()

        ########################################################################
        # Memory Access Callbacks
        ########################################################################
        self._read_callbacks = list()
        self._write_callbacks = list()
        self._svd_read_callbacks = list()
        self._svd_write_callbacks = list()
        self._log_callbacks = list()

        if trace_data:
            self._read_callbacks.append(self.mmio_data_trace.record_read_access)
            self._write_callbacks.append(self.mmio_data_trace.record_write_access)
            self._svd_read_callbacks.append(self.mmio_data_trace.record_svd_read_access)
            self._svd_write_callbacks.append(self.mmio_data_trace.record_svd_write_access)

        if log:
            self._read_callbacks.append(mmio_logger.log_read_access)
            self._write_callbacks.append(mmio_logger.log_write_access)
            self._svd_read_callbacks.append(mmio_logger.log_svd_read_access)
            self._svd_write_callbacks.append(mmio_logger.log_svd_write_access)

        ########################################################################
        # Memory Access Interceptor
        ########################################################################
        MmioInterceptor(
            self.cpu,
            self._monitored_memory,
            self._read_callbacks,
            self._write_callbacks,
            self._svd_read_callbacks,
            self._svd_write_callbacks,
            mmio_filters=mmio_filters,
            svd_index=svd_index)
