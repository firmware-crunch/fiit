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
    'MmioTraceVizFrontend'
]

from typing import List, Union

from tabulate import tabulate

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from fiit.iotrace import MmioTracer, MmioTraceViz

from ..shell import Shell

# ==============================================================================


@IPython.core.magic.magics_class
class MmioTraceVizFrontend(IPython.core.magic.Magics):
    def __init__(self, mmio_tracer_list: List[MmioTracer], shell: Shell):
        self._mmio_tracer_list = mmio_tracer_list
        self._trace_viz_list = {
            mmio_tracer: MmioTraceViz(mmio_tracer.mmio_data_trace)
            for mmio_tracer in self._mmio_tracer_list
        }
        super(MmioTraceVizFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        self._shell.register_magics(self)
        self._shell.register_aliases(self)

    def _get_mmio_tracer(self, cpu_name: str) -> Union[MmioTracer, None]:
        for mmio_tracer in self._mmio_tracer_list:
            if mmio_tracer.cpu.name == cpu_name:
                return mmio_tracer

    @magic_arguments()
    @argument('cpu_name', type=str, help='')
    @IPython.core.magic.line_magic
    def mmio_access_count(self, line: str):
        kwargs = parse_argstring(self.mmio_access_count, line)
        mmio_tracer = self._get_mmio_tracer(kwargs.cpu_name)

        if mmio_tracer is None:
            print(f'mmio tracer not found for CPU name {kwargs.cpu_name}')
        else:
            print(f'{mmio_tracer.mmio_data_trace.mmio_access_count()}')

    @magic_arguments()
    @argument('cpu_name', type=str, help='')
    @argument('--multi-bar', nargs='?', choices=['true', 'false'],
              const='true', default='false')
    @IPython.core.magic.line_magic
    def mmio_access_stats(self, line: str):
        """ Print MMIO access statistics as read, write, write with change"""
        kwargs = parse_argstring(self.mmio_access_stats, line)
        multi_bar = True if kwargs.multi_bar == 'true' else False
        mmio_tracer = self._get_mmio_tracer(kwargs.cpu_name)

        if mmio_tracer is None:
            print(f'mmio tracer not found for CPU name {kwargs.cpu_name}')
        else:
            trace_viz = self._trace_viz_list[mmio_tracer]
            print(trace_viz.mmio_access_stats_to_str(multi_bar))

    @magic_arguments()
    @argument('cpu_name', type=str, help='')
    @argument('--start', nargs='?', type=int, const=0, default=0,
              help='Start the MMIO access timeline at specific offset.')
    @argument('--count', nargs='?', type=int, const=0, default=0,
              help='Number of access to include.')
    @argument('--access-by-line', nargs='?', type=int, const=20, default=20,
              help='Number of MMIO access by line.')
    @argument('--color', nargs='?', choices=['hls', 'husl', 'rand'],
              const='hls', default='hls', help='Cell colorization style.')
    @argument('--output', nargs='?', choices=['term', 'html'],
              const='term', default='term', help='Output type.')
    @IPython.core.magic.line_magic
    def mmio_access_timeline(self, line: str):
        """Print MMIO access timeline"""
        kwargs = parse_argstring(self.mmio_access_timeline, line)
        mmio_tracer = self._get_mmio_tracer(kwargs.cpu_name)

        if mmio_tracer is None:
            print(f'mmio tracer not found for CPU name {kwargs.cpu_name}')
        else:
            trace_viz = self._trace_viz_list[mmio_tracer]
            print(trace_viz.mmio_access_timeline_to_str(**vars(kwargs)))

    @magic_arguments()
    @argument('cpu_name', type=str, help='')
    @IPython.core.magic.line_magic
    def mmio_access_locations_info(self, line: str):
        """Display MMIO access location."""
        kwargs = parse_argstring(self.mmio_access_locations_info, line)
        mmio_tracer = self._get_mmio_tracer(kwargs.cpu_name)

        if mmio_tracer is None:
            print(f'mmio tracer not found for CPU name {kwargs.cpu_name}')
        else:
            table_cell = mmio_tracer.mmio_data_trace.mmio_access_locations_data()
            table_cell = list(table_cell)

            for cell in table_cell:
                cell[0] = self._mmio_trace.cpu.mem.addr_to_str(cell[0])
                cell[1] = self._mmio_trace.cpu.mem.addr_to_str(cell[1])

            print(
                f'\n '
                f'{len(mmio_tracer.mmio_data_trace.mmio_access_registers())} '
                f'MMIO registers accessed from '
                f'{len(mmio_tracer.mmio_data_trace.mmio_access_locations())} '
                f'code locations.\n'
            )

            tab = tabulate(
                table_cell,
                ['Access From', 'MMIO Address', 'Name', 'Access'],
                tablefmt='simple'
            )

            print(tab)

    @argument('cpu_name', type=str, help='')
    @IPython.core.magic.line_magic
    def mmio_access_locations_count(self, line: str):
        """Display MMIO access location number."""
        kwargs = parse_argstring(self.mmio_access_locations_info, line)
        mmio_tracer = self._get_mmio_tracer(kwargs.cpu_name)

        if mmio_tracer is None:
            print(f'mmio tracer not found for CPU name {kwargs.cpu_name}')
        else:
            print(len(mmio_tracer.mmio_data_trace.mmio_access_locations()))
