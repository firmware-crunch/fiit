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

import os
import datetime
import tempfile
from random import randrange
from typing import List, Tuple

import seaborn
import plotext
from cmsis_svd.model import SVDRegister

from .mmio_trace import MmioDataTrace, MmioReadRecord, MmioWriteRecord


class MmioTraceViz:
    def __init__(self, trace: MmioDataTrace):
        self._data = trace

    def mmio_access_stats_to_str(self, multi_bar=False) -> str:
        all_regs = list()
        change_percent = list()
        write_percent = list()
        read_percent = list()

        for counter in self._data.access_count.get_all_counters():
            if counter.svd is not None:
                all_regs.append(f'{counter.svd.parent.name}:{counter.svd.name}')
                change_percent.append(counter.change)
                write_percent.append(counter.write)
                read_percent.append(counter.read)

        plotext.clear_data()
        plot_args = (all_regs, [read_percent, write_percent, change_percent])
        plot_kwargs = dict(
            width=150, labels=['read', 'write', 'write with change'],
            title='MMIO Access Statistics')

        if len(all_regs) == 0:
            return ''
        elif not multi_bar:
            plotext.simple_stacked_bar(*plot_args, **plot_kwargs)
        elif multi_bar:
            plotext.simple_multiple_bar(*plot_args, **plot_kwargs)

        return plotext.build()

    @staticmethod
    def _color_generator(
        nb: int, color_style: str
    ) -> List[Tuple[int, int, int]]:
        color_conv = lambda x: round(min(max(x, 0.0), 1.0) * 255)

        if color_style == 'hls' or color_style == 'husl':
            colors = [
                (color_conv(c[0]), color_conv(c[1]), color_conv(c[2]))
                for c in seaborn.color_palette(color_style, nb)]
        else:
            colors = list()
            for i in range(0, nb):
                while True:
                    gen_color = (randrange(255), randrange(255), randrange(255))
                    if gen_color not in colors:
                        colors.append(gen_color)
                        break

        return colors

    def mmio_access_timeline_to_str(
        self, start: int = 0, count: int = 0, access_by_line: int = 20,
        color: str = 'hls', output: str = 'term'
    ) -> str:
        legend = dict()
        legend_buff = []
        color_access_buff = [f'\n  {start:06}-']
        rgb_f_term = '\033[48;2;{};{};{}m {} \033[0m'
        rgb_f_html = ('<data style="background-color:rgb({}, {}, {}); '
                      'border-color: black; border-width: 1px; '
                      'border-style: solid;">{}</data>')
        rgb_f = rgb_f_term if output == 'term' else rgb_f_html
        end = None if count == 0 else start+count
        time_slice = self._data.access_timeline[start:end]

        if len(time_slice) == 0:
            return ''

        legend_keys = []
        for access_data in time_slice:
            if access_data.svd is not None:
                legend_keys.append(f'{access_data.svd.parent.name}'
                                   f':{access_data.svd.name}')
            else:
                legend_keys.append(f'0x{access_data.address:x}')

        colors = self._color_generator(self._data.access_count.periph_count(), color)

        r_id = 0
        for idx, periph_name in enumerate(self._data.access_count.get_all_peripherals()):
            for reg in self._data.access_count.get_all_registers():
                if isinstance(reg, SVDRegister) and reg.parent.name == periph_name:
                    r_id += 1
                    legend[f'{reg.parent.name}:{reg.name}'] = [colors[idx], r_id]

        for idx, access_data in enumerate(time_slice):
            if access_data.svd is not None:
                svd_key = f'{access_data.svd.parent.name}:{access_data.svd.name}'
                reg_id = f'{legend[svd_key][1]:03}'
                col = legend[svd_key][0]
            else:
                reg_id = f'{legend[access_data.address][1]:03}'
                col = legend[access_data.address][0]

            if isinstance(access_data, MmioReadRecord):
                access_str = 'r'
            elif (isinstance(access_data, MmioWriteRecord)
                    and access_data.state != access_data.new_state):
                access_str = 'c'
            else:
                access_str = 'w'

            color_access_buff.append(rgb_f.format(col[0], col[1], col[2],
                                                  f'{reg_id}-{access_str}'))

            if (idx+1) % (access_by_line*5) == 0:
                color_access_buff.append(f'\n  {start+idx+1:06}-')
            elif (idx+1) % access_by_line == 0:
                color_access_buff.append('\n         ')

        previous_color = None
        legend_item_by_line = 0
        for idx, reg_key in enumerate(legend):
            color_cur = legend[reg_key][0]

            if idx == 0:
               previous_color = color_cur

            if (isinstance(reg_key, str)
                    and (legend_item_by_line % 4 == 0
                         or color_cur != previous_color)):
                legend_item_by_line = 0
                endline = '\n\n' if color_cur != previous_color else '\n'
                legend_buff.append(endline)
            elif isinstance(reg_key, int) and legend_item_by_line % 4 == 0:
                legend_buff.append('\n')

            name = f'0x{reg_key:x}' if isinstance(reg_key, int) else reg_key

            if name not in legend_keys:
                continue

            color_code = rgb_f.format(
                *color_cur, f'{legend[reg_key][1]:03}')
            legend_buff.append(f'[{name} {color_code}]  ')

            previous_color = color_cur
            legend_item_by_line += 1

        out = (
            f'\n{len(self._data.access_timeline)} MMIO Access\n\n'
            f'{"".join(color_access_buff)}\n\n{"".join(legend_buff)}')

        if output == 'html':
            out = f'<pre>\n{out}\n</pre>'
            str_date = "{:%y-%m-%d-%H-%M-%S}".format(datetime.datetime.now())
            out_path = f'{tempfile.gettempdir()}{os.path.sep}{str_date}' \
                       f'-mmio_access_timeline_to_str.html'
            with open(out_path, 'w') as f:
                f.write(out)
            out = f'\n\nMMIO access timeline save to {out_path}.\n\n'

        return out
