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

from typing import List, Literal, Optional, Tuple
import sys
import struct

import tabulate

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from ..emu.emu_types import ADDRESS_FORMAT
from ..dbg import (
    Debugger, Breakpoint, Watchpoint, DBG_EVENT_STEP, DBG_EVENT_WATCHPOINT,
    DBG_EVENT_BREAKPOINT)
from ..shell import Shell, register_alias


class DbgFormatter:
    ADDR_FORMAT_NO_PRE = {
        8: '{:02x}'.format, 16: '{:04x}'.format, 32: '{:08x}'.format,
        64: '{:016x}'.format}

    def __init__(self, mem_bit_size: Literal[8, 16, 32, 64]):
        self._mem_bit_size = mem_bit_size
        self._addr_f = ADDRESS_FORMAT[mem_bit_size]
        self._addr_f_no_pre = self.ADDR_FORMAT_NO_PRE[mem_bit_size]

    def hexdump(self, src: bytes, start_addr: int = 0, length: int = 16,
                sep: str = '.') -> str:
        lines = []

        chr_filter = ''.join([(
            len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])

        for c in range(0, len(src), length):
            chars = src[c: c + length]
            hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
            if len(hex_) > 24:
                hex_ = '{} {}'.format(hex_[:24], hex_[24:])
            printable = ''.join(['{}'.format(
                (x <= 127 and chr_filter[x]) or sep) for x in chars])
            lines.append('{0:}  {1:{2}s} |{3:{4}s}|'.format(
                self._addr_f_no_pre(c + start_addr),
                hex_, length * 3, printable, length))

        return '\n'.join(lines)

    def breakpoints(self, breakpoints: List[Breakpoint]) -> str:
        headers = ['index', 'address', 'hit']
        table = [[idx+1, self._addr_f(b.address), b.hit_count]
                 for idx, b in enumerate(breakpoints)]
        return tabulate.tabulate(table, headers, tablefmt="simple")

    def watchpoints(self, watchpoints: List[Watchpoint]):
        headers = ['index', 'begin', 'end', 'access', 'hit']
        table = [[idx+1, self._addr_f(w.begin), self._addr_f(w.end), w.access,
                  w.hit_count]
                 for idx, w in enumerate(watchpoints)]
        return tabulate.tabulate(table, headers, tablefmt="simple")

    def registers(self, registers: dict) -> str:
        out = []
        for idx, r in enumerate(registers):
            if idx % 3 == 0 and idx != 0:
                out.append('\n')
            out.append('{: <5}{}   '.format(r, self._addr_f(registers[r])))
        return ''.join(out)


@IPython.core.magic.magics_class
class DbgFrontend(IPython.core.magic.Magics):
    def __init__(self, dbg: Debugger, shell: Shell):
        #####################################
        # Debugger Callbacks Settings
        #####################################
        self.dbg = dbg
        dbg.debug_event_callbacks.append(self.debug_event_callback)
        self._current_event: Optional[Tuple[int, dict]] = None

        #####################################
        # Shell Init
        #####################################
        super(DbgFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        shell.register_magics(self)
        shell.register_aliases(self)
        shell.stream_logger_to_shell_stdout(self.dbg.LOGGER_NAME)

        #####################################
        # Output Formatters
        #####################################
        self._formatter = DbgFormatter(dbg.mem_bit_size)

    def debug_event_callback(
        self, _: Debugger, event: int, args: dict
    ):
        if event in [DBG_EVENT_BREAKPOINT, DBG_EVENT_WATCHPOINT,
                     DBG_EVENT_STEP]:
            self._current_event = (event, args)
            self._shell.resume()
            self._shell.wait_for_prompt_suspend()
            self._current_event = None

    @register_alias('c')
    @IPython.core.magic.line_magic
    def cont(self, _: str):
        """Continue emulation."""
        if self._current_event is not None:
            self._shell.suspend()
        else:
            print('Emulation is not started.')

    @register_alias('s')
    @IPython.core.magic.line_magic
    def step(self, _: str):
        """Steps to the next instruction."""
        if self._current_event is not None:
            self.dbg.set_step()
            self._shell.suspend()
        else:
            print('Emulation is not started.')

    @magic_arguments()
    @argument('registers', nargs='*', default=[],
              help='CPU Register name(s) to dump.')
    @register_alias('rg')
    @IPython.core.magic.line_magic
    def register_get(self, line: str):
        """Get CPU register(s)."""
        args = parse_argstring(self.register_get, line)
        regs = self.dbg.get_cpu_registers(args.registers)
        sys.stdout.write(self._formatter.registers(regs))

    @magic_arguments()
    @argument('register', help='CPU Register name to set.')
    @argument('value', help='Hexadecimal value to set.')
    @register_alias('rs')
    @IPython.core.magic.line_magic
    def register_set(self, line: str):
        """Set CPU register."""
        args = parse_argstring(self.register_set, line)
        self.dbg.set_cpu_register(args.register, int(args.value, 16))

    @magic_arguments()
    @argument('address', help='Starting memory address to disassemble.')
    @argument('count', nargs='?', type=int, default=1,
              help='Number of instruction to disassemble, default 1.')
    @register_alias('dis')
    @IPython.core.magic.line_magic
    def disassemble(self, line: str):
        """Disassemble memory."""
        args = parse_argstring(self.disassemble, line)
        addr = int(args.address, 16)
        insns = self.dbg.disassemble(addr, args.count)
        sys.stdout.write('\n'.join(insns))

    @magic_arguments()
    @argument('address', help='Starting memory address to read.')
    @argument('size', nargs='?', type=int, default=256,
              help='Memory size to read in byte. (default 256)')
    @register_alias('mr')
    @IPython.core.magic.line_magic
    def mem_read(self, line: str):
        """Read Memory."""
        args = parse_argstring(self.mem_read, line)
        addr = int(args.address, 16)
        sys.stdout.write(
            self._formatter.hexdump(
                self.dbg.uc.mem_read(addr, args.size), addr))

    @magic_arguments()
    @argument('address', help='Starting memory address to write.')
    @argument('type', choices=['word', 'cstring'], help='Value type to write.')
    @argument('value', help='Value to write.')
    @register_alias('mw')
    @IPython.core.magic.line_magic
    def mem_write(self, line: str):
        """Write Memory."""
        args = parse_argstring(self.mem_write, line)
        addr = int(args.address, 16)
        if args.type == 'word':
            value = int(args.value, 16)
            endian = '>' if self.dbg.endiannes == 'big' else '<'
            self.dbg.uc.mem_write(
                addr, struct.pack(f'{endian}I', value))
        if args.type == 'cstring':
            self.dbg.uc.mem_write(addr, args.value.encode())

    @magic_arguments()
    @argument('address', help='Address where to pause the execution.')
    @argument('count', nargs='?', type=int, default=0,
              help='Hit count before delete breakpoint, '
                   'if 0 the breakpoint is never deleted.')
    @register_alias('bps')
    @IPython.core.magic.line_magic
    def breakpoint_set(self, line: str):
        """Set breakpoint."""
        args = parse_argstring(self.breakpoint_set, line)
        self.dbg.breakpoint_set(int(args.address, 16), int(args.count))

    @magic_arguments()
    @argument('index', type=int, help='Breakpoint Index')
    @register_alias('bpd')
    @IPython.core.magic.line_magic
    def breakpoint_del(self, line: str):
        """Delete breakpoint"""
        args = parse_argstring(self.breakpoint_del, line)
        self.dbg.breakpoint_del_by_index(args.index)

    @IPython.core.magic.line_magic
    @register_alias('bpp')
    def breakpoint_print(self, _: str):
        """Print breakpoint."""
        print(self._formatter.breakpoints(list(self.dbg._breakpoints.values())))

    @magic_arguments()
    @argument('access', choices=['r', 'w', 'rw'], help='Access type to monitor')
    @argument('begin', help='Start address of the memory area to monitor '
              'access')
    @argument('end', help='End address of the memory area to monitor access')
    @argument('count', nargs='?', type=int, default=0,
              help='Hit count before delete watchpoint, '
                   'if 0 the watchpoint is never deleted. (default=0)')
    @register_alias('wpa')
    @IPython.core.magic.line_magic
    def watchpoint_area(self, line: str):
        """Set watchpoint on memory area access."""
        args = parse_argstring(self.watchpoint_area, line)
        begin, end = int(args.begin, 16), int(args.end, 16)
        count = int(args.count)
        self.dbg.watchpoint_set(begin, end, args.access, count)

    @magic_arguments()
    @argument('access', choices=['r', 'w', 'rw'], help='Access type to monitor')
    @argument('address', help='Address of the variable to monitor')
    @argument('count', nargs='?', type=int, default=0,
              help='Hit count before delete watchpoint, '
                   'if 0 the watchpoint is never deleted. (default=0)')
    @register_alias('wpv')
    @IPython.core.magic.line_magic
    def watchpoint_var(self, line: str):
        """Set watchpoint on variable access."""
        args = parse_argstring(self.watchpoint_var, line)
        address = int(args.address, 16)
        count = int(args.count)
        self.dbg.watchpoint_set(address, address, args.access, count)

    @magic_arguments()
    @argument('index', type=int, help='Watchpoint index')
    @register_alias('wpd')
    @IPython.core.magic.line_magic
    def watchpoint_del(self, line: str):
        """Delete watchpoint."""
        args = parse_argstring(self.watchpoint_del, line)
        self.dbg.watchpoint_del_by_index(args.index)

    @register_alias('wpp')
    @IPython.core.magic.line_magic
    def watchpoint_print(self, _: str):
        """Print watchpoint."""
        print(self._formatter.watchpoints(list(self.dbg._watchpoints.values())))
