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

from typing import List, Any, Literal, Dict, Callable, Optional, Tuple
from collections import OrderedDict
import sys
import struct
import logging
import dataclasses

import tabulate

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring)

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_MEM_FETCH_UNMAPPED)

from .arch_unicorn import ArchUnicorn
from fiit.core.shell import register_alias
from fiit.core.dis_capstone import DisassemblerCapstone, CAPSTONE_CONFIG
from fiit.core.emulator_types import ADDRESS_FORMAT
from fiit.core.shell import Shell


@dataclasses.dataclass
class Breakpoint:
    address: int
    count: int
    hit_count: int = 0


@dataclasses.dataclass
class Watchpoint:
    begin: int
    end: int
    access: str
    count: int = 0
    hit_count: int = 0


DBG_EVENT_SEGFAULT = 1
DBG_EVENT_BREAKPOINT = 2
DBG_EVENT_WATCHPOINT = 3
DBG_EVENT_STEP = 4

DBG_BP_COUNTER_INS = 1
DBG_BP_COUNTER_BLOCK = 2


class UnicornDbg:
    LOGGER_NAME = 'fiit.unicorn_dbg'

    def __init__(self, uc: Uc, debug_event_callback: Callable = None):
        self._logger = logging.getLogger(self.LOGGER_NAME)

        ############################
        # Emulation settings
        ############################
        self.uc = uc
        self.arch = ArchUnicorn.get_arch_str_by_uc(self.uc)
        self.mem_bit_size = ArchUnicorn.get_mem_bit_size(self.arch)
        self.endiannes = ArchUnicorn.get_unicorn_endianness(self.uc._mode)
        self.cpu_reg = ArchUnicorn.get_unicorn_registers(self.arch)
        self.pc_code = ArchUnicorn.get_unicorn_pc_code(self.uc._arch)

        ############################
        # Debugger hook settings
        ############################
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED
            | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_segfault)

        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                         self._hook_watchpoint)

        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

        ############################
        # Disassembler
        ############################
        cpu, size, endian, _ = self.arch.split(':')

        if self.arch in CAPSTONE_CONFIG:
            dis_arch_str = self.arch
        else:
            dis_arch_str = f'{cpu}:{size}:{endian}:default'

        self._disassembler = DisassemblerCapstone(dis_arch_str)

        ############################
        # Breakpoint
        ############################
        self._step_ins_flag = False
        self._breakpoints: OrderedDict[int, Breakpoint] = OrderedDict()

        ############################
        # Watchpoint
        ############################
        self._watchpoints: OrderedDict[str, Watchpoint] = OrderedDict()

        ############################
        # Debugger event callback
        ############################
        self.debug_event_callbacks: List[Callable] = []

        if debug_event_callback:
            self.debug_event_callbacks.append(debug_event_callback)

        ############################
        # Debugger frontend
        ############################
        self._addr_f = ADDRESS_FORMAT[self.mem_bit_size]

    def get_cpu_register(self, register: int) -> int:
        return self.uc.reg_read(register)

    def get_cpu_registers(self, registers: List[str] = None) -> Dict[str, int]:
        regs = registers if registers else self.cpu_reg
        return {r: self.get_cpu_register(self.cpu_reg[r]) for r in regs}

    def set_cpu_register(self, register: str, value: int) -> None:
        self.uc.reg_write(self.cpu_reg[register], value)

    def get_pc(self) -> int:
        return self.get_cpu_register(self.pc_code)

    def debug_event_callback(self, event_id: int, args: dict):
        for callback in self.debug_event_callbacks:
            callback(self, event_id, args)

    def _hook_segfault(self, uc: Uc, access: int, address: int, size: int,
                       value: int, user_data: Any):
        if access == UC_MEM_FETCH_UNMAPPED:
            self._logger.info(f'Invalid memory fetch to {self._addr_f(address)}')
        elif access in [UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED]:
            access_str = 'write' if access == UC_MEM_WRITE_UNMAPPED else 'read'
            self._logger.info(f'Invalid memory access {access_str} from '
                              f'{self._addr_f(self.get_pc())} to '
                              f'{self._addr_f(address)}')

        self.debug_event_callback(DBG_EVENT_SEGFAULT, {'address': address})

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: Any):
        if address in self._breakpoints or self._step_ins_flag:
            if self._step_ins_flag:
                self._step_ins_flag = False
                event = DBG_EVENT_STEP
                self._logger.info(f'step instruction at {self._addr_f(address)}')

            if address in self._breakpoints:
                bp = self._breakpoints[address]
                bp.hit_count += 1
                event = DBG_EVENT_BREAKPOINT
                self._logger.info(f'Breakpoint at {self._addr_f(address)}, '
                                  f'hit {bp.hit_count}')

                if bp.count > 0 and bp.count == bp.hit_count:
                    self.breakpoint_del(address)

            self.debug_event_callback(event, {'address': address})

    def breakpoint_set(self, address: int, count=0):
        if address not in self._breakpoints:
            self._breakpoints.update({address: Breakpoint(address, count)})

    def breakpoint_del(self, address: int):
        self._breakpoints.pop(address)

    def breakpoint_del_by_index(self, idx: int):
        address = list(self._breakpoints.keys())[idx - 1]
        self.breakpoint_del(address)

    def set_step(self):
        self._step_ins_flag = True

    def _hook_watchpoint(
        self, uc: Uc, access: int, address: int, size: int, value: int,
        current_run: Any
    ):
        for area, wp in self._watchpoints.items():
            access_type = 'w' if access == UC_MEM_WRITE else 'r'
            if wp.begin >= address <= wp.end and access_type in wp.access:
                pc = self.get_pc()
                wp.hit_count += 1
                begin, end = area.split(':')
                access_str = 'write' if access == UC_MEM_WRITE else 'read'
                self._logger.info(
                    f'watchpoint at {self._addr_f(address)}, '
                    f'area [{self._addr_f(int(begin))}'
                    f'-{self._addr_f(int(end))}], '
                    f'hit {wp.hit_count}, '
                    f'access {access_str} from {self._addr_f(pc)}')
                meta = {'address': address, 'pc_address': pc,
                        'access': access_type, 'size': size}
                self.debug_event_callback(DBG_EVENT_WATCHPOINT, meta)

                if wp.count > 0 and wp.count == wp.hit_count:
                    self.watchpoint_del(area)

    def watchpoint_set(self, begin: int, end: int,
                       access: Literal['r', 'w', 'rw'], count=0):
        if end < begin:
            raise ValueError('Invalid Watch Memory area (begin < end).')

        if (area := f'{begin}:{end}') not in self._watchpoints:
            wp = Watchpoint(begin, end, access, count)
            self._watchpoints.update({area: wp})

    def watchpoint_del_by_index(self, idx: int):
        self.watchpoint_del(list(self._watchpoints.keys())[idx - 1])

    def watchpoint_del(self, area: str):
        self._watchpoints.pop(area)

    def disassemble(self, address: int, count: int) -> List[str]:
        mm = list(filter(
            lambda x: x[0] <= address < x[1], self.uc.mem_regions()))

        if len(mm) == 1:
            mm = mm[0]
            chunk_size = (mm[1]-mm[0]) - 1 - (address - mm[0])
            code = self.uc.mem_read(address, chunk_size)
            return self._disassembler.disassemble_mem_range(
                code, address, count)
        else:
            raise ValueError(f'Fail to disassemble at {address}, not mapped.')


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
class UnicornDbgFrontend(IPython.core.magic.Magics):
    def __init__(self, dbg: UnicornDbg, shell: Shell):
        #####################################
        # Debugger Callbacks Settings
        #####################################
        self.dbg = dbg
        dbg.debug_event_callbacks.append(self.debug_event_callback)
        self._current_event: Optional[Tuple[int, dict]] = None

        #####################################
        # Shell Init
        #####################################
        super(UnicornDbgFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        shell.register_magics(self)
        shell.register_aliases(self)
        shell.stream_logger_to_shell_stdout(self.dbg.LOGGER_NAME)

        #####################################
        # Output Formatters
        #####################################
        self._formatter = DbgFormatter(dbg.mem_bit_size)

    def debug_event_callback(
        self, dbg: UnicornDbg, event: int, args: dict
    ):
        if event in [DBG_EVENT_BREAKPOINT, DBG_EVENT_WATCHPOINT,
                     DBG_EVENT_STEP]:
            self._current_event = (event, args)
            self._shell.resume()
            self._shell.wait_for_prompt_suspend()
            self._current_event = None

    @register_alias('c')
    @IPython.core.magic.line_magic
    def cont(self, line: str):
        """Continue emulation."""
        if self._current_event is not None:
            self._shell.suspend()
        else:
            print('Emulation is not started.')

    @register_alias('s')
    @IPython.core.magic.line_magic
    def step(self, line: str):
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
    def breakpoint_print(self, line: str):
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
    def watchpoint_print(self, line: str):
        """Print watchpoint."""
        print(self._formatter.watchpoints(list(self.dbg._watchpoints.values())))
