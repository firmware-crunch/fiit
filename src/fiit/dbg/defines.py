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
    # breakpoint primitive
    'BreakpointBase',
    # breakpoint interface (code)
    'BreakpointType',
    'Breakpoint',
    'BreakpointOOB',
    # watchpoint interface (memory)
    'WatchpointAccess',
    'WatchpointType',
    'Watchpoint',
    'WatchpointReadOOB',
    'WatchpointWriteOOB',
    'WatchpointRwOOB',
    # event primitives
    'DbgEventBase',
    'DbgEventStop',
    # event interface
    'DbgEventStartProgram',
    'DbgEventContinue',
    'DbgEventStopType',
    'DbgEventBreakpoint',
    'DbgEventWatchpoint',
    'DbgEventStepInst',
    'DbgEventMemFetchUnmapped',
    'DbgEventMemAccessUnmapped',
    'DbgEventMemWriteUnmapped',
    'DbgEventMemWrite',
    'DbgEventMemReadUnmapped',
    'DbgEventBreakpointCreated',
    'DbgEventBreakpointDeleted',
    'DbgEventBreakpointChanged',
    'DbgEventRegisterWrite'
]

from typing import Callable, Any, Union, Optional, Type
import datetime
import enum
import abc

from fiit.machine import Memory, CpuBits

# ==============================================================================


# ------------------------------------------------------------------------------
# breakpoint base interface

BreakpointCondition = Callable[[Any, Union['Breakpoint', 'Watchpoint']], bool]
BreakpointHitCb = Callable[[Any, Union['Breakpoint', 'Watchpoint']], None]
BreakpointInvalidateCb = Callable[[Union['Breakpoint', 'Watchpoint', 'BreakpointBase']], None]


class BreakpointBase(abc.ABC):

    @staticmethod
    def _default_condition(_: Any, __: 'BreakpointBase') -> bool:
        return True

    def __init__(
        self,
        bp_type: Union['BreakpointType', 'WatchpointType'],
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        assert isinstance(bp_type, (BreakpointType, WatchpointType))
        self._is_watchpoint = isinstance(bp_type, WatchpointType)
        self._break_type = bp_type
        self.hit_count: int = 0
        self.condition = (
            self._default_condition if condition is None else condition
        )
        self._hit_callback = hit_callback
        self._enabled = True
        self._is_valid = False
        self._owner: Optional['Debugger'] = None

    @property
    def is_breakpoint(self) -> bool:
        return not self._is_watchpoint

    @property
    def is_watchpoint(self) -> bool:
        return self._is_watchpoint

    @property
    def break_type(self) -> Union[Type['BreakpointType'], Type['WatchpointType']]:
        return self._break_type

    @property
    def is_valid(self) -> bool:
        if self._owner is not None:
            return True
        return False

    @property
    def owner(self) -> Any:
        return self._owner

    @owner.setter
    def owner(self, owner: 'Debugger') -> None:
        if self._owner is None:  # freeze the owner
            self._owner = owner
            self._is_valid = True
        else:
            raise RuntimeError('breakpoint owner is frozen')

    def invalidate(self) -> None:
        if self._is_valid and self._owner is not None:
            if isinstance(self, Breakpoint):
                self._owner.breakpoint_del(self)
            elif isinstance(self, Watchpoint):
                self._owner.watchpoint_del(self)

            self._is_valid = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, flag: bool) -> None:
        saved_flag = self._enabled
        self._enabled = flag

        if saved_flag != flag and self._is_valid and self._owner is not None:
            event = DbgEventBreakpointChanged(self)
            self._owner.trigger_event(event)

    @property
    def hit_callback(self) -> Union[BreakpointHitCb, None]:
        return self._hit_callback

    @hit_callback.setter
    def hit_callback(self, callback: BreakpointHitCb) -> None:
        self._hit_callback = callback


# ------------------------------------------------------------------------------
# breakpoint interface (code)

class BreakpointType(enum.IntEnum):
    OOB = (1, 'out-of-band')

    label: str

    def __new__(
        cls, value: int, label: str
    ) -> 'BreakpointType':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        return obj


class Breakpoint(BreakpointBase):
    def __init__(
        self,
        address: int,
        type_: BreakpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        BreakpointBase.__init__(self, type_, condition, hit_callback)
        self.address = address


class BreakpointOOB(Breakpoint):
    def __init__(
        self,
        address: int,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        Breakpoint.__init__(
            self, address, BreakpointType.OOB, condition, hit_callback
        )


# ------------------------------------------------------------------------------
# breakpoint interface (memory)


class WatchpointType(enum.IntEnum):
    OOB = (1, 'out-of-band')

    label: str

    def __new__(
        cls, value: int, label: str
    ) -> 'WatchpointType':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        return obj


class WatchpointAccess(enum.IntEnum):
    READ = (1, 'r', 'r-', 'read')
    WRITE = (2, 'w', '-w', 'write')
    READ_WRITE = (3, 'rw', 'rw', 'read-write')

    label: str
    label_unix: str
    label_full: str

    def __new__(
        cls, value: int, label: str, label_unix: str, label_full: str
    ) -> 'WatchpointAccess':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        obj.label_unix = label_unix
        obj.label_full = label_full
        return obj

    @classmethod
    def from_str(cls, value: str) -> 'WatchpointAccess':
        for wpt in cls:
            if value in [wpt.label, wpt.label_unix, wpt.label_full]:
                return wpt

        raise ValueError(f'illegal watchpoint type "{value}"')


class Watchpoint(BreakpointBase):
    def __init__(
        self,
        begin: int,
        end: int,
        access: WatchpointAccess,
        type_: WatchpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        BreakpointBase.__init__(self, type_, condition, hit_callback)
        self.access = access
        self.begin = begin
        self.end = end


class WatchpointReadOOB(Watchpoint):
    def __init__(
        self,
        begin: int,
        end: int,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        super().__init__(
            begin, end, WatchpointAccess.READ, WatchpointType.OOB,
            condition, hit_callback
        )


class WatchpointWriteOOB(Watchpoint):
    def __init__(
        self,
        begin: int,
        end: int,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        Watchpoint.__init__(
            self, begin, end, WatchpointAccess.WRITE,
            WatchpointType.OOB, condition, hit_callback
        )


class WatchpointRwOOB(Watchpoint):
    def __init__(
        self,
        begin: int,
        end: int,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ):
        Watchpoint.__init__(
            self, begin, end, WatchpointAccess.READ_WRITE,
            WatchpointType.OOB, condition, hit_callback
        )


# ------------------------------------------------------------------------------
# event interface


class DbgEventBase(abc.ABC):
    def __init__(self) -> None:
        self._seq = 0  # Assume 0 is an invalid sequence number
        self._timestamp = datetime.datetime.now()
        self._arch_bits: Optional[int] = None
        default_fmt = '{:#x}'.format
        self._addr_fmt = default_fmt
        self._dbg: Optional['Debugger'] = None

    @property
    def dbg(self) -> Optional['Debugger']:
        return self._dbg

    @dbg.setter
    def dbg(self, dbg: Optional['Debugger']) -> None:
        if self._dbg is None:  # freeze debugger reference
            self._dbg = dbg
        else:
            raise RuntimeError('debugger reference is read only')

    @property
    def dev_name(self) -> Optional[str]:
        if self._dbg is not None:
            return self._dbg.dev_name

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @property
    def arch_bits(self) -> Optional[CpuBits]:
        return self._arch_bits

    @arch_bits.setter
    def arch_bits(self, arch_bits: int) -> None:
        self._arch_bits = CpuBits(arch_bits)
        self._addr_fmt = Memory.get_addr_fmt(self._arch_bits.value)

    @property
    def seq(self) -> int:
        return self._seq

    @seq.setter
    def seq(self, seq: int) -> None:
        if seq == 0:
            raise ValueError('debug event sequence number start from 1')

        if self._seq == 0:  # freeze sequence number
            self._seq = seq
        else:
            raise RuntimeError('debug event sequence number is read only')


class DbgEventStartProgram(DbgEventBase):
    def __init__(self, address: int):
        DbgEventBase.__init__(self)
        self._address = address

    def __str__(self) -> str:
        return f'start program at {self._addr_fmt(self.address)}'

    @property
    def address(self) -> int:
        return self._address


class DbgEventContinue(DbgEventBase):
    def __init__(self, address: int):
        DbgEventBase.__init__(self)
        self._address = address

    def __str__(self) -> str:
        return f'continue from {self._addr_fmt(self.address)}'

    @property
    def address(self) -> int:
        return self._address


class DbgEventStopType(enum.IntEnum):
    BREAKPOINT = (1, 'breakpoint')
    WATCHPOINT = (2, 'watchpoint')
    STEP = (3, 'step')
    MEM_FETCH_UNMAPPED = (4, 'mem_fetch_unmapped')
    MEM_READ_UNMAPPED = (5, 'mem_read_unmapped')
    MEM_WRITE_UNMAPPED = (6, 'mem_write_unmapped')

    label: str

    def __new__(cls, value: int, label: str) -> 'DbgEventStopType':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        return obj


class DbgEventStop(DbgEventBase):
    def __init__(self, reason: DbgEventStopType):
        DbgEventBase.__init__(self)
        self._reason = reason

    def __str__(self) -> str:
        return f'stop program, reason "{self.reason}"'

    @property
    def reason(self) -> DbgEventStopType:
        return self._reason


class DbgEventBreakpoint(DbgEventStop):
    def __init__(self, bp: Breakpoint):
        DbgEventStop.__init__(self, DbgEventStopType.BREAKPOINT)
        self._address = bp.address
        self._breakpoint = bp

    def __str__(self) -> str:
        return (
            f'breakpoint hit at {self._addr_fmt(self.breakpoint.address)}, hit '
            f'{self.breakpoint.hit_count}'
        )

    @property
    def address(self) -> int:
        return self._address

    @property
    def breakpoint(self) -> Breakpoint:
        return self._breakpoint


class DbgEventWatchpointAccess(enum.IntEnum):
    READ = (1, 'r', 'r-', 'read')
    WRITE = (2, 'w', '-w', 'write')

    label: str
    label_unix: str
    label_full: str

    def __new__(
        cls, value: int, label: str, label_unix: str, label_full: str
    ) -> 'DbgEventWatchpointAccess':
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.label = label
        obj.label_unix = label_unix
        obj.label_full = label_full
        return obj


class DbgEventWatchpoint(DbgEventStop):
    def __init__(
        self,
        access: DbgEventWatchpointAccess,
        from_address: int,
        to_address: int,
        size: int,
        watchpoint: Watchpoint
    ):
        DbgEventStop.__init__(self, DbgEventStopType.WATCHPOINT)
        self._from_address = from_address
        self._to_address = to_address
        self._access = access
        self._size = size
        self._watchpoint = watchpoint
        # hit count is frozen to avoid post event analysis error
        self._hit_number = self._watchpoint.hit_count

    def __str__(self) -> str:
        return (
            f'watchpoint hit, {self._access.label_unix} access from '
            f'{self._addr_fmt(self.from_address)} to '
            f'{self._addr_fmt(self._watchpoint.begin)}-'
            f'{self._addr_fmt(self._watchpoint.end)}, hit {self.hit_count}'
        )

    @property
    def watchpoint(self) -> Watchpoint:
        return self._watchpoint

    @property
    def from_address(self) -> int:
        return self._from_address

    @property
    def to_address(self) -> int:
        return self._to_address

    @property
    def access(self) -> DbgEventWatchpointAccess:
        return self._access

    @property
    def size(self) -> int:
        return self._size

    @property
    def hit_count(self) -> int:
        return self._hit_number


class DbgEventStepInst(DbgEventStop):
    def __init__(self, address: int):
        DbgEventStop.__init__(self, DbgEventStopType.STEP)
        self._address = address

    def __str__(self) -> str:
        return f'step instruction at {self._addr_fmt(self.address)}'

    @property
    def address(self) -> int:
        return self._address


class DbgEventMemFetchUnmapped(DbgEventStop):
    def __init__(self, address: int):
        DbgEventStop.__init__(self, DbgEventStopType.MEM_FETCH_UNMAPPED)
        self._address = address

    def __str__(self) -> str:
        return f'fetch unmapped memory {self._addr_fmt(self.address)}'

    @property
    def address(self) -> int:
        return self._address


class DbgEventMemAccessUnmapped(DbgEventStop):
    def __init__(
        self,
        reason: DbgEventStopType,
        from_address: int,
        to_address: int
    ):
        DbgEventStop.__init__(self, reason)
        self._from_address = from_address
        self._to_address = to_address

    def __str__(self) -> str:
        return (
            f'{self.reason.label.replace("_", " ")} '
            f'from {self._addr_fmt(self.from_address)}'
            f' to {self._addr_fmt(self.to_address)}'
        )

    @property
    def from_address(self) -> int:
        return self._from_address

    @property
    def to_address(self) -> int:
        return self._to_address


class DbgEventMemWriteUnmapped(DbgEventMemAccessUnmapped):
    def __init__(self, from_address: int, to_address: int):
        DbgEventMemAccessUnmapped.__init__(
            self, DbgEventStopType.MEM_WRITE_UNMAPPED, from_address, to_address
        )


class DbgEventMemReadUnmapped(DbgEventMemAccessUnmapped):
    def __init__(self, from_address: int, to_address: int):
        DbgEventMemAccessUnmapped.__init__(
            self, DbgEventStopType.MEM_READ_UNMAPPED, from_address, to_address
        )


class DbgEventMemWrite(DbgEventBase):
    def __init__(self, address: int, length: int):
        DbgEventBase.__init__(self)
        self._address = address
        self._length = length

    @property
    def address(self) -> int:
        return self._address

    @property
    def length(self) -> int:
        return self._length


class DbgEventBreakpointCreated(DbgEventBase):
    def __init__(self, bp: Union[Breakpoint, Watchpoint]):
        DbgEventBase.__init__(self)
        self._breakpoint = bp

    def __str__(self) -> str:
        renderer = ''

        if isinstance(self._breakpoint, Breakpoint):
            renderer = (
                f'breakpoint created at {self._addr_fmt(self.breakpoint.address)}'
            )
        elif isinstance(self._breakpoint, Watchpoint):
            renderer = (
                f'watchpoint created with access '
                f'{self._breakpoint.access.label_unix} on memory range '
                f'{self._addr_fmt(self.breakpoint.begin)}-'
                f'{self._addr_fmt(self.breakpoint.end)}'
            )

        return renderer

    @property
    def breakpoint(self) -> Union[Breakpoint, Watchpoint]:
        return self._breakpoint


class DbgEventBreakpointDeleted(DbgEventBase):
    def __init__(self, bp: Union[Breakpoint, Watchpoint]):
        DbgEventBase.__init__(self)
        self._breakpoint = bp

    def __str__(self) -> str:
        renderer = ''

        if isinstance(self._breakpoint, Breakpoint):
            renderer = (
                f'breakpoint deleted at '
                f'{self._addr_fmt(self.breakpoint.address)}'
            )
        elif isinstance(self._breakpoint, Watchpoint):
            renderer = (
                f'watchpoint deleted with access '
                f'{self.breakpoint.access.label_unix} on memory range '
                f'{self._addr_fmt(self.breakpoint.begin)}-'
                f'{self._addr_fmt(self.breakpoint.end)}'
            )
        return renderer

    @property
    def breakpoint(self) -> Union[Breakpoint, Watchpoint]:
        return self._breakpoint


class DbgEventBreakpointChanged(DbgEventBase):
    def __init__(self, bp: Union[Breakpoint, Watchpoint]):
        DbgEventBase.__init__(self)
        self._breakpoint = bp

    def __str__(self) -> str:
        renderer = ''

        if isinstance(self._breakpoint, Breakpoint):
            renderer = (
                f'breakpoint changed at '
                f'{self._addr_fmt(self.breakpoint.address)}'
            )
        elif isinstance(self._breakpoint, Watchpoint):
            renderer = (
                f'watchpoint changed with access '
                f'{self.breakpoint.access.label_unix} on memory range '
                f'{self._addr_fmt(self.breakpoint.begin)}-'
                f'{self._addr_fmt(self.breakpoint.end)}'
            )
        return renderer

    @property
    def breakpoint(self) -> Union[Breakpoint, Watchpoint]:
        return self._breakpoint


class DbgEventRegisterWrite(DbgEventBase):
    def __init__(self, register: str, value: int):
        DbgEventBase.__init__(self)
        self._register = register
        self._value = value

    @property
    def register(self) -> str:
        return self._register

    @property
    def value(self) -> int:
        return self._value
