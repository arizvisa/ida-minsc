r"""
MIPS series (32-bit) processors (mips)

This module contains the register state and operand encoders/decoders
for the 32-bit instructions belonging to the MIPS-architecture (MIPS32).
"""

import idaapi, database, internal, __catalog__ as catalog
from internal import interface, types

import functools, operator, itertools, architecture

class MIPS(interface.architecture_t):
    """
    An implementation of all the registers available on the MIPS architectures.

    This includes the different coprocessor registers that are also available
    but are treated as special instructions by IDA.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is MIPS.
    """
    prefix = '$'
    def __init__(self, BITS):
        super(MIPS, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        setitem('zero', self.new('zero', BITS, idaname='$zero'))
        setitem('at', self.new('at', BITS, idaname='$at'))

        setitem('gp', self.new('gp', BITS, idaname='$gp'))
        setitem('sp', self.new('sp', BITS, idaname='$sp'))
        setitem('fp', self.new('fp', BITS, idaname='$fp'))
        setitem('ra', self.new('ra', BITS, idaname='$ra'))
        setitem('pc', self.new('pc', BITS))

        [ setitem("v{:d}".format(_), self.new("v{:d}".format(_), BITS, idaname="$v{:d}".format(_))) for _ in range(2) ]
        [ setitem("a{:d}".format(_), self.new("a{:d}".format(_), BITS, idaname="$a{:d}".format(_))) for _ in range(8) ]
        [ setitem("t{:d}".format(_), self.new("t{:d}".format(_), BITS, idaname="$t{:d}".format(_))) for _ in range(0, 10) ]
        [ setitem("s{:d}".format(_), self.new("s{:d}".format(_), BITS, idaname="$s{:d}".format(_))) for _ in range(8) ]
        [ setitem("k{:d}".format(_), self.new("k{:d}".format(_), BITS, idaname="$k{:d}".format(_))) for _ in range(2) ]

        # FIXME: add the register definitions for : cs, ds, mips16

        # floating-point registers
        if BITS > 32:
            [ setitem("f{:d}".format(_), self.new("f{:d}".format(_), BITS, idaname="$f{:d}".format(_), dtype=idaapi.dt_double, ptype=types.float)) for _ in range(32) ]
        else:
            [ setitem("f{:d}".format(_), self.new("f{:d}".format(_), BITS, idaname="$f{:d}".format(_), dtype=idaapi.dt_float, ptype=types.float)) for _ in range(32) ]

        # FIXME: we should probably include all of the selector versions for the
        #        coprocessor registers too...
        i2s = "{:d}".format

        # coprocessor registers (0 - 31)
        setitem('Index', self.new('Index', BITS, id=0))         # 0
        setitem('Random', self.new('Random', BITS, id=0))       # 1
        setitem('EntryLo0', self.new('EntryLo0', BITS, id=0))   # 2
        setitem('EntryLo1', self.new('EntryLo1', BITS, id=0))   # 3
        setitem('Context', self.new('Context', BITS, id=0))     # 4
        setitem('PageMask', self.new('PageMask', BITS, id=0))   # 5
        setitem('Wired', self.new('Wired', BITS, id=0))         # 6
        setitem('HWREna', self.new('HWREna', BITS, id=0))       # 7
        setitem('BadVAddr', self.new('BadVAddr', BITS, id=0))   # 8
        setitem('Count', self.new('Count', BITS, id=0))         # 9
        setitem('EntryHi', self.new('EntryHi', BITS, id=0))     # 10
        setitem('Compare', self.new('Compare', BITS, id=0))     # 11
        setitem('SR', self.new('SR', BITS, id=0))               # 12.0
        setitem('IntCtl', self.new('IntCtl', BITS, id=0))       # 12.1
        setitem('SRSCtl', self.new('STSCtl', BITS, id=0))       # 12.2
        setitem('SRSMap', self.new('STSMap', BITS, id=0))       # 12.3
        setitem('Cause', self.new('Cause', BITS, id=0))         # 13
        setitem('EPC', self.new('EPC', BITS, id=0))             # 14
        setitem('PRId', self.new('PRId', BITS, id=0))           # 15.0
        setitem('EBase', self.new('EBase', BITS, id=0))         # 15.1
        setitem('Config', self.new('Config', BITS, id=0))       # 16.0
        setitem('Config1', self.new('Config1', BITS, id=0))     # 16.1
        setitem('Config2', self.new('Config2', BITS, id=0))     # 16.2
        setitem('Config3', self.new('Config3', BITS, id=0))     # 16.3
        setitem('LLAddr', self.new('LLAddr', BITS, id=0))       # 17
        setitem('WatchLo', self.new('WatchLo', BITS, id=0))     # 18
        setitem('WatchHi', self.new('WatchHi', BITS, id=0))     # 19
        setitem('XContext', self.new('XContext', BITS, id=0))   # 20
        setitem(i2s(21), self.new(i2s(21), BITS, id=0))         # 21
        setitem(i2s(22), self.new(i2s(22), BITS, id=0))         # 22
        setitem('Debug', self.new('Debug', BITS, id=0))         # 23
        setitem('DEPC', self.new('DEPC', BITS, id=0))           # 24
        setitem('PerfCtl', self.new('PerfCtl', BITS, id=0))     # 25.0
        setitem('PerfCnt', self.new('PerfCnt', BITS, id=0))     # 25.1
        setitem('ECC', self.new('ECC', BITS, id=0))             # 26
        setitem('CacheErr', self.new('CacheErr', BITS, id=0))   # 27
        setitem('TagLo', self.new('TagLo', BITS, id=0))         # 28.0
        setitem('DataLo', self.new('DataLo', BITS, id=0))       # 28.1
        setitem('TagHi', self.new('TagHi', BITS, id=0))         # 29.0
        setitem('DataHi', self.new('DataHi', BITS, id=0))       # 29.1
        setitem('ErrorEPC', self.new('ErrorEPC', BITS, id=0))   # 30
        setitem('DESAVE', self.new('DESAVE', BITS, id=0))       # 31

    def by_coprocessor(self, index, selector=0):
        '''Return the coprocessor register by the selected `index` and `selector`.'''
        file = self.register

        # FIXME: Should include _all_ of the coprocessor registers with their
        #        selector versions too..
        registers = {
            0x00 : file.Index,      0x01 : file.Random,     0x02 : file.EntryLo0,   0x03 : file.EntryLo1,
            0x04 : file.Context,    0x05 : file.PageMask,   0x06 : file.Wired,      0x07 : file.HWREna,
            0x08 : file.BadVAddr,   0x09 : file.Count,      0x0a : file.EntryHi,    0x0b : file.Compare,
            0x0c : file.SR,         0x0d : file.Cause,      0x0e : file.EPC,        0x0f : file.PRId,
            0x10 : file.Config,     0x11 : file.LLAddr,     0x12 : file.WatchLo,    0x13 : file.WatchHi,
            0x14 : file.XContext,

            0x17 : file.Debug,      0x18 : file.DEPC,       0x19 : file.PerfCtl,    0x1a : file.ECC,
            0x1b : file.CacheErr,   0x1c : file.TagLo,      0x1d : file.TagHi,      0x1e : file.ErrorEPC,
            0x1f : file.DESAVE,
        }

        if index in registers:
            return registers[index]
        return self.by_name("{:d}".format(index))

    def by_float(self, index):
        '''Return the floating-point register by the selected `index`.'''
        return self.by_name("$f{:d}".format(index))

## mips operand type registration
class operand:
    """
    This internal namespace is responsible for registering the operand
    type handlers for each architecture inside ``__optype__`` and is
    deleted after they are registered.
    """
    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_void)
    def void(insn, op):
        '''Operand type decoder for ``idaapi.o_void``.'''
        return ()

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_reg, int)
    def register(insn, op):
        '''Operand type decoder for ``idaapi.o_reg`` which returns a ``register_t``.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # On PLFM_ARM, op.specflag1 specifies the SIMD vector element size (0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits, 5=128 bits)
        # On PLFM_ARM, op.specflag3 specifies the SIMD scalar index + 1 (Vn.H[i])
        # On PLFM_ARM, if the APSR register is specified, then op.specflag1 contains flags (1=APSR_nzcv, 2=APSR_q, 4=APSR_g)
        # On PLFM_ARM, if the SPSR/CPSR register is specified, then op.specflag1 contains flags (1=CPSR_c, 2=CPSR_x, 4=CPSR_s, 8=CPSR_f)
        # On PLFM_ARM, if a banked register is specified, then op.specflag1 has its high bit (0x80) set

        return architecture.by_indextype(op.reg, get_dtype_attribute(op))

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_imm, int)
    def immediate(insn, op):
        '''Operand type decoder for ``idaapi.o_imm`` which returns an immediate integer.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # On PLFM_ARM, op.specflag2 specifies a shift type
        # On PLFM_ARM, op.specval specifies a shift counter

        bits = 8 * get_dtype_size(get_dtype_attribute(op))

        # Figure out the maximum operand size using the operand's type,
        # and convert the value that was returned by IDAPython into its
        # signed format so that we can figure out what to return.
        maximum, value = pow(2, bits), op.value
        res = idaapi.as_signed(value, bits)

        # Immediates appear to be handled differently from phrases, so if
        # our operand is in regular form, then we always return it unsigned
        # by masking it within the maximum operand value. If the operand is
        # inverted, then we take the signed variation if it's less than 0.
        # If it isn't, then we take the difference form the maximum in
        # order to ensure it's signed.
        regular = value & (maximum - 1)
        inverted = res if res < 0 else value - maximum
        return res and inverted if interface.node.alt_opinverted(insn.ea, op.n) else regular

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_mem, types.type)
    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_near, types.type)
    def address(insn, op):
        '''Operand type decoder for address operands which return just an immediate address.'''
        segrg, segsel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
        return op.addr

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_displ, types.type)
    def phrase(insn, op):
        '''Operand type decoder for memory phrases on MIPS architecturs.'''

        rt, imm = architecture.by_index(op.reg), op.addr
        return phrase(rt, imm)

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_idpspec0, int)
    def code(insn, op):
        '''Operand type decoder for trap codes on MIPS architectures.'''
        res = op.value
        return trap(int(res))

    @catalog.operand(idaapi.PLFM_MIPS, idaapi.o_idpspec1, types.float)
    def float(insn, op):
        '''Operand type decoder for floating-point registers on MIPS architectures.'''
        index = op.reg
        return float(index)

## mips operands

"""
This internal namespace contains the different operand types that
are used by the MIPS architectures.
"""

class phrase(interface.phrase_t):
    """
    A tuple for representing a memory phrase operand on the MIPS architectures.

    Has the format `(Rn, Offset)` where `Rn` is the register and
    `Offset` is the immediate that is added to the `Rn` register.
    """
    _fields = ('Rn', 'Offset')
    _types = (interface.register_t, types.integer)
    _operands = (internal.utils.fconstant, internal.utils.fcurry)
    _formats = "{!s}".format, "{:#x}".format

    register = property(fget=operator.itemgetter(0))
    immediate = property(fget=operator.itemgetter(1))

class trap(interface.namedtypedtuple, interface.symbol_t):
    """
    A tuple for representing a trap code that can be encoded within
    certain instructions on the MIPS architectures.

    Simply wraps the encoded integer in a single-element tuple with
    the format of `(code)`.
    """
    _fields = ('code',)
    _types = (types.integer,)

    code = property(fget=operator.itemgetter(0))

    @property
    def symbols(self):
        '''This operand type is not composed of any symbols.'''
        return
        yield   # so that this function is still treated as a generator

def coprocessor(index):
    """
    A callable that returns a coprocessor register on the MIPS architectures.

    Takes an integer argument which returns the coprocessor register for
    the requested `index`.
    """
    return architecture.by_coprocessor(index)

def float(index):
    """
    A callable that returns a floating-point register on the MIPS architectures.

    Takes an integer representing the `index` of the desired floating-point
    register to return.
    """
    return architecture.by_float(index)

## mips processor
class MIPS32(MIPS):
    """
    An implementation of all the registers available on the MIPS32 architecture.

    This includes the different coprocessor registers that are also available
    but are treated as special instructions by IDA.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is MIPS.
    """

    def __init__(self):
        return super(MIPS32, self).__init__(32)

@catalog.processor(idaapi.PLFM_MIPS)
def __newprc__(plfm):
    '''MIPS32'''

    # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
    if not hasattr(database, 'config'):
        return

    if plfm == idaapi.PLFM_MIPS and database.config.bits() < 64:    # id == 12
        return MIPS32()
    return
