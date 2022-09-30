r"""
ARM (32-bit) processors (arm)

This module contains the register state and operand encoders/decoders
for the 32-bit instructions (AArch32) of the ARM-architecture family.
"""

import idaapi, database, internal, __catalog__ as catalog
from internal import interface, types

import functools, operator, itertools, architecture

class AArch(interface.architecture_t):
    """
    An implementation of all the registers available on the AArch32 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is either
    AArch32 or AArch64.
    """
    prefix = '%'
    def __init__(self, BITS):
        super(AArch, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        [ setitem("v{:d}".format(_), self.new("v{:d}".format(_), 128, idaname="V{:d}".format(_))) for _ in range(32) ]
        [ setitem("q{:d}".format(_), self.new("q{:d}".format(_), 128, idaname="Q{:d}".format(_))) for _ in range(32) ]

        for _ in range(32):
            rv, rq = getitem("v{:d}".format(_)), getitem("q{:d}".format(_))
            rv.alias, rq.alias = { rq }, { rv }

        [ setitem("r{:d}".format(_), self.new("r{:d}".format(_), 32, idaname="R{:d}".format(_))) for _ in range(13) ]
        [ setitem("r{:d}h".format(_), self.child(getitem("r{:d}".format(_)), "r{:d}h".format(_), 0, 16, idaname="R{:d}".format(_))) for _ in range(13) ]
        [ setitem("r{:d}b".format(_), self.child(getitem("r{:d}".format(_)), "r{:d}b".format(_), 0, 8, idaname="R{:d}".format(_))) for _ in range(13) ]

        # Sub-registers that compose the V register (floating-point)
        if BITS > 32:
            [ setitem("d{:d}".format(_), self.child(getitem("v{:d}".format(_)), "d{:d}".format(_), 0, 64, idaname="V{:d}".format(_), dtype=idaapi.dt_double, ptype=types.float)) for _ in range(32) ]
        else:
            [ setitem("d{:d}".format(_), self.child(getitem("v{:d}".format(_)), "d{:d}".format(_), 0, 64, idaname="D{:d}".format(_), dtype=idaapi.dt_double, ptype=types.float)) for _ in range(32) ]
        [ setitem("s{:d}".format(_), self.child(getitem("d{:d}".format(_)), "s{:d}".format(_), 0, 32, idaname="S{:d}".format(_), dtype=idaapi.dt_float, ptype=types.float)) for _ in range(32) ]
        [ setitem("h{:d}".format(_), self.child(getitem("s{:d}".format(_)), "h{:d}".format(_), 0, 16, idaname="X{:d}".format(_), dtype=getattr(idaapi, 'dt_half', idaapi.dt_word), ptype=types.float)) for _ in range(32) ]
        [ setitem("b{:d}".format(_), self.child(getitem("h{:d}".format(_)), "b{:d}".format(_), 0, 8, idaname="X{:d}".format(_), ptype=types.float)) for _ in range(32) ]

        # General-purpose registers
        [ setitem("x{:d}".format(_), self.new("x{:d}".format(_), BITS, idaname="X{:d}".format(_))) for _ in range(31) ]
        if BITS > 32:
            [ setitem("w{:d}".format(_), self.child(self.by_name("x{:d}".format(_)), "w{:d}".format(_), 0, 32, idaname="X{:d}".format(_))) for _ in range(31) ]
        setitem('lr', self.new('lr', BITS, idaname='LR', alias={'x31'}))

        # Zero registers and special regs
        setitem('xzr', self.new('xzr', BITS, idaname='XZR'))
        if BITS > 32:
            setitem('wzr', self.child(getitem('xzr'), 'wzr', 0, 32))
        setitem('sp', self.new('sp', BITS, idaname='SP', alias={'r13'}))
        if BITS > 32:
            setitem('wsp', self.child(getitem('sp'), 'wsp', 0, 32))
        setitem('pc', self.new('pc', BITS, idaname='PC'))
        setitem('msp', self.child(getitem('sp'), 'msp', 0, BITS, idaname='MSP'))
        setitem('psp', self.child(getitem('sp'), 'psp', 0, BITS, idaname='PSP'))

        # Status registers (all)
        # XXX: These registers are busted because they're actually individual
        #      combinations of 3 registers.
        setitem('xpsr', self.new('xpsr', 96, idaname='XPSR', alias={'psr'}))
        setitem('iepsr', self.child(getitem('xpsr'), 'iepsr', 0, 96, idaname='IEPSR'))
        setitem('iapsr', self.child(getitem('xpsr'), 'iapsr', 0, 96, idaname='IAPSR'))
        setitem('eapsr', self.child(getitem('xpsr'), 'eapsr', 0, 96, idaname='EAPSR'))

        # Status registers (application)
        # XXX: We only define these registers as children of the parent
        #      registers that can be written to.
        setitem('apsr', self.child(getitem('xpsr'), 'apsr', 0, 32, idaname='APSR'))
        setitem('q', self.child(getitem('apsr'), 'q', 27, 1))
        setitem('vf', self.child(getitem('apsr'), 'vf', 28, 1, idaname='VF'))
        setitem('cf', self.child(getitem('apsr'), 'cf', 29, 1, idaname='CF'))
        setitem('zf', self.child(getitem('apsr'), 'zf', 30, 1, idaname='ZF'))
        setitem('nf', self.child(getitem('apsr'), 'nf', 31, 1, idaname='NF'))

        # Status registers (execution)
        setitem('epsr', self.child(getitem('xpsr'), 'epsr', 32, 32, idaname='EPSR'))
        setitem('ts', self.child(getitem('epsr'), 'Ts', 24, 1, idaname='T'))

        # Status registers (interrupt)
        setitem('ipsr', self.child(getitem('xpsr'), 'ipsr', 64, 32, idaname='IPSR'))

        # Status registers (current program)
        setitem('cpsr', self.new('cpsr', 32, idaname='CPSR'))
        setitem('m', self.child(getitem('cpsr'), 'm', 0, 4))
        setitem('res1', self.child(getitem('cpsr'), 'res1', 4, 1))
        setitem('res0', self.child(getitem('cpsr'), 'res0', 5, 1))
        setitem('f', self.child(getitem('cpsr'), 'f', 6, 1))
        setitem('i', self.child(getitem('cpsr'), 'i', 7, 1))
        setitem('a', self.child(getitem('cpsr'), 'a', 8, 1))
        setitem('e', self.child(getitem('cpsr'), 'e', 9, 1))
        [ setitem("it{:d}".format(2 + _), self.child(getitem('cpsr'), "it{:d}".format(2 + _), 10 + _, 1)) for _ in range(6) ]
        setitem('ge', self.child(getitem('cpsr'), 'ge', 16, 3))
        setitem('dit', self.child(getitem('cpsr'), 'dit', 21, 1))
        setitem('pan', self.child(getitem('cpsr'), 'pan', 22, 1))
        setitem('ssbs', self.child(getitem('cpsr'), 'ssbs', 23, 1))
        setitem('j', self.child(getitem('cpsr'), 'j', 24, 1))
        setitem('it0', self.child(getitem('cpsr'), 'it0', 25, 1))
        setitem('it1', self.child(getitem('cpsr'), 'it1', 26, 1))
        setitem('q', self.child(getitem('cpsr'), 'q', 27, 1))
        setitem('v', self.child(getitem('cpsr'), 'v', 28, 1))
        setitem('c', self.child(getitem('cpsr'), 'c', 29, 1))
        setitem('z', self.child(getitem('cpsr'), 'z', 30, 1))
        setitem('n', self.child(getitem('cpsr'), 'n', 31, 1))

        setitem('spsr', self.child(getitem('cpsr'), 'spsr', 0, 32, idaname='SPSR'))
        setitem('cpsr_flag', self.child(getitem('cpsr'), 'cpsr_flag', 27, 5, idaname='CPSR_flg'))
        setitem('spsr_flag', self.child(getitem('spsr'), 'spsr_flag', 27, 5, idaname='SPSR_flg'))

        # Status registers (floating point)
        setitem('fpscr', self.new('fpscr', 32, idaname='FPSCR'))
        setitem('ioc', self.child(getitem('fpscr'), 'ioc', 0, 1))
        setitem('dzc', self.child(getitem('fpscr'), 'dzc', 1, 1))
        setitem('ofc', self.child(getitem('fpscr'), 'ofc', 2, 1))
        setitem('ufc', self.child(getitem('fpscr'), 'ufc', 3, 1))
        setitem('ixc', self.child(getitem('fpscr'), 'ixc', 4, 1))
        setitem('idc', self.child(getitem('fpscr'), 'idc', 7, 1))
        setitem('ioe', self.child(getitem('fpscr'), 'ioe', 8, 1))
        setitem('dze', self.child(getitem('fpscr'), 'dze', 9, 1))
        setitem('ofe', self.child(getitem('fpscr'), 'ofe', 10, 1))
        setitem('ufe', self.child(getitem('fpscr'), 'ufe', 11, 1))
        setitem('ixe', self.child(getitem('fpscr'), 'ixe', 12, 1))
        setitem('ide', self.child(getitem('fpscr'), 'ide', 15, 1))
        setitem('len', self.child(getitem('fpscr'), 'Len', 16, 3))
        setitem('stride', self.child(getitem('fpscr'), 'Stride', 20, 2))
        setitem('rmode', self.child(getitem('fpscr'), 'Rmode', 22, 2))
        setitem('fz', self.child(getitem('fpscr'), 'fz', 24, 1))
        setitem('dn', self.child(getitem('fpscr'), 'dn', 25, 1))
        setitem('ahp', self.child(getitem('fpscr'), 'ahp', 26, 1))
        setitem('qc', self.child(getitem('fpscr'), 'qc', 27, 1))
        setitem('Fv', self.child(getitem('fpscr'), 'Fv', 28, 1))
        setitem('Fc', self.child(getitem('fpscr'), 'Fc', 29, 1))
        setitem('Fz', self.child(getitem('fpscr'), 'Fz', 30, 1))
        setitem('Fn', self.child(getitem('fpscr'), 'Fn', 31, 1))

        # Media registers
        setitem('mvfr0', self.new('mvfr0', 32, idaname='MVFR0'))
        setitem('mvrb', self.child(getitem('mvfr0'), 'MVrb', 0, 4))
        setitem('mvsp', self.child(getitem('mvfr0'), 'MVsp', 4, 4))
        setitem('mvdp', self.child(getitem('mvfr0'), 'MVdp', 8, 4))
        setitem('mvte', self.child(getitem('mvfr0'), 'MVte', 12, 4))
        setitem('mvd', self.child(getitem('mvfr0'), 'MVd', 16, 4))
        setitem('mvsr', self.child(getitem('mvfr0'), 'MVsr', 20, 4))
        setitem('mvsv', self.child(getitem('mvfr0'), 'MVsv', 24, 4))
        setitem('mvrm', self.child(getitem('mvfr0'), 'MVrm', 28, 4))

        setitem('mvfr1', self.new('mvfr1', 32, idaname='MVFR1'))
        setitem('mvfz', self.child(getitem('mvfr1'), 'MVfz', 0, 4))
        setitem('mvdn', self.child(getitem('mvfr1'), 'MVdn', 0, 4))
        setitem('mnls', self.child(getitem('mvfr1'), 'MNls', 0, 4))
        setitem('mni', self.child(getitem('mvfr1'), 'MNi', 0, 4))
        setitem('mnsp', self.child(getitem('mvfr1'), 'MNsp', 0, 4))

        # Opaque registers
        setitem('fpsid', self.new('fpsid', 32, idaname='FPSID'))
        setitem('fpexc', self.new('fpexc', 32, idaname='FPEXC'))
        setitem('fpinst', self.new('fpinst', 32, idaname='FPINST'))
        setitem('fpinst2', self.new('fpinst2', 32, idaname='FPINST2'))
        setitem('primask', self.new('primask', 32, idaname='PRIMASK'))
        setitem('basepri', self.new('basepri', 32, idaname='BASEPRI'))
        setitem('faultmask', self.new('faultmask', 32, idaname='FAULTMASK'))
        setitem('control', self.new('control', 32, idaname='CONTROL'))
        setitem('basepri_max', self.new('basepri_max', 32, idaname='BASEPRI_MAX'))

        # XScale register(s?)
        setitem('acc0', self.new('acc0', 32, idaname='acc0'))

        # XXX: for some reason IDA defines the CS and DS registers??

        # Conditions (not really registers, but condition_t)
        [ setitem(_, condition_t(index)) for index, _ in enumerate(['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']) ]

    def by_condition(self, index):
        '''Return the condition type for the specified `index`.'''
        cc = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']
        return self.by_name(cc[index])

## arm operand type registration
class operand:
    """
    This internal namespace is responsible for registering the operand
    type handlers for each architecture inside ``__optype__`` and is
    deleted after they are registered.
    """

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_void)
    def void(insn, op):
        '''Operand type decoder for ``idaapi.o_void``.'''
        return ()

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_reg, int)
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

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_imm, int)
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

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_phrase, types.type)
    def phrase(insn, op):
        '''Operand type decoder for returning a memory phrase on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.specflag3 specifies the NEON alignment by power-of-two

        Rn, Rm = architecture.by_index(op.reg), architecture.by_index(op.specflag1)
        return registerphrase(Rn, Rm)

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_displ, types.type)
    def phrase(insn, op):
        '''Operand type decoder for returning a memory displacement on either the AArch32 or AArch64 architectures.'''
        Rn = architecture.by_index(op.reg)
        return immediatephrase(Rn, idaapi.as_signed(op.addr))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_mem, types.type)
    def memory(insn, op):
        '''Operand type decoder for returning a memory reference on either the AArch32 or AArch64 architectures.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size
        get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

        # get the address and the operand size
        addr, size = op.addr, get_dtype_size(get_dtype_attribute(op))
        maxval = 1 << size * 8

        # dereference the address and return its integer.
        res = get_bytes(addr, size) or b''
        res = res[::-1] if database.config.byteorder() in {'little'} else res[:]
        res = functools.reduce(lambda agg, item: (agg * 0x100) | item, bytearray(res), 0)
        sf = bool(res & maxval >> 1)

        return memory(addr, res - maxval if sf else res)

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec0, int)
    def flex(insn, op):
        '''Operand type decoder for returning a flexible operand (shift-op) on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.specflag2 = shift-type
        # op.specflag1 = shift register to use
        # op.value = shift count

        Rn = architecture.by_index(op.reg)
        shift = 0                                           # XXX: This should be implemented using the above information
        return flex(Rn, int(shift), int(op.value))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec1)
    def list(insn, op):
        '''Operand type decoder for returning a register list on either the AArch32 or AArch64 architectures.'''
        res = set()

        # FIXME: op.specflag1 specifies the PSR and force-user bit, which has the ^ suffix

        # op.specval represents a bitmask specifying which registers are included
        specval = op.specval
        for index in range(16):
            if specval & 1:
                res.add(architecture.by_index(index))
            specval >>= 1
        return list(res)

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec2)
    def coprocessorlist(insn, op):
        '''Operand type decoder for the coprocessor register list (CDP) on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.reg == CRd
        # op.specflag1 == CRn
        # op.specflag2 == CRm

        raise E.UnsupportedCapability(u"{:s}.coprocessorlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), insn.ea, op.type, op.type))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec3)
    def coprocessorlist(insn, op):
        '''Operand type decoder for the coprocessor register list (LDC/STC) on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.reg == register number
        # op.specflag1 == processor number

        raise E.UnsupportedCapability(u"{:s}.coprocessorlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), insn.ea, op.type, op.type))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec4, types.float)
    def extensionlist(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec4`` which returns a floating-point register list on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.reg == first floating-point register
        # op.value == number of floating-point registers
        # op.specflag2 == spacing between registers (0: {Dd, Dd+1,... }, 1: {Dd, Dd+2, ...} etc)
        # op.specflag3 == neon scalar index + 1 (Dd[x]). if index is 254, then this represents the entire set (Dd[...])

        raise E.UnsupportedCapability(u"{:s}.extensionlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), insn.ea, op.type, op.type))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec5, types.type)
    def text(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec5`` which returns arbitrary text on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # The entire op_t structure contains the designated text starting at op.value

        raise E.UnsupportedCapability(u"{:s}.text({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), insn.ea, op.type, op.type))

    @catalog.operand(idaapi.PLFM_ARM, idaapi.o_idpspec5 + 1)
    def condition(insn, op):
        '''Operand type decoder for dealing with an undocumented operand type found on AArch64.'''

        # FIXME: There's a couple of attributes here that seem relevant: op.value, op.reg, op.n
        # op.value == condition
        cc = op.value & 0x0f
        return architecture.by_condition(cc)

## arm operands

"""
This internal namespace contains the different operand types that
can be returned for the AArch32 and AArch64 architectures.
"""

class flex(interface.namedtypedtuple, interface.symbol_t):
    """
    A tuple representing a flexible operand type that can be decoded on either the AArch32 or AArch64 architectures.

    Has the format `(Rn, shift, n)` which allows the architecture to apply
    a binary shift or rotation to the value of a register `Rn`.
    """
    _fields = ('Rn', 'shift', 'n')
    _types = (
        interface.register_t,
        types.integer,
        types.integer
    )

    register = property(fget=operator.itemgetter(0))
    t = type = property(fget=operator.itemgetter(1))
    imm = immediate = property(fget=operator.itemgetter(2))

    @property
    def symbols(self):
        '''Yield the `Rn` register from the tuple.'''
        register, _, _ = self
        yield register

class list(interface.namedtypedtuple, interface.symbol_t):
    """
    A tuple representing a register list operand on either the AArch32 or AArch64 architectures.

    Has the simple format `(reglist)` where `reglist` is a set of registers
    that can be explicitly tested as a set for membership.
    """
    _fields = ('reglist', )
    _types = (types.set, )

    @property
    def symbols(self):
        '''Yield any of the registers within the `reglist` field belonging to the tuple.'''
        list, = self
        for register in list:
            yield register
        return

class immediatephrase(interface.phrase_t):
    """
    A tuple representing a memory displacement operand on either the AArch32 or AArch64 architectures.

    Has the format `(Rn, Offset)` where `Rn` is a register and `Offset` is
    the integer that is added to the register.
    """
    _fields = ('Rn', 'offset')

    register = property(fget=operator.itemgetter(0))
    offset = property(fget=operator.itemgetter(1))

class registerphrase(interface.namedtypedtuple, interface.symbol_t):
    """
    A tuple for representing a memory phrase on either the AArch32 or AArch64 architectures.

    Has the format `(Rn, Rm)` where both values are registers that compose
    the phrase.
    """
    _fields = ('Rn', 'Rm')
    _types = (
        interface.register_t,
        interface.register_t,
    )

    first = property(fget=operator.itemgetter(0))
    second = property(fget=operator.itemgetter(1))

    @property
    def symbols(self):
        '''Yield the `Rn` and `Rm` registers from the tuple.'''
        register_n, register_m = self
        yield register_n
        yield register_m

class memory(interface.integerish, interface.symbol_t):
    """
    A tuple for representing a memory operand on either the AArch32 or AArch64 architectures.

    Has the format `(address, value)` where `address` is the actual value
    stored in the operand and `value` is the value that would be dereferenced.
    """
    _fields = ('address', 'value')
    _types = (types.integer, types.integer)
    _operands = internal.utils.fcurry, internal.utils.fconstant
    _formats = "{:#x}".format, "{:#x}".format

    @property
    def symbols(self):
        '''This operand type is not composed of any symbols.'''
        return
        yield   # so that this function is still treated as a generator

    # we need to write some really stupid code here...like seriously dumb.
    # since we're not storing any operand information other than the address
    # and its dereferenced value, we have no idea of the length of the
    # deref'd operand or if it's signed...so, we actually have to guess it.

    @classmethod
    def __consume_integer(cls, ea):
        get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

        # depending on the byteorder, we shift either the aggregate or the multiplier.
        shifts = [1, 0x100] if database.config.byteorder() in {'little'} else [0x100, 1]
        Fs = [functools.partial(operator.mul, item) for item in shifts]

        # we need extra vars here, because of for-loops and not having pre or post.
        result, shift, position = 0, 1, 0
        for size in map(functools.partial(operator.pow, 2), range(4)):
            for item in bytearray(get_bytes(ea + position, size - position) or b''):
                res = item * shift
                result, shift = (F(item) for F, item in zip(Fs, [result, shift]))
                result |= res
            yield size, result
            position = size
        return

    @classmethod
    def __guess_size(cls, address, goal):
        '''Return the number of bytes to read at the specified `address` in order to return the specified value.'''
        for size, integer in cls.__consume_integer(address):
            result = {integer : +size, integer - pow(2, 8 * size) : -size}
            if goal in result:
                return result[goal]
            continue
        return 0

    def __remake(self, address):
        '''Use the guessed size of the current instance to create another one pointing to a different address.'''
        cls, get_bytes = self.__class__, idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

        # Re-read the old address and figure out what our size could be. If we
        # figure it out, then we read from the new address and reconstruct.
        size = self.__guess_size(*self)
        res, maximum = get_bytes(address, abs(size)) or b'', pow(2, 8 * size)

        # Handle the byteorder and reduce it to an integer before we signify it.
        res = res[::-1] if database.config.byteorder() in {'little'} else res[:]
        res = functools.reduce(lambda agg, item: (agg * 0x100) | item, bytearray(res), 0)

        # Now we "calculate" the sign flag if our previous value allowed us to
        # sign it, and then we can use it to reconstruct this thing.
        SF = maximum // 2 if size < 0 else 0
        return cls(address, res - maximum if res & SF else res)

    def __int__(self):
        result, _ = self
        return result

    def __operator__(self, operation, other):
        address, _ = self
        if isinstance(other, types.integer):
            return self.__remake(operation(address, other))
        elif isinstance(other, self.__class__):
            return self.__operator__(operation, int(other))
        elif hasattr(other, '__int__'):
            logging.warning(u"{:s}.__operator__({!s}, {!r}) : Coercing the instance of type `{:s}` to an integer due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, other.__class__.__name__, self.__class__.__name__))
            return self.__operator__(operation, int(other))
        raise TypeError(u"{:s}.__operator__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__, cls.__name__))

    def __operation__(self, operation):
        res = super(memory, self).__operation__(operation)
        return self.__remake(int(res))

class condition_t(interface.symbol_t):
    """
    A symbol for representing a condition operand on either the AArch32 or AArch64 architectures.
    """
    __flags__ = {
        0x0 : {'Z': 1}, 0x1 : {'Z': 0},
        0x2 : {'C': 1}, 0x3 : {'C': 0},
        0x4 : {'N': 1}, 0x5 : {'N': 0},
        0x6 : {'V': 1}, 0x7 : {'V': 0},
    }

    # FIXME: define the required flag state needed to satisfy the specified condition.
    __cflags__ = {}

    def __init__(self, index):
        cc = {
            0x0 : 'EQ', 0x1 : 'NE', 0x2 : 'CS', 0x3 : 'CC',
            0x4 : 'MI', 0x5 : 'PL', 0x6 : 'VS', 0x7 : 'VC',
            0x8 : 'HI', 0x9 : 'LS', 0xa : 'GE', 0xb : 'LT',
            0xc : 'GT', 0xd : 'LE', 0xe : 'AL', 0xf : 'NV',
        }
        self.__cond__, self.__name__ = index, cc[index]

    def __hash__(self):
        items = condition_t, self.__cond__
        return hash(items)

    @property
    def flags(self):
        '''Return the required flags for the current condition to be true.'''
        cc, flags = self.__cond__, self.__flags__
        if cc < 8:
            flag, value = next(item for item in flags[cc].items())
            return [(flag, True if value else False)]
        raise NotImplementedError("{:s}.condition_t({:#x}) : Unable to return the flags needed to satisfy condition ({:s}) due to its code ({:d} being unimplemented.".format(__name__, cc, self.name, cc))

    @property
    def symbols(self):
        '''A condition_t is actually a symbol that yields itself.'''
        yield self

    @property
    def name(self):
        return self.__name__

    def __str__(self):
        return self.__name__

    def __repr__(self):
        cls, cc = condition_t, self.__cond__
        if cc < 8:
            description = ','.join("{:s}={:d}".format(*item) for item in self.flags)
            return "<class '{:s}' name='{!s}' flags='{:s}'>".format(cls.__name__, internal.utils.string.escape(self.name, '\''), description)
        return "<class '{:s}' name='{!s}'>".format(cls.__name__, internal.utils.string.escape(self.name, '\''))

    def __eq__(self, other):
        if isinstance(other, types.string):
            return self.name.lower() == other.lower()
        elif isinstance(other, condition_t):
            return self.__cond__ == other.__cond__
        return other is self

    def __ne__(self, other):
        return not (self == other)

## arm procesor
class AArch32(AArch):
    """
    An implementation of all the registers available on the AArch32 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is AArch32.
    """

    def __init__(self):
        return super(AArch32, self).__init__(32)

@catalog.processor(idaapi.PLFM_ARM)
def __newprc__(plfm):
    '''AArch32'''

    # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
    if not hasattr(database, 'config'):
        return

    if plfm == idaapi.PLFM_ARM and database.config.bits() < 64: # id == 1
        return AArch32()
    return
