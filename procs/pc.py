r"""
Intel 80x86 (32-bit) processors (pc)

This module contains the register state and operand encoders/decoders
for the 32-bit instruction set (80x86) belonging to Intel's architecture.
The module name directly corresponds to the processor module that is
distributed with the IDA Pro disassembler.
"""

import idaapi, database, internal, __catalog__ as catalog
from internal import interface, types

import functools, operator, itertools, architecture

class Intel(internal.architecture.architecture_t):
    """
    An implementation of all the registers available on the Intel architecture.

    This keeps track of the relationships between registers to allow one to
    promote or demote a register to the different sizes that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is Intel.
    """
    prefix = '%'
    def __init__(self):
        super(Intel, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        # miscellaneous tools for helping out with the register definitions.
        i2s = "{:d}".format
        Fidaname = lambda idaname, available={name for name in idaapi.ph_get_regnames()}: {'idaname': idaname} if idaname in available else {}

        [ setitem('r'+_, self.new('r'+_, 64, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_, self.new('r'+_, 64)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('e'+_, self.child(self.by_name('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_+'d', self.child(self.by_name('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('r'+_+'w', self.child(self.by_name('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('r'+_+'b', self.child(self.by_name('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem(    _, self.child(self.by_name('e'+_), _, 0, 16)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem(_+'h', self.child(self.by_name(_+'x'), _+'h', 8, 8, idaname=_+'h')) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_+'x'), _+'l', 0, 8, idaname=_+'l')) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_), _+'l', 0, 8, idaname=_+'l')) for _ in ('sp', 'bp', 'si', 'di') ]
        [ setitem(    _, self.new(_, 16)) for _ in ('es', 'cs', 'ss', 'ds', 'fs', 'gs') ]

        # FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit
        for _ in ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip']:
            r32, r64 = getitem('e'+_), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }
        for _ in map(i2s, range(8, 16)):
            r32, r64 = getitem('r'+_+'d'), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }

        # explicitly set the lookups for (word-register, idaapi.dt_byte) which exist due to ida's love for the inconsistent
        [ self.__cache__.setdefault((_+'x', self.by_name(_+'l').dtype), self.by_name(_+'l').__name__) for _ in ('a', 'c', 'd', 'b') ]

        setitem('fpstack', self.new('fpstack', 80*8, dtype=None))
        # umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
        [ setitem("st{:d}".format(_), self.child(self.by_name('fpstack'), "st{:d}".format(_), _*80, 80, dtype=idaapi.dt_packreal, ptype=types.float)) for _ in range(8) ]
        # double precision
        [ setitem("st{:d}d".format(_), self.child(self.by_name("st{:d}".format(_)), "st{:d}d".format(_), 0, 64, dtype=idaapi.dt_double, ptype=types.float)) for _ in range(8) ]
        # single precision
        [ setitem("st{:d}f".format(_), self.child(self.by_name("st{:d}d".format(_)), "st{:d}f".format(_), 0, 32, dtype=idaapi.dt_float, ptype=types.float)) for _ in range(8) ]
        # half precision
        [ setitem("st{:d}h".format(_), self.child(self.by_name("st{:d}f".format(_)), "st{:d}h".format(_), 0, 16, dtype=getattr(idaapi, 'dt_half', idaapi.dt_word), ptype=types.float)) for _ in range(8) ]

        # not sure if the mmx registers trash the other 16 bits of an fp register
        [ setitem("mm{:d}u".format(_), self.child(self.by_name('fpstack'), "mm{:d}u".format(_), _*80, 80, dtype=idaapi.dt_tbyte)) for _ in range(8) ]
        [ setitem("mm{:d}".format(_), self.child(self.by_name("mm{:d}u".format(_)), "mm{:d}".format(_), 0, 64, "mm{:d}".format(_), dtype=idaapi.dt_qword)) for _ in range(8) ]

        # sse1/sse2 simd registers
        [ setitem("zmm{:d}".format(_), self.new("zmm{:d}".format(_), 512, dtype=idaapi.dt_byte64, ptype=types.float)) for _ in range(32) ]
        [ setitem("ymm{:d}".format(_), self.child(self.by_name("zmm{:d}".format(_)), "ymm{:d}".format(_), 0, 256, dtype=idaapi.dt_byte32, ptype=types.float)) for _ in range(32) ]
        [ setitem("xmm{:d}".format(_), self.child(self.by_name("ymm{:d}".format(_)), "xmm{:d}".format(_), 0, 128, dtype=idaapi.dt_byte16, ptype=types.float)) for _ in range(32) ]

        # control registers (32-bit and 64-bit)
        [ setitem("cr{:d}".format(_), self.new("cr{:d}".format(_), database.config.bits())) for _ in range(0, 8) ]
        [ setitem("cr{:d}".format(_), self.new("cr{:d}".format(_), database.config.bits())) for _ in range(8, 16) ]

        # kr registers
        [ setitem("k{:d}".format(_), self.new("k{:d}".format(_), database.config.bits())) for _ in range(8) ]

        # 64-bit flags
        setitem('rflags', self.new('rflags', 64))
        setitem('eflags', self.child(self.by_name('rflags'), 'eflags', 0, 32, idaname='efl'))

        # NOTE: we don't include the 16-bit "flags" register, because hex-rays
        #       actually lays these out directly under the "eflags" register.

        # 16-bit flags
        setitem('cf', self.child(self.by_name('eflags'), 'cf',  0, 1, idaname='cf'))
        setitem('pf', self.child(self.by_name('eflags'), 'pf',  2, 1, idaname='pf'))
        setitem('af', self.child(self.by_name('eflags'), 'af',  4, 1, idaname='af'))
        setitem('zf', self.child(self.by_name('eflags'), 'zf',  6, 1, idaname='zf'))
        setitem('sf', self.child(self.by_name('eflags'), 'sf',  7, 1, idaname='sf'))
        setitem('tf', self.child(self.by_name('eflags'), 'tf',  8, 1, idaname='tf'))
        setitem('if', self.child(self.by_name('eflags'), 'if',  9, 1, idaname='if'))
        setitem('df', self.child(self.by_name('eflags'), 'df', 10, 1, idaname='df'))
        setitem('of', self.child(self.by_name('eflags'), 'of', 11, 1, idaname='of'))
        setitem('iopl', self.child(self.by_name('eflags'), 'iopl', 12, 2))
        setitem('nt', self.child(self.by_name('eflags'), 'nt', 14, 1))
        setitem('md', self.child(self.by_name('eflags'), 'md', 15, 1))

        # 32-bit flags
        setitem('rf', self.child(self.by_name('eflags'), 'rf', 16, 1))
        setitem('vm', self.child(self.by_name('eflags'), 'vm', 17, 1))
        setitem('ac', self.child(self.by_name('eflags'), 'ac', 18, 1))
        setitem('vif', self.child(self.by_name('eflags'), 'vif', 19, 1))
        setitem('vip', self.child(self.by_name('eflags'), 'vip', 20, 1))
        setitem('id', self.child(self.by_name('eflags'), 'id', 21, 1))

        # fpstat (fpsr)
        setitem('fpsw', self.new('fpsw', 16, idaname='fpstat'))
        setitem('fpsw_ie',  self.child(self.by_name('fpsw'), 'fpsw.ie',  0,  1))    # invalid exception
        setitem('fpsw_de',  self.child(self.by_name('fpsw'), 'fpsw.de',  1,  1))    # denormalized exception
        setitem('fpsw_ze',  self.child(self.by_name('fpsw'), 'fpsw.ze',  2,  1))    # zero-divide exception
        setitem('fpsw_oe',  self.child(self.by_name('fpsw'), 'fpsw.oe',  3,  1))    # overflow exception
        setitem('fpsw_ue',  self.child(self.by_name('fpsw'), 'fpsw.ue',  4,  1))    # underflow exception
        setitem('fpsw_pe',  self.child(self.by_name('fpsw'), 'fpsw.pe',  5,  1))    # precision exception
        setitem('fpsw_sf',  self.child(self.by_name('fpsw'), 'fpsw.sf',  6,  1))    # stack fault
        setitem('fpsw_es',  self.child(self.by_name('fpsw'), 'fpsw.es',  7,  1))    # error status
        setitem('fpsw_c0',  self.child(self.by_name('fpsw'), 'fpsw.c0',  8,  1))    # cc 0
        setitem('fpsw_c1',  self.child(self.by_name('fpsw'), 'fpsw.c1',  9,  1))    # cc 1
        setitem('fpsw_c2',  self.child(self.by_name('fpsw'), 'fpsw.c2',  10, 1))    # cc 2
        setitem('fpsw_top', self.child(self.by_name('fpsw'), 'fpsw.top', 11, 3))    # top of register stack
        setitem('fpsw_c3',  self.child(self.by_name('fpsw'), 'fpsw.c3',  14, 1))    # cc 3
        setitem('fpsw_b',   self.child(self.by_name('fpsw'), 'fpsw.b',   15, 1))    # busy

        # fpstat aliases (because of hexrays)
        setitem('c0', self.by_name('fpsw.c0'))
        setitem('c1', self.by_name('fpsw.c1'))
        setitem('c2', self.by_name('fpsw.c2'))
        setitem('c3', self.by_name('fpsw.c3'))

        # fpctrl (fpcr)
        setitem('fpcr', self.new('fpcr', 16, idaname='fpctrl'))
        setitem('fpcr_im',  self.child(self.by_name('fpcr'), 'fpcr.im',  0,  1))    # invalid mask
        setitem('fpcr_dm',  self.child(self.by_name('fpcr'), 'fpcr.dm',  1,  1))    # denormal mask
        setitem('fpcr_zm',  self.child(self.by_name('fpcr'), 'fpcr.zm',  2,  1))    # zero-divide mask
        setitem('fpcr_om',  self.child(self.by_name('fpcr'), 'fpcr.om',  3,  1))    # overflow mask
        setitem('fpcr_um',  self.child(self.by_name('fpcr'), 'fpcr.um',  4,  1))    # underflow mask
        setitem('fpcr_pm',  self.child(self.by_name('fpcr'), 'fpcr.pm',  5,  1))    # precision mask
        setitem('fpcr_ext', self.child(self.by_name('fpcr'), 'fpcr.ext', 6,  2))
        setitem('fpcr_pc',  self.child(self.by_name('fpcr'), 'fpcr.pc',  8,  2))    # precision control
        setitem('fpcr_rc',  self.child(self.by_name('fpcr'), 'fpcr.rc',  10, 2))    # rounding control
        setitem('fpcr_ic',  self.child(self.by_name('fpcr'), 'fpcr.ic',  12, 1))    # infinity control

        # fptags (fptw)
        setitem('fptw', self.new('fptw', 16, idaname='fptags'))
        [ setitem("fptw_t{:d}".format(_), self.child(self.by_name('fptw'), "fptw.t{:d}".format(_), 2*_, 2)) for _ in range(8) ]

        #mxcsr
        setitem('mxcsr', self.new('mxcsr', 32, idaname='mxcsr'))
        setitem('mxcsr_ie',  self.child(self.by_name('fpcr'), 'mxcsr.ie',  0,  1))  # invalid exception
        setitem('mxcsr_de',  self.child(self.by_name('fpcr'), 'mxcsr.de',  1,  1))  # denormalized exception
        setitem('mxcsr_ze',  self.child(self.by_name('fpcr'), 'mxcsr.ze',  2,  1))  # zero-divide exception
        setitem('mxcsr_oe',  self.child(self.by_name('fpcr'), 'mxcsr.oe',  3,  1))  # overflow exception
        setitem('mxcsr_ue',  self.child(self.by_name('fpcr'), 'mxcsr.ue',  4,  1))  # underflow exception
        setitem('mxcsr_pe',  self.child(self.by_name('fpcr'), 'mxcsr.pe',  5,  1))  # precision exception
        setitem('mxcsr_daz', self.child(self.by_name('fpcr'), 'mxcsr.daz', 6,  1))  # denormals are zeros
        setitem('mxcsr_im',  self.child(self.by_name('fpcr'), 'mxcsr.im',  7,  1))  # invalid mask
        setitem('mxcsr_dm',  self.child(self.by_name('fpcr'), 'mxcsr.dm',  8,  1))  # denormal mask
        setitem('mxcsr_zm',  self.child(self.by_name('fpcr'), 'mxcsr.zm',  9,  1))  # zero-divide mask
        setitem('mxcsr_om',  self.child(self.by_name('fpcr'), 'mxcsr.om', 10,  1))  # overflow mask
        setitem('mxcsr_um',  self.child(self.by_name('fpcr'), 'mxcsr.um', 11,  1))  # underflow mask
        setitem('mxcsr_pm',  self.child(self.by_name('fpcr'), 'mxcsr.pm', 12,  1))  # precision mask
        setitem('mxcsr_rc',  self.child(self.by_name('fpcr'), 'mxcsr.rc', 13,  2))  # rounding control
        setitem('mxcsr_fz',  self.child(self.by_name('fpcr'), 'mxcsr.fz', 15,  1))  # flush-zero

        [ setitem("bnd{:d}".format(_), self.new("bnd{:d}".format(_), 128)) for _ in range(4) ]

    def by_float(self, index):
        '''Return the desired floating-point stack register by the specified `index`.'''
        return self.by_name("st{:d}".format(index))

    def by_control(self, index):
        '''Return the desired control register by the specified `index`.'''
        return self.by_name("cr{:d}".format(index))

    def by_mmx(self, index):
        '''Return the desired MultiMedia eXtension register of the specified `index`.'''
        return self.by_name("mm{:d}".format(index))

    def by_xmm(self, index):
        '''Return the desired SSE vector register of the specified `index`.'''
        return self.by_name("xmm{:d}".format(index))

    def by_ymm(self, index):
        '''Return the desired 256-bit Advanced Vector Extensions register of the specified `index`.'''
        return self.by_name("ymm{:d}".format(index))

    def by_zmm(self, index):
        '''Return the desired 512-bit Advanced Vector Extensions register of the specified `index`.'''
        return self.by_name("zmm{:d}".format(index))

## intel operand type registration
class operand:
    """
    This internal namespace is responsible for registering the operand
    type handlers for the Intel architecture.
    """
    @catalog.operand(idaapi.PLFM_386, idaapi.o_void)
    def void(insn, op):
        '''Operand type decoder for ``idaapi.o_void``.'''
        return ()

    @catalog.operand(idaapi.PLFM_386, idaapi.o_reg, int)
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

    @catalog.operand(idaapi.PLFM_386, idaapi.o_imm, int)
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

    @catalog.operand(idaapi.PLFM_386, idaapi.o_far, types.type)
    @catalog.operand(idaapi.PLFM_386, idaapi.o_near, types.type)
    def address(insn, op):
        '''Operand type decoder for address operands which return just an immediate address.'''
        SEGREG_IMM = 0xffff
        segrg, segsel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
        sel = segsel if segrg == SEGREG_IMM else architecture.by_index(segrg)
        return SegmentOffset(sel, op.addr)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec0, int)
    def trregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec0`` which returns a trap register on the Intel architecture.'''
        raise E.UnsupportedCapability(u"{:s}.trregister({:#x}, ...) : Trap registers (`%trX`) are not implemented for the Intel platform.".format('.'.join([__name__, 'operand_types']), insn.ea))

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec1, int)
    def dbregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec1`` which returns a Db register on the Intel architecture.'''
        raise E.UnsupportedCapability(u"{:s}.dbregister({:#x}, ...) : Db registers (`%dbX`) are not implemented for the Intel platform.".format('.'.join([__name__, 'operand_types']), insn.ea))

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec2, int)
    def crregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec2`` which returns a control register on the Intel architecture.'''
        regnum = op.reg
        return architecture.by_control(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec3, types.float)
    def fpregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec3`` which returns an FPU register on the Intel architecture.'''
        regnum = op.reg
        return architecture.by_float(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec4, int)
    def mmxregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec4`` which returns an MMX register on the Intel architecture.'''
        regnum = op.reg
        return architecture.by_mmx(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec5, types.float)
    def xmmregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec5`` which returns an XMM register on the Intel architecture.'''
        regnum = op.reg
        return architecture.by_xmm(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec5+1, types.float)
    def ymmregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec5+1`` which returns an YMM register on the Intel architecture.'''
        regnum = op.reg
        return architecture.by_ymm(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_idpspec5+2, types.float)
    def zmmregister(insn, op):
        '''Operand type decoder for ``idaapi.o_idpspec5+2`` which returns an ZMM register on the Intel architecture.'''
        raise E.UnsupportedCapability(u"{:s}.zmmregister({:#x}, ...) : ZMM registers (`%zmmX`) are not implemented for the Intel platform.".format('.'.join([__name__, 'operand_types']), insn.ea))

        regnum = op.reg
        return architecture.by_zmm(regnum)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_mem, types.type)
    def memory(insn, op):
        '''Operand type decoder for returning a memory address including a segment on the Intel architecture.'''
        REX_B, REX_X, REX_R, REX_W, VEX_L, SEGREG_IMM = 1, 2, 4, 8, 0x80, 0xffff
        INDEX_NONE, aux_use32, aux_use64, aux_natad = 0x4, 0x8, 0x10, 0x1000

        # First we'll extract the necessary attributes from the operand and its instruction.
        hasSIB, sib, insnpref = op.specflag1, op.specflag2, insn.insnpref
        auxpref, segrg, segsel = insn.auxpref, (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
        bits = 64 if auxpref & aux_use64 else 32 if auxpref & aux_use32 else 16
        rex, = bytearray(insnpref) if isinstance(insnpref, types.bytes) else [insnpref]

        # FIXME: verify that support for 16-bit addressing actually works if we're 32-bit
        #        and the prefix has been toggled.

        # If there's no SIB, then all we need to do is to clamp our operand address
        # using the number of bits for the instruction's segment type.
        if not hasSIB:
            maximum = pow(2, bits)
            address = op.addr & (maximum - 1)

            # We've figured out all that we've needed, so just determine whether
            # we're using a segment register or a selector and return it.
            sel = segsel if segrg == SEGREG_IMM else architecture.by_index(segrg)
            return SegmentOffset(sel, address)

        # Otherwise we have to figure out the specifics about the operand type. The
        # base register doesn't actually exist in o_mem types, so we label it as unknown.
        unknown, index = (sib & 0x07) >> 0, (sib & 0x38) >> 3

        # If the index register is INDEX_NONE, then there there's nothing here and we'll
        # eventually be returning a SegmentOffset. We still process our unknown index though
        # so that it follows rules for o_phrase.
        if index in {INDEX_NONE}:
            index = None
            unknown |= 8 if rex & REX_B else 0

        # Otherwise, we're good and all we need to do is to add the 64-bit
        # flag to the index registers if it's relevant.
        else:
            index |= 8 if rex & REX_X else 0
            unknown |= 8 if rex & REX_B else 0

        # Now we need to figure out what the displacement actually is for the operand.
        offset = op.addr
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        maximum, dtype = pow(2, bits), dtype_by_size(bits // 8)
        res = idaapi.as_signed(offset, bits)

        # We do this using the exact same methodology implemented by o_phrase and o_displ.
        regular = res if res < 0 else offset & (maximum - 1)
        inverted = offset & (maximum - 1) if res < 0 else offset - maximum

        # Figure out the selector and the offset. If our index is None, then we don't
        # need to return a phrase and can return the segment and its offset.
        sel = segsel if segrg == SEGREG_IMM else architecture.by_index(segrg)
        offset_ = res and inverted if interface.node.alt_opinverted(insn.ea, op.n) else regular
        if index is None:
            return SegmentOffset(sel, offset_)

        # Otherwise we calculate the index register and scale and return our tuple.
        index_ = architecture.by_indextype(index, dtype)
        scale_ = [1, 2, 4, 8][(sib & 0xc0) // 0x40]
        return SegmentOffsetBaseIndexScale(sel, offset_, None, index_, scale_)

    @catalog.operand(idaapi.PLFM_386, idaapi.o_displ, types.type)
    @catalog.operand(idaapi.PLFM_386, idaapi.o_phrase, types.type)
    def phrase(insn, op):
        '''Operand type decoder for returning a phrase or displacement on the Intel architecture.'''
        REX_B, REX_X, REX_R, REX_W, VEX_L, SEGREG_IMM = 1, 2, 4, 8, 0x80, 0xffff
        INDEX_NONE, aux_use32, aux_use64, aux_natad = 0x4, 0x8, 0x10, 0x1000

        # First we'll extract the necessary attributes from the operand and its instruction.
        hasSIB, sib, insnpref = op.specflag1, op.specflag2, insn.insnpref
        auxpref, segrg, segsel = insn.auxpref, (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
        bits = 64 if auxpref & aux_use64 else 32 if auxpref & aux_use32 else 16
        rex, = bytearray(insnpref) if isinstance(insnpref, types.bytes) else [insnpref]

        # Now we can figure out the operand's specifics.
        if hasSIB:
            base = (sib & 0x07) >> 0
            index = (sib & 0x38) >> 3

            # If the index register is INDEX_NONE, then there isn't an index
            # register and we need to clear it. The base register might still
            # need to be promoted however, so we check it.
            if index in {INDEX_NONE}:
                base |= 8 if rex & REX_B else 0
                index = None

            # Otherwise, we're good and all we need to do is to add the 64-bit
            # flag to the base and index registers if it's relevant.
            else:
                base |= 8 if rex & REX_B else 0
                index |= 8 if rex & REX_X else 0

                # FIXME: we need to check insn.itype to support the VSIB variant of
                #        SIB which requires we promote the index to xmm, ymm, or zmm.

        # If this is a 16-bit addressing scheme, then we need to explicitly
        # figure out what phrase type is being used.
        elif not (auxpref & (aux_use32 | aux_use64)):

            # FIXME: Test this thing out whenever a user complains about it.
            R_bx, R_bp, R_si, R_di, R_sp = (architecture.by_name(name).id for name in ['bx', 'bp', 'si', 'di', 'sp'])
            phrase_table = {
                0: (R_bx, R_si), 2: (R_bp, R_si), 1: (R_bx, R_di),
                3: (R_bp, R_di), 4: (R_si, None), 5: (R_di, None),
                7: (R_bx, None), 6: (R_bp, None),-1: (R_sp, None),
            }
            base, index = phrase_table[op.phrase]

        # If there isn't an SIB, then the base register is in op_t.phrase.
        else:
            base = op.phrase
            index = None

        # Figure out which property contains our offset depending on the type.
        if op.type in {idaapi.o_displ, idaapi.o_mem}:
            offset = op.addr
        elif op.type in {idaapi.o_phrase}:
            offset = op.value
        else:
            raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the offset for op.type ({:d}).".format('.'.join([__name__, 'operand_types']), insn.ea, op, op.type))

        # Figure out the maximum value for the offset part of the phrase from
        # the number of bits for the instruction's segment type in order to
        # clamp it. Then, we can convert the value that we get from IDAPython
        # into both its signed and unsigned form. This way we can calculate the
        # correct value for whatever variation we need to actually return.
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        maximum, dtype = pow(2, bits), dtype_by_size(bits // 8)
        res = idaapi.as_signed(offset, bits)

        # If our operand is defined as its regular form, then we either
        # clamp it or take its signed value. This is because IDA appears to
        # treat all SIB-encoded operands as a signed value. Likewise, if the
        # operand is inverted, then we essentially swap these values.
        regular = res if res < 0 else offset & (maximum - 1)
        inverted = offset & (maximum - 1) if res < 0 else offset - maximum

        # Finally we can calculate all of the components for the operand, and
        # then return them to the user.
        sel = segsel if segrg == SEGREG_IMM else architecture.by_index(segrg)
        offset_ = res and inverted if interface.node.alt_opinverted(insn.ea, op.n) else regular
        base_ = None if base is None else architecture.by_indextype(base, dtype)
        index_ = None if index is None else architecture.by_indextype(index, dtype)
        scale_ = [1, 2, 4, 8][(sib & 0xc0) // 0x40]
        return SegmentOffsetBaseIndexScale(sel, offset_, base_, index_, scale_)

## intel operands

"""
This internal namespace contains the different operand types that
can be returned for the Intel architecture.
"""

class SegmentOffset(interface.phrase_t):
    """
    A tuple representing an address with a segment register attached on the Intel architecture.

    Has the format `(segment, offset)` where `segment` is a segment register.
    """
    _fields = ('segment', 'offset')
    _types = (
        (types.none, interface.register_t, types.integer),
        types.integer,
    )

    @property
    def symbols(self):
        '''Yield the `segment` register from the tuple if it is defined.'''
        segment, _ = self
        if segment:
            yield segment
        return

    def __int__(self):
        _, offset = self
        return offset

    def __same__(self, other):
        segment, _ = self
        osegment, _ = other
        return any([segment is None, osegment is None, segment == osegment])

class SegmentOffsetBaseIndexScale(interface.integerish, interface.symbol_t):
    """
    A tuple representing a memory phrase operand on the Intel architecture.

    Has the format `(segment, offset, base, index, scale)` where `segment`
    includes the segment register and both the `base` and `index` registers
    are both optional.
    """
    _fields = ('segment', 'offset', 'base', 'index', 'scale')
    _types = (
        (types.none, interface.register_t, types.integer),
        types.integer,
        (types.none, interface.register_t),
        (types.none, interface.register_t),
        types.integer,
    )
    _operands = (internal.utils.fconstant, internal.utils.fcurry, internal.utils.fconstant, internal.utils.fconstant, internal.utils.fconstant)
    _formats = "{!s}".format, "{:#x}".format, "{!s}".format, "{!s}".format, "{!s}".format

    @property
    def symbols(self):
        '''Yield the `segment`, `base`, and the `index` registers from the tuple if they are defined.'''
        segment, _, base, index, _ = self
        if segment:
            yield segment
        if base:
            yield base
        if index:
            yield index
        return

    def __int__(self):
        _, offset, _, _, _ = self
        return offset

    def __same__(self, other):
        segment, _, base, index, scale = self
        osegment, _, obase, oindex, oscale = other
        return all(any([this == that, this is None, that is None]) for this, that in [(segment, osegment), (base, obase), (index, oindex)])

    def __repr__(self):
        cls, fields = self.__class__, {'offset'}
        res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

class OffsetBaseIndexScale(interface.integerish, interface.symbol_t):
    """
    A tuple representing a memory phrase for the Intel architecture.

    Has the format `(offset, base, index, scale)` where both
    `base` and `index` are both optional registers.
    """
    _fields = ('offset', 'base', 'index', 'scale')
    _types = (
        types.integer,
        (types.none, interface.register_t),
        (types.none, interface.register_t),
        types.integer,
    )
    _formats = "{:#x}".format, "{!s}".format, "{!s}".format, "{!s}".format

    @property
    def symbols(self):
        '''Yield the `base`, and the `index` registers from the tuple if they are defined.'''
        _, base, index, _ = self
        if base:
            yield base
        if index:
            yield index
        return

    def __int__(self):
        offset, _, _, _ = self
        return offset

    def __same__(self, other):
        _, base, index, scale = self
        _, obase, oindex, oscale = other
        return all(any([this == that, this is None, that is None]) for this, that in [(base, obase), (index, oindex), (scale, oscale)])

@catalog.processor(idaapi.PLFM_386)
def __newprc__(plfm):
    '''Intel architecture 32-bit (flat)'''
    if plfm == idaapi.PLFM_386 and interface.database.bits() == 32: # id == 15
        return Intel()
    return

@catalog.processor(idaapi.PLFM_386)
def __newprc__(plfm):
    '''Intel architecture 16-bit/32-bit'''
    if plfm == idaapi.PLFM_386 and interface.database.bits() == 16: # id == 15
        return Intel()
    return
