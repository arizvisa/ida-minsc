import idc,idaapi,database

## functions vs the instruction at an ea
def at(ea):
    length = idaapi.decode_insn(ea)
    return idaapi.cmd.copy()

def size(ea):
    return at(ea).size

def feature(ea):
    return at(ea).get_canon_feature()

def mnem(ea):
    '''Returns the mnemonic of an instruction'''
    return idaapi.ua_mnem(ea) or None
mnemonic = mnem

def op(ea, n=None):
    '''Returns the `n`th operand of the instruction at `ea`'''
    insn = at(ea)
    if n is None:
        return tuple(insn.Operands[n] for n in xrange(ops_count(insn.ea)))
    return insn.Operands[n]

## functions vs all operands of an insn
def ops_count(ea):
    '''Return the number of operands of given instruction'''
    insn = at(ea)
    for c,v in enumerate(insn.Operands):
        if v.type == idaapi.o_void:
            return c
        continue
    # maximum operand count. ida might be wrong here...
    return c

def ops_repr(ea):
    '''Returns the repr of each operand of an instruction'''
    insn = at(ea)
    res = (idaapi.ua_outop2(insn.ea, n) for n in range(ops_count(insn.ea)))
    return [idaapi.tag_remove(res) if res else None for res in res]

def ops_value(ea):
    return [ op_value(ea,i) for i in range(ops_count(ea)) ]

def ops_state(ea):
    '''Returns 'r','w','rw' for each operand of an instruction'''
    read = [ getattr(idaapi, 'CF_USE%d'%n) for n in range(1,7) ]
    write = [ getattr(idaapi, 'CF_CHG%d'%n) for n in range(1,7) ]
    f = feature(ea)
    res = ( ((f&read[i]),(f&write[i])) for i in range(ops_count(ea)) )
    return [ (r and 'r' or '') + (w and 'w' or '') for r,w in res ]

## functions vs a specific operand of an insn
def op_repr(ea, n):
    '''Returns the string representation of an operand'''
    return ops_repr(ea)[n]
def op_state(ea, n):
    '''Returns 'r','w','rw' of an operand'''
    return ops_state(ea)[n]
def op_size(ea, n):
    '''Returns the size of an operand'''
    insn = at(ea)
    return opt.size(insn.Operands[n])
def op_type(ea, n):
    '''Returns the type of an operand (opt_imm, opt_reg, opt_phrase, opt_addr)'''
    insn = at(ea)
    return opt.type(insn.Operands[n]).__name__
def op_native(ea, n):
    '''Returns the value for an operand as per ida's format'''
    insn = at(ea)
    return opt.native(insn.Operands[n])
def op_value(ea, n):
    '''Returns an operand's value converted to register names, immediate, or offset,(base reg,index reg,scale)'''
    insn = at(ea)
    return opt.value(insn.Operands[n])

## operand types
class opt(object):
    cache = {}

    @classmethod
    def define(cls, type):
        def decorator(fn):
            cls.cache[type] = fn
            return fn
        return decorator

    @classmethod
    def lookup(cls, type):
        return cls.cache[type]

    @classmethod
    def value(cls, op):
        res = cls.cache[op.type](op)
        if op.type in (idaapi.o_reg,):
            return reg_t.byIndex(res,op.dtyp).name
        elif op.type in (idaapi.o_phrase,idaapi.o_displ):
            dt = ord(idaapi.get_dtyp_by_size(database.config.bits()//8))
            ofs,(b,i,s) = res
            return ofs,(None if b is None else reg_t.byIndex(b,dt).name,None if i is None else reg_t.byIndex(i,dt).name,s)
        elif op.type in (idaapi.o_mem,idaapi.o_far,idaapi.o_near):
            return res
        return res

    @classmethod
    def native(cls, op):
        return cls.cache[op.type](op)

    @classmethod
    def type(cls, op):
        return cls.cache[op.type]

    @classmethod
    def repr(cls, op):
        return cls.cache[op.type].__name__

    @classmethod
    def size(cls, op):
        return idaapi.get_dtyp_size(op.dtyp)

@opt.define(idaapi.o_void)
def opt_void(op):
    return ()

@opt.define(idaapi.o_displ)
@opt.define(idaapi.o_phrase)
def opt_phrase(op):
    """Returns (offset, (basereg, indexreg, scale))"""
    if op.type == idaapi.o_displ:
        if op.specflag1 == 0:
            index = None
            base = op.reg
            offset = op.addr
        elif op.specflag1 == 1:
            index = (op.specflag2&0x07) >> 0
            base = None
            offset = op.addr
        else:
            raise TypeError, os.specflag1

        # OF_NO_BASE_DISP = 1 then .addr doesn't exist
        # OF_OUTER_DISP = 1 then .value exists
    elif op.type == idaapi.o_phrase:
        if op.specflag1 == 0:
            index = None
            base  = op.reg
        elif op.specflag1 == 1:
            index = (op.specflag2&0x38) >> 3
            base =  (op.specflag2&0x07) >> 0
        else:
            raise TypeError, os.specflag1
        offset = op.value
    else:
        raise TypeError, op.type

    # if arch == x64, then index += 8

    res = op.specflag2 & 0xc0
    if res == 0x00:     # 00
        scale = 1
    elif res == 0x40:   # 01
        scale = 2
    elif res == 0x80:   # 10
        scale = 4
    elif res == 0xc0:   # 11
        scale = 8

    signbit = 2**(database.config.bits()-1)
    maxint = 2**database.config.bits()

    return int(offset-maxint) if offset&signbit else offset,(base,index,scale)

@opt.define(idaapi.o_reg)
def opt_reg(op):
    if op.type in (idaapi.o_reg,):
        return op.reg
    #o_trreg  =       idaapi.o_idpspec0      # trace register
    #o_dbreg  =       idaapi.o_idpspec1      # debug register
    #o_crreg  =       idaapi.o_idpspec2      # control register
    #o_fpreg  =       idaapi.o_idpspec3      # floating point register
    #o_mmxreg  =      idaapi.o_idpspec4      # mmx register
    #o_xmmreg  =      idaapi.o_idpspec5      # xmm register
    raise TypeError, op.type

@opt.define(idaapi.o_imm)
def opt_imm(op):
    if op.type in (idaapi.o_imm,idaapi.o_phrase):
        return op.value
    raise TypeError, op.type

@opt.define(idaapi.o_mem)
@opt.define(idaapi.o_far)
@opt.define(idaapi.o_near)
def opt_addr(op):
    if op.type in (idaapi.o_mem,idaapi.o_far,idaapi.o_near,idaapi.o_displ):
        return op.addr
    raise TypeError, op.type

## instruction type references
def isGlobalRef(ea):
    '''Return True if the specified instruction references data (like a global)'''
    return len(database.dxdown(ea)) > len(database.cxdown(ea))
def isImportRef(ea):
    return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0

## types of instructions
def isReturn(ea):
    #return idaapi.is_ret_insn(ea)
    return feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
def isShift(ea):
    return feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
def isJmpi(ea):
    return feature(ea) & idaapi.CF_JUMP == idaapi.CF_JUMP
def isCall(ea):
    return feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL

## op_t.flags
#OF_NO_BASE_DISP = 0x80 #  o_displ: base displacement doesn't exist meaningful only for o_displ type if set, base displacement (x.addr) doesn't exist.
#OF_OUTER_DISP = 0x40 #  o_displ: outer displacement exists meaningful only for o_displ type if set, outer displacement (x.value) exists.
#PACK_FORM_DEF = 0x20 #  !o_reg + dt_packreal: packed factor defined
#OF_NUMBER = 0x10 # can be output as number only if set, the operand can be converted to a number only
#OF_SHOW = 0x08 #  should the operand be displayed? if clear, the operand is hidden and should not be displayed

#def set_op_type(*args):
#def op_enum(*args):
#def get_enum_id(*args):
#def op_seg(*args):
#def op_stkvar(*args):
#def op_*(
#def? op_offset(ea, n, type, target = BADADDR, base = 0, tdelta = 0) -> int

class reg_t:
    cache = {}

    class type(object):
        @property
        def id(self):
            res = idaapi.ph.regnames
            return res.index(self.realname or self.name)
        @property
        def name(self):
            return self.__name__
        @property
        def type(self):
            return self.dtyp
        @property
        def size(self):
            return self.size
        @property
        def offset(self):
            return self.offset
        def __repr__(self):
            dt, = [name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi,name) == self.dtyp]
            return '{:s} {:s} {:d}:+{:d}'.format(self.__class__, dt, self.offset, self.size, dt)

    @classmethod
    def new(cls, name, bits, idaname=None):
        dtyp = idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8))
        namespace = dict(cls.type.__dict__)
        namespace.update({'__name__':name, 'parent':None, 'children':{}, 'dtyp':dtyp, 'offset':0, 'size':bits, 'realname':idaname or name})
        namespace['realname'] = idaname
        res = type(name, (cls.type,), namespace)()
        cls.cache[name] = cls.cache[idaname or name,dtyp] = res
        return res
    @classmethod
    def child(cls, parent, name, offset, bits, idaname=None):
        dtyp = idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8))
        namespace = dict(cls.type.__dict__)
        namespace.update({'__name__':name, 'parent':parent, 'children':{}, 'dtyp':dtyp, 'offset':offset, 'size':bits})
        namespace['realname'] = idaname
        res = type(name, (cls.type,), namespace)()
        cls.cache[name] = cls.cache[idaname or name,dtyp] = res
        parent.children[offset] = res
        return res
    @classmethod
    def byIndex(cls, index, dtyp):
        name = idaapi.ph.regnames[index]
        return cls.cache[name,dtyp]
    @classmethod
    def byName(cls, name):
        return cls.cache[name]

class register: pass

[ setattr(register, 'r'+_, reg_t.new('r'+_, 64, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_, reg_t.new('r'+_, 64)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'e'+_, reg_t.child(reg_t.byName('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_, reg_t.child(reg_t.byName('r'+_), 'r'+_+'d', 0, 32)) for _ in map(str,range(8,16)) ]
[ setattr(register,     _, reg_t.child(reg_t.byName('e'+_), _, 0, 16)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, _+'h', reg_t.child(reg_t.byName(_+'x'), _+'h', 8, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg_t.child(reg_t.byName(_+'x'), _+'l', 0, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg_t.child(reg_t.byName(_), _+'l', 0, 8)) for _ in ('sp','bp','si','di') ]
[ setattr(register,     _, reg_t.new('es',16)) for _ in ('es','cs','ss','ds','fs','gs') ]
# 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',

## fpu state         #o_fpreg = idaapi.o_idpspec3      # floating point register
#[reg_t.define('st%d'%_, idaapi.dt_float) for _ in range(8)]
## mmx state         #o_mmxreg = idaapi.o_idpspec4      # mmx register
#[reg_t.define('mm%d'%_, idaapi.dt_qword) for _ in range(8)]
## sse1 state        #o_xmmreg = idaapi.o_idpspec5      # xmm register
#[reg_t.define('xmm%d'%_, idaapi.dt_float) for _ in range(16)]
## sse2 state
#[reg_t.define('ymm%d'%_, idaapi.dt_double) for _ in range(16)]

#['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
#'al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl', 'sil', 'dil', 'ip', 
# 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',
#'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7',
#'fpctrl', 'fpstat', 'fptags',
#'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7',
#'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
#'mxcsr',
#'ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7', 'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15']
