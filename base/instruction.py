import database,function
import idaapi

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
    return idaapi.ua_mnem(ea) or ''
mnemonic = mnem

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

def ops_read(ea):
    '''Returns the indexes of the operands in an instruction that are read from'''
    return [i for i,s in enumerate(ops_state(ea)) if 'r' in s]
def ops_write(ea):
    '''Returns the indexes of the operands in an instruction that are written to'''
    return [i for i,s in enumerate(ops_state(ea)) if 'w' in s]

## functions vs a specific operand of an insn
def operand(ea, n=None):
    '''Returns the `n`th op_t of the instruction at `ea`'''
    insn = at(ea)
    if n is None:
        return tuple(insn.Operands[n] for n in xrange(ops_count(insn.ea)))
    return insn.Operands[n]
def op_repr(ea, n):
    '''Returns the string representation of an operand'''
    return ops_repr(ea)[n]
def op_state(ea, n):
    '''Returns 'r','w','rw' of an operand'''
    return ops_state(ea)[n]
def op_size(ea, n):
    '''Returns the read size of an operand'''
    insn = at(ea)
    return opt.size(insn.Operands[n])
def op_type(ea, n):
    '''Returns the type of an operand (opt_imm, opt_reg, opt_phrase, opt_addr)'''
    insn = at(ea)
    return opt.type(insn.Operands[n]).__name__

def op_segment(ea, n):
    insn = at(ea)
    segment = insn.Operands[n].specval & 0x00ff0000
    if segment == 0x001f0000:
        return 'ss'
    elif segment == 0x00200000:
        return 'ds'
    elif segment == 0x00210000:
        return 'fs'
    raise NotImplementedError, hex(segment)

## flags
# idaapi.stroffflag()
# idaapi.stkvarflag()
# idaapi.offflag()
# idaapi.struflag()

## lvars
#def op_stkvar(ea, n):
#    '''Return the member of a stack variable'''
#    py_op = operand(ea,n)    
#    py_v = py_op.addr
#    member,_ = idaapi.get_stkvar(py_op, py_v)
#    return member

# def op_type(ea, n)
#    '''Apply the specified type to a stack variable'''
#    py_op = operand(ea,n)
#    py_v = py_op.addr
#    py_t = idc.ParseType("type string", flags)[1]
#    py_name = "stack variable name"
#    idaapi.apply_type_to_stkarg(py_op, py_v, py_t, py_name)

## structure operands
#def op_stroff(ea, n):
#    '''Convert the specified operand repr to a structure field'''
#    path = idaapi.tid_array(1)
#    path[0] = structureId
#    lengthOfPath = 1
#    return idaapi.op_stroff(ea, n, path.cast(), lengthOfPath, delta)

## set_stroff_path
# length = 1
# pathvar = idaapi.tid_array(length)
# delta = 0
# res = idaapi.set_stroff_path(ea, n, pathvar, length, delta)

## get_Stroff_path
# pathvar = idaapi.tid_array(length)
# res = idapi.get_stroff_path(ea, n, pathvar, delta)
    
    #https://www.hex-rays.com/products/ida/support/idapython_docs/
    # xreflist_t
    #https://www.hex-rays.com/products/ida/support/sdkdoc/frame_8hpp.html#aaeba4d56367ba26fb9a04923cfc89bb6
    # idaman void ida_export build_stkvar_xrefs(xreflist_t * out, func_t * pfn, const member_t * mptr)  
    #https://www.hex-rays.com/products/ida/support/sdkdoc/frame_8hpp.html#a88d80d5d38b062a7743afc80d32e8a2c
    # typedef qvector<xreflist_entry_t> xreflist_t // vector of xrefs to variables in a function's stack frame 
    #https://www.hex-rays.com/products/ida/support/sdkdoc/structxreflist__entry__t.html
    # xreflist_entry_t  


    # shortcut to get from a stkvar operand to the frame structure offset
    #   without needing to calculate with the sp-delta
    #fn = function.byAddress(ea)
    #ofs = idaapi.calc_stkvar_struc_offset(fn, ea, n)
    #return member,ofs

#def op_xref(ea, n):
#    '''Returns whether the operand has a local or global xref'''
#   return idaapi.op_adds_xrefs(idaapi.getFlags(ea),n) 

def op_decode(ea, n):
    '''Returns the value for an operand in a parseable form'''
    insn = at(ea)
    return opt.decode(insn.Operands[n])
def op_value(ea, n):
    '''Returns an operand's written value converted to register names, immediate, or offset,(base reg,index reg,scale)'''
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
        if op.type in (idaapi.o_reg,idaapi.o_idpspec3,idaapi.o_idpspec4,idaapi.o_idpspec5):
            return reg_t.byIndexType(res,op.dtyp).name

        elif op.type in (idaapi.o_mem,idaapi.o_phrase,idaapi.o_displ):
            dt = ord(idaapi.get_dtyp_by_size(database.config.bits()//8))
            ofs,(b,i,s) = res
            return ofs,(None if b is None else reg_t.byIndexType(b,dt).name,None if i is None else reg_t.byIndexType(i,dt).name,s)

        elif op.type in (idaapi.o_far,idaapi.o_near):
            return res
        return res

    @classmethod
    def decode(cls, op):
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

@opt.define(idaapi.o_mem)
@opt.define(idaapi.o_displ)
@opt.define(idaapi.o_phrase)
def opt_phrase(op):
    """Returns (offset, (basereg, indexreg, scale))"""
    if op.type == idaapi.o_displ:
        if op.specflag1 == 0:
            base = op.reg
            index = None

        elif op.specflag1 == 1:
            base = (op.specflag2&0x07) >> 0
            index = (op.specflag2&0x38) >> 3

        else:
            raise TypeError, os.specflag1
        offset = op.addr

        # XXX: for some reason stack variables include both base and index
        #      testing .specval seems to be a good way to determine whether
        #      something is referencing the stack
        if op.specval & 0x00ff0000 == 0x001f0000 and index == base:
            index = None

        # OF_NO_BASE_DISP = 1 then .addr doesn't exist
        # OF_OUTER_DISP = 1 then .value exists
    elif op.type == idaapi.o_phrase:
        if op.specflag1 == 0:
            base  = op.reg
            index = None

        elif op.specflag1 == 1:
            base =  (op.specflag2&0x07) >> 0
            index = (op.specflag2&0x38) >> 3

        else:
            raise TypeError, os.specflag1
        offset = op.value

    elif op.type == idaapi.o_mem:
        if op.specflag1 == 0:
            base = None
            index = None

        elif op.specflag1 == 1:
            base = None
            index = (op.specflag2&0x38) >> 3

        else:
            raise TypeError, os.specflag1
        offset = op.addr

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
    '''opt_genreg'''
    if op.type in (idaapi.o_reg,):
        return op.reg
    raise TypeError, op.type

@opt.define(idaapi.o_imm)
def opt_imm(op):
    if op.type in (idaapi.o_imm,idaapi.o_phrase):
        return op.value
    raise TypeError, op.type

@opt.define(idaapi.o_far)
@opt.define(idaapi.o_near)
def opt_addr(op):
    if op.type in (idaapi.o_mem,idaapi.o_far,idaapi.o_near,idaapi.o_displ):
        return op.addr
    raise TypeError, op.type

@opt.define(idaapi.o_idpspec0)
def opt_reg(op):
    '''opt_trreg'''
    raise NotImplementedError
@opt.define(idaapi.o_idpspec1)
def opt_reg(op):
    '''opt_dbreg'''
    raise NotImplementedError
@opt.define(idaapi.o_idpspec2)
def opt_reg(op):
    '''opt_crreg'''
    raise NotImplementedError
    return getattr(register, 'cr{:d}'.format(op.reg)).id
@opt.define(idaapi.o_idpspec3)
def opt_reg(op):
    '''opt_fpreg'''
    return getattr(register, 'st{:d}'.format(op.reg)).id
@opt.define(idaapi.o_idpspec4)
def opt_reg(op):
    '''opt_mmxreg'''
    return getattr(register, 'mmx{:d}'.format(op.reg)).id
@opt.define(idaapi.o_idpspec5)
def opt_reg(op):
    '''opt_xmmreg'''
    return getattr(register, 'xmm{:d}'.format(op.reg)).id

## instruction type references
def isGlobalRef(ea):
    '''Return True if the specified instruction references data (like a global)'''
    return len(database.dxdown(ea)) > len(database.cxdown(ea))
def isImportRef(ea):
    return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0

## types of instructions
def isReturn(ea):
    return idaapi.is_ret_insn(ea)
#    return feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
def isShift(ea):
    return feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
def isBranch(ea):
    return isJmp(ea) or isJxx(ea) or isJmpi(ea)
def isJmp(ea):
    MASK_BRANCH = 0b111
    CF_JMPIMM = 0b001
    CF_JMPCOND = 0b000
    CF_CALL = 0b010
    return not isJmpi(ea) and (feature(ea) & MASK_BRANCH == CF_JMPIMM) and bool(database.xref.down(ea))
def isJxx(ea):
    MASK_BRANCH = 0b111
    CF_JMPIMM = 0b001
    CF_JMPCOND = 0b000
    CF_CALL = 0b010
    return (feature(ea) & MASK_BRANCH == CF_JMPCOND) and bool(database.xref.down(ea))
def isJmpi(ea):
    return feature(ea) & idaapi.CF_JUMP == idaapi.CF_JUMP
def isCall(ea):
    # return idaapi.is_call_insn(ea)
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

## register lookups and types
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
            try:
                dt, = [name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi,name) == self.dtyp]
            except ValueError:
                dt = 'unknown'
            return '{:s} {:s} {:d}:+{:d}'.format(self.__class__, dt, self.offset, self.size, dt)

        def __contains__(self, other):
            return other in self.children.values()

        def subset(self, other):
            '''Returns true if register other is a part of self'''
            def collect(node):
                res = set([node])
                [res.update(collect(n)) for n in node.children.values()]
                return res
            return other in collect(self)

        def superset(self, other):
            '''Returns true if register `other` is a superset of `self`'''
            res,pos = set(),self
            while pos is not None:
                res.add(pos)
                pos = pos.parent
            return other in res

        def related(self, other):
            '''Returns true if the register `other` affects this one if it's modified'''
            return self.superset(other) or self.subset(other)

    @classmethod
    def new(cls, name, bits, idaname=None, **kwds):
        dtyp = kwds.get('dtyp', idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8)))
        namespace = dict(cls.type.__dict__)
        namespace.update({'__name__':name, 'parent':None, 'children':{}, 'dtyp':dtyp, 'offset':0, 'size':bits})
        namespace['realname'] = idaname
        res = type(name, (cls.type,), namespace)()
        cls.cache[name] = cls.cache[idaname or name,dtyp] = res
        return res
    @classmethod
    def child(cls, parent, name, offset, bits, idaname=None, **kwds):
        dtyp = kwds.get('dtyp', idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8)))
        namespace = dict(cls.type.__dict__)
        namespace.update({'__name__':name, 'parent':parent, 'children':{}, 'dtyp':dtyp, 'offset':offset, 'size':bits})
        namespace['realname'] = idaname
        res = type(name, (cls.type,), namespace)()
        cls.cache[name] = cls.cache[idaname or name,dtyp] = res
        parent.children[offset] = res
        return res
    @classmethod
    def byIndex(cls, index):
        name = idaapi.ph.regnames[index]
        return cls.byName(name)
    @classmethod
    def byIndexType(cls, index, dtyp):
        name = idaapi.ph.regnames[index]
        return cls.cache[name,dtyp]
    @classmethod
    def byName(cls, name):
        return cls.cache[name]

class register: pass

[ setattr(register, 'r'+_, reg_t.new('r'+_, 64, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_, reg_t.new('r'+_, 64)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'e'+_, reg_t.child(reg_t.byName('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_+'d', reg_t.child(reg_t.byName('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'r'+_+'w', reg_t.child(reg_t.byName('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'r'+_+'b', reg_t.child(reg_t.byName('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register,     _, reg_t.child(reg_t.byName('e'+_), _, 0, 16)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, _+'h', reg_t.child(reg_t.byName(_+'x'), _+'h', 8, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg_t.child(reg_t.byName(_+'x'), _+'l', 0, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg_t.child(reg_t.byName(_), _+'l', 0, 8)) for _ in ('sp','bp','si','di') ]
[ setattr(register,     _, reg_t.new('es',16)) for _ in ('es','cs','ss','ds','fs','gs') ]
setattr(register, 'fpstack', reg_t.new('st', 80*8, dtyp=None))

# FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit

# explicitly set the lookups for (word-register,idaapi.dt_byte) which exist due to ida's love for the inconsistent
[ reg_t.cache.setdefault((_+'x', reg_t.byName(_+'l').type), reg_t.byName(_+'l')) for _ in ('a','c','d','b') ]

# single precision
[ setattr(register, 'st{:d}f'.format(_), reg_t.child(register.fpstack, 'st{:d}f'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_float)) for _ in range(8) ]
# double precision
[ setattr(register, 'st{:d}d'.format(_), reg_t.child(register.fpstack, 'st{:d}d'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_double)) for _ in range(8) ]
# umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
[ setattr(register, 'st{:d}'.format(_), reg_t.child(register.fpstack, 'st{:d}'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_tbyte)) for _ in range(8) ]

# not sure if the mmx registers trash the other 16 bits of an fp register
[ setattr(register, 'mm{:d}'.format(_), reg_t.child(register.fpstack, 'mm{:d}'.format(_), _*80, 64, dtyp=idaapi.dt_qword)) for _ in range(8) ]

# sse1/sse2 simd registers
[ setattr(register, 'xmm{:d}'.format(_), reg_t.new('xmm{:d}'.format(_), 128, dtyp=idaapi.dt_byte16)) for _ in range(16) ]
[ setattr(register, 'ymm{:d}'.format(_), reg_t.new('ymm{:d}'.format(_), 128, dtyp=idaapi.dt_ldbl)) for _ in range(16) ]

#fpctrl, fpstat, fptags
#mxcsr
# 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',

# FIXME: implement switch_t to determine information about switch statements

class ir:
    """Returns an operand as a parseable intermediary representation"""
    class operation:
        class __base__(object):
            def __init__(self, size=0):
                self.size = size
            def __repr__(self):
                return '{:s}({:d})'.format(self.__class__.__name__,self.size)
        class store(__base__): pass
        class load(__base__): pass
        class assign(__base__): pass
        class value(__base__): pass
        class modify(__base__): pass
        class unknown(__base__): pass

    table = {
        'opt_imm':     {'r':operation.value,   'w':operation.assign, 'rw':operation.modify, '':operation.value},
        'opt_addr':    {'r':operation.load,    'w':operation.store, 'rw':operation.unknown},
        'opt_phrase':  {'r':operation.load,    'w':operation.store, 'rw':operation.unknown},
        'opt_reg':     {'r':operation.value,   'w':operation.assign, 'rw':operation.modify},
    }

    @classmethod
    def op(cls, ea, opnum):
        """Returns an operand as a normalized type.

        (store,(immediate,register,index,scale))
        (load,(immediate,register,index,scale))
        (value,(immediate,register,index,scale))
        (assign,(immediate,register,index,scale))
        """
        op = operand(ea, opnum)
        t = opt.type(op)
        operation = cls.table[t.__name__][op_state(ea,opnum)]

        # if mnemonic is lea, then demote it from a memory operation
        # FIXME: i don't like this hack.
        if mnem(ea).upper() == 'LEA':
            if operation == cls.operation.load:
                operation = cls.operation.value
            elif operation == cls.operation.store:
                operation = cls.operation.assign
            else:
                operation = operation

        if t == opt_phrase:
            imm,(reg, index, scale) = t(op)
        elif t in (opt_imm, opt_addr):
            imm,reg,index,scale = t(op),None,None,None
        else:
            imm,reg,index,scale = None,t(op), None, None

        return operation(opt.size(op)),(imm,reg,index,scale)

    @classmethod
    def instruction(cls, ea):
        operands = [cls.op(ea, i) for i in range(ops_count(ea))]
        result = []
        for opnum in range(ops_count(ea)):
            operation,value = cls.op(ea, opnum)
            if operation == cls.operation.modify:
                result.append((cls.operation.assign,value))
                result.append((cls.operation.value,value))
            else:
                result.append((operation,value))
            continue
        return mnem(ea),result
