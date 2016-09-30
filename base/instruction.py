import logging,__builtin__
import itertools,functools,operator
import six,types

import database,function,ui
import structure,enum
import internal
from internal import utils,interface

import idaapi

## functions vs the instruction at an ea
@utils.multicase()
def at(): return at(ui.current.address())
@utils.multicase(ea=six.integer_types)
def at(ea):
    ea = interface.address.inside(ea)
    if not database.is_code(ea):
        raise TypeError('{:s}.at : Unable to decode a non-instruction at address : 0x{:x}'.format(__name__, ea))
    length = idaapi.decode_insn(ea)
    return idaapi.cmd.copy()

@utils.multicase()
def size(): return size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def size(ea):
    return at(ea).size

@utils.multicase()
def feature(): return feature(ui.current.address())
@utils.multicase(ea=six.integer_types)
def feature(ea):
    return at(ea).get_canon_feature()

@utils.multicase()
def mnem(): return mnem(ui.current.address())
@utils.multicase(ea=six.integer_types)
def mnem(ea):
    '''Returns the mnemonic of an instruction'''
    ea = interface.address.inside(ea)
    return idaapi.ua_mnem(ea) or ''
mnemonic = utils.alias(mnem)

## functions vs all operands of an insn
@utils.multicase()
def ops_count(): return ops_count(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_count(ea):
    '''Return the number of operands of given instruction'''
    return len(operand(ea, None))

@utils.multicase()
def ops_repr(): return ops_repr(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_repr(ea):
    '''Returns the repr of each operand of an instruction'''
    insn = at(ea)
    res = (idaapi.ua_outop2(insn.ea, n) for n in range(ops_count(insn.ea)))
    return [idaapi.tag_remove(res) if res else str(op_value(insn.ea,i)) for i,res in enumerate(res)]

@utils.multicase()
def ops_value(): return ops_value(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_value(ea):
    return [ op_value(ea,i) for i in range(ops_count(ea)) ]

@utils.multicase()
def ops_state(): return ops_state(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_state(ea):
    '''Returns 'r','w','rw' for each operand of an instruction'''
    f = feature(ea)
    res = ( ((f&ops_state.read[i]),(f&ops_state.write[i])) for i in range(ops_count(ea)) )
    return [ (r and 'r' or '') + (w and 'w' or '') for r,w in res ]
# pre-cache the CF_ flags inside idaapi for ops_state
ops_state.read, ops_state.write = zip(*((getattr(idaapi,'CF_USE{:d}'.format(_+1)), getattr(idaapi,'CF_CHG{:d}'.format(_+1))) for _ in range(idaapi.UA_MAXOP)))

@utils.multicase()
def ops_read(): return ops_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_read(ea):
    '''Returns the indexes of the operands in an instruction that are read from'''
    return [i for i,s in enumerate(ops_state(ea)) if 'r' in s]

@utils.multicase()
def ops_write(): return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_write(ea):
    '''Returns the indexes of the operands in an instruction that are written to'''
    return [i for i,s in enumerate(ops_state(ea)) if 'w' in s]

## functions vs a specific operand of an insn
@utils.multicase()
def operand(): return operand(ui.current.address(), None)
@utils.multicase(none=types.NoneType)
def operand(none): return operand(ui.current.address(), None)
@utils.multicase(n=int)
def operand(n): return operand(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def operand(ea, none):
    insn = at(ea)
    res = itertools.takewhile(lambda n: n.type != idaapi.o_void, (n.copy() for n in insn.Operands))
    return tuple(res)
@utils.multicase(ea=six.integer_types, n=int)
def operand(ea, n):
    '''Returns the `n`th op_t of the instruction at `ea`'''
    insn = at(ea)
    return insn.Operands[n].copy()

@utils.multicase(n=int)
def op_repr(n): return op_repr(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_repr(ea, n):
    '''Returns the string representation of an operand'''
    return ops_repr(ea)[n]

@utils.multicase(n=int)
def op_state(n): return op_state(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_state(ea, n):
    '''Returns 'r','w','rw' of an operand'''
    return ops_state(ea)[n]

@utils.multicase(n=int)
def op_size(n): return op_size(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_size(ea, n):
    '''Returns the read size of an operand'''
    res = operand(ea, n)
    return opt.size(res)

@utils.multicase(n=int)
def op_type(n): return op_type(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_type(ea, n):
    '''Returns the type of an operand (opt_imm, opt_reg, opt_phrase, opt_addr)'''
    res = operand(ea,n)
    return opt.type(res).__name__

@utils.multicase(n=int)
def op_segment(n): return op_segment(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_segment(ea, n):
    op = operand(ea, n)
    segment = op.specval & 0x00ff0000
    if segment == 0x001f0000:
        return 'ss'
    elif segment == 0x00200000:
        return 'ds'
    elif segment == 0x00210000:
        return 'fs'
    raise NotImplementedError('{:s}.op_segment : Unable to determine the segment register for operand {:d} at 0x{:x} : {!r}'.format(__name__, n, ea, segment))

## flags
# idaapi.stroffflag()
# idaapi.stkvarflag()
# idaapi.offflag()
# idaapi.struflag()

# idaapi.set_opinfo(ea, opnum, flags, ti)
# idaapi.get_opinfo(ea, opnum, &flags, &buf)

# idaapi.set_typeinfo(ea, opnum, flags, ti)
# idaapi.get_typeinfo(ea, opnum, &flags, &buf)

# idaapi.set_op_type(ea, type, opnum)
# idaapi.typeflag(ea, &oldflag, type, opnum)

# idaapi.op_stkvar(ea, opnum)

# tid = idaapi.tid_array(1)
# tid[0] = structure_id
# idaapi.op_stroff(ea, opnum, tid, len(tid), delta)
# idaapi.get_stroff_path(ea, opnum, &tid, delta)

# idaapi.op_enum(ea, opnum, enumid, enumserial)
# idaapi.get_enum_id(ea, opnum)

## lvars
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

## get_stroff_path
# pathvar = idaapi.tid_array(length)
# res = idapi.get_stroff_path(ea, n, pathvar.cast(), delta)

@utils.multicase(n=int)
def op_refs(n):
    '''Returns the (address, opnum, type) of all the instructions that reference the ``n``th operand of the current instruction.'''
    return op_refs(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_refs(ea, n):
    '''Returns the (address, opnum, type) of all the instructions that reference the ``n``th operand of the instruction at ``ea``.'''
    fn = idaapi.get_func(ea)
    if fn is None:
        raise LookupError("{:s}.op_refs(0x{:x}, {:d}) : Unable to locate function for address. : {:x}".format(__name__, ea, n, ea))
    F = idaapi.getFlags(ea)

    # reference types
    #Ref_Types = {
    #    0 : 'Data_Unknown', 1 : 'Data_Offset',
    #    2 : 'Data_Write', 3 : 'Data_Read', 4 : 'Data_Text',
    #    5  : 'Data_Informational',
    #    16 : 'Code_Far_Call', 17 : 'Code_Near_Call',
    #    18 : 'Code_Far_Jump', 19 : 'Code_Near_Jump',
    #    20 : 'Code_User', 21 : 'Ordinary_Flow'
    #}
    Ref_T = {
        2 : 'w', 3 : 'r',
#        16:'x', 17:'x', 18:'x', 19:'x', 20:'x', 21:'x'
    }

    # sanity: returns whether the operand has a local or global xref
    ok = idaapi.op_adds_xrefs(F, n)
    if not ok:
        logging.warn('{:s}.op_refs(0x{:x}, {:d}) : Instruction operand does not directly contain any data references.'.format(__name__, ea, n))
        # FIXME: try and match operand offset to structure
        return ()

    # FIXME: gots to be a better way to determine operand representation
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(ea, n, F, ti)

    # stkvar
    if res is None:
        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, ea, n)
        # check that the stkofs_ from get_stkvar and calc_stkvar are the same
        op = operand(ea, n)
        member,stkofs = idaapi.get_stkvar(op, op.addr)
        if stkofs != stkofs_:
            logging.warn('{:s}.op_refs(0x{:x}, {:d}) : Stack offsets for instruction operand do not match. : {:x} != {:x}'.format(__name__, ea, n, stkofs, stkofs_))

        # build the xrefs
        xl = idaapi.xreflist_t()
        idaapi.build_stkvar_xrefs(xl, fn, member)
        res = ((x.ea,x.opnum,Ref_T.get(x.type,'')) for x in xl)

    # struc member
    elif res.tid != idaapi.BADADDR:    # FIXME: is this right?
        # structures are defined in a supval at index 0xf+opnum
        # the supval has the format 0001c0xxxxxx where 'x' is the low 3 bytes of the structure id

        # structure member xrefs (outside function)
        pathvar = idaapi.tid_array(1)
        delta = idaapi.sval_pointer()
        delta.assign(0)
        ok = idaapi.get_stroff_path(ea, n, pathvar.cast(), delta.cast())
        if not ok:
            raise LookupError("{:s}.op_refs(0x{:x}, {:d}) : Unable to get structure id for operand. : {:x}".format(__name__, ea, n, ea))

        # get the structure offset and then figure it's member
        memofs = operand(ea, n).addr    # FIXME: this will be incorrect for an offsetted struct
        st = idaapi.get_struc(pathvar[0])
        if st is None:
            raise LookupError("{:s}.op_refs(0x{:x}, {:d}) : Unable to get structure for id. : {:x}".format(__name__, ea, n, pathvar[0]))
        mem = idaapi.get_member(st, memofs)
        if mem is None:
            raise LookupError("{:s}.op_refs(0x{:x}, {:d}) : Unable to find member for offset in structure {:x}. : {:x}".format(__name__, ea, n, st.id, memofs))

        # extract the references
        x = idaapi.xrefblk_t()
        x.first_to(mem.id, 0)
        if x is None:
            return ()
        refs = [(x.frm,x.iscode,x.type)]
        while x.next_to():
            refs.append((x.frm,x.iscode,x.type))

        # now figure out the operands if there are any
        res = []
        for ea,_,t in refs:
            ops = ((idx, internal.netnode.sup.get(ea, 0xf+idx)) for idx in range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf+idx) is not None)
            ops = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx,val in ops)
            ops = (idx for idx,ids in ops if st.id in ids)
            res.extend( (ea,op,Ref_T.get(t,'')) for op in ops)
        res = res

    # enums
    elif res.tid != idaapi.BADADDR:
        e = enum.by_identifier(res.tid)
        # enums are defined in a altval at index 0xb+opnum
        # the int points straight at the enumeration id
        # FIXME: references to enums don't seem to work
        raise NotImplementedError

    # global
    else:
        # anything that's just a reference is a single-byte supval at index 0x9+opnum
        # 9 -- '\x02' -- offset to segment 2
        gid = operand(ea, n).value if operand(ea, n).type in (idaapi.o_imm,) else operand(ea, n).addr
        x = idaapi.xrefblk_t()
        x.first_to(gid, 0)
        if x is None:
            return ()
        refs = [(x.frm,x.iscode,x.type)]
        while x.next_to():
            refs.append((x.frm,x.iscode,x.type))

        # now figure out the operands if there are any
        res = []
        for ea,_,t in refs:
            if idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_CODE:
                ops = ((idx, operand(ea, idx).value if operand(ea, idx).type in (idaapi.o_imm,) else operand(ea,idx).addr) for idx in range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 9+idx) is not None)
                ops = (idx for idx,val in ops if val == gid)
                res.extend( (ea,op,Ref_T.get(t,'')) for op in ops)
            else: res.append((ea, None, Ref_T.get(t,'')))
        res = res
    return tuple(res)
op_ref = utils.alias(op_refs)

@utils.multicase(n=int)
def op_decode(n): return op_decode(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_decode(ea, n):
    '''Returns the value for an operand in a parseable form'''
    res = operand(ea, n)
    return opt.decode(res)

@utils.multicase(n=int)
def op_value(n): return op_value(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_value(ea, n):
    '''Returns an operand's written value converted to register names, immediate, or offset,(base reg,index reg,scale)'''
    res = operand(ea, n)
    return opt.value(res)

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
            return reg.by_indextype(res,op.dtyp).name

        elif op.type in (idaapi.o_mem,idaapi.o_phrase,idaapi.o_displ):
            dt = ord(idaapi.get_dtyp_by_size(database.config.bits()//8))
            ofs,(b,i,s) = res
            return ofs,(None if b is None else reg.by_indextype(b,dt).name,None if i is None else reg.by_indextype(i,dt).name,s)

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
    if op.type in (idaapi.o_displ, idaapi.o_phrase):
        if op.specflag1 == 0:
            base = op.reg
            index = None

        elif op.specflag1 == 1:
            base = (op.specflag2&0x07) >> 0
            index = (op.specflag2&0x38) >> 3

        else:
            raise TypeError('{:s}.opt_phrase : Unable to determine the operand format for op.type {:d} : {:x}'.format(__name__, op.type, op.specflag1))

        if op.type == idaapi.o_displ:
            offset = op.addr
        elif op.type == idaapi.o_phrase:
            offset = op.value
        else:
            raise NotImplementedError

        # XXX: for some reason stack variables include both base and index
        #      testing .specval seems to be a good way to determine whether
        #      something is referencing the stack
        if op.specval & 0x00ff0000 == 0x001f0000 and index == base:
            index = None

        # OF_NO_BASE_DISP = 1 then .addr doesn't exist
        # OF_OUTER_DISP = 1 then .value exists

    elif op.type == idaapi.o_mem:
        if op.specflag1 == 0:
            base = None
            index = None

        elif op.specflag1 == 1:
            base = None
            index = (op.specflag2&0x38) >> 3

        else:
            raise TypeError('{:s}.opt_phrase : Unable to determine the operand format for op.type {:d} : {:x}'.format(__name__, op.type, op.specflag1))
        offset = op.addr

    else:
        raise TypeError('{:s}.opt_phrase : Invalid operand type. : {:d}'.format(__name__, op.type))

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
    raise TypeError('{:s}.opt_reg : Invalid operand type. : {:d}'.format(__name__, op.type))

@opt.define(idaapi.o_imm)
def opt_imm(op):
    if op.type in (idaapi.o_imm,idaapi.o_phrase):
        bits = idaapi.get_dtyp_size(op.dtyp) * 8
        return op.value & (2**bits-1)
    raise TypeError('{:s}.opt_imm : Invalid operand type. : {:d}'.format(__name__, op.type))

@opt.define(idaapi.o_far)
@opt.define(idaapi.o_near)
def opt_addr(op):
    if op.type in (idaapi.o_mem,idaapi.o_far,idaapi.o_near,idaapi.o_displ):
        return op.addr
    raise TypeError('{:s}.opt_addr : Invalid operand type. : {:d}'.format(__name__, op.type))

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
@utils.multicase()
def is_globalref(): return is_globalref(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_globalref(ea):
    '''Return True if the instruction at ``ea`` references global data.'''
    return len(database.dxdown(ea)) > len(database.cxdown(ea))
isGlobalRef = is_globalref

@utils.multicase()
def is_importref(): return is_importref(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_importref(ea):
    '''Returns True if the instruction at ``ea`` references an import.'''
    return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0
isImportRef = utils.alias(is_importref)

## types of instructions
@utils.multicase()
def is_return(): return is_return(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_return(ea):
    '''Returns True if the instruction at ``ea`` is a ret-type instruction.'''
    idaapi.decode_insn(ea)
    return database.is_code(ea) and idaapi.is_ret_insn(ea)
#    return feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
isReturn = utils.alias(is_return)

@utils.multicase()
def is_shift(): return is_shift(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_shift(ea):
    '''Returns True if the instruction at ``ea`` is a bit-shifting instruction.'''
    return database.is_code(ea) and feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
isShift = utils.alias(is_shift)

@utils.multicase()
def is_branch(): return is_branch(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_branch(ea):
    '''Returns True if the instruction at ``ea`` is a branch instruction.'''
    return database.is_code(ea) and isJmp(ea) or isJxx(ea) or isJmpi(ea)
isBranch = utils.alias(is_branch)

@utils.multicase()
def is_jmp(): return is_jmp(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jmp(ea):
    '''Returns True if the instruction at ``ea`` is a jmp (both immediate and indirect) instruction.'''
    MASK_BRANCH = 0b111
    CF_JMPIMM = 0b001
    CF_JMPCOND = 0b000
    CF_CALL = 0b010
    return database.is_code(ea) and not isJmpi(ea) and (feature(ea) & MASK_BRANCH == CF_JMPIMM) and bool(database.xref.down(ea))
isJmp = utils.alias(is_jmp)

@utils.multicase()
def is_jxx(): return is_jxx(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jxx(ea):
    '''Returns True if the instruction at ``ea`` is a conditional branch.'''
    MASK_BRANCH = 0b111
    CF_JMPIMM = 0b001
    CF_JMPCOND = 0b000
    CF_CALL = 0b010
    return database.is_code(ea) and (feature(ea) & MASK_BRANCH == CF_JMPCOND) and bool(database.xref.down(ea))
isJxx = utils.alias(is_jxx)

@utils.multicase()
def is_jmpi(): return is_jmpi(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jmpi(ea):
    '''Returns True if the instruction at ``ea`` is an indirect branch.'''
    return database.is_code(ea) and feature(ea) & idaapi.CF_JUMP == idaapi.CF_JUMP
isJmpi = utils.alias(is_jmpi)

@utils.multicase()
def is_call(): return is_call(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_call(ea):
    '''Returns True if the instruction at ``ea`` is a call instruction.'''
    idaapi.decode_insn(ea)
    return idaapi.is_call_insn(ea)
#    return database.is_code(ea) and feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL
isCall = utils.alias(is_call)

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
class reg:
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
    def by_index(cls, index):
        name = idaapi.ph.regnames[index]
        return cls.by_name(name)
    byIndex = utils.alias(by_index, 'reg')
    @classmethod
    def by_indextype(cls, index, dtyp):
        name = idaapi.ph.regnames[index]
        return cls.cache[name,dtyp]
    byIndexType = utils.alias(by_indextype, 'reg')
    @classmethod
    def by_name(cls, name):
        return cls.cache[name]
    byName = utils.alias(by_name, 'reg')

class register: pass
[ setattr(register, 'r'+_, reg.new('r'+_, 64, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_, reg.new('r'+_, 64)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'e'+_, reg.child(reg.by_name('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, 'r'+_+'d', reg.child(reg.by_name('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'r'+_+'w', reg.child(reg.by_name('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register, 'r'+_+'b', reg.child(reg.by_name('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(str,range(8,16)) ]
[ setattr(register,     _, reg.child(reg.by_name('e'+_), _, 0, 16)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
[ setattr(register, _+'h', reg.child(reg.by_name(_+'x'), _+'h', 8, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg.child(reg.by_name(_+'x'), _+'l', 0, 8)) for _ in ('a','c','d','b') ]
[ setattr(register, _+'l', reg.child(reg.by_name(_), _+'l', 0, 8)) for _ in ('sp','bp','si','di') ]
[ setattr(register,     _, reg.new('es',16)) for _ in ('es','cs','ss','ds','fs','gs') ]
setattr(register, 'fpstack', reg.new('st', 80*8, dtyp=None))

# FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit

# explicitly set the lookups for (word-register,idaapi.dt_byte) which exist due to ida's love for the inconsistent
[ reg.cache.setdefault((_+'x', reg.by_name(_+'l').type), reg.by_name(_+'l')) for _ in ('a','c','d','b') ]

# single precision
[ setattr(register, 'st{:d}f'.format(_), reg.child(register.fpstack, 'st{:d}f'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_float)) for _ in range(8) ]
# double precision
[ setattr(register, 'st{:d}d'.format(_), reg.child(register.fpstack, 'st{:d}d'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_double)) for _ in range(8) ]
# umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
[ setattr(register, 'st{:d}'.format(_), reg.child(register.fpstack, 'st{:d}'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_tbyte)) for _ in range(8) ]

# not sure if the mmx registers trash the other 16 bits of an fp register
[ setattr(register, 'mm{:d}'.format(_), reg.child(register.fpstack, 'mm{:d}'.format(_), _*80, 64, dtyp=idaapi.dt_qword)) for _ in range(8) ]

# sse1/sse2 simd registers
[ setattr(register, 'xmm{:d}'.format(_), reg.new('xmm{:d}'.format(_), 128, dtyp=idaapi.dt_byte16)) for _ in range(16) ]
[ setattr(register, 'ymm{:d}'.format(_), reg.new('ymm{:d}'.format(_), 128, dtyp=idaapi.dt_ldbl)) for _ in range(16) ]

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
            def str(self):
                return '{:s}({:d})'.format(self.__class__.__name__, self.size)
            def __repr__(self):
                return self.str()
            def __eq__(self, other):
                classname = self.__class__.__name__
                if isinstance(other, basestring):
                    if other.endswith(')'):
                        other_name = other.split('(')[0]
                        other_size = other.split('(')[-1].split(')')[0]
                        try: return cmp(classname, other_name) == 0 and self.size == int(other_size)
                        except ValueError: return False
                    return cmp(classname, other) == 0
                return isinstance(self, other) if isinstance(other, __builtin__.type) else cmp(self,other) == 0
        class store(__base__): pass
        class load(__base__): pass
        class loadstore(__base__): pass
        class assign(__base__): pass
        class value(__base__): pass
        class modify(__base__): pass
        class unknown(__base__): pass

    table = {
        'opt_imm':     {'r':operation.value,   'w':operation.assign, 'rw':operation.modify, '':operation.value},
        'opt_addr':    {'r':operation.load,    'w':operation.store, 'rw':operation.loadstore, '':operation.unknown},
        'opt_phrase':  {'r':operation.load,    'w':operation.store, 'rw':operation.loadstore, '':operation.unknown},
        'opt_reg':     {'r':operation.value,   'w':operation.assign, 'rw':operation.modify, '':operation.unknown},
    }

    @utils.multicase()
    @classmethod
    def op(cls, opnum): return cls.op(ui.current.address(), opnum)
    @utils.multicase(ea=six.integer_types, opnum=six.integer_types)
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

    @utils.multicase()
    @classmethod
    def instruction(cls): return cls.instruction(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def instruction(cls, ea):
        operands = [cls.op(ea, i) for i in range(ops_count(ea))]
        result = []
        for opnum in range(ops_count(ea)):
            operation,value = cls.op(ea, opnum)
            sz = operation.size
            if operation == cls.operation.modify:
                result.append((cls.operation.assign(sz),value))
                result.append((cls.operation.value(sz),value))
            elif operation == cls.operation.loadstore:
                result.append((cls.operation.load(sz),value))
                result.append((cls.operation.store(sz),value))
            else:
                result.append((operation,value))
            continue

        # if mnemonic is stack-related, then add the other implicit operation
        # FIXME: ...and another pretty bad hack to figure out how to remove
        sp,sz = register.sp,database.config.bits()/8
        if mnem(ea).upper() == 'PUSH':
            result.append((cls.operation.store(sz), (0, sp.id, 0, 1)))
        elif mnem(ea).upper() == 'POP':
            result.append((cls.operation.load(sz), (0, sp.id, 0, 1)))
        elif mnem(ea).upper().startswith('RET'):
            if len(result) > 0:
                result.append((cls.operation.modify(sz), (0, sp.id, 0, 1)))
            result.append((cls.operation.load(sz), (0, sp.id, 0, 1)))
        elif mnem(ea).upper() == 'CALL':
            result.append((cls.operation.store(sz), (0, sp.id, 0, 1)))

        return mnem(ea),result
    at = utils.alias(instruction, 'ir')

    @utils.multicase()
    @classmethod
    def get_value(cls): return cls.get_value(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_value(cls, ea):
        _,res = cls.at(ea)
        value = [v for t,v in res if t == 'value']
        return value or None

    @utils.multicase()
    @classmethod
    def get_store(cls): return cls.get_store(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_store(cls, ea):
        _,res = cls.at(ea)
        store = [v for t,v in res if t == 'store']
        return store or None

    @utils.multicase()
    @classmethod
    def get_load(cls): return cls.get_load(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_load(cls, ea):
        _,res = cls.at(ea)
        load = [v for t,v in res if t == 'load']
        return load or None

    @utils.multicase()
    @classmethod
    def get_assign(cls): return cls.get_assign(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_assign(cls, ea):
        _,res = cls.at(ea)
        assign = [v for t,v in res if t == 'assign']
        return assign or None
