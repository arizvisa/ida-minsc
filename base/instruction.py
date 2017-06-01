import logging,__builtin__
import itertools,functools,operator
import six,types,collections

import database,function,ui
import structure,enum
import internal
from internal import utils,interface

import idaapi

@utils.multicase()
def at():
    '''Returns the insn_t instance at the current address.'''
    return at(ui.current.address())
@utils.multicase(ea=six.integer_types)
def at(ea):
    '''Returns the insn_t instance at the address ``ea``.'''
    ea = interface.address.inside(ea)
    if not database.is_code(ea):
        raise TypeError('{:s}.at({:x}) : Unable to decode a non-instruction at specified address.'.format(__name__, ea))
    length = idaapi.decode_insn(ea)
    return idaapi.cmd.copy()

@utils.multicase()
def size():
    '''Returns the length of the instruction at the current address.'''
    return size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def size(ea):
    '''Returns the length of the instruction at ``ea``.'''
    return at(ea).size

@utils.multicase()
def feature():
    '''Returns the feature bitmask of the instruction at the current address.'''
    return feature(ui.current.address())
@utils.multicase(ea=six.integer_types)
def feature(ea):
    '''Return the feature bitmask for the instruction at address ``ea``.'''
    return at(ea).get_canon_feature()

@utils.multicase()
def mnemonic():
    '''Returns the mnemonic of an instruction at the current address.'''
    return mnem(ui.current.address())
@utils.multicase(ea=six.integer_types)
def mnemonic(ea):
    '''Returns the mnemonic of the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    return (idaapi.ua_mnem(ea) or '').lower()
mnem = utils.alias(mnemonic)

## functions vs all operands of an insn
@utils.multicase()
def ops_count():
    '''Returns the number of operands of the instruction at the current address.'''
    return ops_count(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_count(ea):
    '''Returns the number of operands of the instruction at the address ``ea``.'''
    return len(operand(ea, None))

@utils.multicase()
def ops_repr():
    '''Returns a tuple of the repr of all the operands at the instruction at the current address.'''
    return ops_repr(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_repr(ea):
    '''Returns a tuple of the repr of all the operands at the instruction at the address ``ea``.'''
    insn = at(ea)
    res = (idaapi.ua_outop2(insn.ea, n) for n in range(ops_count(insn.ea)))
    return [idaapi.tag_remove(res) if res else str(op_value(insn.ea,i)) for i,res in enumerate(res)]

@utils.multicase()
def ops_value():
    '''Returns a tuple of all the abstracted operands of the instruction at the current address.'''
    return ops_value(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_value(ea):
    '''Returns a tuple of all the abstracted operands of the instruction at the address ``ea``.'''
    return [ op_value(ea,i) for i in range(ops_count(ea)) ]
ops = utils.alias(ops_value)

@utils.multicase()
def ops_size():
    '''Returns a tuple with all the sizes for each operand in the instruction at the current address.'''
    return ops_size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_size(ea):
    '''Returns a tuple with all the sizes for each operand in the instruction at the address ``ea``.'''
    return [ int(idaapi.get_dtyp_size(operand(ea,i).dtyp)) for i in range(ops_count(ea)) ]

@utils.multicase()
def ops_type():
    '''Returns a tuple of the types for all the operands of the instruction at the current address.'''
    return ops_type(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_type(ea):
    '''Returns a tuple of the types for all the operands of the instruction at the address ``ea``.'''
    return [ op_type(ea,i) for i in range(ops_count(ea)) ]
opts = utils.alias(ops_type)

@utils.multicase()
def ops_state():
    '''Returns a tuple of the state (r,w,rw) for all the operands of the instruction at the current address.'''
    return ops_state(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_state(ea):
    '''Returns a tuple of the state (r,w,rw) for all the operands of the instruction at address ``ea``.'''
    f = feature(ea)
    res = ( ((f&ops_state.read[i]),(f&ops_state.write[i])) for i in range(ops_count(ea)) )
    return [ (r and 'r' or '') + (w and 'w' or '') for r,w in res ]
# pre-cache the CF_ flags inside idaapi for ops_state
ops_state.read, ops_state.write = zip(*((getattr(idaapi,'CF_USE{:d}'.format(_+1)), getattr(idaapi,'CF_CHG{:d}'.format(_+1))) for _ in range(idaapi.UA_MAXOP)))

@utils.multicase()
def ops_read():
    '''Returns the indexes of all of the operands that are being read from the instruction at the current address.'''
    return ops_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_read(ea):
    '''Returns the indexes of all of the operands that are being read from the instruction at the address ``ea``.'''
    return [i for i,s in enumerate(ops_state(ea)) if 'r' in s]

@utils.multicase()
def ops_write():
    '''Returns the indexes of all of the operands that are being written to from the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_write(ea):
    '''Returns the indexes of all of the operands that are being written to from the instruction at the address ``ea``.'''
    return [i for i,s in enumerate(ops_state(ea)) if 'w' in s]

## functions vs a specific operand of an insn
@utils.multicase()
def operand():
    '''Returns all the op_t's of the instruction at the current address.'''
    return operand(ui.current.address(), None)
@utils.multicase(none=types.NoneType)
def operand(none):
    """Returns all the op_t's of the instruction at the current address.
    (Not really intended to be used. Please use the zero-argument version.))
    """
    return operand(ui.current.address(), None)
@utils.multicase(n=int)
def operand(n):
    '''Returns the ``n``th op_t of the instruction at the current address.'''
    return operand(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def operand(ea, none):
    '''Return all the op_t's of the instruction at ``ea``.'''
    insn = at(ea)
    res = itertools.takewhile(lambda n: n.type != idaapi.o_void, (n.copy() for n in insn.Operands))
    return tuple(res)
@utils.multicase(ea=six.integer_types, n=int)
def operand(ea, n):
    '''Returns the ``n``th op_t of the instruction at the address ``ea``.'''
    insn = at(ea)
    return insn.Operands[n].copy()

@utils.multicase(n=int)
def op_repr(n):
    '''Returns a repr of the ``n``th operand of the instruction at the current address.'''
    return op_repr(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_repr(ea, n):
    '''Returns a repr of the ``n``th operand of the instruction at the address ``ea``.'''
    insn = at(ea)
    res = idaapi.ua_outop2(insn.ea, n)
    return idaapi.tag_remove(res) if res else str(op_value(insn.ea, n))

@utils.multicase(n=int)
def op_state(n):
    '''Returns the state (r,w,rw) of the ``n``th operand for the instruction at the current address.'''
    return op_state(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_state(ea, n):
    '''Returns the state (r,w,rw) of the ``n``th operand for the instruction at address ``ea``.'''
    f = feature(ea)
    r, w = f&ops_state.read[n], f&ops_state.write[n]
    return (r and 'r' or '') + (w and 'w' or '')

@utils.multicase(n=int)
def op_size(n):
    '''Returns the size of the ``n``th operand for the current instruction.'''
    return op_size(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_size(ea, n):
    '''Returns the size of the ``n``th operand for the instruction at the address ``ea``.'''
    res = operand(ea, n)
    return idaapi.get_dtyp_size(res.dtyp)

@utils.multicase(n=int)
def op_type(n):
    '''Returns the string type of the ``n``th operand for the instruction at the current address.'''
    return op_type(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_type(ea, n):
    """Returns the string type of the ``n``th operand for the instruction at the address ``ea``.
    Some of the types returned are: imm, reg, phrase, or addr
    """
    res = operand(ea,n)
    return __optype__.type(res)
opt = utils.alias(op_type)

#@utils.multicase(n=int)
#def op_decode(n):
#    '''Returns the value of the ``n``th operand for the current instruction in byte form.'''
#    return op_decode(ui.current.address(), n)
#@utils.multicase(ea=six.integer_types, n=int)
#def op_decode(ea, n):
#    """Returns the value of the ``n``th operand for the instruction at address ``ea`` in byte form.
#
#    The formats are based on the operand type as emitted by the ins.op_type function:
#    imm -> integer
#    reg -> register index
#    addr -> address
#    phrase -> (offset, base-register index, index-register index, scale)
#    """
#    res = operand(ea, n)
#    return __optype__.decode(res)

@utils.multicase(n=int)
def op_value(n):
    '''Returns the value of the ``n``th operand for the current instruction.'''
    return op_value(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_value(ea, n):
    """Returns the value of the ``n``th operand for the instruction at the address ``ea``.

    The formats are based on the operand type as emitted by the ins.op_type function:
    imm -> integer
    reg -> register name
    addr -> address
    phrase -> (offset, base-register name, index-register name, scale)
    """
    res = operand(ea, n)
    return __optype__.decode(res)
op = op_decode = utils.alias(op_value)

## tag:intel
# FIXME: deprecate this, and somehow associate the segment register with the operand for the intel arch
@utils.multicase(n=int)
def op_segment(n):
    '''Returns the segment register name of the ``n``th operand for the instruction at the current address.'''
    return op_segment(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_segment(ea, n):
    '''Returns the segment register name of the ``n``th operand for the instruction at the address ``ea``.'''
    op = operand(ea, n)
    segment = op.specval & 0x00ff0000
    if segment == 0x001f0000:
        return 'ss'
    elif segment == 0x00200000:
        return 'ds'
    elif segment == 0x00210000:
        return 'fs'
    raise NotImplementedError('{:s}.op_segment({:x}, {:d}) : Unable to determine the segment register for specified operand number. : {!r}'.format(__name__, ea, n, segment))

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

class AddressOpnumReftype(interface.namedtypedtuple):
    '''A named tuple containing (address, operand-number, reference-type).'''
    _fields = ('address','opnum','reftype')
    _types = (long, int, basestring)
OREF = AddressOpnumReftype

@utils.multicase(n=int)
def op_refs(n):
    '''Returns the (address, opnum, type) of all the instructions that reference the ``n``th operand of the current instruction.'''
    return op_refs(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=int)
def op_refs(ea, n):
    '''Returns the (address, opnum, type) of all the instructions that reference the ``n``th operand of the instruction at ``ea``.'''
    fn = idaapi.get_func(ea)
    if fn is None:
        raise LookupError("{:s}.op_refs({:x}, {:d}) : Unable to locate function for address. : {:x}".format(__name__, ea, n, ea))
    F = database.type.flags(ea)

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
    ok = idaapi.op_adds_xrefs(F, n) ## FIXME: on tag:arm, this returns T for some operands

    # FIXME: gots to be a better way to determine operand representation
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(ea, n, F, ti)

    # FIXME: this is incorrect on ARM for the 2nd op in `ADD R7, SP, #0x430+lv_dest_41c`
    # stkvar
    if ok and res is None:
        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, ea, n)
        # check that the stkofs_ from get_stkvar and calc_stkvar are the same
        op = operand(ea, n)
        member,stkofs = idaapi.get_stkvar(op, op.addr)
        if stkofs != stkofs_:
            logging.warn('{:s}.op_refs({:x}, {:d}) : Stack offsets for instruction operand do not match. : {:x} != {:x}'.format(__name__, ea, n, stkofs, stkofs_))

        # build the xrefs
        xl = idaapi.xreflist_t()
        idaapi.build_stkvar_xrefs(xl, fn, member)
        res = [ OREF(x.ea,x.opnum,Ref_T.get(x.type,'')) for x in xl ]

    # struc member
    elif ok and res.tid != idaapi.BADADDR:    # FIXME: is this right?
        # structures are defined in a supval at index 0xf+opnum
        # the supval has the format 0001c0xxxxxx where 'x' is the low 3 bytes of the structure id

        # structure member xrefs (outside function)
        pathvar = idaapi.tid_array(1)
        delta = idaapi.sval_pointer()
        delta.assign(0)
        ok = idaapi.get_stroff_path(ea, n, pathvar.cast(), delta.cast())
        if not ok:
            raise LookupError("{:s}.op_refs({:x}, {:d}) : Unable to get structure id for operand. : {:x}".format(__name__, ea, n, ea))

        # get the structure offset and then figure it's member
        memofs = operand(ea, n).value    # FIXME: this will be incorrect for an offsetted struct
        st = idaapi.get_struc(pathvar[0])
        if st is None:
            raise LookupError("{:s}.op_refs({:x}, {:d}) : Unable to get structure for id. : {:x}".format(__name__, ea, n, pathvar[0]))
        mem = idaapi.get_member(st, memofs)
        if mem is None:
            raise LookupError("{:s}.op_refs({:x}, {:d}) : Unable to find member for offset in structure {:x}. : {:x}".format(__name__, ea, n, st.id, memofs))

        # extract the references
        x = idaapi.xrefblk_t()
        x.first_to(mem.id, 0)
        refs = [ (x.frm,x.iscode,x.type) ]
        while x.next_to():
            refs.append( (x.frm,x.iscode,x.type) )

        # now figure out the operands if there are any
        res = []
        for ea,_,t in refs:
            ops = ((idx, internal.netnode.sup.get(ea, 0xf+idx)) for idx in range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf+idx) is not None)
            ops = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx,val in ops)
            ops = (idx for idx,ids in ops if st.id in ids)
            res.extend( OREF(ea,op,Ref_T.get(t,'')) for op in ops)
        res = res

    # enums
    elif ok and res.tid != idaapi.BADADDR:
        e = enum.by_identifier(res.tid)
        # enums are defined in a altval at index 0xb+opnum
        # the int points straight at the enumeration id
        # FIXME: references to enums don't seem to work
        raise NotImplementedError

    # FIXME: is this supposed to execute if ok == T? or not?
    # global
    else:
        # anything that's just a reference is a single-byte supval at index 0x9+opnum
        # 9 -- '\x02' -- offset to segment 2
        gid = operand(ea, n).value if operand(ea, n).type in (idaapi.o_imm,) else operand(ea, n).addr
        x = idaapi.xrefblk_t()
        x.first_to(gid, 0)
        if x is None:
            return []
        refs = [ (x.frm,x.iscode,x.type) ]
        while x.next_to():
            refs.append( (x.frm,x.iscode,x.type) )

        # now figure out the operands if there are any
        res = []
        for ea,_,t in refs:
            if ea == idaapi.BADADDR: continue
            if database.type.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:
                ops = ((idx, operand(ea, idx).value if operand(ea, idx).type in (idaapi.o_imm,) else operand(ea,idx).addr) for idx in range(ops_count(ea)))
                ops = (idx for idx,val in ops if val == gid)
                res.extend( OREF(ea,op,Ref_T.get(t,'')) for op in ops)
            else: res.append( OREF(ea, None, Ref_T.get(t,'')) )
        res = res
    return res
op_ref = utils.alias(op_refs)

## instruction type references
@utils.multicase()
def is_globalref(): return is_globalref(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_globalref(ea):
    '''Return True if the instruction at ``ea`` references global data.'''
    return len(database.dxdown(ea)) > len(database.cxdown(ea))
isGlobalRef = globalrefQ = is_globalref

@utils.multicase()
def is_importref(): return is_importref(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_importref(ea):
    '''Returns True if the instruction at ``ea`` references an import.'''
    return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0
isImportRef = importrefQ = utils.alias(is_importref)

## types of instructions
@utils.multicase()
def is_return(): return is_return(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_return(ea):
    '''Returns True if the instruction at ``ea`` is a ret-type instruction.'''
    idaapi.decode_insn(ea)
    return database.is_code(ea) and idaapi.is_ret_insn(ea)
#    return feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
isReturn = returnQ = utils.alias(is_return)

@utils.multicase()
def is_shift(): return is_shift(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_shift(ea):
    '''Returns True if the instruction at ``ea`` is a bit-shifting instruction.'''
    return database.is_code(ea) and feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
isShift = shiftQ = utils.alias(is_shift)

@utils.multicase()
def is_branch(): return is_branch(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_branch(ea):
    '''Returns True if the instruction at ``ea`` is a branch instruction.'''
    return database.is_code(ea) and isJmp(ea) or isJxx(ea) or isJmpi(ea)
isBranch = branchQ = utils.alias(is_branch)

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
isJmp = JmpQ = utils.alias(is_jmp)

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
isJxx = JxxQ = utils.alias(is_jxx)

@utils.multicase()
def is_jmpi(): return is_jmpi(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jmpi(ea):
    '''Returns True if the instruction at ``ea`` is an indirect branch.'''
    return database.is_code(ea) and feature(ea) & idaapi.CF_JUMP == idaapi.CF_JUMP
isJmpi = jmpiQ = utils.alias(is_jmpi)

@utils.multicase()
def is_call(): return is_call(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_call(ea):
    '''Returns True if the instruction at ``ea`` is a call instruction.'''
    idaapi.decode_insn(ea)
    return idaapi.is_call_insn(ea)
#    return database.is_code(ea) and feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL
isCall = callQ = utils.alias(is_call)

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
class register_t(interface.symbol_t):
    '''A register type.'''

    @property
    def __symbols__(self):
        yield self

    @property
    def id(self):
        '''Returns the index of the register.'''
        res = idaapi.ph.regnames
        try: return res.index(self.realname or self.name)
        except ValueError: pass
        return -1

    @property
    def name(self):
        '''Returns the register's name.'''
        return self.__name__
    @property
    def type(self):
        '''Returns the IDA dtype of the register.'''
        return self.dtyp
    @property
    def size(self):
        '''Returns the size of the register.'''
        return self.size
    @property
    def offset(self):
        '''Returns the binary offset into the full register where it begins at.'''
        return self.offset
    def __repr__(self):
        try:
            dt, = [name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi,name) == self.dtyp]
        except ValueError:
            dt = 'unknown'
        return '<{:s}({:d},{:s}) {!r} {:d}:+{:d}>'.format('.'.join((__name__,'register',self.__class__.__name__)), self.id, dt, self.name, self.offset, self.size)
        #return '{:s} {:s} {:d}:+{:d}'.format(self.__class__, dt, self.offset, self.size, dt)

    def __eq__(self, other):
        if isinstance(other, basestring):
            return self.name.lower() == other.lower()
        return self is other

    def __contains__(self, other):
        '''Returns True if the register ``other`` is a sub-register of ``self``.'''
        return other in self.children.values()

    def subsetQ(self, other):
        '''Returns True if the register ``other`` is a part of ``self``.'''
        def collect(node):
            res = set([node])
            [res.update(collect(n)) for n in node.children.values()]
            return res
        return other in self.alias or other in collect(self)

    def supersetQ(self, other):
        '''Returns True if the register ``other`` is a superset of ``self``.'''
        res,pos = set(),self
        while pos is not None:
            res.add(pos)
            pos = pos.parent
        return other in self.alias or other in res

    def relatedQ(self, other):
        '''Returns True if the the register ``other`` affects ``self`` when it's modified'''
        return self.supersetQ(other) or self.subsetQ(other)

class map_t(object):
    __slots__ = ('__state__',)
    def __init__(self):
        object.__setattr__(self, '__state__', {})

    def __getattr__(self, name):
        res = self.__state__
        return res[name]

    def __setattr__(self, name, register):
        res = self.__state__
        return res.__setitem__(name, register)

    def __repr__(self):
        return '{:s} {!r}'.format(str(self.__class__), self.__state__)

class architecture_t(object):
    """Base class to represent how IDA maps the registers and types returned from an operand to a register that's uniquely identifiable by the user.

    This is necessary as for some architectures IDA will not include all the register names and thus will use the same register-index to represent two registers that are of different types. As an example, on the Intel processor module the `al` and `ax` regs are returned in the operand as an index to the "ax" string. Similarly on the 64-bit version of the processor module, all of the registers `ax`, `eax`, and `rax` have the same index.
    """
    __slots__ = ('__register__', '__cache__',)
    r = register = property(fget=lambda s: s.__register__)

    def __init__(self, **cache):
        """Instantiate an architecture_t object which represents the registers available to an architecture.
        If ``cache`` is defined, then use the specified dictionary to map an ida (register-name, register-dtyp) to a string containing the commonly recognized register-name.
        """
        self.__register__, self.__cache__ = map_t(), cache.get('cache', {})

    def new(self, name, bits, idaname=None, **kwargs):
        '''Add a register to the architecture's cache.'''
        dtyp = kwargs.get('dtyp', idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8)))
        namespace = dict(register_t.__dict__)
        namespace.update({'__name__':name, 'parent':None, 'children':{}, 'dtyp':dtyp, 'offset':0, 'size':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', set())
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name,dtyp] = name
        return res

    def child(self, parent, name, offset, bits, idaname=None, **kwargs):
        '''Add a child-register to the architecture's cache.'''
        dtyp = kwargs.get('dtyp', idaapi.dt_bitfld if bits == 1 else ord(idaapi.get_dtyp_by_size(bits//8)))
        namespace = dict(register_t.__dict__)
        namespace.update({'__name__':name, 'parent':parent, 'children':{}, 'dtyp':dtyp, 'offset':offset, 'size':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', set())
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name,dtyp] = name
        parent.children[offset] = res
        return res

    def by_index(self, index):
        """Lookup a register according to it's ``index``.
        Size is the default that's set according to the IDA version.
        """
        res = idaapi.ph.regnames[index]
        return self.by_name(res)
    byIndex = utils.alias(by_index, 'architecture')
    def by_indextype(self, index, dtyp):
        """Lookup a register according to it's ``index`` and ``dtyp``.
        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res,dtyp]
        return getattr(self.__register__, name)
    byIndexType = utils.alias(by_indextype, 'architecture')
    def by_name(self, name):
        '''Lookup a register according to it's ``name``.'''
        return getattr(self.__register__, name.lower())
    byName = utils.alias(by_name, 'architecture')
    def by_indexsize(self, index, size):
        '''Lookup a register according to it's ``index`` and ``size``.'''
        dtyp = idaapi.get_dtyp_by_size(size)
        return self.by_indextype(index, ord(dtyp))

## operand types
class __optype__(object):
    '''static lookup table for operand type decoders'''
    cache = {}
    @classmethod
    def define(cls, processor, type):
        def decorator(fn):
            res = processor, type
            return cls.cache.setdefault(res, fn)
        return decorator

    @classmethod
    def lookup(cls, type, processor=None):
        try: return cls.cache[processor or idaapi.ph.id, type]
        except KeyError: return cls.cache[0, type]

    @classmethod
    def decode(cls, op, processor=None):
        return cls.lookup(op.type, processor=processor)(op)

    @classmethod
    def type(cls, op, processor=None):
        return cls.lookup(op.type, processor=processor).__name__

    @classmethod
    def size(cls, op, processor=None):
        return idaapi.get_dtyp_size(op.dtyp)

## XXX: This namespace is deleted after each method has been assigned to their lookup table
class operand_types:
    """Namespace containing all of the operand type handlers.
    """
    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_void)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_void)
    def void(op):
        '''An o_void operand...which is nothing.'''
        return ()

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_reg)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_reg)
    def register(op):
        '''Return the operand as a register_t.'''
        if op.type in (idaapi.o_reg,):
            res, dt = op.reg, ord(idaapi.get_dtyp_by_size(database.config.bits()//8))
            return reg.by_indextype(res, op.dtyp)
        optype = '{:s}({:d})'.format('idaapi.o_reg', idaapi.o_reg)
        raise TypeError('{:s}.register(...) : {:s} : Invalid operand type. : {:d}'.format('.'.join((__name__, 'operand_types')), s_optype, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_imm)
    def immediate(op):
        '''Return the operand as an integer.'''
        if op.type in (idaapi.o_imm,idaapi.o_phrase):
            bits = idaapi.get_dtyp_size(op.dtyp) * 8
            return op.value & (2**bits-1)
        optype = '{:s}({:d})'.format('idaapi.o_imm', idaapi.o_imm)
        raise TypeError('{:s}.immediate(...) : {:s} : Invalid operand type. : {:d}'.format('.'.join((__name__, 'operand_types')), optype, op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_far)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_near)
    def memory(op):
        '''Return the operand.addr field from an operand.'''
        if op.type in (idaapi.o_mem,idaapi.o_far,idaapi.o_near,idaapi.o_displ):
            return op.addr
        optype = map(utils.unbox('{:s}({:d})'.format), [('idaapi.o_far', idaapi.o_far), ('idaapi.o_near', idaapi.o_near)])
        raise TypeError('{:s}.address(...) : {:s},{:s} : Invalid operand type. : {:d}'.format('.'.join((__name__, 'operand_types')), optype[0], optype[1], op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec0)
    def trregister(op):
        '''trreg'''
        raise NotImplementedError
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec1)
    def dbregister(op):
        '''dbreg'''
        raise NotImplementedError
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec2)
    def crregister(op):
        '''crreg'''
        raise NotImplementedError
        return getattr(register, 'cr{:d}'.format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec3)
    def fpregister(op):
        '''fpreg'''
        return getattr(register, 'st{:d}'.format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec4)
    def mmxregister(op):
        '''mmxreg'''
        return getattr(register, 'mmx{:d}'.format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec5)
    def xmmregister(op):
        '''xmmreg'''
        return getattr(register, 'xmm{:d}'.format(op.reg)).id

    @__optype__.define(idaapi.PLFM_386, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_displ)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_phrase)
    def phrase(op):
        """Returns an operand as a (offset, basereg, indexreg, scale) tuple."""
        if op.type in (idaapi.o_displ, idaapi.o_phrase):
            if op.specflag1 == 0:
                base = op.reg
                index = None

            elif op.specflag1 == 1:
                base = (op.specflag2&0x07) >> 0
                index = (op.specflag2&0x38) >> 3

            else:
                optype = map(utils.unbox('{:s}({:d})'.format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
                raise TypeError('{:s}.phrase(...) : {:s},{:s},{:s} : Unable to determine the operand format for op.type {:d} : {:x}'.format(__name__, optype[0], optype[1], optype[2], op.type, op.specflag1))

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
                optype = map(utils.unbox('{:s}({:d})'.format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
                raise TypeError('{:s}.phrase(...) : {:s} : Unable to determine the operand format for op.type {:d} : {:x}'.format(__name__, optype[0], optype[1], optype[2], op.type, op.specflag1))
            offset = op.addr

        else:
            optype = map(utils.unbox('{:s}({:d})'.format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
            raise TypeError('{:s}.phrase(...) : {:s},{:s},{:s} : Invalid operand type. : {:d}'.format(__name__, optype[0], optype[1], optype[2], op.type))

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

        dt = ord(idaapi.get_dtyp_by_size(database.config.bits()//8))
        res = long((offset-maxint) if offset&signbit else offset), None if base is None else reg.by_indextype(base, dt), None if index is None else reg.by_indextype(index, dt), scale
        return intelop.OBIS(*res)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_phrase)
    def phrase(op):
        Rn, Rm = reg.by_index(op.reg), reg.by_index(op.specflag1)
        return armop.phrase(Rn, Rm)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_displ)
    def disp(op):
        '''Convert an arm operand into an armop.disp tuple (register, offset).'''
        Rn = reg.by_index(op.reg)
        return armop.disp(Rn, long(op.addr))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_mem)
    def memory(op):
        '''Convert an arm operand into an armop.mem tuple (address, dereferenced-value).'''
        # get the address and the operand size
        addr, size = op.addr, idaapi.get_dtyp_size(op.dtyp)
        maxval = 1<<size*8

        # dereference the address and return it's integer.
        res = idaapi.get_many_bytes(addr, size) or ''
        res = reversed(res) if database.config.byteorder() == 'little' else iter(res)
        res = reduce(lambda t,c: (t*0x100) | ord(c), res, 0)
        sf = bool(res & maxval>>1)

        return armop.mem(long(addr), long(res-maxval) if sf else long(res))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec0)
    def flex(op):
        '''Convert an arm operand into an arm.flexop tuple (register, type, immediate).'''
        # tag:arm, this is a register with a shift-op applied
        Rn = reg.by_index(op.reg)
        shift = 0   # FIXME: find out where the shift-type is stored
        return armop.flex(Rn, int(shift), int(op.value))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec1)
    def list(op):
        '''Convert a bitmask of a registers into an armop.list.'''
        # op.specval -- a bitmask specifying which registers are included
        res, n = [], op.specval
        for i in range(16):
            if n & 1:
                res.append(reg.by_index(i))
            n >>= 1
        return armop.list(set(res))
del(operand_types)

class intelop:
    class OffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an intel operand (offset, base, index, scale).
        Within the tuple, `base` and `index` are registers.
        """
        _fields = ('offset','base','index','scale')
        _types = (long, (types.NoneType,register_t), (types.NoneType,register_t), int)

        @property
        def __symbols__(self):
            _, b, i, _ = self
            if b is not None: yield b
            if i is not None: yield i
    OBIS = OffsetBaseIndexScale

class armop:
    class flex(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an arm flexible-operand (Rn, shift, n).
        A flexible operand is an operation that allows the architecture to apply
        a binary shift or rotation to the value of a register.
        """
        _fields = ('Rn', 'shift', 'n')
        _types = (register_t, int, int)

        register = property(fget=operator.itemgetter(0))
        t = type = property(fget=operator.itemgetter(1))
        imm = immediate = property(fget=operator.itemgetter(2))

        @property
        def __symbols__(self):
            r, _, _ = self
            yield r

    class list(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an arm register list (reglist,).
        `list` contains a set of register_t which can be used to test membership.
        """
        _fields = ('reglist',)
        _types = (set,)

        @property
        def __symbols__(self):
            res, = self
            for r in res: yield r

    class disp(interface.namedtypedtuple, interface.symbol_t):
        '''A tuple for an arm operand containing the (Rn, Offset).'''
        _fields = ('Rn', 'offset')
        _types = (register_t, long)

        register = property(fget=operator.itemgetter(0))
        offset = property(fget=operator.itemgetter(1))

        @property
        def __symbols__(self):
            r, _ = self
            yield r

    class phrase(interface.namedtypedtuple, interface.symbol_t):
        '''A tuple for an arm operand containing the (Rn, Rm).'''
        _fields = ('Rn', 'Rm')
        _types = (register_t, register_t)

        register = property(fget=operator.itemgetter(0))
        offset = property(fget=operator.itemgetter(1))

        @property
        def __symbols__(self):
            r, _ = self
            yield r

    class mem(interface.namedtypedtuple, interface.symbol_t):
        """A tuple for an arm memory operand containing the (address, value).
        `address` contains the actual value that's stored within the operand.
        `value` contains the dereferenced value at the operand's address.
        """
        _fields = ('address', 'value')
        _types = (long, long)

        @property
        def __symbols__(self):
            raise StopIteration
            yield   # so that this function is still treated as a generator

class Intel(architecture_t):
    """An implementation of the Intel architecture.
    This can be used to locate registers that are of a specific size
    or are related to another set of registers.
    """
    def __init__(self):
        super(Intel, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        [ setitem('r'+_, self.new('r'+_, 64, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
        [ setitem('r'+_, self.new('r'+_, 64)) for _ in map(str,range(8,16)) ]
        [ setitem('e'+_, self.child(self.by_name('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
        [ setitem('r'+_+'d', self.child(self.by_name('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(str,range(8,16)) ]
        [ setitem('r'+_+'w', self.child(self.by_name('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(str,range(8,16)) ]
        [ setitem('r'+_+'b', self.child(self.by_name('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(str,range(8,16)) ]
        [ setitem(    _, self.child(self.by_name('e'+_), _, 0, 16)) for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip') ]
        [ setitem(_+'h', self.child(self.by_name(_+'x'), _+'h', 8, 8)) for _ in ('a','c','d','b') ]
        [ setitem(_+'l', self.child(self.by_name(_+'x'), _+'l', 0, 8)) for _ in ('a','c','d','b') ]
        [ setitem(_+'l', self.child(self.by_name(_), _+'l', 0, 8)) for _ in ('sp','bp','si','di') ]
        [ setitem(    _, self.new('es',16)) for _ in ('es','cs','ss','ds','fs','gs') ]
        setitem('fpstack', self.new('fptags', 80*8, dtyp=None))    # FIXME: is this the right IDA register name??

        # FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit
        for _ in ('ax','cx','dx','bx','sp','bp','si','di','ip'):
            r32, r64 = getitem('e'+_), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }
        for _ in map(str,range(8,16)):
            r32, r64 = getitem('r'+_+'d'), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }

        # explicitly set the lookups for (word-register,idaapi.dt_byte) which exist due to ida's love for the inconsistent
        [ self.__cache__.setdefault((_+'x', self.by_name(_+'l').type), self.by_name(_+'l').__name__) for _ in ('a','c','d','b') ]

        fpstack = self.__register__.fpstack
        # single precision
        [ setitem('st{:d}f'.format(_), self.child(fpstack, 'st{:d}f'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_float)) for _ in range(8) ]
        # double precision
        [ setitem('st{:d}d'.format(_), self.child(fpstack, 'st{:d}d'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_double)) for _ in range(8) ]
        # umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
        [ setitem('st{:d}'.format(_), self.child(fpstack, 'st{:d}'.format(_), _*80, 80, 'st{:d}'.format(_), dtyp=idaapi.dt_tbyte)) for _ in range(8) ]

        # not sure if the mmx registers trash the other 16 bits of an fp register
        [ setitem('mm{:d}'.format(_), self.child(fpstack, 'mm{:d}'.format(_), _*80, 64, dtyp=idaapi.dt_qword)) for _ in range(8) ]

        # sse1/sse2 simd registers
        [ setitem('xmm{:d}'.format(_), self.new('xmm{:d}'.format(_), 128, dtyp=idaapi.dt_byte16)) for _ in range(16) ]
        [ setitem('ymm{:d}'.format(_), self.new('ymm{:d}'.format(_), 128, dtyp=idaapi.dt_ldbl)) for _ in range(16) ]

        ##fpctrl, fpstat, fptags
        ##mxcsr
        ## 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',

class AArch32(architecture_t):
    """An implementation of the AArch32 architecture.
    This class is used to locate registers by name, index, or size.
    """
    def __init__(self):
        super(AArch32, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        [ setitem('v{:d}'.format(_), self.new('v{:d}'.format(_), 128, idaname='V{:d}'.format(_))) for _ in range(32) ]
        [ setitem('q{:d}'.format(_), self.new('q{:d}'.format(_), 128, idaname='Q{:d}'.format(_))) for _ in range(32) ]

        for _ in range(32):
            rv, rq = getitem('v{:d}'.format(_)), getitem('q{:d}'.format(_))
            rv.alias, rq.alias = { rq }, { rv }

        [ setitem('r{:d}'.format(_), self.new('r{:d}'.format(_), 32, idaname='R{:d}'.format(_))) for _ in range(13) ]
        [ setitem(_, self.new(_, 32, _.upper())) for _ in ('sp', 'lr', 'pc') ]

        [ setitem('d{:d}'.format(_), self.child(getitem('v{:d}'.format(_)), 'd{:d}'.format(_), 0, 64, idaname='D{:d}'.format(_))) for _ in range(32) ]
        [ setitem('s{:d}'.format(_), self.child(getitem('d{:d}'.format(_)), 's{:d}'.format(_), 0, 32, idaname='S{:d}'.format(_))) for _ in range(32) ]

        # FIXME: include x registers

def __newprc__(id):
    plfm, m = idaapi.ph.id, __import__('sys').modules[__name__]
    if plfm == idaapi.PLFM_386:     # id == 15
        m.reg = Intel()
        m.register = m.reg.r
    elif plfm == idaapi.PLFM_ARM:   # id == 1
        m.reg = AArch32()
        m.register = m.reg.r
    else:
        logging.warn('{:s} : IDP_Hooks.newprc({:d}) : {:d} : Unknown processor type. instruction module might not work properly.'.format(__name__, id, plfm))
    return
__newprc__(0)

# FIXME: implement switch_t to determine information about switch statements with an instruction

### FIXME: the following code is entirely dependant on the intel architecture, fix it or delete it
# an intermediary representation for operands/operations
OOBIS = collections.namedtuple('OpOffsetBaseIndexScale', ('op','offset','base','index','scale'))

## tag:intel
class ir_op:
    """Returns an operand as a parseable intermediary representation"""
    class __base__(object):
        def __init__(self, size=0):
            self.__size = size
        name = property(fget=lambda s: s.__class__.__name__)
        size = property(fget=lambda s: s.__size)
        def str(self):
            return '{:s}({:d})'.format(self.name, self.size)
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
            return isinstance(self, other) if isinstance(other, __builtin__.type) else super(object, self) == other
    class store(__base__): pass
    class load(__base__): pass
    class loadstore(__base__): pass
    class assign(__base__): pass
    class value(__base__): pass
    class modify(__base__): pass
    class unknown(__base__): pass

## tag:intel
class ir:
    """Returns a sort-of intermediary representation that excludes the semantics of an instruction."""
    table = {
        'immediate':     {'r':ir_op.value,   'w':ir_op.assign, 'rw':ir_op.modify,    '':ir_op.value},
        'address':    {'r':ir_op.load,    'w':ir_op.store,  'rw':ir_op.loadstore, '':ir_op.unknown},
        'phrase':  {'r':ir_op.load,    'w':ir_op.store,  'rw':ir_op.loadstore, '':ir_op.unknown},
        'register':     {'r':ir_op.value,   'w':ir_op.assign, 'rw':ir_op.modify,    '':ir_op.unknown},
    }

    @utils.multicase(opnum=six.integer_types)
    @classmethod
    def op(cls, opnum): return cls.op(ui.current.address(), opnum)
    @utils.multicase(ea=six.integer_types, opnum=six.integer_types)
    @classmethod
    def op(cls, ea, opnum):
        """Returns an operand as a tuple.

        (store,immediate,register,index,scale)
        (load,immediate,register,index,scale)
        (value,immediate,register,index,scale)
        (assign,immediate,register,index,scale)
        """
        op,state = operand(ea, opnum), op_state(ea, opnum)
        t, sz = __optype__.lookup(op), __optype__.size(op)
        operation = cls.table[t.__name__][state]

        # if mnemonic is lea, then demote it from a memory operation
        # FIXME: i don't like this hack.
        if mnem(ea).upper() == 'LEA':
            if operation == ir_op.load:
                operation = ir_op.value
            elif operation == ir_op.store:
                operation = ir_op.assign
            else:
                operation = operation

        if t.__name__ == 'phrase':
            imm,base,index,scale = t(op)
        elif t.__name__ in ('immediate', 'address'):
            imm,base,index,scale = t(op),None,None,None
        else:
            imm,base,index,scale = None,t(op),None,None

        if operation == ir_op.load:
            sz = database.config.bits() // 8

        base = None if base is None else reg(base, size=sz)
        index = None if index is None else reg(index, size=sz)

        return OOBIS(operation(__optype__.size(op)),*(imm,base,index,scale))

    @utils.multicase()
    @classmethod
    def instruction(cls): return cls.instruction(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def instruction(cls, ea):
        result = []
        for opnum in range(ops_count(ea)):
            operation,offset,base,index,scale = cls.op(ea, opnum)
            sz = operation.size
            if operation == ir_op.modify:
                result.append(OOBIS(ir_op.assign(sz),offset,base,index,scale))
                result.append(OOBIS(ir_op.value(sz),offset,base,index,scale))
            elif operation == ir_op.loadstore:
                result.append(OOBIS(ir_op.load(sz),offset,base,index,scale))
                result.append(OOBIS(ir_op.store(sz),offset,base,index,scale))
            else:
                result.append(OOBIS(operation,offset,base,index,scale))
            continue

        # if mnemonic is stack-related, then add the other implicit operation
        # FIXME: ...and another pretty bad hack to figure out how to remove
        sp,sz = register.sp.id,database.config.bits()/8
        if mnem(ea).upper() == 'PUSH':
            result.append(OOBIS(ir_op.store(sz), 0, reg(sp,size=sz), 0, 1))
        elif mnem(ea).upper() == 'POP':
            result.append(OOBIS(ir_op.load(sz), 0, reg(sp,size=sz), 0, 1))
        elif mnem(ea).upper().startswith('RET'):
            if len(result) > 0:
                result.append(OOBIS(ir_op.modify(sz), 0, reg(sp,size=sz), 0, 1))
            result.append(OOBIS(ir_op.load(sz), 0, reg(sp,size=sz), 0, 1))
        elif mnem(ea).upper() == 'CALL':
            result.append(OOBIS(ir_op.store(sz), 0, reg(sp,size=sz), 0, 1))

        return mnem(ea),result
    at = utils.alias(instruction, 'ir')

    @utils.multicase()
    @classmethod
    def value(cls): return cls.value(ui.current.address())
    @utils.multicase()
    @classmethod
    def value(cls, ea):
        _,res = cls.at(ea)
        value = [v for v in res if v.op == 'value']
        return value

    @utils.multicase()
    @classmethod
    def store(cls): return cls.store(ui.current.address())
    @utils.multicase()
    @classmethod
    def store(cls, ea):
        _,res = cls.at(ea)
        store = [v for v in res if v.op == 'store']
        return store

    @utils.multicase()
    @classmethod
    def load(cls): return cls.load(ui.current.address())
    @utils.multicase()
    @classmethod
    def load(cls, ea):
        _,res = cls.at(ea)
        load = [v for v in res if v.op == 'load']
        return load

    @utils.multicase()
    @classmethod
    def assign(cls): return cls.assign(ui.current.address())
    @utils.multicase()
    @classmethod
    def assign(cls, ea):
        _,res = cls.at(ea)
        assign = [v for v in res if v.op == 'assign']
        return assign
