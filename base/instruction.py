"""
Instruction module

This module exposes a number of tools for interacting with an
instruction defined within the database. There are three types
of tools within this module and each can be distinguished by their
prefixes which can be used to decode the operands for an instruction.
At the present time, only the Intel, AArch32 (ARM), and MIPS
architectures are supported.

Although IDA internally uses the ``idaapi.insn_t`` and ``idaapi.op_t``
to represent an instruction and its operands, this module's base
argument type is typically an address or an operand index. When
dealing with an instruction's operands, the ``ops_`` prefix represents
all of the instructions operands and typically will take only an
address.  Likewise when dealing with a single operand, the ``op_``
prefix is used and will take an address and the operand index.

To request the actual IDA types (``idaapi.insn_t`` and ``idaapi.op_t``)
there are two tools that are provided. The ``instruction.at`` tool will
take an address and return an ``idaapi.insn_t``. To get an operand type
(``idaapi.op_t``), a user can use ``instruction.operand``.  This will
take an address and an operand index and return the desired type.

Some globals are also defined for the given architecture which
can be used to query or access the registers that are currently
available. Once IDA has determined the architecture for the database
the ``register_t`` class is instantiated for each available register.
This object allows one to reference any register that is defined for
the architecture.

Another object that is created is the ``architecture_t`` object.
Searching for a register can be done by index and size or simply by
its name. This object also allows one to promote or demote a register
between its various sizes. This allows one to navigate between the
8-bit, 16-bit, 32-bit, or 64-bit versions of a register available in
the architecture.
"""

import six
from six.moves import builtins

import functools, operator, itertools, types
import logging, collections

import database, function
import structure, enumeration
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

## operand types
@document.hidden
class __optype__(object):
    """
    This namespace is a registration table for all the different operand
    type decoders available for the known architectures. This is used
    for looking up an operand according to the operand and processor
    types.
    """
    cache = {}
    @classmethod
    def define(cls, processor, type):
        '''Register the operand decoder for the specfied `processor` an `type`'''
        def decorator(fn):
            res = processor, type
            return cls.cache.setdefault(res, fn)
        return decorator

    @classmethod
    def lookup(cls, type, processor=None):
        '''Lookup the operand decoder for a specific `type` and `processor`.'''
        try: return cls.cache[processor or idaapi.ph.id, type]
        except KeyError: return cls.cache[0, type]

    @classmethod
    def decode(cls, ea, op, processor=None):
        '''Using the specified `processor`, decode the operand `op` at the specified address `ea`.'''
        res = cls.lookup(op.type, processor=processor)
        return res(ea, op)

    @classmethod
    def type(cls, op, processor=None):
        '''Return the operand type's name for the specified `processor` and `op`.'''
        res = cls.lookup(op.type, processor=processor)
        return res.__name__

    @classmethod
    def size(cls, op, processor=None):
        '''Return the size of the operand identified by `op` for the specified `processor`.'''
        return idaapi.get_dtyp_size(op.dtyp)

## general functions
@utils.multicase()
def at():
    '''Returns the ``idaapi.insn_t`` instance at the current address.'''
    return at(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def at(ea):
    '''Returns the ``idaapi.insn_t`` instance at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.at({:#x}) : Unable to decode a non-instruction at specified address.".format(__name__, ea))
    length = idaapi.decode_insn(ea)
    if idaapi.__version__ < 7.0:
        return idaapi.cmd.copy()

    tmp = idaapi.insn_t()
    tmp.assign(idaapi.cmd)
    return tmp

@utils.multicase()
def size():
    '''Returns the length of the instruction at the current address.'''
    return size(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def size(ea):
    '''Returns the length of the instruction at the address `ea`.'''
    return at(ea).size

@utils.multicase()
def feature():
    '''Returns the feature bitmask of the instruction at the current address.'''
    return feature(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def feature(ea):
    '''Return the feature bitmask for the instruction at the address `ea`.'''
    if database.is_code(ea):
        return at(ea).get_canon_feature()
    return None

@document.aliases('mnem')
@utils.multicase()
def mnemonic():
    '''Returns the mnemonic of the instruction at the current address.'''
    return mnemonic(ui.current.address())
@document.aliases('mnem')
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def mnemonic(ea):
    '''Returns the mnemonic of the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    res = (idaapi.ua_mnem(ea) or '').lower()
    return utils.string.of(res)
mnem = utils.alias(mnemonic)

## functions that return an ``idaapi.op_t`` for an operand
@utils.multicase()
def operands():
    '''Returns all of the ``idaapi.op_t`` instances for the instruction at the current address.'''
    return operands(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def operands(ea):
    '''Returns all of the ``idaapi.op_t`` instances for the instruction at the address `ea`.'''
    insn = at(ea)

    # take operands until we encounter an idaapi.o_void
    res = itertools.takewhile(utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), insn.Operands)

    # if we're using IDA < 7.0, then make copies of each instruction and return it
    if idaapi.__version__ < 7.0:
        return tuple(op.copy() for op in res)

    # otherwise, we need to make an instance of it and then assign to make a copy
    res = ((idaapi.op_t(), op) for op in res)
    return tuple([n.assign(op), n][1] for n, op in res)

@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def operand(opnum):
    '''Returns the ``idaapi.op_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return operand(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def operand(ea, opnum):
    '''Returns the ``idaapi.op_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    insn = at(ea)

    # IDA < 7.0 means we can just call .copy() to duplicate it
    if idaapi.__version__ < 7.0:
        return insn.Operands[opnum].copy()

    # Otherwise we'll need to instantiate it, and then .assign() into it
    res = idaapi.op_t()
    res.assign(insn.Operands[opnum])
    return res

## functions vs all operands of an insn
@utils.multicase()
def ops_count():
    '''Returns the number of operands of the instruction at the current address.'''
    return ops_count(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_count(ea):
    '''Returns the number of operands of the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return len(operands(ea))

@utils.multicase()
def ops_repr():
    '''Returns a tuple of the ``op_repr`` of all the operands for the instruction at the current address.'''
    return ops_repr(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_repr(ea):
    '''Returns a tuple of the ``op_repr`` of all the operands for the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_repr, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))

@document.aliases('ops_value')
@utils.multicase()
def ops():
    '''Returns a tuple of all the operands for the instruction at the current address.'''
    return ops(ui.current.address())
@document.aliases('ops_value')
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops(ea):
    '''Returns a tuple of all the operands for the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))
ops_value = utils.alias(ops)

@utils.multicase()
def ops_size():
    '''Returns a tuple with all the sizes of each operand for the instruction at the current address.'''
    return ops_size(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_size(ea):
    '''Returns a tuple with all the sizes of each operand for the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = utils.fcompose(functools.partial(operand, ea), operator.attrgetter('dtyp'), idaapi.get_dtyp_size, int)
    return tuple(map(f, six.moves.range(ops_count(ea))))

@document.aliases('ops_type')
@utils.multicase()
def opts():
    '''Returns a tuple of the types for all the operands in the instruction at the current address.'''
    return ops_type(ui.current.address())
@document.aliases('ops_type')
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def opts(ea):
    '''Returns a tuple of the types for all the operands in the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(opt, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))
ops_type = utils.alias(opts)

@utils.multicase()
def ops_state():
    '''Returns a tuple for all the operands containing one of the states "r", "w", or "rw"` describing how the operands for the current instruction operands are modified.'''
    return ops_state(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_state(ea):
    '''Returns a tuple of for all the operands containing one of the states "r", "w", or "rw" describing how the operands are modified for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = feature(ea)
    res = ( ((f&ops_state.read[i]), (f&ops_state.write[i])) for i in six.moves.range(ops_count(ea)) )
    return tuple((r and 'r' or '') + (w and 'w' or '') for r, w in res)

# pre-cache the CF_ flags from idaapi inside ops_state
ops_state.read, ops_state.write = zip(*((getattr(idaapi, "CF_USE{:d}".format(idx + 1), 1 << (7 + idx)), getattr(idaapi, "CF_CHG{:d}".format(idx + 1), 1 << (1 + idx))) for idx in six.moves.range(idaapi.UA_MAXOP)))

@utils.multicase()
def ops_read():
    '''Returns the indices of any operands that are being read from by the instruction at the current address.'''
    return ops_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_read(ea):
    '''Returns the indices of any operands that are being read from by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'r' in state)

@utils.multicase()
def ops_write():
    '''Returns the indices of the operands that are being written to by the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_write(ea):
    '''Returns the indices of the operands that are being written to by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'w' in state)

@document.aliases('ops_const')
@utils.multicase()
def ops_constant():
    '''Return the indices of any operands in the current instruction that are constants.'''
    return ops_constant(ui.current.address())
@document.aliases('ops_const')
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='the address of an instruction')
def ops_constant(ea):
    '''Return the indices of any operands in the instruction at `ea` that are constants.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, value in enumerate(ops_value(ea)) if isinstance(value, six.integer_types))
ops_const = utils.alias(ops_constant)

@document.aliases('ops_reg', 'ops_regs')
@utils.multicase(reg=(basestring, interface.register_t))
@document.parameters(reg='the register to search the operands for', regs='any other registers to include', modifiers='if ``write`` is specified, then only return operands that write to the specified registers. if ``read`` is specified then do the same but for operands that read from them.')
def ops_register(reg, *regs, **modifiers):
    """Yields the index of each operand in the instruction at the current address that uses `reg` or any one of the registers in `regs`.

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    return ops_register(ui.current.address(), reg, *regs, **modifiers)
@document.aliases('ops_reg', 'ops_regs')
@utils.multicase(reg=(basestring, interface.register_t))
@document.parameters(ea='the address of an instruction', reg='the register to search the operands for', regs='any other registers to include', modifiers='if ``write`` is specified, then only return operands that write to the specified registers. if ``read`` is specified then do the same but for operands that read from them.')
def ops_register(ea, reg, *regs, **modifiers):
    """Yields the index of each operand in the instruction at address `ea` that uses `reg` or any one of the registers in `regs`.

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    uses = interface.regmatch.use( (reg,) + regs )
    return tuple(filter(functools.partial(uses, ea), iterops(ea)))
ops_reg = ops_regs = utils.alias(ops_register)

## functions vs a specific operand of an insn
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_repr(opnum):
    '''Returns the representation for the operand `opnum` belonging to the instruction at the current address.'''
    return op_repr(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_repr(ea, opnum):
    '''Returns the representation for the operand `opnum` belonging to the instruction at the address `ea`.'''
    insn = at(ea)
    oppr = idaapi.ua_outop2 if idaapi.__version__ < 7.0 else idaapi.print_operand
    outop = utils.fcompose(idaapi.ua_outop2, idaapi.tag_remove) if idaapi.__version__ < 7.0 else utils.fcompose(idaapi.print_operand, idaapi.tag_remove)
    try:
        res = outop(insn.ea, opnum) or "{:s}".format(op(insn.ea, opnum))
    except:
        logging.warn(u"{:s}({:#x}, {:d}) : Unable to strip tags from operand \"{:s}\". Returning the result from {:s} instead.".format('.'.join((__name__, 'op_repr')), ea, opnum, utils.string.escape(oppr(insn.ea, opnum), '"'), '.'.join((__name__, 'op'))))
        return u"{!s}".format(op(insn.ea, opnum))
    return utils.string.of(res)

@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_state(opnum):
    '''Returns the modification state for the operand `opnum` belonging to the current instruction.'''
    return op_state(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_state(ea, opnum):
    """Returns the modification state for the operand `opnum` belonging to the instruction at the address `ea`.

    The returned state is a string that can be "r", "w", or "rw" depending on
    whether the operand is being read from, written to, or modified (both).
    """
    f = feature(ea)
    r, w = f&ops_state.read[opnum], f&ops_state.write[opnum]
    return (r and 'r' or '') + (w and 'w' or '')

@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_size(opnum):
    '''Returns the size for the operand `opnum` belonging to the current instruction.'''
    return op_size(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_size(ea, opnum):
    '''Returns the size for the operand `opnum` belonging to the instruction at the address `ea`.'''
    res = operand(ea, opnum)
    return 0 if res.type == idaapi.o_void else idaapi.get_dtyp_size(res.dtyp)
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_bits(opnum):
    '''Returns the size (in bits) for the operand `opnum` belonging to the current instruction.'''
    return 8 * op_size(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_bits(ea, opnum):
    '''Returns the size (in bits) for the operand `opnum` belonging to the instruction at the address `ea`.'''
    return 8 * op_size(ea, opnum)

@document.aliases('op_type')
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def opt(opnum):
    '''Returns the type of the operand `opnum` belonging to the current instruction.'''
    return opt(ui.current.address(), opnum)
@document.aliases('op_type')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def opt(ea, opnum):
    """Returns the type of the operand `opnum` belonging to the instruction at the address `ea`.

    The types returned are dependant on the architecture.
    """
    res = operand(ea, opnum)
    return __optype__.type(res)
op_type = utils.alias(opt)

#@utils.multicase(opnum=six.integer_types)
#@document.parameters(opnum='the operand number of the current instruction')
#def op_decode(opnum):
#    '''Returns the value of the operand `opnum` in byte form belonging to the current instruction (if possible).'''
#    raise NotImplementedError
#@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
#@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
#def op_decode(ea, opnum):
#    '''Returns the value of the operand `opnum` in byte form belonging to the instruction at address `ea`.'''
#    raise NotImplementedError

@document.aliases('op_value', 'op_decode')
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op(opnum):
    '''Decodes the operand `opnum` for the current instruction.'''
    return op(ui.current.address(), opnum)
@document.aliases('op_value', 'op_decode')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op(ea, opnum):
    '''Decodes the operand `opnum` for the instruction at the address `ea`.'''
    res = operand(ea, opnum)
    return __optype__.decode(ea, res)
op_value = op_decode = utils.alias(op)

## older typeinfo stuff
# idaapi.set_typeinfo(ea, opnum, flags, ti)
# idaapi.get_typeinfo(ea, opnum, &flags, &buf)
# idaapi.typeflag(ea, &oldflag, type, opnum)

## XXX: maybe figure out if there's some way to do this generically
# idaapi.set_op_type(ea, type, opnum)

## XXX: figure out a useful name to implement the following to apply a data offset to an operand
# def? op_offset(ea, opnum, type, target = BADADDR, base = 0, tdelta = 0) -> int

## XXX: maybe we should figure out how to use this if we can distinguish between a structure_t and a frame's member_t
# def op_stkvar(*args):

## old method for applying a complex type to an operand
# def op_type(ea, opnum)
#    '''Apply the specified type to a stack variable'''
#    py_op = operand(ea, opnum)
#    py_v = py_op.addr
#    py_t = idc.ParseType("type string", flags)[1]
#    py_name = "stack variable name"
#    idaapi.apply_type_to_stkarg(py_op, py_v, py_t, py_name)

## XXX: deprecate this, and somehow associate the segment register with the operand for the intel arch
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_segment(opnum):
    '''Returns the segment register used by the operand `opnum` for the instruction at the current address.'''
    return op_segment(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_segment(ea, opnum):
    '''Returns the segment register used by the operand `opnum` for the instruction at the address `ea`.'''
    op = operand(ea, opnum)
    segment  = (op.specval & 0xffff0000) >> 16
    selector = (op.specval & 0x0000ffff) >> 0
    if segment:
        global architecture
        return architecture.by_index(segment)
    #raise NotImplementedError("{:s}.op_segment({:#x}, {:d}) : Unable to determine the segment register for the specified operand number. {!r} was returned.".format(__name__, ea, opnum, segment))
    return None
# FIXME: maybe use idaapi.op_seg(*args) to apply a segment to an operand?

@document.aliases('op_struc', 'op_struct')
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_structure(opnum):
    '''Return the structure that operand `opnum` at the current instruction actually references.'''
    return op_structure(ui.current.address(), opnum)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_structure(ea, opnum):
    '''Return the structure that operand `opnum` for instruction `ea` actually references.'''
    ti, fl, op = idaapi.opinfo_t(), database.type.flags(ea), operand(ea, opnum)
    if all(fl & ff != ff for ff in {idaapi.FF_STRUCT, idaapi.FF_0STRO, idaapi.FF_1STRO}):
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:#x}) : Operand {:d} does not contain a structure.".format(__name__, ea, opnum, opnum))

    # pathvar = idaapi.tid_array(length)
    # idaapi.get_stroff_path(ea, opnum, pathvar.cast(), delta)
    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if res is None:
        raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:#x}) : Unable to get operand info for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, fl))

    # get the path and the delta
    delta, path = res.path.delta, [res.path.ids[idx] for idx in six.moves.range(res.path.len)]
    value = op.addr if op.type in {idaapi.o_displ, idaapi.o_phrase} else op.value

    # if it's a single path, then convert it to a multiple entry path
    if len(path) == 1:
        # get the member offset of the operand
        st = structure.by(path[0])
        try:
            m = st.by(value)

        # if we couldn't find one, then figure out whether to use
        # the last or first member depending where we are
        except E.OutOfBoundsError:
            if value > st.members[-1].offset:
                m = st.members[-1]
            elif value < st.members[0].offset:
                m = st.members[0]
            else:
                raise

        # now to build the path that gets walked
        path = [st.id, m.id]

    # if there's no path, then this is not a structure
    elif len(path) == 0:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:#x}) : Operand {:d} does not contain a structure.".format(__name__, ea, opnum, opnum))

    # collect all the path members
    moff, st = 0, structure.by(path.pop(0))
    res = [st]
    for pid in path:
        st = st.by_identifier(pid)
        res.append(st)
        moff, st = moff + st.offset, st.type

    ofs = delta - moff + value
    return tuple(res + [ofs]) if ofs != 0 else tuple(res)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(opnum=six.integer_types, structure=(structure.structure_t, structure.member_t))
@document.parameters(opnum='the operand number of the current instruction', structure='the `structure_t` to apply', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(opnum, structure, **delta):
    '''Apply the specified `structure` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, [structure], **delta)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(opnum=six.integer_types, id=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction', id='the id of a structure', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(opnum, id, **delta):
    '''Apply the structure identified by `id` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, id, **delta)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(opnum=six.integer_types, path=(types.TupleType, types.ListType))
@document.parameters(opnum='the operand number of the current instruction', path='an iterable containing structures, members, or integers that is used to calculate the offset into the structure to apply to the operand', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(opnum, path, **delta):
    '''Apply the structure members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, path, **delta)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, structure=(structure.structure_t, structure.member_t))
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', structure='the `structure_t` to apply', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(ea, opnum, structure, **delta):
    '''Apply the specified `structure` to the instruction operand `opnum` at the address `ea`.'''
    return op_structure(ea, opnum, structure.id, **delta)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', id='the id of a structure', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(ea, opnum, id, **delta):
    """Apply the structure identified by `id` to the instruction operand `opnum` at the address `ea`.

    If the offset `delta` is specified, shift the structure by that amount.
    """
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.op_structure({:#x}, {:#x}, {:#x}{:s}) : Item type at requested address is not of a code type.".format(__name__, ea, opnum, id, ", {:s}".format(utils.string.kwargs(delta)) if delta else ''))

    offset, sptr, name = 0, idaapi.get_struc(id), idaapi.get_member_fullname(id)
    if sptr is not None:
        offset = idaapi.get_struc_first_offset(sptr)
        sid, mptr = sptr.id, idaapi.get_member(sptr, offset)
        if mptr is None:
            raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:#x}, {:#x}{:s}) : Unable to locate the first member of the structure with the specified id.".format(__name__, ea, opnum, id, ", {:s}".format(utils.string.kwargs(delta)) if delta else ''))
        mid = mptr.id
    elif name is not None:
        fn = idaapi.get_member_fullname(id)
        sptr = idaapi.get_member_struc(name)
        sid, mid = sptr.id, id
    else:
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:#x}, {:#x}{:s}) : Unable to locate the structure member for the specified id.".format(__name__, ea, opnum, id, ", {:s}".format(utils.string.kwargs(delta)) if delta else ''))

    # if an offset was specified such as if the first member of the structure
    # is not at offset 0, then adjust the delta by its value
    if offset:
        delta['delta'] = delta.get('delta', 0) - offset

    st = structure.by(sid)
    m = st.by_identifier(mid)
    return op_structure(ea, opnum, [st, m], **delta)
@document.aliases('op_struc', 'op_struct')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, path=(types.TupleType, types.ListType))
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', path='an iterable containing structures, members, or integers that is used to calculate the offset into the structure to apply to the operand', delta='if ``delta`` is specified as an integer, then offset the structure by it')
def op_structure(ea, opnum, path, **delta):
    """Apply the structure members in `path` to the instruction operand `opnum` at the address `ea`.

    If the offset `delta` is specified, shift the structure by that amount.
    """
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : Item type at requested address is not of a code type.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # validate the path
    if len(path) == 0:
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : No structure members were specified.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    if any(not isinstance(m, (structure.structure_t, structure.member_t, basestring)+six.integer_types) for m in path):
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : A member of an invalid type was specified.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # ensure the path begins with a structure.structure_t
    if isinstance(path[0], structure.member_t):
        path[0:0] = [path[0].owner]

    # crop elements to valid ones in case the delta is specified at the end
    res = list(itertools.takewhile(lambda t: not isinstance(t, six.integer_types), path))
    if len(res) < len(path):
        res.append(path[len(res)])

    if len(res) < len(path):
        logging.warn(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : Culling path down to {:d} elements due to an invalid type discovered in the structure path.".format(__name__, ea, opnum, path, delta.get('delta', 0), len(path) - len(res) + 1))
    path = res[:]

    # if the delta is in the path, move it into the delta kwarg
    if isinstance(path[-1], six.integer_types):
        delta['delta'] = delta.get('delta', 0) + path.pop(-1)

    # figure out the structure that this all starts with
    sptr, path = path[0].ptr, list(path)

    # collect each member resolving them to an id
    moff, tids = 0, []
    for i, item in enumerate(path[1:]):
        if isinstance(item, basestring):
            m = idaapi.get_member_by_name(sptr, item)
        elif isinstance(item, structure.member_t):
            m = item.ptr
        else:
            raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : Item {:d} in the specified path is of an unsupported type ({!r}).".format(__name__, ea, opnum, path, delta.get('delta', 0), i+1, item.__class__))
        tids.append(m.id)
        moff += m.soff

        # if member is not a structure, then terminate the loop
        mptr = idaapi.get_sptr(m)
        if not mptr:
            break

        # continue to the next iteration
        res = mptr

    # check what was different
    if len(path) != len(tids) + 1:
        logging.warn(u"{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : There was an error trying to determine the path for the list of members (not all members were pointing to structures).".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # build the list of member ids and prefix it with a structure id
    length = len(tids) + 1
    tid = idaapi.tid_array(length)
    tid[0] = sptr.id
    for i, id in enumerate(tids):
        tid[i + 1] = id

    # figure out the real position (ida handles this actually)
    # value = operand(ea, opnum).value if opt(ea, opnum) == 'immediate' else operand(ea, opnum).addr
    ofs = moff + delta.get('delta', 0)

    # grab the base offset to factor it into the calculation of the struct member
    baseoffset = path[0].members.baseoffset

    # now we can finally apply the path to the specified operand
    ok = idaapi.op_stroff(ea, opnum, tid.cast(), length, ofs - baseoffset)
    #ok = idaapi.set_stroff_path(ea, opnum, tid.cast(), length, moff - ofs)

    return True if ok else False
op_struc = op_struct = utils.alias(op_structure)

@document.aliases('op_enum')
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_enumeration(opnum):
    '''Return the enumeration id of operand `opnum` for the current instruction.'''
    return op_enumeration(ui.current.address(), opnum)
@document.aliases('op_enum')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_enumeration(ea, opnum):
    '''Return the enumeration id of operand `opnum` for the instruction at `ea`.'''
    ti, fl = idaapi.opinfo_t(), database.type.flags(ea)
    if all(fl & n == 0 for n in (idaapi.FF_0ENUM, idaapi.FF_1ENUM)):
        raise E.MissingTypeOrAttribute(u"{:s}.op_enumeration({:#x}, {:#x}) : Operand {:d} does not contain an enumeration.".format(__name__, ea, opnum, opnum))

    # XXX: is the following api call the proper way to do this?
    # idaapi.get_enum_id(*args):

    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if res is None:
        raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:#x}) : Unable to get operand info for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, fl))
    return enumeration.by(res.ec.tid)
@document.aliases('op_enum')
@utils.multicase(opnum=six.integer_types, name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(opnum='the operand number of the current instruction', name='the name of the enumeration to apply')
def op_enumeration(opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the current instruction.'''
    return op_enumeration(ui.current.address(), opnum, enumeration.by(name))
@document.aliases('op_enum')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', name='the name of the enumeration to apply')
def op_enumeration(ea, opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the instruction at `ea`.'''
    return op_enumeration(ea, opnum, enumeration.by(name))
@document.aliases('op_enum')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=six.integer_types+(types.TupleType,))
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', id='the identifer of an enumeration to apply')
def op_enumeration(ea, opnum, id):
    '''Apply the enumeration `id` to operand `opnum` of the instruction at `ea`.'''
    return idaapi.op_enum(ea, opnum, *id) if isinstance(id, types.TupleType) else idaapi.op_enum(ea, opnum, id, 0)
op_enum = utils.alias(op_enumeration)

@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_string(opnum):
    '''Return the string type of operand `opnum` for the current instruction.'''
    return op_string(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_string(ea, opnum):
    '''Return the string type (``idaapi.STRTYPE_``) of operand `opnum` for the instruction at `ea`.'''
    ti, fl = idaapi.opinfo_t(), database.type.flags(ea)
    if fl & idaapi.FF_STRLIT == 0:
        raise E.MissingTypeOrAttribute(u"{:s}.op_string({:#x}, {:#x}) : Operand {:d} does not contain a literate string.".format(__name__, ea, opnum, opnum))

    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if res is None:
        raise E.DisassemblerError(u"{:s}.op_string({:#x}, {:#x}) : Unable to get operand info for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, fl))

    return res.strtype
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, strtype=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction', strtype='an IDA string type to apply to the operand')
def op_string(ea, opnum, strtype):
    '''Set the string type used by operand `opnum` for the instruction at `ea` to `strtype`.'''
    res, fl = idaapi.opinfo_t(), database.type.flags(ea)

    fl |= idaapi.FF_STRLIT
    res.strtype = strtype

    ok = idaapi.set_opinfo(ea, opnum, fl, res)

    # FIXME: verify that set_opinfo was actually applied by checking via get_opinfo
    return True if ok else False

## flags
@document.aliases('op_ref')
@utils.multicase(opnum=six.integer_types)
@document.parameters(opnum='the operand number of the current instruction')
def op_refs(opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the current instruction.'''
    return op_refs(ui.current.address(), opnum)
@document.aliases('op_ref')
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
@document.parameters(ea='the address of an instruction', opnum='the operand number of the instruction')
def op_refs(ea, opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the instruction at `ea`.'''
    inst = at(ea)

    # sanity: returns whether the operand has a local or global xref
    F = database.type.flags(inst.ea)
    ok = idaapi.op_adds_xrefs(F, opnum) ## FIXME: on tag:arm, this returns T for some operands

    # FIXME: gots to be a better way to determine operand representation
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(inst.ea, opnum, F, ti)

    # FIXME: this is incorrect on ARM for the 2nd op in `ADD R7, SP, #0x430+lv_dest_41c`
    # stkvar
    if ok and res is None:
        fn = idaapi.get_func(ea)
        if fn is None:
            raise E.FunctionNotFoundError(u"{:s}.op_refs({:#x}, {:d}) : Unable to locate function for address {:#x}.".format(__name__, ea, opnum, ea))

        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, inst.ea if idaapi.__version__ < 7.0 else inst, opnum)

        # check that the stkofs_ from get_stkvar and calc_stkvar are the same
        op = operand(inst.ea, opnum)

        res = interface.sval_t(op.addr).value
        if idaapi.__version__ < 7.0:
            member, stkofs = idaapi.get_stkvar(op, res)
        else:
            member, stkofs = idaapi.get_stkvar(inst, op, res)

        if stkofs != stkofs_:
            logging.warn(u"{:s}.op_refs({:#x}, {:d}) : The stack offset for the instruction operand ({:#x}) does not match what was expected ({:#x}).".format(__name__, inst.ea, opnum, stkofs, stkofs_))

        # build the xrefs
        xl = idaapi.xreflist_t()
        idaapi.build_stkvar_xrefs(xl, fn, member)
        res = [ interface.OREF(x.ea, int(x.opnum), interface.ref_t.of(x.type)) for x in xl ]
        # FIXME: how do we handle the type for an LEA instruction which should include '&'...

    # struc member
    elif ok and res.tid != idaapi.BADADDR:    # FIXME: is this right?
        # structures are defined in a supval at index 0xf+opnum
        # the supval has the format 0001c0xxxxxx where 'x' is the low 3 bytes of the structure id

        # structure member xrefs (outside function)
        pathvar = idaapi.tid_array(1)
        delta = idaapi.sval_pointer()
        delta.assign(0)
        if idaapi.__version__ < 7.0:
            ok = idaapi.get_stroff_path(inst.ea, opnum, pathvar.cast(), delta.cast())
        else:
            ok = idaapi.get_stroff_path(pathvar.cast(), delta.cast(), inst.ea, opnum)
        if not ok:
            raise E.DisassemblerError(u"{:s}.op_refs({:#x}, {:d}) : Unable to get structure id for operand.".format(__name__, inst.ea, opnum))

        # get the structure offset and then use that to figure out the correct member
        addr = operator.attrgetter('value' if idaapi.__version__ < 7.0 else 'addr')     # FIXME: this will be incorrect for an offsetted struct
        memofs = addr(operand(inst.ea, opnum)) + delta.value()

        # FIXME: use interface.node.sup_opstruct to figure out the actual path to search for

        st = idaapi.get_struc(pathvar[0])
        if st is None:
            raise E.DisassemblerError(u"{:s}.op_refs({:#x}, {:d}) : Unable to get structure pointer for id {:#x}.".format(__name__, inst.ea, opnum, pathvar[0]))

        # get the member at the specified offset in order to snag its id
        mem = idaapi.get_member(st, memofs)
        if mem is None:
            # if memofs does not point to the size of structure, then warn that we're falling back to the structure
            if memofs != idaapi.get_struc_size(st):
                logging.warn(u"{:s}.op_refs({:#x}, {:d}) : Unable to find the member for offset ({:#x}) in the structure {:#x}. Falling back to references to the structure itself.".format(__name__, inst.ea, opnum, memofs, st.id))
            mem = st

        # extract the references
        x = idaapi.xrefblk_t()

        if not x.first_to(mem.id, 0):
            logging.warn(u"{:s}.op_refs({:#x}, {:d}) : No references found to struct member \"{:s}\".".format(__name__, inst.ea, opnum, utils.string.escape(mem.fullname, '"')))

        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # now figure out the operands if there are any
        res = []
        for ea, _, t in refs:
            ops = ((idx, internal.netnode.sup.get(ea, 0xf + idx)) for idx in six.moves.range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf + idx) is not None)
            ops = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx, val in ops)
            ops = (idx for idx, ids in ops if st.id in ids)
            res.extend( interface.OREF(ea, int(op), interface.ref_t.of(t)) for op in ops)
        res = res

    # enums
    elif ok and res.tid != idaapi.BADADDR:
        e = enumeration.by_identifier(res.tid)
        # enums are defined in a altval at index 0xb+opnum
        # the int points straight at the enumeration id
        # FIXME: references to enums don't seem to work
        raise E.UnsupportedCapability(u"{:s}.op_refs({:#x}, {:d}) : References are not implemented for enumeration types.".format(__name__, inst.ea, opnum))

    # FIXME: is this supposed to execute if ok == T? or not?
    # global
    else:
        # anything that's just a reference is a single-byte supval at index 0x9+opnum
        # 9 -- '\x02' -- offset to segment 2
        gid = operand(inst.ea, opnum).value if operand(inst.ea, opnum).type in {idaapi.o_imm} else operand(inst.ea, opnum).addr
        x = idaapi.xrefblk_t()
        if not x.first_to(gid, 0):
            return []

        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # now figure out the operands if there are any
        res = []
        for ea, _, t in refs:
            if ea == idaapi.BADADDR: continue
            if database.type.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:
                ops = ((idx, operand(ea, idx).value if operand(ea, idx).type in {idaapi.o_imm} else operand(ea, idx).addr) for idx in six.moves.range(ops_count(ea)))
                ops = (idx for idx, val in ops if val == gid)
                res.extend( interface.OREF(ea, int(op), interface.ref_t.of(t)) for op in ops)
            else:
                res.append( interface.OREF(ea, None, interface.ref_t.of(t)) )
            continue
        res = res
    return res
op_ref = utils.alias(op_refs)

## types of instructions
class type(object):
    """
    This namespace is for fetching information about the instruction
    type at a given address within the database. The functions within
    this namespace return a boolean based on whether the instruction at
    the given address fits a particular type.

    It is prudent to note that the information that these functions
    expose are essentially flags for the instruction and is provided
    in order to allow a user to infer how IDA has processed the
    instruction. These flags are used by IDA in order to determine
    things such as whether or not it should continue disassembling,
    or if it should add the instruction's operand to its queue in
    order to recursively disassemble code witin the database.

    This namespace is also aliased as ``instruction.t``.

    Some examples of using this namespace are::

        > print instruction.type.is_return(ea)
        > print instruction.type.is_jxx(ea)
        > print instruction.type.is_call(ea)
        > print instruction.type.is_branch(ea)

    """
    @document.aliases('is_return', 'type.isReturn', 'type.returnQ', 'type.retQ', 'isReturn', 'returnQ', 'retQ')
    @utils.multicase()
    @classmethod
    def is_return(cls):
        '''Returns true if the current instruction is a return-type instruction.'''
        return cls.is_return(ui.current.address())
    @document.aliases('is_return', 'type.isReturn', 'type.returnQ', 'type.retQ', 'isReturn', 'returnQ', 'retQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_return(cls, ea):
        '''Returns true if the instruction at `ea` is a return-type instruction.'''
        ea = interface.address.inside(ea)
        returnQ = lambda ea: feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP

        # Older versions of IDA required idaapi.cmd to be populated for is_ret_insn to work.
        if hasattr(idaapi, 'is_ret_insn'):
            idaapi.decode_insn(ea)
            returnQ = idaapi.is_ret_insn

        return database.is_code(ea) and returnQ(ea)
    isReturn = returnQ = retQ = utils.alias(is_return, 'type')

    @document.aliases('is_shift', 'type.isShift', 'type.shiftQ', 'isShift', 'shiftQ')
    @utils.multicase()
    @classmethod
    def is_shift(cls):
        '''Returns true if the current instruction is a bit-shifting instruction.'''
        return cls.is_shift(ui.current.address())
    @document.aliases('is_shift', 'type.isShift', 'type.shiftQ', 'isShift', 'shiftQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_shift(cls, ea):
        '''Returns true if the instruction at `ea` is a bit-shifting instruction.'''
        ea = interface.address.inside(ea)
        return database.is_code(ea) and feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
    isShift = shiftQ = utils.alias(is_shift, 'type')

    @document.aliases('is_branch', 'type.isBranch', 'type.branchQ', 'isBranch', 'branchQ')
    @utils.multicase()
    @classmethod
    def is_branch(cls):
        '''Returns true if the current instruction is any kind of branch.'''
        return cls.is_branch(ui.current.address())
    @document.aliases('is_branch', 'type.isBranch', 'type.branchQ', 'isBranch', 'branchQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_branch(cls, ea):
        '''Returns true if the instruction at `ea` is any kind of branch.'''
        ea = interface.address.inside(ea)
        return database.is_code(ea) and cls.is_jmp(ea) or cls.is_jxx(ea) or cls.is_jmpi(ea)
    isBranch = branchQ = utils.alias(is_branch, 'type')

    @document.aliases('is_jmp', 'type.isJmp', 'type.JmpQ', 'type.jmpQ', 'isJmp', 'JmpQ', 'jmpQ', 'isJmp')
    @utils.multicase()
    @classmethod
    def is_jmp(cls):
        '''Returns true if the current instruction is an immediate and indirect branch.'''
        return cls.is_jmp(ui.current.address())
    @document.aliases('is_jmp', 'type.isJmp', 'type.JmpQ', 'type.jmpQ', 'isJmp', 'JmpQ', 'jmpQ', 'isJmp')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_jmp(cls, ea):
        '''Returns true if the instruction at `ea` is an immediate and indrect branch.'''
        ea = interface.address.inside(ea)

        F, X = feature(ea), interface.xiterate(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)
        return database.is_code(ea) and (F & idaapi.CF_CALL != idaapi.CF_CALL) and (F & idaapi.CF_STOP == idaapi.CF_STOP) and len(list(X)) == 1 and not cls.is_return(ea)
    isJmp = jmpQ = utils.alias(is_jmp, 'type')

    @document.aliases('is_jxx', 'type.isJxx', 'type.JxxQ', 'type.jxxQ', 'isJxx', 'JxxQ', 'jxxQ')
    @utils.multicase()
    @classmethod
    def is_jxx(cls):
        '''Returns true if the current instruction is a conditional branch.'''
        return cls.is_jxx(ui.current.address())
    @document.aliases('is_jxx', 'type.isJxx', 'type.JxxQ', 'type.jxxQ', 'isJxx', 'JxxQ', 'jxxQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_jxx(cls, ea):
        '''Returns true if the instruction at `ea` is a conditional branch.'''
        ea = interface.address.inside(ea)

        F, X = feature(ea), interface.xiterate(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)
        return database.is_code(ea) and all((F&x != x) for x in {idaapi.CF_CALL, idaapi.CF_STOP}) and len(list(X)) > 1
    isJxx = jxxQ = utils.alias(is_jxx, 'type')

    @document.aliases('is_jmpi', 'type.isJmpi', 'type.JmpiQ', 'type.jmpiQ', 'isJmpi', 'JmpiQ', 'jmpiQ')
    @utils.multicase()
    @classmethod
    def is_jmpi(cls):
        '''Returns true if the instruction at the current address is an indirect branch.'''
        return cls.is_jmpi(ui.current.address())
    @document.aliases('is_jmpi', 'type.isJmpi', 'type.JmpiQ', 'type.jmpiQ', 'isJmpi', 'JmpiQ', 'jmpiQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_jmpi(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect branch.'''
        ea = interface.address.inside(ea)
        F = feature(ea)
        return database.is_code(ea) and (F & idaapi.CF_CALL != idaapi.CF_CALL) and (F & idaapi.CF_JUMP == idaapi.CF_JUMP)
    isJmpi = jmpiQ = utils.alias(is_jmpi, 'type')

    @document.aliases('is_call', 'type.isCall', 'type.callQ', 'isCall', 'callQ')
    @utils.multicase()
    @classmethod
    def is_call(cls):
        '''Returns true if the current instruction is a call.'''
        return cls.is_call(ui.current.address())
    @document.aliases('is_call', 'type.isCall', 'type.callQ', 'isCall', 'callQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_call(cls, ea):
        '''Returns true if the instruction at `ea` is a call.'''
        ea = interface.address.inside(ea)
        if hasattr(idaapi, 'is_call_insn'):
            idaapi.decode_insn(ea)
            return idaapi.is_call_insn(ea)

        F = feature(ea)
        return database.is_code(ea) and (feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL)
    isCall = callQ = utils.alias(is_call, 'type')

    @document.aliases('is_calli', 'type.isCalli', 'type.calliQ', 'isCalli', 'calliQ')
    @utils.multicase()
    @classmethod
    def is_calli(cls):
        '''Return true if the current instruction is an indirect call.'''
        return cls.is_calli(ui.current.address())
    @document.aliases('is_calli', 'type.isCalli', 'type.calliQ', 'isCalli', 'calliQ')
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @document.parameters(ea='the address of an instruction')
    def is_calli(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect call.'''
        ea = interface.address.inside(ea)
        F = feature(ea)
        return cls.is_call(ea) and all(F&x == x for x in {idaapi.CF_CALL, idaapi.CF_JUMP})
    isCalli = calliQ = utils.alias(is_calli, 'type')

t = type    # XXX: ns alias

is_return = returnQ = retQ = utils.alias(type.is_return, 'type')
is_shift = shiftQ = utils.alias(type.is_shift, 'type')
is_branch = branchQ = utils.alias(type.is_branch, 'type')
is_jmp = jmpQ = utils.alias(type.is_jmp, 'type')
is_jxx = jxxQ = utils.alias(type.is_jxx, 'type')
is_jmpi = jmpiQ = utils.alias(type.is_jmpi, 'type')
is_call = callQ = utils.alias(type.is_call, 'type')
is_calli = calliQ = utils.alias(type.is_calli, 'type')

## operand type registration
## XXX: This namespace is deleted after each method has been assigned to their lookup table
@document.hidden
class operand_types:
    """
    This internal namespace is responsible for registering the operand
    type handlers for each architecture inside ``__optype__`` and is
    deleted after they are registered.
    """
    @__optype__.define(idaapi.PLFM_386, idaapi.o_void)
    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_void)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_void)
    def void(ea, op):
        '''Operand type decoder for ``idaapi.o_void``.'''
        return ()

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_reg)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_reg)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_reg)
    def register(ea, op):
        '''Operand type decoder for ``idaapi.o_reg`` which returns a ``register_t``.'''
        global architecture
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtyp_by_size
        if op.type in {idaapi.o_reg}:
            res, dt = op.reg, dtype_by_size(database.config.bits()//8)
            return architecture.by_indextype(res, op.dtyp)
        optype = "{:s}({:d})".format('idaapi.o_reg', idaapi.o_reg)
        raise E.InvalidTypeOrValueError(u"{:s}.register({:#x}, {!r}) : Expected operand type `{:s}` but operand type {:d} was received.".format('.'.join((__name__, 'operand_types')), ea, op, optype, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_imm)
    def immediate(ea, op):
        '''Operand type decoder for ``idaapi.o_imm`` which returns an integer.'''
        if op.type in {idaapi.o_imm, idaapi.o_phrase}:
            bits = idaapi.get_dtyp_size(op.dtyp) * 8

            # figure out the sign flag
            sf, res = 2 ** (bits - 1), op.value

            # if op.value has its sign inverted, then signify it otherwise just use it
            return -2 ** bits + res if interface.node.alt_opinverted(ea, op.n) else res & (2 ** bits - 1)
        optype = "{:s}({:d})".format('idaapi.o_imm', idaapi.o_imm)
        raise E.InvalidTypeOrValueError(u"{:s}.immediate({:#x}, {!r}) : Expected operand type `{:s}` but operand type {:d} was received.".format('.'.join((__name__, 'operand_types')), ea, op, optype, op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_far)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_near)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_near)
    def memory(ea, op):
        '''Operand type decoder for memory-type operands which return an address.'''
        if op.type in {idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ}:
            seg, sel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
            return op.addr
        optype = map(utils.funbox("{:s}({:d})".format), [('idaapi.o_far', idaapi.o_far), ('idaapi.o_near', idaapi.o_near)])
        raise E.InvalidTypeOrValueError(u"{:s}.address({:#x}, {!r}) : Expected operand type `{:s}` or `{:s}` but operand type {:d} was received.".format('.'.join((__name__, 'operand_types')), ea, op, optype[0], optype[1], op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec0)
    def trregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec0`` which returns a trap register.'''
        raise E.UnsupportedCapability(u"{:s}.trregister({:#x}, ...) : Trap registers (`%trX`) are not implemented for the Intel platform.".format('.'.join((__name__, 'operand_types')), ea))
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec1)
    def dbregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec1`` which returns a db register.'''
        raise E.UnsupportedCapability(u"{:s}.dbregister({:#x}, ...) : Db registers (`%dbX`) are not implemented for the Intel platform.".format('.'.join((__name__, 'operand_types')), ea))
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec2)
    def crregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec2`` which returns a control reigster.'''
        raise E.UnsupportedCapability(u"{:s}.crregister({:#x}, ...) : Cr registers (`%crX`) are not implemented for the Intel platform.".format('.'.join((__name__, 'operand_types')), ea))
        return getattr(reg, "cr{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec3)
    def fpregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec3`` which returns an fpu register.'''
        return getattr(reg, "st{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec4)
    def mmxregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec4`` which returns an mmx register.'''
        return getattr(reg, "mm{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec5)
    def xmmregister(ea, op):
        '''Operand type decoder for Intel's ``idaapi.o_idpspec5`` which returns an xmm register.'''
        return getattr(reg, "xmm{:d}".format(op.reg)).id

    @__optype__.define(idaapi.PLFM_386, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_displ)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_phrase)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory phrase on Intel.'''
        F1, F2 = op.specflag1, op.specflag2
        if op.type in {idaapi.o_displ, idaapi.o_phrase}:
            if F1 == 0:
                base = op.reg
                index = None

            elif F1 == 1:
                base = (F2 & 0x07) >> 0
                index = (F2 & 0x38) >> 3

            else:
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the operand format for op.type {:d}. The value of `op_t.specflag1` was {:d}.".format('.'.join((__name__, 'operand_types')), ea, op, op.type, F1))

            if op.type == idaapi.o_displ:
                offset = op.addr
            elif op.type == idaapi.o_phrase:
                offset = op.value
            else:
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the offset for op.type ({:d}).".format('.'.join((__name__, 'operand_types')), ea, op, op.type))

            # XXX: for some reason stack variables include both base and index
            #      testing .specval seems to be a good way to determine whether
            #      something is referencing the stack
            if op.specval & 0x00ff0000 == 0x001f0000 and index == base:
                index = None

            ## specval means kind of the following:
            # OF_NO_BASE_DISP = 1 then .addr doesn't exist
            # OF_OUTER_DISP = 1 then .value exists

            ## op_t.flags:
            # OF_NO_BASE_DISP = 0x80 #  o_displ: base displacement doesn't exist meaningful only for o_displ type if set, base displacement (x.addr) doesn't exist.
            # OF_OUTER_DISP = 0x40 #  o_displ: outer displacement exists meaningful only for o_displ type if set, outer displacement (x.value) exists.
            # PACK_FORM_DEF = 0x20 #  !o_reg + dt_packreal: packed factor defined
            # OF_NUMBER = 0x10 # can be output as number only if set, the operand can be converted to a number only
            # OF_SHOW = 0x08 #  should the operand be displayed? if clear, the operand is hidden and should not be displayed

        elif op.type == idaapi.o_mem:
            if F1 == 0:
                base = None
                index = None

            elif F1 == 1:
                base = None
                index = (F2 & 0x38) >> 3

            else:
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the operand format for op.type {:d}. The value of `op_t.specflag1` was {:d}.".format('.'.join((__name__, 'operand_types')), ea, op, op.type, F1))
            offset = op.addr

        else:
            optype = map(utils.funbox("{:s}({:d})".format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
            raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Expected operand type {:s}, {:s}, or {:s} but operand type {:d} was received.".format('.'.join((__name__, 'operand_types')), ea, op, optype[0], optype[1], optype[2], op.type))

        # if arch == x64, then index += 8

        scale_lookup = {
            0x00 : 1,   # 00
            0x40 : 2,   # 01
            0x80 : 4,   # 10
            0xc0 : 8,   # 11
        }
        scale = scale_lookup[F2 & 0xc0]

        bits = database.config.bits()
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtyp_by_size

        seg, sel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0

        global architecture
        sf, dt = 2 ** (bits - 1), dtype_by_size(database.config.bits() // 8)

        inverted, regular = offset & (2 ** bits - 1) if offset & sf else -2 ** bits + offset, -2 ** bits + offset if offset & sf else offset & (sf - 1)
        res = long(inverted) if interface.node.alt_opinverted(ea, op.n) else long(regular), None if base is None else architecture.by_indextype(base, dt), None if index is None else architecture.by_indextype(index, dt), scale
        return intelops.OffsetBaseIndexScale(*res)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_phrase)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory phrase on ARM.'''
        global architecture
        Rn, Rm = architecture.by_index(op.reg), architecture.by_index(op.specflag1)
        return armops.phrase(Rn, Rm)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_displ)
    def disp(ea, op):
        '''Operand type decoder for returning a memory displacement on ARM.'''
        global architecture
        Rn = architecture.by_index(op.reg)
        return armops.disp(Rn, long(op.addr))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_mem)
    def memory(ea, op):
        '''Operand type decoder for returning a memory referece on ARM.'''
        # get the address and the operand size
        addr, size = op.addr, idaapi.get_dtyp_size(op.dtyp)
        maxval = 1<<size*8

        # dereference the address and return its integer.
        res = idaapi.get_many_bytes(addr, size) or ''
        res = reversed(res) if database.config.byteorder() == 'little' else iter(res)
        res = reduce(lambda agg, n: (agg*0x100)|n, six.iterbytes(res), 0)
        sf = bool(res & maxval>>1)

        return armops.mem(long(addr), long(res-maxval) if sf else long(res))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec0)
    def flex(ea, op):
        '''Operand type decoder for returning a flexible operand (shift-op) on ARM.'''
        global architecture

        Rn = architecture.by_index(op.reg)
        shift = 0   # FIXME: find out where the shift "type" is stored
        return armops.flex(Rn, int(shift), int(op.value))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec1)
    def list(ea, op):
        '''Operand type decoder for returning a register list on ARM.'''
        global architecture
        res = set()

        # op.specval represents a bitmask specifying which registers are included
        specval = op.specval
        for index in six.moves.range(16):
            if specval & 1:
                res.add(architecture.by_index(index))
            specval >>= 1
        return armops.list(res)

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_displ)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory displacement on MIPS.'''
        global architecture

        rt, imm = architecture.by_index(op.reg), op.addr
        return mipsops.phrase(rt, imm)

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_idpspec1)
    def coprocessor(ea, op):
        '''Operand type decoder for returning a co-processor register on MIPS.'''
        return mipsops.coproc(op.reg)
del(operand_types)

## intel operands
@document.namespace
class intelops:
    """
    This internal namespace contains the different operand types that
    can be returned for the Intel architecture.
    """
    @document.classdef
    class SegmentOffset(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing an address with a segment register attached for Intel.

        Has the format `(segment, offset)` where `segment` is a segment register.
        """
        _fields = ('segment', 'offset')
        _types = (
            (types.NoneType, interface.register_t),
            six.integer_types,
        )

        @property
        def symbols(self):
            '''Yield the `segment` register from the tuple if it is defined.'''
            s, _ = self
            if s is not None: yield s
    SO = SegmentOffset

    @document.classdef
    class SegmentOffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory phrase for the Intel architecture.

        Has the format `(segment, offset, base, index, scale)` where
        `segment` includes the segment register and `base` and
        `index` are both optional registers.
        """
        _fields = ('segment', 'offset', 'base', 'index', 'scale')
        _types = (
            (types.NoneType, interface.register_t),
            six.integer_types,
            (types.NoneType, interface.register_t),
            (types.NoneType, interface.register_t),
            six.integer_types,
        )

        @property
        def symbols(self):
            '''Yield the `segment`, `base`, and the `index` registers from the tuple if they are defined.'''
            s, _, b, i, _ = self
            if s is not None: yield s
            if b is not None: yield b
            if i is not None: yield i
    SOBIS = SegmentOffsetBaseIndexScale

    @document.classdef
    class OffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory phrase for the Intel architecture.

        Has the format `(offset, base, index, scale)` where both
        `base` and `index` are both optional registers.
        """
        _fields = ('offset', 'base', 'index', 'scale')
        _types = (
            six.integer_types,
            (types.NoneType, interface.register_t),
            (types.NoneType, interface.register_t),
            six.integer_types,
        )

        @property
        def symbols(self):
            '''Yield the `base`, and the `index` registers from the tuple if they are defined.'''
            _, b, i, _ = self
            if b is not None: yield b
            if i is not None: yield i
    OBIS = OffsetBaseIndexScale

## arm operands
@document.namespace
class armops:
    """
    This internal namespace contains the different operand types that
    can be returned for the ARM architecture.
    """

    @document.classdef
    class flex(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a flexible operand as available on the ARM architecture.

        Has the format `(Rn, shift, n)` which allows the architecture to apply
        a binary shift or rotation to the value of a register `Rn`.
        """
        _fields = ('Rn', 'shift', 'n')
        _types = (
            interface.register_t,
            six.integer_types,
            six.integer_types
        )

        register = property(fget=operator.itemgetter(0))
        t = type = property(fget=operator.itemgetter(1))
        imm = immediate = property(fget=operator.itemgetter(2))

        @property
        def symbols(self):
            '''Yield the `Rn` register from the tuple.'''
            r, _, _ = self
            yield r

    @document.classdef
    class list(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a register list on the ARM architecture.

        Has the simple format `(reglist,)` where `reglist` is a set of registers
        that can be explicitly tested for membership.
        """
        _fields = ('reglist', )
        _types = (set, )

        @property
        def symbols(self):
            '''Yield any of the registers within the `reglist` field belonging to the tuple.'''
            res, = self
            for r in res: yield r

    @document.classdef
    class disp(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory displacement on the ARM architecture.

        Has the format `(Rn, Offset)` where `Rn` is a register and `Offset` is
        the integer that is added to the register.
        """
        _fields = ('Rn', 'offset')
        _types = (
            interface.register_t,
            six.integer_types,
        )

        register = property(fget=operator.itemgetter(0))
        offset = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            '''Yield the `Rn` register from the tuple.'''
            r, _ = self
            yield r

    @document.classdef
    class phrase(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a memory phrase on the ARM architecture

        Has the format `(Rn, Rm)` where both are registers that compose the
        phrase.
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
            rn, rm = self
            yield rn
            yield rm

    @document.classdef
    class mem(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a memory operand on the ARM architecture.

        Has the format `(address, value)` where `address` is the actual value
        stored in the operand and `value` is the value that is dereferenced.
        """
        _fields = ('address', 'value')
        _types = (six.integer_types, six.integer_types)

        @property
        def symbols(self):
            '''This operand type is not composed of any symbols.'''
            raise StopIteration
            yield   # so that this function is still treated as a generator

## mips operands
@document.namespace
class mipsops:
    """
    This internal namespace contains the different operand types that
    can be returned for the MIPS architecture.
    """

    @document.classdef
    class phrase(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a memory phrase on the MIPS architecture.

        Has the format `(Rn, Offset)` where `Rn` is the register and
        `Offset` is the immediate that is added to the register.
        """
        _fields = ('Rn', 'Offset')
        _types = (interface.register_t, six.integer_types)

        register = property(fget=operator.itemgetter(0))
        immediate = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            '''Yield the `Rn` register from this tuple.'''
            r, _ = self
            yield r

    @document.hidden
    @staticmethod
    def coproc(regnum):
        """
        A callable that returns a co-processor for the MIPS architecture.

        Takes a `regnum` argument which returns the correct register.
        """
        global register, architecture
        res = {
            0x00 : register.Index, 0x01 : register.Random, 0x02 : register.EntryLo0, 0x03 : register.EntryLo1,
            0x04 : register.Context, 0x05 : register.PageMask, 0x06 : register.Wired, 0x08 : register.BadVAddr,
            0x09 : register.Count, 0x0a : register.EntryHi, 0x0b : register.Compare, 0x0c : register.SR,
            0x0d : register.Cause, 0x0e : register.EPC, 0x0f : register.PRId, 0x10 : register.Config,
            0x11 : register.LLAddr, 0x12 : register.WatchLo, 0x13 : register.WatchHi, 0x14 : register.XContext,
            0x1a : register.ECC, 0x1b : register.CacheErr, 0x1c : register.TagLo, 0x1d : register.TagHi,
            0x1e : register.ErrorEPC,
        }
        return res[regnum] if regnum in res else architecture.by_name("{:d}".format(regnum))

## architecture registers
@document.classdef
class Intel(interface.architecture_t):
    """
    An implementation of all the registers available on the Intel architecture.

    This keeps track of the relationships between registers to allow one to
    promote or demote a register to the different sizes that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is Intel.
    """
    prefix = ''
    def __init__(self):
        super(Intel, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__
        i2s = "{:d}".format

        [ setitem('r'+_, self.new('r'+_, 64, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_, self.new('r'+_, 64)) for _ in map(i2s, six.moves.range(8, 16)) ]
        [ setitem('e'+_, self.child(self.by_name('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_+'d', self.child(self.by_name('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(i2s, six.moves.range(8, 16)) ]
        [ setitem('r'+_+'w', self.child(self.by_name('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(i2s, six.moves.range(8, 16)) ]
        [ setitem('r'+_+'b', self.child(self.by_name('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(i2s, six.moves.range(8, 16)) ]
        [ setitem(    _, self.child(self.by_name('e'+_), _, 0, 16)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem(_+'h', self.child(self.by_name(_+'x'), _+'h', 8, 8)) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_+'x'), _+'l', 0, 8)) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_), _+'l', 0, 8)) for _ in ('sp', 'bp', 'si', 'di') ]
        [ setitem(    _, self.new(_, 16)) for _ in ('es', 'cs', 'ss', 'ds', 'fs', 'gs') ]
        setitem('fpstack', self.new('fptags', 80*8, dtyp=None))    # FIXME: is this the right IDA register name??

        # FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit
        for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip'):
            r32, r64 = getitem('e'+_), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }
        for _ in map(i2s, six.moves.range(8, 16)):
            r32, r64 = getitem('r'+_+'d'), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }

        # explicitly set the lookups for (word-register, idaapi.dt_byte) which exist due to ida's love for the inconsistent
        [ self.__cache__.setdefault((_+'x', self.by_name(_+'l').dtype), self.by_name(_+'l').__name__) for _ in ('a', 'c', 'd', 'b') ]

        fpstack = self.__register__.fpstack
        # single precision
        [ setitem("st{:d}f".format(_), self.child(fpstack, "st{:d}f".format(_), _*80, 80, "st{:d}".format(_), dtyp=idaapi.dt_float)) for _ in six.moves.range(8) ]
        # double precision
        [ setitem("st{:d}d".format(_), self.child(fpstack, "st{:d}d".format(_), _*80, 80, "st{:d}".format(_), dtyp=idaapi.dt_double)) for _ in six.moves.range(8) ]
        # umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
        [ setitem("st{:d}".format(_), self.child(fpstack, "st{:d}".format(_), _*80, 80, "st{:d}".format(_), dtyp=idaapi.dt_tbyte)) for _ in six.moves.range(8) ]

        # not sure if the mmx registers trash the other 16 bits of an fp register
        [ setitem("mm{:d}".format(_), self.child(fpstack, "mm{:d}".format(_), _*80, 64, dtyp=idaapi.dt_qword)) for _ in six.moves.range(8) ]

        # sse1/sse2 simd registers
        [ setitem("xmm{:d}".format(_), self.new("xmm{:d}".format(_), 128, dtyp=idaapi.dt_byte16)) for _ in six.moves.range(16) ]
        [ setitem("ymm{:d}".format(_), self.new("ymm{:d}".format(_), 128, dtyp=idaapi.dt_ldbl)) for _ in six.moves.range(16) ]

        ##fpctrl, fpstat, fptags
        ##mxcsr
        ## 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',

@document.classdef
class AArch32(interface.architecture_t):
    """
    An implementation of all the registers available on the AArch32 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is ARM.
    """
    prefix = '%'
    def __init__(self):
        super(AArch32, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        [ setitem("v{:d}".format(_), self.new("v{:d}".format(_), 128, idaname="V{:d}".format(_))) for _ in six.moves.range(32) ]
        [ setitem("q{:d}".format(_), self.new("q{:d}".format(_), 128, idaname="Q{:d}".format(_))) for _ in six.moves.range(32) ]

        for _ in six.moves.range(32):
            rv, rq = getitem("v{:d}".format(_)), getitem("q{:d}".format(_))
            rv.alias, rq.alias = { rq }, { rv }

        [ setitem("r{:d}".format(_), self.new("r{:d}".format(_), 32, idaname="R{:d}".format(_))) for _ in six.moves.range(13) ]
        [ setitem(_, self.new(_, 32, _.upper())) for _ in ('sp', 'lr', 'pc') ]

        [ setitem("d{:d}".format(_), self.child(getitem("v{:d}".format(_)), "d{:d}".format(_), 0, 64, idaname="D{:d}".format(_))) for _ in six.moves.range(32) ]
        [ setitem("s{:d}".format(_), self.child(getitem("d{:d}".format(_)), "s{:d}".format(_), 0, 32, idaname="S{:d}".format(_))) for _ in six.moves.range(32) ]

        # FIXME: include x registers

@document.classdef
class Mips(interface.architecture_t):
    """
    An implementation of all the registers available on the MIPS architecture.

    This includes the different co-processor registers that are also available
    but are treated as special instructions by IDA.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is MIPS.
    """
    prefix = '$'
    def __init__(self):
        super(Mips, self).__init__()
        getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

        setitem('zero', self.new('zero', 32, idaname='$zero'))
        setitem('at', self.new('at', 32, idaname='$at'))
        [ setitem("v{:d}".format(_), self.new("v{:d}".format(_), 32, idaname="$v{:d}".format(_))) for _ in six.moves.range(2) ]
        [ setitem("a{:d}".format(_), self.new("a{:d}".format(_), 32, idaname="$a{:d}".format(_))) for _ in six.moves.range(4) ]
        [ setitem("t{:d}".format(_), self.new("t{:d}".format(_), 32, idaname="$t{:d}".format(_))) for _ in six.moves.range(8) ]
        [ setitem("s{:d}".format(_), self.new("s{:d}".format(_), 32, idaname="$s{:d}".format(_))) for _ in six.moves.range(8) ]
        [ setitem("t{:d}".format(_), self.new("t{:d}".format(_), 32, idaname="$t{:d}".format(_))) for _ in six.moves.range(8, 10) ]
        [ setitem("k{:d}".format(_), self.new("k{:d}".format(_), 32, idaname="$k{:d}".format(_))) for _ in six.moves.range(2) ]
        setitem('gp', self.new('gp', 32, idaname='$gp'))
        setitem('sp', self.new('sp', 32, idaname='$sp'))
        setitem('fp', self.new('fp', 32, idaname='$fp'))
        setitem('ra', self.new('ra', 32, idaname='$ra'))
        [ setitem("f{:d}".format(_), self.new("f{:d}".format(_), 32, idaname="$f{:d}".format(_))) for _ in six.moves.range(32) ]
        setitem('pc', self.new('pc', 32))

        # FIXME: add the register definitions for : cs, ds, mips16

        # coprocessor registers
        setitem('Index', self.new('Index', 32, id=0))
        setitem('Random', self.new('Random', 32, id=0))
        setitem('EntryLo0', self.new('EntryLo0', 32, id=0))
        setitem('EntryLo1', self.new('EntryLo1', 32, id=0))
        setitem('Context', self.new('Context', 32, id=0))
        setitem('PageMask', self.new('PageMask', 32, id=0))
        setitem('Wired', self.new('Wired', 32, id=0))
        setitem('BadVAddr', self.new('BadVAddr', 32, id=0))
        setitem('Count', self.new('Count', 32, id=0))
        setitem('EntryHi', self.new('EntryHi', 32, id=0))
        setitem('Compare', self.new('Compare', 32, id=0))
        setitem('SR', self.new('SR', 32, id=0))
        setitem('Cause', self.new('Cause', 32, id=0))
        setitem('EPC', self.new('EPC', 32, id=0))
        setitem('PRId', self.new('PRId', 32, id=0))
        setitem('Config', self.new('Config', 32, id=0))
        setitem('LLAddr', self.new('LLAddr', 32, id=0))
        setitem('WatchLo', self.new('WatchLo', 32, id=0))
        setitem('WatchHi', self.new('WatchHi', 32, id=0))
        setitem('XContext', self.new('XContext', 32, id=0))
        setitem('ECC', self.new('ECC', 32, id=0))
        setitem('CacheErr', self.new('CacheErr', 32, id=0))
        setitem('TagLo', self.new('TagLo', 32, id=0))
        setitem('TagHi', self.new('TagHi', 32, id=0))
        setitem('ErrorEPC', self.new('ErrorEPC', 32, id=0))

        # unmarked coprocessor registers
        i2s = "{:d}".format
        [ setitem(i2s(_), self.new(i2s(_), 32)) for _ in itertools.chain([7, 31], six.moves.range(20, 26))]

## global initialization
def __ev_newprc__(pnum, keep_cfg):
    return __newprc__(pnum)
def __newprc__(id):
    """
    Determine the architecture from the current processor and use it to initialize
    the globals (``architecture`` and ``register``) within this module.
    """
    plfm, m = idaapi.ph.id, __import__('sys').modules[__name__]
    if plfm == idaapi.PLFM_386:     # id == 15
        res = Intel()
    elif plfm == idaapi.PLFM_ARM:   # id == 1
        res = AArch32()
    elif plfm == idaapi.PLFM_MIPS:  # id == 12
        res = Mips()
    else:
        iogging.warn("{:s} : IDP_Hooks.newprc({:d}) : Unsupported processor type {:d} was specified. Tools that use the instruction module might not work properly.".format(__name__, id, plfm))
        return

    # assign our required globals
    m.architecture, m.register = res, res.r

    # assign some aliases so that its much shorter to type
    m.arch, m.reg = m.architecture, m.register

# initialize with a default processor on the initial import but not on reload()
if 'architecture' not in locals() or 'register' not in locals():
    __newprc__(0)
