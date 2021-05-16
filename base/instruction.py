"""
Instruction module

This module exposes a number of tools for interacting with an
instruction defined within the database. There are three types
of tools within this module and each can be distinguished by their
prefixes which can be used to decode the operands for an instruction.
At the present time, only the Intel, AArch32/AArch64 (ARM), and the
MIPS32/MIPS64 architectures are currently supported.

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

import six, builtins

import functools, operator, itertools, types
import logging, collections, math

import database, function
import structure, enumeration
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

## operand types
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
        '''Register the operand decoder for the specfied `processor` and `type`'''
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
        if idaapi.__version__ < 7.0:
            return idaapi.get_dtyp_size(op.dtyp)
        return idaapi.get_dtype_size(op.dtype)

## general functions
@utils.multicase()
def at():
    '''Returns the ``idaapi.insn_t`` instance at the current address.'''
    return at(ui.current.address())
@utils.multicase(ea=six.integer_types)
def at(ea):
    '''Returns the ``idaapi.insn_t`` instance at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.at({:#x}) : Unable to decode a non-instruction at the specified address ({:#x}).".format(__name__, ea, ea))

    # If we're using backwards-compatiblity mode (which means decode_insn takes
    # different parameters, then manage the result using idaapi.cmd
    if hasattr(idaapi, 'cmd'):
        length = idaapi.decode_insn(ea)
        if idaapi.__version__ < 7.0:
            return idaapi.cmd.copy()

        tmp = idaapi.insn_t()
        tmp.assign(idaapi.cmd)
        return tmp

    # Otherwise we can just use the API as we see fit
    res = idaapi.insn_t()
    length = idaapi.decode_insn(res, ea)
    return res

@utils.multicase()
def size():
    '''Returns the length of the instruction at the current address.'''
    return size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def size(ea):
    '''Returns the length of the instruction at the address `ea`.'''
    return at(ea).size

@utils.multicase(opnum=six.integer_types)
def opinfo(opnum):
    '''Returns the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return opinfo(ui.current.address(), opnum)
@utils.multicase(opnum=six.integer_types, info=idaapi.opinfo_t)
def opinfo(opnum, info, **flags):
    '''Set the opinfo for the operand `opnum` at the current address to the ``idaapi.opinfo_t`` provided by `info`.'''
    return opinfo(ui.current.address(), opnum, info, **flags)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def opinfo(ea, opnum):
    '''Returns the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    ti, flags = idaapi.opinfo_t(), database.type.flags(ea)
    return idaapi.get_opinfo(ea, opnum, flags, ti) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(ti, ea, opnum, flags)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, info=idaapi.opinfo_t)
def opinfo(ea, opnum, info, **flags):
    """Set the operand info for the operand `opnum` at the address `ea` to the ``idaapi.opinfo_t`` provided by `info`.

    If any `flags` have been specified, then also set the operand's flags to the provided value.
    """
    ok = idaapi.set_opinfo(ea, opnum, flags.get('flags', database.type.flags(ea)), info)
    if not ok:
        raise E.DisassemblerError(u"{:s}.opinfo({:#x}, {:d}, {!s}) : Unable to set the operand info for operand {:d}.".format(__name__, ea, opnum, info, opnum))
    return opinfo(ea, opnum)

@utils.multicase()
def mnemonic():
    '''Returns the mnemonic of the instruction at the current address.'''
    return mnemonic(ui.current.address())
@utils.multicase(ea=six.integer_types)
def mnemonic(ea):
    '''Returns the mnemonic of the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.mnemonic({:#x}) : Unable to get the mnemonic for a non-instruction at the specified address ({:#x}).".format(__name__, ea, ea))

    res = (idaapi.ua_mnem(ea) or '').lower()
    return utils.string.of(res)
mnem = utils.alias(mnemonic)

## functions that return an ``idaapi.op_t`` for an operand
@utils.multicase()
def operands():
    '''Returns all of the ``idaapi.op_t`` instances for the instruction at the current address.'''
    return operands(ui.current.address())
@utils.multicase(ea=six.integer_types)
def operands(ea):
    '''Returns all of the ``idaapi.op_t`` instances for the instruction at the address `ea`.'''
    insn = at(ea)

    # if we're in compatibility mode, then old-fashioned IDA requires us to copy
    # our operands into our new types.
    if hasattr(idaapi, 'cmd'):

        # take operands until we encounter an idaapi.o_void
        iterable = itertools.takewhile(utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), insn.Operands)

        # if we're using IDA < 7.0, then make copies of each instruction and return it
        if idaapi.__version__ < 7.0:
            return tuple(op.copy() for op in iterable)

        # otherwise, we need to make an instance of it and then assign to make a copy
        iterable = ((idaapi.op_t(), op) for op in iterable)
        return tuple([n.assign(op), n][1] for n, op in iterable)

    # apparently idaapi is not increasing a reference count for our operands, so we
    # need to make a copy of them quickly before we access them.
    operands = [idaapi.op_t() for index in range(idaapi.UA_MAXOP)]
    [ op.assign(insn.ops[index]) for index, op in enumerate(operands)]

    # now we can just fetch them until idaapi.o_void
    iterable = itertools.takewhile(utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), operands)

    # and return it as a tuple
    return tuple(iterable)

@utils.multicase(opnum=six.integer_types)
def operand(opnum):
    '''Returns the ``idaapi.op_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return operand(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def operand(ea, opnum):
    '''Returns the ``idaapi.op_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    insn = at(ea)
    if opnum >= len(operands(ea)):
        raise E.InvalidTypeOrValueError(u"{:s}.operand({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # If we're using backwards-compatiblity mode then we need to assign the
    # operand into our op_t.
    if hasattr(idaapi, 'cmd'):
        # IDA < 7.0 means we can just call .copy() to duplicate it
        if idaapi.__version__ < 7.0:
            return insn.Operands[opnum].copy()

        # Otherwise we'll need to instantiate it, and then .assign() into it
        res = idaapi.op_t()
        res.assign(insn.Operands[opnum])
        return res

    # Otherwise we need to make a copy of it because IDA will crash if we don't
    res = idaapi.op_t()
    res.assign(insn.ops[opnum])
    return res

## functions vs all operands of an insn
@utils.multicase()
def ops_count():
    '''Returns the number of operands of the instruction at the current address.'''
    return ops_count(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_count(ea):
    '''Returns the number of operands of the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return len(operands(ea))

@utils.multicase()
def ops_repr():
    '''Returns a tuple of the ``op_repr`` of all the operands for the instruction at the current address.'''
    return ops_repr(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_repr(ea):
    '''Returns a tuple of the ``op_repr`` of all the operands for the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_repr, ea)
    return tuple(map(f, range(ops_count(ea))))

@utils.multicase()
def ops():
    '''Returns a tuple of all the operands for the instruction at the current address.'''
    return ops(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops(ea):
    '''Returns a tuple of all the operands for the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op, ea)
    return tuple(map(f, range(ops_count(ea))))
ops_value = utils.alias(ops)

@utils.multicase()
def ops_size():
    '''Returns a tuple with all the sizes of each operand for the instruction at the current address.'''
    return ops_size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_size(ea):
    '''Returns a tuple with all the sizes of each operand for the instruction at the address `ea`.'''
    get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
    get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

    ea = interface.address.inside(ea)
    f = utils.fcompose(functools.partial(operand, ea), get_dtype_attribute, get_dtype_size, int)
    return tuple(map(f, range(ops_count(ea))))

@utils.multicase()
def opts():
    '''Returns a tuple of the types for all the operands in the instruction at the current address.'''
    return ops_type(ui.current.address())
@utils.multicase(ea=six.integer_types)
def opts(ea):
    '''Returns a tuple of the types for all the operands in the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(opt, ea)
    return tuple(map(f, range(ops_count(ea))))
ops_type = utils.alias(opts)

@utils.multicase()
def ops_state():
    '''Returns a tuple for all the operands containing one of the states "r", "w", or "rw"` describing how the operands for the current instruction operands are modified.'''
    return ops_state(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_state(ea):
    '''Returns a tuple of for all the operands containing one of the states "r", "w", or "rw" describing how the operands are modified for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = type.feature(ea)
    res = ( ((f & ops_state.read[i]), (f & ops_state.write[i])) for i in range(ops_count(ea)) )
    return tuple(interface.reftype_t.of_action((r and 'r' or '') + (w and 'w' or '')) for r, w in res)

# pre-cache the CF_ flags from idaapi inside ops_state
ops_state.read, ops_state.write = zip(*((getattr(idaapi, "CF_USE{:d}".format(1 + idx), 1 << (7 + idx)), getattr(idaapi, "CF_CHG{:d}".format(1 + idx), 1 << (1 + idx))) for idx in range(idaapi.UA_MAXOP)))

@utils.multicase()
def opsi_read():
    '''Returns the indices of any operands that are being read from by the instruction at the current address.'''
    return opsi_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
def opsi_read(ea):
    '''Returns the indices of any operands that are being read from by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'r' in state)
@utils.multicase()
def ops_read():
    '''Return the operands that are being read from by the instruction at the current address.'''
    return ops_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_read(ea):
    '''Return the operands that are being read from by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_read(ea))

@utils.multicase()
def opsi_write():
    '''Returns the indices of the operands that are being written to by the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
def opsi_write(ea):
    '''Returns the indices of the operands that are being written to by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'w' in state)
@utils.multicase()
def ops_write():
    '''Return the operands that are being written to by the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_write(ea):
    '''Return the operands that are being written to by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_write(ea))

@utils.multicase()
def opsi_constant():
    '''Return the indices of any operands in the current instruction that are constants.'''
    return ops_constant(ui.current.address())
@utils.multicase(ea=six.integer_types)
def opsi_constant(ea):
    '''Return the indices of any operands in the instruction at `ea` that are constants.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, value in enumerate(ops_value(ea)) if isinstance(value, six.integer_types))
opsi_const = utils.alias(opsi_constant)
@utils.multicase()
def ops_constant():
    '''Return the operands that are being written to by the instruction at the current address.'''
    return ops_constant(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_constant(ea):
    '''Return the operands that are being written to by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_constant(ea))
ops_const = utils.alias(ops_constant)

@utils.multicase()
def opsi_register(**modifiers):
    '''Returns the index of each operand in the instruction at the current address which uses a register.'''
    return ops_register(ui.current.address(), **modifiers)
@utils.multicase(ea=six.integer_types)
def opsi_register(ea, **modifiers):
    '''Returns the index of each operand in the instruction at the address `ea` which uses a register.'''
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    fregisterQ = utils.fcompose(op, utils.fcondition(utils.finstance(interface.symbol_t))(utils.fcompose(utils.fattribute('symbols'), functools.partial(map, utils.finstance(interface.register_t)), any), utils.fconstant(False)))
    return tuple(filter(functools.partial(fregisterQ, ea), iterops(ea)))
@utils.multicase(reg=(six.string_types, interface.register_t))
def opsi_register(reg, *regs, **modifiers):
    '''Returns the index of each operand in the instruction at the current address that uses `reg` or any one of the registers in `regs`.'''
    return ops_register(ui.current.address(), reg, *regs, **modifiers)
@utils.multicase(ea=six.integer_types, reg=(six.string_types, interface.register_t))
def opsi_register(ea, reg, *regs, **modifiers):
    """Returns the index of each operand in the instruction at address `ea` that uses `reg` or any one of the registers in `regs`.

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    uses = interface.regmatch.use( (reg,) + regs )
    return tuple(filter(functools.partial(uses, ea), iterops(ea)))
opsi_regi = opsi_regs = opsi_registers = utils.alias(opsi_register)

@utils.multicase()
def ops_register(**modifiers):
    '''Returns each register operand in the instruction at the current address.'''
    return ops_register(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_register(ea, **modifiers):
    '''Returns each register operand in the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_register(ea, **modifiers))
@utils.multicase(reg=(six.string_types, interface.register_t))
def ops_register(reg, *regs, **modifiers):
    '''Returns each register operand in the instruction at the current address that is `reg` or any one of the registers in `regs`.'''
    return ops_register(ui.current.address(), reg, *regs, **modifiers)
@utils.multicase(ea=six.integer_types, reg=(six.string_types, interface.register_t))
def ops_register(ea, reg, *regs, **modifiers):
    """Returns each register operand in the instruction at the address `ea` that is `reg` or any one of the registers in `regs`.'''

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    return tuple(op(ea, index) for index in opsi_register(ea, reg, *regs, **modifiers))
ops_reg = ops_regs = ops_registers = utils.alias(ops_register)

## functions vs a specific operand of an insn
@utils.multicase(opnum=six.integer_types)
def op_repr(opnum):
    '''Returns the representation for the operand `opnum` belonging to the instruction at the current address.'''
    return op_repr(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_repr(ea, opnum):
    '''Returns the representation for the operand `opnum` belonging to the instruction at the address `ea`.'''
    insn = at(ea)
    oppr = idaapi.ua_outop2 if idaapi.__version__ < 7.0 else idaapi.print_operand
    outop = utils.fcompose(idaapi.ua_outop2, idaapi.tag_remove) if idaapi.__version__ < 7.0 else utils.fcompose(idaapi.print_operand, idaapi.tag_remove)
    try:
        res = outop(insn.ea, opnum) or "{:s}".format(op(insn.ea, opnum))
    except:
        logging.warning(u"{:s}({:#x}, {:d}) : Unable to strip tags from operand \"{:s}\". Returning the result from {:s} instead.".format('.'.join([__name__, 'op_repr']), ea, opnum, utils.string.escape(oppr(insn.ea, opnum), '"'), '.'.join([__name__, 'op'])))
        return u"{!s}".format(op(insn.ea, opnum))
    return utils.string.of(res)

@utils.multicase(opnum=six.integer_types)
def op_state(opnum):
    '''Returns the modification state for the operand `opnum` belonging to the current instruction.'''
    return op_state(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_state(ea, opnum):
    """Returns the modification state for the operand `opnum` belonging to the instruction at the address `ea`.

    The returned state is a string that can be "r", "w", or "rw" depending on
    whether the operand is being read from, written to, or modified (both).
    """
    f = type.feature(ea)

    # Verify that we're using a valid operand number.
    if opnum >= len(operands(ea)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_state({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Now we can check our instruction feature for what the operand state is.
    r, w = f & ops_state.read[opnum], f & ops_state.write[opnum]
    res = (r and 'r' or '') + (w and 'w' or '')

    # Make a reftype_t from the state we determined. If we couldn't figure it out,
    # then fallback to "r" as the operand still exists and it must be doing something.
    return interface.reftype_t.of_action(res or 'r')

@utils.multicase(opnum=six.integer_types)
def op_size(opnum):
    '''Returns the size for the operand `opnum` belonging to the current instruction.'''
    return op_size(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_size(ea, opnum):
    '''Returns the size for the operand `opnum` belonging to the instruction at the address `ea`.'''
    get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
    get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

    res = operand(ea, opnum)
    return 0 if res.type == idaapi.o_void else get_dtype_size(get_dtype_attribute(res))
@utils.multicase(opnum=six.integer_types)
def op_bits(opnum):
    '''Returns the size (in bits) for the operand `opnum` belonging to the current instruction.'''
    return 8 * op_size(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_bits(ea, opnum):
    '''Returns the size (in bits) for the operand `opnum` belonging to the instruction at the address `ea`.'''
    return 8 * op_size(ea, opnum)

@utils.multicase(opnum=six.integer_types)
def opt(opnum):
    '''Returns the type of the operand `opnum` belonging to the current instruction.'''
    return opt(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def opt(ea, opnum):
    """Returns the type of the operand `opnum` belonging to the instruction at the address `ea`.

    The types returned are dependant on the architecture.
    """
    res = operand(ea, opnum)
    return __optype__.type(res)
op_type = utils.alias(opt)

#@utils.multicase(opnum=six.integer_types)
#def op_decode(opnum):
#    '''Returns the value of the operand `opnum` in byte form belonging to the current instruction (if possible).'''
#    raise NotImplementedError
#@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
#def op_decode(ea, opnum):
#    '''Returns the value of the operand `opnum` in byte form belonging to the instruction at address `ea`.'''
#    raise NotImplementedError

@utils.multicase(opnum=six.integer_types)
def op(opnum):
    '''Decodes the operand `opnum` for the current instruction.'''
    return op(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
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

## old method for applying a complex type to an operand
# def op_type(ea, opnum)
#    '''Apply the specified type to a stack variable'''
#    py_op = operand(ea, opnum)
#    py_v = py_op.addr
#    py_t = idc.parse_decl("type string", flags)[1]
#    py_name = "stack variable name"
#    idaapi.apply_type_to_stkarg(py_op, py_v, py_t, py_name)

## XXX: deprecate this, and somehow associate the segment register with the operand for the intel arch
@utils.multicase(opnum=six.integer_types)
def op_segment(opnum):
    '''Returns the segment register used by the operand `opnum` for the instruction at the current address.'''
    return op_segment(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
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

@utils.multicase(opnum=six.integer_types)
def op_number(opnum):
    '''Set the type for operand `opnum` at the current instruction to a number and return it.'''
    return op_number(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_number(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to a number and return it.'''
    t = idaapi.num_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_number({:#x}, {:d}) : Unable to restore the type of operand {:d} to a number.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        return 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    bits = utils.string.digits(idaapi.BADADDR, 2)
    maximum, flag = pow(2, bits), pow(2, bits - 1)
    integer = (res.addr - maximum) if res.addr & flag else res.addr

    # Now we can return the value transformed if the operand has an inverted sign
    return 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer
op_num = utils.alias(op_number)

@utils.multicase(opnum=six.integer_types)
def op_character(opnum):
    '''Set the type for operand `opnum` at the current instruction to a character and return it.'''
    return op_character(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_character(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to a character and return it.'''
    t = idaapi.char_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_character({:#x}, {:d}) : Unable to set the type of operand {:d} to a character.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        result = 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    else:
        bits = utils.string.digits(idaapi.BADADDR, 2)
        maximum, flag = pow(2, bits), pow(2, bits - 1)
        integer = (res.addr - maximum) if res.addr & flag else res.addr

        # Now we can use the value transformed if the operand has an inverted sign
        result = 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer

    # There's no such thing as a signed character, so if we do get a signed
    # value back from our above logic, then we need to figure out its absolute
    # value so we can return it properly.
    absolute = abs(result)

    # IDA actually returns integers larger than a byte as a string, so we'll
    # first chunk our integer into octets.
    octets = []
    while absolute > 0:
        octets.append(absolute & 0xff)
        absolute //= 0x100

    # Last thing to do is to join each octet together back into some bytes
    return bytes(bytearray(reversed(bytearray(octets))))
op_chr = op_char = utils.alias(op_character)

@utils.multicase(opnum=six.integer_types)
def op_binary(opnum):
    '''Set the type for operand `opnum` at the current instruction to binary and return it.'''
    return op_binary(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_binary(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to binary and return it.'''
    t = idaapi.bin_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_binary({:#x}, {:d}) : Unable to set the type of operand {:d} to binary.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        return 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    bits = utils.string.digits(idaapi.BADADDR, 2)
    maximum, flag = pow(2, bits), pow(2, bits - 1)
    integer = (res.addr - maximum) if res.addr & flag else res.addr

    # Now we can return the value transformed if the operand has an inverted sign
    return 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer
op_bin = utils.alias(op_binary)

@utils.multicase(opnum=six.integer_types)
def op_octal(opnum):
    '''Set the type for operand `opnum` at the current instruction to octal and return it.'''
    return op_octal(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_octal(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to octal and return it.'''
    t = idaapi.oct_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_octal({:#x}, {:d}) : Unable to set the type of operand {:d} to octal.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        return 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    bits = utils.string.digits(idaapi.BADADDR, 2)
    maximum, flag = pow(2, bits), pow(2, bits - 1)
    integer = (res.addr - maximum) if res.addr & flag else res.addr

    # Now we can return the value transformed if the operand has an inverted sign
    return 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer
op_oct = utils.alias(op_octal)

@utils.multicase(opnum=six.integer_types)
def op_decimal(opnum):
    '''Set the type for operand `opnum` at the current instruction to decimal and return it.'''
    return op_decimal(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_decimal(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to decimal and return it.'''
    t = idaapi.dec_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_decimal({:#x}, {:d}) : Unable to set the type of operand {:d} to decimal.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        return 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    bits = utils.string.digits(idaapi.BADADDR, 2)
    maximum, flag = pow(2, bits), pow(2, bits - 1)
    integer = (res.addr - maximum) if res.addr & flag else res.addr

    # Now we can return the value transformed if the operand has an inverted sign
    return 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer
op_dec = utils.alias(op_decimal)

@utils.multicase(opnum=six.integer_types)
def op_hexadecimal(opnum):
    '''Set the type for operand `opnum` at the current instruction to hexadecimal and return it.'''
    return op_hexadecimal(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_hexadecimal(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to hexadecimal and return it.'''
    t = idaapi.hex_flag()
    ok, signed = idaapi.set_op_type(ea, t, opnum), idaapi.is_invsign(ea, database.type.flags(ea), opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_hexadecimal({:#x}, {:d}) : Unable to set the type of operand {:d} to hexadecimal.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its maximum value, as we'll use this to
    # transform the value if necessary.
    res, max = operand(ea, opnum), pow(2, op_bits(ea, opnum))

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (max - 1)
        return 0 if integer == 0 else (integer - max) if signed else integer

    # If the signed-flag is set in our operand, then convert it into its actual
    # signed value.
    bits = utils.string.digits(idaapi.BADADDR, 2)
    maximum, flag = pow(2, bits), pow(2, bits - 1)
    integer = (res.addr - maximum) if res.addr & flag else res.addr

    # Now we can return the value transformed if the operand has an inverted sign
    return 0 if integer == 0 else (maximum + integer) if signed and integer < 0 else (integer - maximum) if signed else integer
op_hex = utils.alias(op_hexadecimal)

@utils.multicase(opnum=six.integer_types)
def op_float(opnum):
    '''Set the type for operand `opnum` at the current instruction to floating-point and return it.'''
    return op_float(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_float(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to floating-point and return it.'''
    t = idaapi.flt_flag()

    # Explicitly set the operand type using idaapi.
    ok = idaapi.set_op_type(ea, t, opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_float({:#x}, {:d}) : Unable to set the type of operand {:d} to floating-point.".format(__name__, ea, opnum, opnum))

    # Read the number of bits for the operand so we can figure out how to properly
    # decode this integer.
    res, bits = operand(ea, opnum), op_bits(ea, opnum)
    integer = res.value if res.type in {idaapi.o_imm} else res.addr

    # Figure out which floating-point components to use for decoding
    if bits == 64:
        fraction, exponent, sign = 52, 11, 1

    elif bits == 32:
        fraction, exponent, sign = 23, 8, 1

    elif bits == 16:
        fraction, exponent, sign = 10, 5, 1

    # If we couldn't find a valid encoding, then raise an exception.
    else:
        raise E.UnsupportedCapability(u"{:s}.op_float({:#x}, {:d}) : Unable to decode operand {:d} for instruction due to an unsupported number of bits ({:d}).".format(__name__, ea, opnum, opnum, bits))

    # Now we can decode the floating-point operand and return it.
    try:
        res = utils.float_of_integer(integer, fraction, exponent, sign)

    # If an exception was raised, then re-raise it with our parameters prefixed.
    except ValueError as message:
        raise ValueError(u"{:s}.op_float({:#x}, {:d}) : {!s}".format(__name__, ea, opnum, message))

    # That's all, folks.
    return res
op_flt = utils.alias(op_float)

@utils.multicase(opnum=six.integer_types)
def op_stackvar(opnum):
    '''Set the type for operand `opnum` at the current instruction to a stack variable and return it.'''
    return op_stackvar(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_stackvar(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to a stack variable and return it.'''
    if not function.within(ea):
        raise E.FunctionNotFoundError(u"{:s}.op_stackvar({:#x}, {:d}) : The specified address ({:#x}) is not within a function.".format(__name__, ea, opnum, ea))

    ok = idaapi.op_stkvar(ea, opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_stackvar({:#x}, {:d}) : Unable to set operand {:d} to a stack variable.".format(__name__, ea, opnum, opnum))

    # Now that it's set, call into op_structure to return it.
    return op_structure(ea, opnum)
op_stack = op_stkvar = utils.alias(op_stackvar)

@utils.multicase(opnum=six.integer_types)
def op_structure(opnum):
    '''Return the structure and members for operand `opnum` at the current instruction.'''
    return op_structure(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_structure(ea, opnum):
    '''Return the structure and members for the operand `opnum` at the instruction `ea`.'''
    F, op = database.type.flags(ea), operand(ea, opnum)

    # First check if our operand is pointing to memory by checking the operand
    # type. If it is, then the operand is not a structure offset and thus we'll
    # need to figure the field being referenced by calculating the offset into
    # the referenced structure ourselves.
    if op.type in {idaapi.o_mem}:
        address = database.address.head(op.addr)
        t, count = database.type.array(address)
        offset = op.addr - address

        # Verify that the type as the given address is a structure
        if not isinstance(t, structure.structure_t):
            raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is not pointing to a structure.".format(__name__, ea, opnum, opnum))

        # Figure out the index and the real offset into the structure,
        # and then hand them off to the walk_to_realoffset method. From
        # this value, we calculate the array member offset and then
        # process it to get the actual path to return.
        index, byte = divmod(offset, t.size)
        path, realdelta = t.members.__walk_to_realoffset__(byte)
        delta = index * t.size + realdelta

        # If we received a list, then we can just return it with the delta.
        if isinstance(path, builtins.list) or count > 1:
            return [item for item in path] + [delta]

        # Figure out whether we need to include the offset in the result.
        results = tuple(path)
        if delta > 0:
            return results + (delta,)
        return tuple(results) if len(results) > 1 else results[0]

    # If the operand is an immediate value, then we need to extract the
    # offset from the value property. Anything else should be a memory
    # address that we'll calculate the offset into the structure from.
    res = op.value if op.type in {idaapi.o_imm} else op.addr
    offset = idaapi.as_signed(res, op_bits(ea, opnum))

    # Verify that the operand is actually represented by a structure offset.
    if all(F & ff != ff for ff in {idaapi.FF_STRUCT, idaapi.FF_0STRO, idaapi.FF_1STRO}):
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is not referencing a structure.".format(__name__, ea, opnum, opnum))

    # Whenever we're done figuring out the mptr path, we'll need to create a
    # filtering function using the path extracted from the operand so that we'll
    # know what members it should be referencing when we descend into it. This
    # closure does exactly that, and will generate a filter function when given
    # the list of mptrs.
    def generate_filter(path):
        members = path[:]

        # Now that we have all of the members that should be in our path, we
        # need to collect them into a dictionary. We'll key this dictionary
        # by their structure id which requires us to determine the sptr, and
        # then we'll store a list for the members referenced by it so that we
        # can still figure out the correct one to choose for each relevant path.
        table = {}
        for mptr in members:
            fullname = idaapi.get_member_fullname(mptr.id)
            sptr = idaapi.get_member_struc(fullname)
            table.setdefault(sptr.id, []).append(mptr.id)

        # Now we can define the closure that will be used to look through
        # our table for what the user suggested. If the structure we're
        # being asked to filter isn't in our table, then just bail by
        # returning all the members because we have no idea how to proceed.
        def filter(sptr, members, table=table):
            if sptr.id not in table:
                return members

            # Grab our list of choices from our table, and convert the list
            # of members into a set of ids so that we can quickly match them.
            choices, candidates = table[sptr.id], {mptr.id for mptr in members}

            # If there's no choices for the sptr available, then we need to
            # bail because things do not correspond to the user path.
            if len(choices) == 0:
                return members

            # Now we can check the user's choice to see if it's in our list
            # of members. If it isn't, then we also need to bail because
            # something is busted with the path that the user gave us.
            choice, tids = choices.pop(0), {item.id for item in members}
            if choice not in tids:
                return members

            # Things seem to be okay, so all we need to do is return the
            # list of mptrs that match the choice the user gave us and
            # then we're good to go.
            res = [mptr for mptr in members if mptr.id == choice]
            return res
        return filter

    # Start out by checking if the operand is a stack variable, because
    # we'll need to handle it differently if so.
    if idaapi.is_stkvar(F, opnum) and function.within(ea):
        fn, insn = function.by(ea), at(ea)

        # Now we can ask IDA what's up with it.
        res = idaapi.get_stkvar(insn, op, offset)
        if not res:
            raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}) : The call to `idaapi.get_stkvar({!r}, {!r}, {:+#x})` returned an invalid stack variable.".format(__name__, ea, opnum, insn, op, offset))
        m, actval = res

        # First we grab our frame, and then find the starting member by its id.
        frame = function.frame(fn)
        member = frame.members.by_identifier(m.id)

        # Use the real offset of the member so that we can figure out which
        # members of the structure are actually part of the path.
        path, realdelta = member.parent.members.__walk_to_realoffset__(member.realoffset)

        # If we got a list as a result, then we encountered an array which
        # requires us to return a list and include the offset.
        if isinstance(path, builtins.list):
            return path + [realdelta]

        # Otherwise it's just a regular path, and we need to determine whether
        # to include the offset in the result or not.
        results = tuple(path)
        if realdelta > 0:
            return results + (realdelta,)
        return tuple(results) if len(results) > 1 else results[0]

    # Otherwise, we have no idea what to do here since we need to know the opinfo_t
    # in order to determine what structure is there.
    elif not idaapi.is_stroff(F, opnum):
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Unable to locate a structure offset in operand {:d} according to flags ({:#x}).".format(__name__, ea, opnum, opnum, F))

    # Since IDAPython's get_stroff_path implementation doesn't recognize NULL,
    # we need to call it twice in order to get the size of needed array.
    delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
    delta.assign(0)
    count = idaapi.get_stroff_path(ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), ea, opnum)
    if not count:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} does not contain a structure.".format(__name__, ea, opnum, opnum))

    # Now that we have the length, we can just actually allocate a tid_array
    # with the correct length, and then use what IDA didn't store to fetch
    # the exact field.
    delta, path = idaapi.sval_pointer(), idaapi.tid_array(count)
    delta.assign(0)
    res = idaapi.get_stroff_path(ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), ea, opnum)
    if res != count:
        raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}) : The length ({:d}) for the structure path at operand {:d} changed ({:d}).".format(__name__, ea, count, opnum, opnum, res))

    # First we'll collect all of the IDs in our path. Then we can start
    # converting them into mptrs so that we can use generate_filter to
    # produce the closure we will need to filter members in the path.
    path = [ path[index] for index in range(count) ]
    logging.debug(u"{:s}.op_structure({:#x}, {:d}) : Processing {:d} members ({:s}) from path that was returned from `{:s}`.".format(__name__, ea, opnum, count, ', '.join("{:#x}".format(mid) for mid in path), "{!s}({:#x}, {:d}, ...)".format('idaapi.get_stroff_path', ea, opnum)))

    # Our first member should always be the sptr identifier. Once we snag
    # that, then the rest of the identifiers need to be converted into
    # mptrs so that we can generate our filter.
    sptr, items, moffset = idaapi.get_struc(path.pop(0)), [], 0
    for i, tid in enumerate(path):
        res = idaapi.get_member_by_id(tid)

        # If we couldn't find a member for the identifier, then warn the
        # user and continue chugging along.
        if res is None:
            logging.warning(u"{:s}.op_structure({:#x}, {:d}) : Unable to find member for the identifier {:#x}.".format(__name__, ea, opnum, tid))
            continue

        # Unpack the result that we got into their 3 components so that we
        # simply collect the mptrs for each id, and update our member offset.
        mptr, fullname, mparent = res
        items.append(mptr)
        moffset += 0 if mparent.is_union() else mptr.soff

    # Generate our filter function, and fetch the structure that we're going
    # to use to walk our path with. This should then give us the actual path
    # along with the real delta that we'll return rather than what IDA gave us.
    st = structure.__instance__(sptr.id, offset=delta.value() + offset - moffset)
    Ffilter = generate_filter(items)
    path, realdelta = st.members.__walk_to_realoffset__(offset + delta.value(), filter=Ffilter)

    # If we got a list, then we encountered an array and we need to make sure
    # that we return a list with the delta.
    if isinstance(path, builtins.list):
        return path + [realdelta]

    # Otherwise, we just got a regular member path. So we need to determine
    # whether to include the offset in the result or not.
    results = tuple(path)
    if realdelta:
        return results + (realdelta,)
    return results if len(results) > 1 else results[0]

@utils.multicase(opnum=six.integer_types, structure=structure.structure_t)
def op_structure(opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    sptr, deltapath = structure.ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ui.current.address(), opnum, sptr, *itertools.chain(path, deltapath))
@utils.multicase(opnum=six.integer_types, sptr=idaapi.struc_t)
def op_structure(opnum, sptr, *path, **delta):
    '''Apply the ``idaapi.struc_t` in `sptr` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    deltapath = [delta.get('delta', 0)] if delta else []
    return op_structure(ui.current.address(), opnum, sptr, *itertools.chain(path, deltapath))
@utils.multicase(opnum=six.integer_types, name=six.string_types)
def op_structure(opnum, name, *path, **delta):
    '''Apply the structure with the specified `name` and the members in `path` to the instruction operand `opnum` at the current address.'''
    sptr, deltapath = structure.by(name).ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ui.current.address(), opnum, sptr, *itertools.chain(path, deltapath))
@utils.multicase(opnum=six.integer_types, member=structure.member_t)
def op_structure(opnum, member, *path, **delta):
    '''Apply the specified `member` to the instruction operand `opnum` at the current address.'''
    sptr, deltapath = member.parent.ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ui.current.address(), opnum, sptr, *itertools.chain([member], path, deltapath))
@utils.multicase(opnum=six.integer_types, mptr=idaapi.member_t)
def op_structure(opnum, mptr, *path, **delta):
    '''Apply the ``idaapi.member_t` in `mptr` to the instruction operand `opnum` at the current address.'''
    sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))
    deltapath = [delta.get('delta', 0)] if delta else []
    return op_structure(ui.current.address(), opnum, sptr, *itertools.chain([mptr], path, deltapath))
@utils.multicase(opnum=six.integer_types, path=(builtins.tuple, builtins.list))
def op_structure(opnum, path, **delta):
    '''Apply the structure members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, path, **delta)

@utils.multicase(ea=six.integer_types, opnum=six.integer_types, structure=structure.structure_t)
def op_structure(ea, opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    sptr, deltapath = structure.ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ea, opnum, sptr, *itertools.chain(path, deltapath))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, name=six.string_types)
def op_structure(ea, opnum, name, *path, **delta):
    '''Apply the structure with the specified `name` and any members in `path` to the instruction operand `opnum` at the address `ea`.'''
    sptr, deltapath = structure.by(name).ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ea, opnum, sptr, *itertools.chain(path, deltapath))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, member=structure.member_t)
def op_structure(ea, opnum, member, *path, **delta):
    '''Apply the specified `member` to the instruction operand `opnum` at the address `ea`.'''
    sptr, deltapath = member.parent.ptr, [delta.get('delta', 0)] if delta else []
    return op_structure(ea, opnum, sptr, *itertools.chain([member], path, deltapath))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, mptr=idaapi.member_t)
def op_structure(ea, opnum, mptr, *path, **delta):
    '''Apply the ``idaapi.member_t` in `mptr` to the instruction operand `opnum` at the address `ea`.'''
    sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))
    deltapath = [delta.get('delta', 0)] if delta else []
    return op_structure(ea, opnum, sptr, *itertools.chain([mptr], path, deltapath))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, path=(builtins.tuple, builtins.list))
def op_structure(ea, opnum, path, **delta):
    '''Apply the structure members in `path` to the instruction operand `opnum` at the address `ea`.'''
    items, deltapath = [item for item in path], [delta.get('delta', 0)] if delta else []
    member = items.pop(0) if len(items) else ''
    if isinstance(member, six.string_types):
        sptr, fullpath = structure.by(member).ptr, items
    elif isinstance(member, idaapi.struc_t):
        sptr, fullpath = structure.by(member.id), items
    elif isinstance(member, structure.structure_t):
        sptr, fullpath = member.ptr, items
    elif isinstance(member, idaapi.member_t):
        sptr = idaapi.get_member_struc(idaapi.get_member_fullname(member.id))
        fullpath = [member] + items
    elif isinstance(member, structure.member_t):
        sptr, fullpath = member.parent.ptr, [member] + items
    else:
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:d}, {!r}, delta={:+d}) : Unable to determine the structure from the provided path due to the first member being of an unsupported type ({!s}).".format(__name__, ea, opnum, path, delta.get('delta', 0), member.__class__))
    return op_structure(ea, opnum, sptr, *itertools.chain(fullpath, deltapath))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, sptr=idaapi.struc_t)
def op_structure(ea, opnum, sptr, *path):
    '''Apply the structure identified by `sptr` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.op_structure({:#x}, {:d}, {!r}) : The requested address ({:#x}) is not defined as a code type.".format(__name__, ea, opnum, path, ea))

    # Convert the path to a list, and then validate it before we use it.
    path, accepted = [item for item in path], (idaapi.member_t, structure.member_t, six.string_types, six.integer_types)
    if any(not isinstance(item, accepted) for item in path):
        index, item = next((index, item) for index, item in enumerate(path) if not isinstance(item, accepted))
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The path member at index {:d} has a type ({!s}) that is not supported.".format(__name__, ea, opnum, sptr.id, path, index, item.__class__))

    # Now we need to examine our operand and stash it so that we can later
    # use it to calculate the delta between it and the actual member offset
    # that we'll collect when traversing the structure path.
    op = operand(ea, opnum)
    res = op.value if op.type in {idaapi.o_imm} else op.addr
    value = idaapi.as_signed(res, op_bits(ea, opnum))

    # If the operand type is not a valid type, then raise an exception so that
    # we don't accidentally apply a structure to an invalid operand type.
    if op.type not in {idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ, idaapi.o_imm}:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : Unable to apply structure path to the operand ({:d}) for the instruction at {:#x} due to its type ({:d}).".format(__name__, ea, opnum, sptr.id, path, opnum, ea, op.type))

    # We have to start somewhere and our first element in the path should be a
    # a member of the sptr we were given. So, now we begin to traverse through
    # all of the members in the path the user gave us so that we can figure out
    # the user wanted and what mptrs and sptrs should be in that path.
    st, offset, delta = structure.__instance__(sptr.id), 0, 0
    items = []
    while path and sptr:
        item = path.pop(0)

        # If we found an integer in the path, then just use it to adjust the
        # delta and proceed through the rest of the path.
        if isinstance(item, six.integer_types):
            delta += item
            continue

        # Members can be specified in all sorts of ways, so we need to check
        # what the user gave us. If we were given a string, then look up the
        # member by its name.
        elif isinstance(item, six.string_types):
            mptr = idaapi.get_member_by_name(sptr, utils.string.to(item))

        # If we were given a structure.member_t, then we can just take its
        # member_t.ptr property and use that.
        elif isinstance(item, structure.member_t):
            mptr = item.ptr

        # If we were given an explicit idaapi.member_t, then we can use it as-is.
        elif isinstance(item, idaapi.member_t):
            mptr = item

        # Anything else is not a supported type, and as such is an error.
        else:
            suggested = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in items)
            suggested = ('.'.join(map(utils.string.of, pair)) for pair in suggested)
            summary = itertools.chain(suggested, [item], path)
            raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The member ({!s}) at index {:d} of the suggested path is using an unsupported type ({!s}).".format(__name__, ea, opnum, st.ptr.id, [item for item in summary], item, len(items), item.__class__))

        # If mptr is undefined, then that's it. We have to stop our traversal,
        # and warn the user about what happened.
        if mptr is None:
            suggested = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in items)
            suggested = ('.'.join(map(utils.string.of, pair)) for pair in suggested)
            summary = itertools.chain(suggested, [item], path)
            logging.warn(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The member ({!s}) at index {:d} of the suggested path was not found in the parent structure ({!s}).".format(__name__, ea, opnum, st.ptr.id, [item for item in summary], item, len(items), utils.string.of(idaapi.get_struc_name(sptr.id))))
            break

        # We got an mptr, so now we can extract its owning sptr and verify that
        # it matches the structure that our path traversal is currently in.
        res = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))
        if res.id != sptr.id:
            suggested = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in items)
            suggested = ('.'.join(map(utils.string.of, pair)) for pair in suggested)
            summary = itertools.chain(suggested, [utils.string.of(idaapi.get_member_fullname(mptr.id))], path)
            logging.warning(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The member ({!s}) at index {:d} of the suggested path is using a structure ({:#x}) that is different from the expected structure ({:#x}).".format(__name__, ea, opnum, st.ptr.id, [item for item in summary], utils.string.of(idaapi.get_member_fullname(mptr.id)), len(items), res.id, sptr.id))
        sptr = res

        # Now we can add the mptr to our list, and update the member offset that
        # we're tracking during this traversal. If it's a union, then our member
        # offset doesn't change at all.
        items.append((sptr, mptr))
        offset += 0 if sptr.is_union() else mptr.soff

        # If the member that we're currently at during our traversal is not a
        # structure, then our loop should stop here.
        sptr = idaapi.get_sptr(mptr)

    # Consume the rest of the integers in the path so that we can finish
    # updating the delta that the user suggested to us.
    while path and isinstance(path[0], six.integer_types):
        delta += path.pop(0)

    # Verify that our path is empty and that we successfully consumed everything.
    if len(path):
        suggested = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in items)
        suggested = ('.'.join(map(utils.string.of, pair)) for pair in suggested)
        summary = itertools.chain(suggested, path)
        logging.warning(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : There was an error trying to traverse the path for the list of members (path will be truncated).".format(__name__, ea, opnum, st.ptr.id, [item for item in summary]))

    # Now that we have the suggested path and thus the desired offset, we're
    # going to use it to generate a filter that we will use to determine the
    # _actual_ path for the desired offset. We'll start by formatting these
    # items into a lookup table.
    table = {}
    for sptr, mptr in items:
        table.setdefault(sptr.id, []).append(mptr.id)

    # Now we can define a closure that uses this table to get as close as we can
    # to what the user suggsted. If the path doesn't correspond, then we're
    # forced to return all the members, and bailing, which lets it sort itself out.
    def filter(sptr, members, table=table):
        if sptr.id not in table:
            return members

        # Grab our choices and convert our candidates into identifiers.
        choices, candidates = table[sptr.id], {mptr.id for mptr in members}
        if len(choices) == 0:
            return members

        # Check that the choice the user gave us is in our list.
        choice, tids = choices.pop(0), {item.id for item in members}
        if choice not in tids:
            return members

        # We found a match and so we should be okay with returning it.
        res = [mptr for mptr in members if mptr.id == choice]
        return res

    # Now we need to use the requested offset to descend through the structure
    # that we're starting at, and then hope it matches the path that was
    # recommended. We need to shift whatever this offset is by the delta that
    # we were given, and then gather our results into mptr and sptrs. If our
    # offset and value are the same, then we don't need to adjust anything.
    res = 0 if offset == value else offset
    rp, realdelta = st.members.__walk_to_realoffset__(res + value + delta, filter=filter)
    results = [(item.parent.ptr, item.ptr) for item in rp]
    moffset = sum(0 if sptr.is_union() else mptr.soff for sptr, mptr in results)

    # Now that we've carved an actual path through the structure and its
    # descendants, we can allocate the tid_array using the starting structure and
    # adding each individual member to it.
    length, (sptr, _) = 1 + len(results), results[0]
    tid = idaapi.tid_array(length)
    tid[0] = sptr.id
    for i, (sptr, mptr) in enumerate(results):
        tid[i + 1] = mptr.id

    # Now we can apply our tid_array to the operand, and include our original
    # member offset from the path the user gave us so that way the user can
    # fetch it later if they so desire.
    res = moffset - value + realdelta
    if idaapi.__version__ < 7.0:
        ok = idaapi.op_stroff(ea, opnum, tid.cast(), length, res)

    # If we're using IDAPython from v7.0 or later, then we're required to grab
    # the instruction to apply our tid_array to its operand.
    else:
        insn = at(ea)
        ok = idaapi.op_stroff(insn, opnum, tid.cast(), length, res)

    # If we failed applying our structure, then we'll just raise an exception.
    if not ok:
        suggested = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in items)
        suggested = ('.'.join(map(utils.string.of, pair)) for pair in suggested)
        resolved = ((idaapi.get_struc_name(sptr.id), idaapi.get_member_name(mptr.id)) for sptr, mptr in results)
        resolved = ('.'.join(map(utils.string.of, pair)) for pair in resolved)
        raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : Unable to apply the resolved structure path ({!r}) to the specified address ({:#x}).".format(__name__, ea, opnum, st.ptr.id, [item for item in suggested], [item for item in resolved], ea))

    # Otherwise, we can chain into our other case to return what was just applied.
    return op_structure(ea, opnum)
op_struc = op_struct = utils.alias(op_structure)

@utils.multicase(opnum=six.integer_types)
def op_enumeration(opnum):
    '''Return the enumeration member id for the operand `opnum` belonging to the current instruction.'''
    return op_enumeration(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_enumeration(ea, opnum):
    '''Return the enumeration member id for the operand `opnum` belonging to the instruction at `ea`.'''

    # If our operand number is actually an enumeration identifier, then shift
    # our parameters, and try again with the current address.
    if enumeration.has(opnum):
        ea, opnum, id = ui.current.address(), ea, opnum
        return op_enumeration(ea, opnum, id)

    # Ensure that the operand number is within our available operands.
    if opnum >= len(operands(ea)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_enumeration({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Check the flags for the given address to ensure there's actually an
    # enumeration defined as one of the operands.
    F = database.type.flags(ea)
    if all(F & item == 0 for item in [idaapi.FF_0ENUM, idaapi.FF_1ENUM]):
        raise E.MissingTypeOrAttribute(u"{:s}.op_enumeration({:#x}, {:d}) : Operand {:d} does not contain an enumeration.".format(__name__, ea, opnum, opnum))

    # After verifying that there's definitely an enumeration at the address, we
    # can ask for the enumeration identifier to figure out the actual member.
    eid, cid = idaapi.get_enum_id(ea, opnum)
    if eid == idaapi.BADNODE:
        raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:d}) : Unable to get enumeration identifier for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, F))

    # After grabbing the member, lets grab the actual value that we're going to
    # need to process the member identifier out of.
    value, bits, signed = op(ea, opnum), op_bits(ea, opnum), interface.node.alt_opinverted(ea, opnum)

    # If this enumeration is a bitfield, then we need to figure out all the masks
    # that this operand uses. If it's not, then we have a single mask which is
    # idaapi.DEFMASK.
    if enumeration.bitfield(eid):
        masks = [mask for mask in enumeration.masks.iterate(eid)]
    else:
        masks = [idaapi.DEFMASK]

    # Now we iterate through all of the masks and attempt to get the enumeration
    # member. We need to figure out whether our value is signed so that we can
    # invert it and then apply the mask to our value for bitfield support.
    res, ok = [], True
    for mask in masks:
        item = (~value + 1 if signed else value) & mask

        # Attempt to get the member using the value that we masked away. We first
        # try fetching it with the value we masked, and if that fails then we try
        # again using the signed value. This is due to how IDA applies an enumeration
        # to an operand in that it seems to discard the OP_REPR altval which forces
        # us to have to figure out how the value is stored in the enumeration
        # ourselves.
        mid = idaapi.get_enum_member(eid, item, cid, mask)
        if mid == idaapi.BADNODE:
            mid = idaapi.get_enum_member(eid, idaapi.as_signed(item, bits), cid, mask)

        # If that still didn't work, then this is an error and we need to warn the
        # user about it.
        if mid == idaapi.BADNODE:
            ok, width = False, 2 * enumeration.size(eid) if enumeration.size(eid) else utils.string.digits(max(masks), 16)
            logging.warn(u"{:s}.op_enumeration({:#x}, {:d}) : No enumeration member was found for the mask ({:s}) in the enumeration ({:#x}) at operand {:d}.".format(__name__, ea, opnum, "{:#0{:d}x} & {:#0{:d}x}".format(item, 3 + width if item < 0 else 2 + width, mask, 3 + width if mask < 0 else 2 + width) if enumeration.bitfield(eid) else "{:#0{:d}x}".format(item, 3 + width if item < 0 else 2 + width), eid, opnum))

        # Otherwise, add it to our results and continue onto the next mask.
        else:
            res.append(mid)
        continue

    # If we found everything without any errors, then return our results to
    # the caller. If it was a bitfield, then we need to check if there's
    # a single result, otherwise we return a tuple. If it was not a bitfield
    # then the enumeration member identifier should be more than enough.
    if ok and res:
        if enumeration.bitfield(eid):
            return builtins.tuple(res) if len(res) > 1 else res[0]
        return res[0]

    # If we did get something but we missed a value for one of the masks,
    # then this result is incomplete, but still okay to return.
    elif res:
        if enumeration.bitfield(eid):
            return builtins.tuple(res) if len(res) > 1 else res[0]
        return res[0]

    # Otherwise, we didn't find anything and there was an error trying to
    # get an enumeration member. This is worth an exception for the caller
    # to figure out what to do with.
    raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:d}) : Unable to get any members for the enumeration ({:#x}) at operand {:d}.".format(__name__, ea, opnum, eid, opnum))
@utils.multicase(opnum=six.integer_types, name=six.string_types)
@utils.string.decorate_arguments('name')
def op_enumeration(opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the current instruction.'''
    return op_enumeration(ui.current.address(), opnum, enumeration.by(name))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, name=six.string_types)
@utils.string.decorate_arguments('name')
def op_enumeration(ea, opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the instruction at `ea`.'''
    return op_enumeration(ea, opnum, enumeration.by(name))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=(six.integer_types, builtins.tuple, builtins.list))
def op_enumeration(ea, opnum, id):
    '''Apply the enumeration `id` to operand `opnum` of the instruction at `ea`.'''
    if opnum >= len(operands(ea)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_enumeration({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    ok = idaapi.op_enum(ea, opnum, *id) if isinstance(id, (builtins.tuple, builtins.tuple)) else idaapi.op_enum(ea, opnum, id, 0)
    if not ok:
        eid, serial = id if isinstance(id, (builtins.tuple, builtins.list)) else (id, 0)
        raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:d}, {:#x}) : Unable to set operand {:d} for instruction ({:#x}) to enumeration {:#x} (serial {:d}).".format(__name__, ea, opnum, eid, opnum, ea, eid, serial))
    return op_enumeration(ea, opnum)
op_enum = utils.alias(op_enumeration)

@utils.multicase(opnum=six.integer_types)
def op_string(opnum):
    '''Return the string type of operand `opnum` for the current instruction.'''
    return op_string(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_string(ea, opnum):
    '''Return the string type (``idaapi.STRTYPE_``) of operand `opnum` for the instruction at `ea`.'''
    F = database.type.flags(ea)
    if F & (idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI) == 0:
        raise E.MissingTypeOrAttribute(u"{:s}.op_string({:#x}, {:d}) : Operand {:d} does not contain a literate string.".format(__name__, ea, opnum, opnum))

    res = opinfo(ea, opnum)
    if res is None:
        raise E.DisassemblerError(u"{:s}.op_string({:#x}, {:d}) : Unable to get `idaapi.opinfo_t` for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, F))

    return res.strtype
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, strtype=six.integer_types)
def op_string(ea, opnum, strtype):
    '''Set the string type used by operand `opnum` for the instruction at `ea` to `strtype`.'''
    info, F = idaapi.opinfo_t(), database.type.flags(ea)

    # Update our flags for the instruction to include the string definition.
    F |= idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
    info.strtype = strtype

    # Now we can actually apply the opinfo_t to the specified operand, and then
    # cross-check that the operand info's string type matches what we set it to.
    res = opinfo(ea, opnum, info, flags=F)
    return True if res.strtype == strtype else False

## flags
@utils.multicase()
def ops_refinfo():
    '''Returns the ``idaapi.refinfo_t`` for the instruction at the current address.'''
    OPND_ALL = getattr(idaapi, 'OPND_ALL', 0xf)
    return op_refinfo(ui.current.address(), OPND_ALL)
@utils.multicase(ea=six.integer_types)
def ops_refinfo(ea):
    '''Returns the ``idaapi.refinfo_t`` for the instruction at the address `ea`.'''
    OPND_ALL = getattr(idaapi, 'OPND_ALL', 0xf)
    return op_refinfo(ea, OPND_ALL)
@utils.multicase(opnum=six.integer_types)
def op_refinfo(opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return op_refinfo(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_refinfo(ea, opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    ri = idaapi.refinfo_t()
    ok = idaapi.get_refinfo(ea, opnum, ri) if idaapi.__version__ < 7.0 else idaapi.get_refinfo(ri, ea, opnum)
    return ri if ok else None

@utils.multicase(opnum=six.integer_types)
def op_refs(opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the current instruction.'''
    return op_refs(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_refs(ea, opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the instruction at `ea`.'''
    inst, ops = at(ea), operands(ea)
    if len(ops) < opnum:
        raise E.InvalidTypeOrValueError(u"{:s}.op_refs({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Start out by doing sanity check so that we can determine whether
    # the operand is referencing a local or a global. We grab both the
    # operand info any the result from idaapi.op_adds_xrefs in order to
    # distinguish the "type" of xrefs that are associated with an operand.
    # This way we can distinguish structure members, enumeration members,
    # locals, globals, etc.
    F = database.type.flags(inst.ea)
    info, has_xrefs = opinfo(inst.ea, opnum), idaapi.op_adds_xrefs(F, opnum)

    # If we have xrefs but no type information, then this operand has to
    # be pointing to a local stack variable that is stored in the frame.
    # This means that we need to be inside a function so that we can
    # grab its frame and search through it.
    if has_xrefs and info is None:
        fn = idaapi.get_func(inst.ea)
        if fn is None:
            raise E.FunctionNotFoundError(u"{:s}.op_refs({:#x}, {:d}) : Unable to locate function for address {:#x}.".format(__name__, inst.ea, opnum, inst.ea))

        # Use IDAPython's api to calculate the structure offset into the
        # function's frame using the instruction operand.
        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, inst.ea if idaapi.__version__ < 7.0 else inst, opnum)

        # For sanity, we're going to grab the actual value of the operand
        # and use it to verify that the result from IDAPython is correct.
        op = operand(inst.ea, opnum)
        sval = interface.sval_t(op.addr).value

        # Now that we have the instruction operand's value, we can use
        # it with IDAPython to check if it's actually a frame member.
        res = idaapi.get_stkvar(op, sval) if idaapi.__version__ < 7.0 else idaapi.get_stkvar(inst, op, sval)
        if res is None:
            raise E.DisassemblerError(u"{:s}.op_refs({:#x}, {:d}) : The instruction operand's value ({:#x}) does not appear to point to a frame variable at the same offset ({:#x}).".format(__name__, inst.ea, opnum, sval.value, stkofs_))

        # Now we have the actual frame member and the offset into the
        # frame, and we can use it to validate against our expectation.
        member, stkofs = res
        if stkofs != stkofs_:
            logging.warning(u"{:s}.op_refs({:#x}, {:d}) : The stack variable offset ({:#x}) for the instruction operand does not match what was expected ({:#x}).".format(__name__, inst.ea, opnum, stkofs, stkofs_))

        # Finally we can instantiate an idaapi.xreflist_t, and call directly
        # into the IDAPython api in order to let it build all of the
        # xrefs for the operand.
        xl = idaapi.xreflist_t()
        idaapi.build_stkvar_xrefs(xl, fn, member)

        # That should've created our xref list, so we can simply transform
        # it directly into a list of interface.opref_t and return it.
        # FIXME: the type for an LEA instruction should include an '&' in the
        #        reftype_t, but in this case we explicitly trust the type.
        return [ interface.opref_t(x.ea, int(x.opnum), interface.reftype_t.of(x.type)) for x in xl ]

    # If we have xrefs and the operand has information associated with it, then
    # we need to check if the type-id is an enumeration. If so, then the user is
    # looking for references to an enumeration member. We start by grabbing both
    # id for the enumeration and its member.
    elif has_xrefs and info and enumeration.has(info.tid):
        eid, mid = info.tid, op_enumeration(inst.ea, opnum)
        NALT_ENUM0, NALT_ENUM1 = (getattr(idaapi, name, 0xb + idx) for idx, name in enumerate(['NALT_ENUM0', 'NALT_ENUM1']))

        # Now we check to see if it has any xrefs that point directly to the id
        # of the member. If not, then there's nothing to do here.
        X = idaapi.xrefblk_t()
        if not X.first_to(mid, idaapi.XREF_ALL):
            fullname = '.'.join([enumeration.name(eid), enumeration.member.name(mid)])
            logging.warning(u"{:s}.op_refs({:#x}, {:d}) : No references found for enumeration member {:s} ({:#x}).".format(__name__, inst.ea, opnum, fullname, m))
            return []

        # As we were able to find one, we can just continue to iterate through
        # the xrefblk_t while gathering all of the necessary properties into
        # our list of references.
        refs = [(X.frm, X.iscode, X.type)]
        while X.next_to():
            refs.append((X.frm, X.iscode, X.type))

        # After gathering all the xrefs into a list, we'll need to transform
        # it into a list of internal.opref_t. In order to do that, we need to
        # figure out which operand the member is in for each address. During
        # this process, we also verify that the member is actually owned by
        # the enumeration we extracted from our original operand information.
        res = []
        for ea, _, t in refs:
            ops = ((opnum, internal.netnode.alt.get(ea, altidx)) for opnum, altidx in enumerate([NALT_ENUM0, NALT_ENUM1]) if internal.netnode.alt.has(ea, altidx))
            ops = (opnum for opnum, mid in ops if enumeration.member.parent(mid) == eid)
            res.extend(interface.opref_t(ea, int(opnum), interface.reftype_t.of(t)) for opnum in ops)
        return res

    # If the operand adds xrefs and there's operand information, then this
    # is a structure. We don't actually have to test the operand information
    # because for some reason there's absolutely nothing in it.
    elif has_xrefs and info:
        NSUP_STROFF0, NSUP_STROFF1 = (getattr(idaapi, name, 0xf + idx) for idx, name in enumerate(['NSUP_STROFF0', 'NSUP_STROFF1']))

        # We need to ask IDA what the structure path for the request operand,
        # however, IDAPython's idaapi.get_stroff_path api doesn't tell us
        # how much space we need to allocate. So we need to allocate the
        # maximum first, and only then will we know the count to actually use.
        delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
        delta.assign(0)
        count = idaapi.get_stroff_path(inst.ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), inst.ea, opnum)
        if not count:
            raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} does not contain a structure.".format(__name__, inst.ea, opnum, opnum))

        # Now that we have the right length, we can use IDAPython to
        # actually populate the tid_array here. Afterwards, we discard
        # our array by converting it into a list.
        delta, path = idaapi.sval_pointer(), idaapi.tid_array(count)
        delta.assign(0)
        res = idaapi.get_stroff_path(inst.ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), inst.ea, opnum)
        if res != count:
            raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}) : The length ({:d}) for the structure path at operand {:d} changed ({:d}).".format(__name__, inst.ea, count, opnum, opnum, res))
        items = [path[idx] for idx in range(count)]

        # After we get the list of member ids, then we can use it to
        # compose the path that we will later match against. We grab
        # the first member (which is the structure id) so that later
        # we can validate it against the sptr that we get from the
        # idaapi.get_member_by_id api.
        sptr = idaapi.get_struc(items.pop(0))
        mptrs = [idaapi.get_member_by_id(item) for item in items if item]
        items = [(sptr, mptr) for mptr, _, sptr in mptrs]

        # Grab the sptr from the first member and compare it against
        # the first member that we got from idaapi.get_stroff_path.
        if items:
            target, _ = items[0]
            if target.id != sptr.id:
                raise E.DisassemblerError(u"{:s}.op_refs({:#x}, {:d}) : The structure id ({:#x}) in the determined path does not have ownership of the first member ({:#x}).".format(__name__, inst.ea, opnum, sptr.id, target.id))
            members = items

        # If IDAPython didn't return any members in the path, then we
        # need to rely on op_structure to find the members we need to
        # search for. As op_structure can return a number of arbitrary
        # types, we need to normalize it into a list of members. This
        # involves packing a single member into a list, and dropping
        # off the integer for the delta at the very end.
        else:
            res = op_structure(inst.ea, opnum)
            items = [item for item in res] if isinstance(res, (builtins.list, builtins.tuple)) else [res]
            items.pop(-1) if isinstance(items[-1], six.integer_types) else items

            # Now we should have a list of structure.member_t, so all
            # we need to do is grab their idaapi.struc_t and idaapi.member_t.
            members = [(item.parent.ptr, item.ptr) for item in items]

        # Now we need to iterate through all of the members and collect their
        # xref'd targets. These will all get filtered later, so we shouldn't
        # have to worry about it too much.
        refs = {item for item in []}
        for sptr, mptr in members:

            # Now we check to see if it has any xrefs that point directly to
            # the id of the member. If not, then there's nothing to do here.
            # First we need to check the first xref of the member. If there
            # isn't anything, then we continue onto the next one.
            X = idaapi.xrefblk_t()
            if not X.first_to(mptr.id, idaapi.XREF_ALL):
                fullname = idaapi.get_member_fullname(mptr.id)
                logging.info(u"{:s}.op_refs({:#x}, {:d}) : No references were found for structure member \"{:s}\".".format(__name__, inst.ea, opnum, utils.string.escape(utils.string.of(fullname), '"')))
                continue

            # If we were able to get an xref, then we can gather the rest of
            # them into our list which we'll verify later.
            items = [(X.frm, X.iscode, X.type)]
            while X.next_to():
                items.append((X.frm, X.iscode, X.type))

            # Update our set with all of the references that we found for the
            # current member, and then continue onto the next one.
            refs.update(items)

        # To verify that the operand is definitely referencing the caller's
        # request, we need to iterate through all of the operands for every
        # reference and gather their structure path. This path could be composed
        # of frame variables or actual structure members, and we definitely
        # need to check both.
        res = []
        for ea, _, t in sorted(refs, key=operator.itemgetter(0)):
            candidates = []

            # Start by gathering any structure candidates that may be referenced
            # by our structure path.
            for refop, supidx in enumerate([NSUP_STROFF0, NSUP_STROFF1]):
                if internal.netnode.sup.has(ea, supidx):
                    supval = internal.netnode.sup.get(ea, supidx)
                    offset, ids = interface.node.sup_opstruct(supval, idaapi.get_inf_structure().is_64bit())
                    candidates.append((refop, ids))
                continue

            # Next we need to check if there were any operands that actually
            # point to stack variables so we can figure out their path and
            # add them to our candidates list if necessary.
            for refop, op in enumerate(operands(ea)):
                if not idaapi.is_stkvar(database.type.flags(ea), refop):
                    continue

                # Use the instruction and the operand to figure out the
                # member id of the frame that we need to descend into.
                item = idaapi.get_stkvar(at(ea), op, op.value if op.type in {idaapi.o_imm} else op.addr)
                if item is None:
                    logging.warning(u"{:s}.op_refs({:#x}, {:d}) : Error trying to get frame variable for the referenced operand ({:d}) of the instruction at {:#x}.".format(__name__, inst.ea, opnum, refop, ea))
                    continue
                mptr, actval = item

                # We have the mptr for the frame variable, so next we just need
                # to get the sptr for it, and use it get its members_t. This way
                # we can use the actual value to compose a path through it.
                sptr = idaapi.get_sptr(mptr)
                if sptr is None:
                    logging.warning(u"{:s}.op_refs({:#x}, {:d}) : The frame variable for the operand ({:d}) in the instruction at {:#x} is not a structure.".format(__name__, inst.ea, opnum, refop, ea))
                    continue

                # Instantiate a structure_t in order to grab its members_t. From
                # this we can then use the actual value to carve a path straight
                # through the member.
                st = structure.__instance__(sptr.id)
                path, delta = st.members.__walk_to_realoffset__(actval) # FIXME: wtf is the offset that we should use
                ids = [sptr.id] + [item.ptr.id for item in path]
                candidates.append((refop, ids))

            # Now that we've gathered all of the relevant operand numbers
            # and the structure ids for their paths, we need to do a final
            # pass of them to filter the operands to include references for.
            filtered, required = [], [item.id for item, _ in members[:1]] + [item.id for _, item in members[1:]]
            for opnum, ids in candidates:

                # If we don't have enough ids, then we only need match
                # exactly what we have.
                if all(item in ids for item in required[:len(ids)]):
                    filtered.append(opnum)
                continue
            res.extend(interface.opref_t(ea, int(op), interface.reftype_t.of(t)) for op in filtered)
        return res

    # If our operand type is a register, then there's no structures here.
    elif operand(inst.ea, opnum).type in {idaapi.o_reg}:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} has a type ({:d}) that cannot contain a structure.".format(__name__, inst.ea, opnum, opnum, operand(inst.ea, opnum).type))

    # Anything else should be just a regular global reference, and to figure this out
    # we just grab the operand's value and work it out from there. The value at the
    # supidx has some format which is documented as "complex reference information".
    # In some cases, I've seen the byte 0x02 used to describe a pointer to a global
    # that is within the second segment.

    # XXX: verify whether globals are supposed to add xrefs (has_xrefs) or not.

    attributes = ['NSUP_REF0', 'NSUP_REF1', 'NSUP_REF2', 'NSUP_REF3', 'NSUP_REF4', 'NSUP_REF5', 'NSUP_REF6', 'NSUP_REF7']
    indices = [9, 10, 11, 21, 22, 23, 33, 34]
    NSUP_REF0, NSUP_REF1, NSUP_REF2, NSUP_REF3, NSUP_REF4, NSUP_REF5, NSUP_REF6, NSUP_REF7 = (getattr(idaapi, name, supidx) for name, supidx in zip(attributes, indices))

    # We start by grabbing the operand's value from the instruction.
    value = operand(inst.ea, opnum).value if operand(inst.ea, opnum).type in {idaapi.o_imm} else operand(inst.ea, opnum).addr

    # Now we can try to get all the xrefs from the address value that
    # we extracted. If we couldn't grab anything, then just warn the
    # user about it and return an empty list.
    X = idaapi.xrefblk_t()
    if not X.first_to(value, idaapi.XREF_ALL):
        name = database.name(value)
        logging.warning(u"{:s}.op_refs({:#x}, {:d}) : No references found to global \"{:s}\" ({:#x}).".format(__name__, inst.ea, opnum, utils.string.escape(name, '"'), value))
        return []

    # However, if we were able to find the first value, then we can
    # proceed to gather the rest of them into a list of references.
    refs = [(X.frm, X.iscode, X.type)]
    while X.next_to():
        refs.append((X.frm, X.iscode, X.type))

    # After gathering all of the references into our list, we need
    # to iterate through all of them to figure out exactly what kind
    # of data each reference is targetting.
    res = []
    for ea, _, t in refs:

        # If we got a bad address, then simply skip over it because
        # it's entirely not relevant.
        if ea == idaapi.BADADDR:
            continue

        # Grab the flags for the address of the reference, and mask
        # out everything but its type. If it's type tells us that
        # it's pointing to something defined as code, then we'll
        # need to figure out what operand is referencing it.
        if database.type.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:

            # We iterate through all of the operands in order to extract
            # the value from each operand. This way we can verify that it's
            # s actually the same value in our original instruction operand.
            ops = ((opnum, operand(ea, opnum).value if operand(ea, opnum).type in {idaapi.o_imm} else operand(ea, opnum).addr) for opnum in range(ops_count(ea)))
            ops = (opnum for opnum, val in ops if val == value)

            # As that's been confirmed, we can now create the interface.opref_t
            # with any of the instruction operands that we've determined.
            iterable = (interface.opref_t(ea, int(op), interface.reftype_t.of(t)) for op in ops)

        # If the address of the reference wasn't actually a code
        # type, then this is a data global which doesn't have an
        # operand for us to search through.
        else:
            ref = interface.ref_t(ea, None, interface.reftype_t.of(t))
            iterable = (item for item in [ref])
        res.extend(iterable)
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

        > print( instruction.type.is_return(ea) )
        > print( instruction.type.is_jxx(ea) )
        > print( instruction.type.is_call(ea) )
        > print( instruction.type.is_branch(ea) )

    """
    @utils.multicase()
    @classmethod
    def feature(cls):
        '''Returns the feature bitmask of the instruction at the current address.'''
        return cls.feature(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def feature(cls, ea):
        '''Return the feature bitmask for the instruction at the address `ea`.'''
        if database.type.is_code(ea):
            return at(ea).get_canon_feature()
        return None
    @utils.multicase(ea=six.integer_types, mask=six.integer_types)
    @classmethod
    def feature(cls, ea, mask):
        '''Return the feature bitmask for the instruction at the address `ea` masked with `mask`.'''
        if database.type.is_code(ea):
            return at(ea).get_canon_feature() & idaapi.as_uint32(mask)
        return None

    @utils.multicase()
    @classmethod
    def is_sentinel(cls):
        '''Returns true if the current instruction is a sentinel-type instruction.'''
        return cls.is_sentinel(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_sentinel(cls, ea):
        '''Returns true if the instruction at `ea` is a sentinel-type instruction.'''
        ea = interface.address.inside(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_STOP)])
    issentinel = sentinelQ = utils.alias(is_sentinel, 'type')

    @utils.multicase()
    @classmethod
    def is_return(cls):
        '''Returns true if the current instruction is a return-type instruction.'''
        return cls.is_return(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_return(cls, ea):
        '''Returns true if the instruction at `ea` is a return-type instruction.'''
        ea, Xcfilter = interface.address.inside(ea), {idaapi.get_item_end(ea)}
        F, (Xci, Xdi) = cls.feature(ea), (interface.xiterate(ea, ffirst, fnext) for ffirst, fnext in [(idaapi.get_first_cref_from, idaapi.get_next_cref_from), (idaapi.get_first_dref_from, idaapi.get_next_dref_from)])
        Xc, Xd = ([item for item in X] for X in [(item for item in Xci if item not in Xcfilter), Xdi])
        return cls.is_sentinel(ea) and not any([F & idaapi.CF_JUMP, Xc, Xd])
    isreturn = returnQ = retQ = utils.alias(is_return, 'type')

    @utils.multicase()
    @classmethod
    def is_shift(cls):
        '''Returns true if the current instruction is a bit-shifting instruction.'''
        return cls.is_shift(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_shift(cls, ea):
        '''Returns true if the instruction at `ea` is a bit-shifting instruction.'''
        ea = interface.address.inside(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_SHFT)])
    isshift = shiftQ = utils.alias(is_shift, 'type')

    @utils.multicase()
    @classmethod
    def is_branch(cls):
        '''Returns true if the current instruction is any kind of branch.'''
        return cls.is_branch(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_branch(cls, ea):
        '''Returns true if the instruction at `ea` is any kind of branch.'''
        ea, Xcfilter = interface.address.inside(ea), {idaapi.get_item_end(ea)}
        F, (Xci, Xdi) = cls.feature(ea), (interface.xiterate(ea, ffirst, fnext) for ffirst, fnext in [(idaapi.get_first_cref_from, idaapi.get_next_cref_from), (idaapi.get_first_dref_from, idaapi.get_next_dref_from)])
        Xc, Xd = ([item for item in X] for X in [(item for item in Xci if item not in Xcfilter), Xdi])
        return database.type.is_code(ea) and all([not any([F & idaapi.CF_CALL, F & idaapi.CF_SHFT]), any([F & idaapi.CF_JUMP, Xc])])
    isbranch = branchQ = utils.alias(is_branch, 'type')

    @utils.multicase()
    @classmethod
    def is_jmp(cls):
        '''Returns true if the current instruction is an immediate and indirect branch.'''
        return cls.is_jmp(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_jmp(cls, ea):
        '''Returns true if the instruction at `ea` is an immediate and indirect branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and all([cls.feature(ea, idaapi.CF_STOP)])
    isjmp = jmpQ = utils.alias(is_jmp, 'type')

    @utils.multicase()
    @classmethod
    def is_jxx(cls):
        '''Returns true if the current instruction is a conditional branch.'''
        return cls.is_jxx(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_jxx(cls, ea):
        '''Returns true if the instruction at `ea` is a conditional branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and not all([cls.feature(ea, idaapi.CF_STOP)])
    isjxx = jxxQ = utils.alias(is_jxx, 'type')

    @utils.multicase()
    @classmethod
    def is_jmpi(cls):
        '''Returns true if the instruction at the current address is an indirect branch.'''
        return cls.is_jmpi(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_jmpi(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and all([cls.feature(ea, idaapi.CF_JUMP)])
    isjmpi = jmpiQ = utils.alias(is_jmpi, 'type')

    @utils.multicase()
    @classmethod
    def is_call(cls):
        '''Returns true if the current instruction is a call.'''
        return cls.is_call(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_call(cls, ea):
        '''Returns true if the instruction at `ea` is a call.'''
        ea = interface.address.inside(ea)
        if idaapi.__version__ < 7.0 and hasattr(idaapi, 'is_call_insn'):
            idaapi.decode_insn(ea)
            return idaapi.is_call_insn(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_CALL)])
    iscall = callQ = utils.alias(is_call, 'type')

    @utils.multicase()
    @classmethod
    def is_calli(cls):
        '''Return true if the current instruction is an indirect call.'''
        return cls.is_calli(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def is_calli(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect call.'''
        ea = interface.address.inside(ea)
        F = cls.feature(ea)
        return database.type.is_code(ea) and all([F & idaapi.CF_CALL, F & idaapi.CF_JUMP])
    iscalli = calliQ = utils.alias(is_calli, 'type')

t = type    # XXX: ns alias

feature = utils.alias(type.feature, 'type')
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
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # On PLFM_ARM, op.specflag1 specifies the SIMD vector element size (0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits, 5=128 bits)
        # On PLFM_ARM, op.specflag3 specifies the SIMD scalar index + 1 (Vn.H[i])
        # On PLFM_ARM, if the APSR register is specified, then op.specflag1 contains flags (1=APSR_nzcv, 2=APSR_q, 4=APSR_g)
        # On PLFM_ARM, if the SPSR/CPSR register is specified, then op.specflag1 contains flags (1=CPSR_c, 2=CPSR_x, 4=CPSR_s, 8=CPSR_f)
        # On PLFM_ARM, if a banked register is specified, then op.specflag1 has its high bit (0x80) set

        global architecture
        if op.type in {idaapi.o_reg}:
            res, dt = op.reg, dtype_by_size(database.config.bits() // 8)
            return architecture.by_indextype(res, get_dtype_attribute(op))

        optype = "{:s}({:d})".format('idaapi.o_reg', idaapi.o_reg)
        raise E.InvalidTypeOrValueError(u"{:s}.register({:#x}, {!r}) : Expected operand type `{:s}` but operand type {:d} was received.".format('.'.join([__name__, 'operand_types']), ea, op, optype, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_imm)
    def immediate(ea, op):
        '''Operand type decoder for ``idaapi.o_imm`` which returns an immediate integer.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # On PLFM_ARM, op.specflag2 specifies a shift type
        # On PLFM_ARM, op.specval specifies a shift counter

        if op.type in {idaapi.o_imm, idaapi.o_phrase}:
            bits = 8 * get_dtype_size(get_dtype_attribute(op))

            # Figure out the maximum operand size using the operand's type,
            # and convert the value that was returned by IDAPython into its
            # signed format so that we can figure out what to return.
            maximum, value = pow(2, bits), op.value
            res = idaapi.as_signed(value, bits)

            # We need to always mask our operand's value to the maximum value
            # supported by the operand. The "inverted" variation needs to be
            # signed, but within our supported bitmask. So if the value is
            # less than 0, then take it as-is. Otherwise if it's positive, then
            # we need to shift it by 1-past the smallest possible value.
            regular = res & (maximum - 1)
            inverted = res if res < 0 else value - maximum
            return res and inverted if interface.node.alt_opinverted(ea, op.n) else regular
        optype = "{:s}({:d})".format('idaapi.o_imm', idaapi.o_imm)
        raise E.InvalidTypeOrValueError(u"{:s}.immediate({:#x}, {!r}) : Expected operand type `{:s}` but operand type {:d} was received.".format('.'.join([__name__, 'operand_types']), ea, op, optype, op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_far)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_near)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_near)
    def memory(ea, op):
        '''Operand type decoder for memory-type operands which return an address.'''
        if op.type in {idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ}:
            seg, sel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
            return op.addr
        optype = map(utils.funpack("{:s}({:d})".format), [('idaapi.o_far', idaapi.o_far), ('idaapi.o_near', idaapi.o_near)])
        raise E.InvalidTypeOrValueError(u"{:s}.address({:#x}, {!r}) : Expected operand type `{:s}` or `{:s}` but operand type {:d} was received.".format('.'.join([__name__, 'operand_types']), ea, op, optype[0], optype[1], op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec0)
    def trregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec0`` which returns a trap register on the Intel architecture.'''
        global architecture
        raise E.UnsupportedCapability(u"{:s}.trregister({:#x}, ...) : Trap registers (`%trX`) are not implemented for the Intel platform.".format('.'.join([__name__, 'operand_types']), ea))
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec1)
    def dbregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec1`` which returns a Db register on the Intel architecture.'''
        global architecture
        raise E.UnsupportedCapability(u"{:s}.dbregister({:#x}, ...) : Db registers (`%dbX`) are not implemented for the Intel platform.".format('.'.join([__name__, 'operand_types']), ea))
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec2)
    def crregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec2`` which returns a control register on the Intel architecture.'''
        global architecture
        regnum = op.reg
        return architecture.by_control(regnum)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec3)
    def fpregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec3`` which returns an FPU register on the Intel architecture.'''
        global architecture
        regnum = op.reg
        return architecture.by_float(regnum)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec4)
    def mmxregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec4`` which returns an MMX register on the Intel architecture.'''
        global architecture
        regnum = op.reg
        return architecture.by_mmx(regnum)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec5)
    def xmmregister(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec5`` which returns an XMM register on the Intel architecture.'''
        global architecture
        regnum = op.reg
        return architecture.by_xmm(regnum)

    @__optype__.define(idaapi.PLFM_386, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_displ)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_phrase)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory phrase on the Intel architecture.'''
        F1, F2 = op.specflag1, op.specflag2
        if op.type in {idaapi.o_displ, idaapi.o_phrase}:
            if F1 == 0:
                base = op.reg
                index = None

            elif F1 == 1:
                base = (F2 & 0x07) >> 0
                index = (F2 & 0x38) >> 3

            else:
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the operand format for op.type {:d}. The value of `op_t.specflag1` was {:d}.".format('.'.join([__name__, 'operand_types']), ea, op, op.type, F1))

            if op.type == idaapi.o_displ:
                offset = op.addr
            elif op.type == idaapi.o_phrase:
                offset = op.value
            else:
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the offset for op.type ({:d}).".format('.'.join([__name__, 'operand_types']), ea, op, op.type))

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
                raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Unable to determine the operand format for op.type {:d}. The value of `op_t.specflag1` was {:d}.".format('.'.join([__name__, 'operand_types']), ea, op, op.type, F1))
            offset = op.addr

        else:
            optype = map(utils.funpack("{:s}({:d})".format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
            raise E.InvalidTypeOrValueError(u"{:s}.phrase({:#x}, {!r}) : Expected operand type {:s}, {:s}, or {:s} but operand type {:d} was received.".format('.'.join([__name__, 'operand_types']), ea, op, optype[0], optype[1], optype[2], op.type))

        # if arch == x64, then index += 8

        scale_lookup = {
            0x00 : 1,   # 00
            0x40 : 2,   # 01
            0x80 : 4,   # 10
            0xc0 : 8,   # 11
        }
        scale = scale_lookup[F2 & 0xc0]

        bits = database.config.bits()
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size

        seg, sel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0

        # Figure out the maximum value for the offset parse of the phrase which
        # IDA seems to use the number of bits from the database to clamp. Then
        # we can convert the value that we get from IDAPython into its signed
        # form so that we can calculate the correct value for whatever variation
        # we need to return.
        maximum, dt = pow(2, bits), dtype_by_size(database.config.bits() // 8)
        res = idaapi.as_signed(offset, bits)

        # Our regular offset needs to be masked within the maximum value as
        # specified by the number of bits for the database's processor. The
        # "inverted" variation also needs to satisfy the same constraints,
        # but needs to be signed. If the value of the offset is less than
        # 0, then we can take it as-is. Otherwise if it's positive, then we
        # need to take the difference of it and 1-past the smallest value.
        regular = res & (maximum - 1)
        inverted = res if res < 0 else offset - maximum

        global architecture
        items = res and inverted if interface.node.alt_opinverted(ea, op.n) else regular, None if base is None else architecture.by_indextype(base, dt), None if index is None else architecture.by_indextype(index, dt), scale
        return intelops.OffsetBaseIndexScale(*items)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_phrase)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory phrase on either the AArch32 or AArch64 architectures.'''
        global architecture

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.specflag3 specifies the NEON alignment by power-of-two

        Rn, Rm = architecture.by_index(op.reg), architecture.by_index(op.specflag1)
        return armops.registerphrase(Rn, Rm)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_displ)
    def phrase(ea, op):
        '''Operand type decoder for returning a memory displacement on either the AArch32 or AArch64 architectures.'''
        global architecture
        Rn = architecture.by_index(op.reg)
        return armops.immediatephrase(Rn, idaapi.as_signed(op.addr))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_mem)
    def memory(ea, op):
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

        return armops.memory(addr, res - maxval if sf else res)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec0)
    def flex(ea, op):
        '''Operand type decoder for returning a flexible operand (shift-op) on either the AArch32 or AArch64 architectures.'''
        global architecture

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.specflag2 = shift-type
        # op.specflag1 = shift register to use
        # op.value = shift count

        Rn = architecture.by_index(op.reg)
        shift = 0                                           # XXX: This should be implemented using the above information
        return armops.flex(Rn, int(shift), int(op.value))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec1)
    def list(ea, op):
        '''Operand type decoder for returning a register list on either the AArch32 or AArch64 architectures.'''
        global architecture
        res = set()

        # FIXME: op.specflag1 specifies the PSR and force-user bit, which has the ^ suffix

        # op.specval represents a bitmask specifying which registers are included
        specval = op.specval
        for index in range(16):
            if specval & 1:
                res.add(architecture.by_index(index))
            specval >>= 1
        return armops.list(res)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec2)
    def coprocessorlist(ea, op):
        '''Operand type decoder for the coprocessor register list (CDP) on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.reg == CRd
        # op.specflag1 == CRn
        # op.specflag2 == CRm

        raise NotImplementedError(u"{:s}.coprocessorlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), ea, op.type, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec3)
    def coprocessorlist(ea, op):
        '''Operand type decoder for the coprocessor register list (LDC/STC) on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.specflag1 == processor number
        raise NotImplementedError(u"{:s}.coprocessorlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), ea, op.type, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec4)
    def extensionlist(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec4`` which returns a floating-point register list on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # op.reg == first floating-point register
        # op.value == number of floating-point registers
        # op.specflag2 == spacing between registers (0: {Dd, Dd+1,... }, 1: {Dd, Dd+2, ...} etc)
        # op.specflag3 == neon scalar index + 1 (Dd[x]). if index is 254, then this represents the entire set (Dd[...])

        raise NotImplementedError(u"{:s}.extensionlist({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), ea, op.type, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec5)
    def text(ea, op):
        '''Operand type decoder for ``idaapi.o_idpspec5`` which returns arbitrary text on either the AArch32 or AArch64 architectures.'''

        # FIXME: This information was found in the sdk by @BrunoPujos.
        # The entire op_t structure contains the designated text starting at op.value

        raise NotImplementedError(u"{:s}.text({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), ea, op.type, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec5 + 1)
    def condition(ea, op):
        '''Operand type decoder for dealing with an undocumented operand type found on AArch64.'''

        # FIXME: There's a couple of attributes here that seem relevant: op.value, op.reg, op.n
        # op.value == condition

        raise NotImplementedError(u"{:s}.condition({:#x}, {:d}) : An undocumented operand type ({:d}) was found at the specified address.".format('.'.join([__name__, 'operand_types']), ea, op.type, op.type))

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_displ)
    def phrase(ea, op):
        '''Operand type decoder for memory phrases on MIPS architecturs.'''
        global architecture

        rt, imm = architecture.by_index(op.reg), op.addr
        return mipsops.phrase(rt, imm)

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_idpspec0)
    def code(ea, op):
        '''Operand type decoder for trap codes on MIPS architectures.'''
        res = op.value
        return mipsops.trap(int(res))

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_idpspec1)
    def float(ea, op):
        '''Operand type decoder for floating-point registers on MIPS architectures.'''
        index = op.reg
        return mipsops.float(index)
del(operand_types)

## intel operands
class intelops:
    """
    This internal namespace contains the different operand types that
    can be returned for the Intel architecture.
    """
    class SegmentOffset(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing an address with a segment register attached on the Intel architecture.

        Has the format `(segment, offset)` where `segment` is a segment register.
        """
        _fields = ('segment', 'offset')
        _types = (
            (None.__class__, interface.register_t),
            six.integer_types,
        )

        @property
        def symbols(self):
            '''Yield the `segment` register from the tuple if it is defined.'''
            segment, _ = self
            if segment:
                yield segment
            return

        def __repr__(self):
            cls, fields = self.__class__, {'offset'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    class SegmentOffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory phrase operand on the Intel architecture.

        Has the format `(segment, offset, base, index, scale)` where `segment`
        includes the segment register and both the `base` and `index` registers
        are both optional.
        """
        _fields = ('segment', 'offset', 'base', 'index', 'scale')
        _types = (
            (None.__class__, interface.register_t),
            six.integer_types,
            (None.__class__, interface.register_t),
            (None.__class__, interface.register_t),
            six.integer_types,
        )

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

        def __repr__(self):
            cls, fields = self.__class__, {'offset'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    class OffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory phrase for the Intel architecture.

        Has the format `(offset, base, index, scale)` where both
        `base` and `index` are both optional registers.
        """
        _fields = ('offset', 'base', 'index', 'scale')
        _types = (
            six.integer_types,
            (None.__class__, interface.register_t),
            (None.__class__, interface.register_t),
            six.integer_types,
        )

        @property
        def symbols(self):
            '''Yield the `base`, and the `index` registers from the tuple if they are defined.'''
            _, base, index, _ = self
            if base:
                yield base
            if index:
                yield index
            return

        def __repr__(self):
            cls, fields = self.__class__, {'offset'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

## arm operands
class armops:
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
            six.integer_types,
            six.integer_types
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
        _types = (set, )

        @property
        def symbols(self):
            '''Yield any of the registers within the `reglist` field belonging to the tuple.'''
            list, = self
            for regster in list:
                yield register
            return

    class immediatephrase(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple representing a memory displacement operand on either the AArch32 or AArch64 architectures.

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
            register, _ = self
            yield register

        def __repr__(self):
            cls, fields = self.__class__, {'offset'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

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

    class memory(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a memory operand on either the AArch32 or AArch64 architectures.

        Has the format `(address, value)` where `address` is the actual value
        stored in the operand and `value` is the value that would be dereferenced.
        """
        _fields = ('address', 'value')
        _types = (six.integer_types, six.integer_types)

        @property
        def symbols(self):
            '''This operand type is not composed of any symbols.'''
            raise StopIteration
            yield   # so that this function is still treated as a generator

        def __repr__(self):
            cls, fields = self.__class__, {'address', 'value'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

## mips operands
class mipsops:
    """
    This internal namespace contains the different operand types that
    are used by the MIPS architectures.
    """

    class phrase(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a memory phrase operand on the MIPS architectures.

        Has the format `(Rn, Offset)` where `Rn` is the register and
        `Offset` is the immediate that is added to the `Rn` register.
        """
        _fields = ('Rn', 'Offset')
        _types = (interface.register_t, six.integer_types)

        register = property(fget=operator.itemgetter(0))
        immediate = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            '''Yield the `Rn` register from this tuple.'''
            register, _ = self
            yield register

        def __repr__(self):
            cls, fields = self.__class__, {'Offset'}
            res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
            return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    class trap(interface.namedtypedtuple, interface.symbol_t):
        """
        A tuple for representing a trap code that can be encoded within
        certain instructions on the MIPS architectures.

        Simply wraps the encoded integer in a single-element tuple with
        the format of `(code)`.
        """
        _fields = ('code',)
        _types = (six.integer_types,)

        code = property(fget=operator.itemgetter(0))

        @property
        def symbols(self):
            '''This operand type is not composed of any symbols.'''
            raise StopIteration
            yield   # so that this function is still treated as a generator

    @staticmethod
    def coprocessor(index):
        """
        A callable that returns a coprocessor register on the MIPS architectures.

        Takes an integer argument which returns the coprocessor register for
        the requested `index`.
        """
        global architecture
        return architecture.by_coprocessor(index)

    @staticmethod
    def float(index):
        """
        A callable that returns a floating-point register on the MIPS architectures.

        Takes an integer representing the `index` of the desired floating-point
        register to return.
        """
        global architecture
        return architecture.by_float(index)

## architecture registers
class Intel(interface.architecture_t):
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
        i2s = "{:d}".format

        [ setitem('r'+_, self.new('r'+_, 64, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_, self.new('r'+_, 64)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('e'+_, self.child(self.by_name('r'+_), 'e'+_, 0, 32, _)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem('r'+_+'d', self.child(self.by_name('r'+_), 'r'+_+'d', 0, 32, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('r'+_+'w', self.child(self.by_name('r'+_+'d'), 'r'+_+'w', 0, 16, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem('r'+_+'b', self.child(self.by_name('r'+_+'w'), 'r'+_+'b', 0, 8, idaname='r'+_)) for _ in map(i2s, range(8, 16)) ]
        [ setitem(    _, self.child(self.by_name('e'+_), _, 0, 16)) for _ in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip') ]
        [ setitem(_+'h', self.child(self.by_name(_+'x'), _+'h', 8, 8)) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_+'x'), _+'l', 0, 8)) for _ in ('a', 'c', 'd', 'b') ]
        [ setitem(_+'l', self.child(self.by_name(_), _+'l', 0, 8)) for _ in ('sp', 'bp', 'si', 'di') ]
        [ setitem(    _, self.new(_, 16)) for _ in ('es', 'cs', 'ss', 'ds', 'fs', 'gs') ]
        setitem('fpstack', self.new('fptags', 80*8, dtype=None))    # FIXME: is this the right IDA register name??

        # FIXME: rex-prefixed 32-bit registers are implicitly extended to the 64-bit regs which implies that 64-bit are children of 32-bit
        for _ in ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip']:
            r32, r64 = getitem('e'+_), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }
        for _ in map(i2s, range(8, 16)):
            r32, r64 = getitem('r'+_+'d'), getitem('r'+_)
            r32.alias, r64.alias = { r64 }, { r32 }

        # explicitly set the lookups for (word-register, idaapi.dt_byte) which exist due to ida's love for the inconsistent
        [ self.__cache__.setdefault((_+'x', self.by_name(_+'l').dtype), self.by_name(_+'l').__name__) for _ in ('a', 'c', 'd', 'b') ]

        fpstack = self.__register__.fpstack
        # single precision
        [ setitem("st{:d}f".format(_), self.child(fpstack, "st{:d}f".format(_), _*80, 80, "st{:d}".format(_), dtype=idaapi.dt_float)) for _ in range(8) ]
        # double precision
        [ setitem("st{:d}d".format(_), self.child(fpstack, "st{:d}d".format(_), _*80, 80, "st{:d}".format(_), dtype=idaapi.dt_double)) for _ in range(8) ]
        # umm..80-bit precision? i've seen op_t's in ida for fsubp with the implied st(0) using idaapi.dt_tbyte
        [ setitem("st{:d}".format(_), self.child(fpstack, "st{:d}".format(_), _*80, 80, "st{:d}".format(_), dtype=idaapi.dt_tbyte)) for _ in range(8) ]

        # not sure if the mmx registers trash the other 16 bits of an fp register
        [ setitem("mm{:d}".format(_), self.child(fpstack, "mm{:d}".format(_), _*80, 64, dtype=idaapi.dt_qword)) for _ in range(8) ]

        # sse1/sse2 simd registers
        [ setitem("xmm{:d}".format(_), self.new("xmm{:d}".format(_), 128, dtype=idaapi.dt_byte16)) for _ in range(16) ]
        [ setitem("ymm{:d}".format(_), self.new("ymm{:d}".format(_), 128, dtype=idaapi.dt_ldbl)) for _ in range(16) ]

        # control registers
        [ setitem("cr{:d}".format(_), self.new("cr{:d}".format(_), database.config.bits())) for _ in range(8) ]

        ##fpctrl, fpstat, fptags
        ##mxcsr
        ## 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if', 'df', 'efl',

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
            [ setitem("d{:d}".format(_), self.child(getitem("v{:d}".format(_)), "d{:d}".format(_), 0, 64, idaname="V{:d}".format(_), dtype=idaapi.dt_double)) for _ in range(32) ]
        else:
            [ setitem("d{:d}".format(_), self.child(getitem("v{:d}".format(_)), "d{:d}".format(_), 0, 64, idaname="D{:d}".format(_), dtype=idaapi.dt_double)) for _ in range(32) ]
        [ setitem("s{:d}".format(_), self.child(getitem("d{:d}".format(_)), "s{:d}".format(_), 0, 32, idaname="S{:d}".format(_), dtype=idaapi.dt_float)) for _ in range(32) ]
        [ setitem("h{:d}".format(_), self.child(getitem("s{:d}".format(_)), "h{:d}".format(_), 0, 16, idaname="X{:d}".format(_), dtype=getattr(idaapi, 'dt_half', idaapi.dt_word))) for _ in range(32) ]
        [ setitem("b{:d}".format(_), self.child(getitem("h{:d}".format(_)), "b{:d}".format(_), 0, 8, idaname="X{:d}".format(_))) for _ in range(32) ]

        # General-purpose registers
        [ setitem("x{:d}".format(_), self.new("x{:d}".format(_), BITS, idaname="X{:d}".format(_))) for _ in range(31) ]
        if BITS > 32:
            [ setitem("w{:d}".format(_), self.child(self.by_name("x{:d}".format(_)), "w{:d}".format(_), 0, 32, idaname="X{:d}".format(_))) for _ in range(31) ]
        setitem('lr', self.new('lr', BITS, idaname='LR', alias={'x31'}))

        # Zero registers and special regs
        setitem('xzr', self.new('xzr', BITS, idaname='XZR'))
        if BITS > 32:
            setitem('wzr', self.new('wzr', 32, idaname='XZR'))
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

class AArch32(AArch):
    """
    An implementation of all the registers available on the AArch32 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is AArch32.
    """

    def __init__(self):
        return super(AArch32, self).__init__(32)

class AArch64(AArch):
    """
    An implementation of all the registers available on the AArch64 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is AArch64.
    """

    def __init__(self):
        return super(AArch64, self).__init__(64)

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
            [ setitem("f{:d}".format(_), self.new("f{:d}".format(_), BITS, idaname="$f{:d}".format(_), dtype=idaapi.dt_double)) for _ in range(32) ]
        else:
            [ setitem("f{:d}".format(_), self.new("f{:d}".format(_), BITS, idaname="$f{:d}".format(_), dtype=idaapi.dt_float)) for _ in range(32) ]

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
        setitem('DataLo', self.new('TagLo', BITS, id=0))        # 28.1
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

class MIPS64(MIPS):
    """
    An implementation of all the registers available on the MIPS64 architecture.

    This includes the different coprocessor registers that are also available
    but are treated as special instructions by IDA.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is MIPS.
    """

    def __init__(self):
        return super(MIPS64, self).__init__(64)

## global initialization
def __nw_newprc__(nw_code, is_old_database):
    pnum = idaapi.ph_get_id()
    return __newprc__(pnum)
def __ev_newprc__(pnum, keep_cfg):
    return __newprc__(pnum)
def __newprc__(id):
    """
    Determine the architecture from the current processor and use it to initialize
    the globals (``architecture`` and ``register``) within this module.
    """
    if not hasattr(database, 'config'):
        # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
        return

    plfm, m = idaapi.ph.id, __import__('sys').modules[__name__]
    if plfm == idaapi.PLFM_386:     # id == 15
        res, description = Intel(), "Intel architecture {:d}-bit".format(database.config.bits())
    elif plfm == idaapi.PLFM_ARM:   # id == 1
        res, description = AArch64() if database.config.bits() > 32 else AArch32(), "AArch{:d}".format(database.config.bits())
    elif plfm == idaapi.PLFM_MIPS:  # id == 12
        res, description = MIPS64() if database.config.bits() > 32 else MIPS32(), "MIPS{:d}".format(database.config.bits())
    else:
        logging.warning("{:s} : IDP_Hooks.newprc({:d}) : Unsupported processor type {:d} was specified. Tools that use the instruction module might not work properly.".format(__name__, id, plfm))
        return

    logging.warning("Detected processor module : {:s} ({:d})".format(description, plfm))

    # assign our required globals
    m.architecture, m.register = res, res.r

    # assign some aliases so that its much shorter to type
    m.arch, m.reg = m.architecture, m.register

# initialize with a default processor on the initial import but not on reload()
if 'architecture' not in locals() or 'register' not in locals():
    __newprc__(0)
