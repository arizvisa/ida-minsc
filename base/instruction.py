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

import builtins, itertools, functools, logging, operator

import database, function, structure, enumeration, architecture, ui
import idaapi, internal, __catalog__ as catalog
from internal import utils, interface, types, exceptions as E

## general functions
@utils.multicase()
def at():
    '''Return the ``idaapi.insn_t`` of the current instruction.'''
    return at(ui.current.address())
@utils.multicase(ea=types.integer)
def at(ea):
    '''Return the ``idaapi.insn_t`` of the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    if interface.address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
        raise E.InvalidTypeOrValueError(u"{:s}.at({:#x}) : Unable to decode a non-instruction at the specified address ({:#x}).".format(__name__, ea, ea))
    return interface.instruction.at(ea)

@utils.multicase()
def size():
    '''Returns the length of the instruction at the current address.'''
    return size(ui.current.address())
@utils.multicase(ea=types.integer)
def size(ea):
    '''Returns the length of the instruction at the address `ea`.'''
    return at(ea).size

@utils.multicase(opnum=types.integer)
def opinfo(opnum):
    '''Returns the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return opinfo(ui.current.address(), opnum)
@utils.multicase(opnum=types.integer, info=idaapi.opinfo_t)
def opinfo(opnum, info, **flags):
    '''Set the opinfo for the operand `opnum` at the current address to the ``idaapi.opinfo_t`` provided by `info`.'''
    return opinfo(ui.current.address(), opnum, info, **flags)
@utils.multicase(reference=interface.opref_t)
def opinfo(reference):
    '''Returns the ``idaapi.opinfo_t`` for the operand pointed to by the provided `reference`.'''
    address, opnum, _ = reference
    return opinfo(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def opinfo(ea, opnum):
    '''Returns the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    ti, flags = idaapi.opinfo_t(), database.type.flags(ea)
    return idaapi.get_opinfo(ea, opnum, flags, ti) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(ti, ea, opnum, flags)
@utils.multicase(reference=interface.opref_t, info=idaapi.opinfo_t)
def opinfo(reference, info, **flags):
    '''Set the operand info for the operand specified by `reference` to the ``idaapi.opinfo_t`` provided by `info`.'''
    address, opnum, _ = reference
    return opinfo(address, opnum, info, **flags)
@utils.multicase(ea=types.integer, opnum=types.integer, info=idaapi.opinfo_t)
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
    '''Return the mnemonic of the current instruction.'''
    return mnemonic(ui.current.address())
@utils.multicase(ea=types.integer)
def mnemonic(ea):
    '''Return the mnemonic of the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    if interface.address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
        raise E.InvalidTypeOrValueError(u"{:s}.mnemonic({:#x}) : Unable to get the mnemonic for a non-instruction at the specified address ({:#x}).".format(__name__, ea, ea))
    return interface.instruction.mnemonic(ea)
mnem = utils.alias(mnemonic)

## functions that return an ``idaapi.op_t`` for an operand
@utils.multicase()
def operands():
    '''Return the ``idaapi.op_t`` of the operands for the current instruction.'''
    return operands(ui.current.address())
@utils.multicase(ea=types.integer)
def operands(ea):
    '''Return the ``idaapi.op_t`` of the operands for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    operands = interface.instruction.operands(ea)
    return tuple(operands)

@utils.multicase(opnum=types.integer)
def operand(opnum):
    '''Return the ``idaapi.op_t`` of the operand `opnum` for the current instruction.'''
    return operand(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def operand(reference):
    '''Return the ``idaapi.op_t`` of the given operand `reference`.'''
    address, opnum, _ = reference
    return operand(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def operand(ea, opnum):
    '''Return the ``idaapi.op_t`` of the operand `opnum` for the instruction at address `ea`.'''
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
    '''Return the number of available operands for the current instruction.'''
    return ops_count(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_count(ea):
    '''Return the number of available operands for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    return len(operands(ea))

@utils.multicase()
def ops_repr():
    '''Return the string representation of the operands for the current instruction.'''
    return ops_repr(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_repr(ea):
    '''Return the string representation of the operands for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_repr, ea)
    return tuple(map(f, range(ops_count(ea))))

@utils.multicase()
def ops():
    '''Return the decoded operands for the current instruction.'''
    return ops(ui.current.address())
@utils.multicase(ea=types.integer)
def ops(ea):
    '''Return the decoded operands for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op, ea)
    return tuple(map(f, range(ops_count(ea))))
ops_value = utils.alias(ops)

@utils.multicase()
def ops_size():
    '''Return the sizes of the operands for the current instruction.'''
    return ops_size(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_size(ea):
    '''Return the sizes of the operands for the instruction at address `ea`.'''
    get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
    get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

    ea = interface.address.inside(ea)
    f = utils.fcompose(functools.partial(operand, ea), get_dtype_attribute, get_dtype_size, int)
    return tuple(map(f, range(ops_count(ea))))

@utils.multicase()
def opts():
    '''Return the pythonic types for the operands belonging to the current instruction.'''
    return ops_type(ui.current.address())
@utils.multicase(ea=types.integer)
def opts(ea):
    '''Return the pythonic types for the operands belonging to the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(opt, ea)
    return tuple(map(f, range(ops_count(ea))))
ops_type = utils.alias(opts)

@utils.multicase()
def ops_decoder():
    '''Return the names of the decoders used to decode the operands for the current instruction.'''
    return ops_decoder(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_decoder(ea):
    '''Return the names of the decoders used for decode the operands for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_decoder, ea)
    return tuple(map(f, range(ops_count(ea))))

@utils.multicase()
def ops_state():
    '''Returns a tuple for all the operands containing one of the states "r", "w", or "rw"` describing how the operands for the current instruction operands are modified.'''
    return ops_state(ui.current.address())
@utils.multicase(ea=types.integer)
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
@utils.multicase(ea=types.integer)
def opsi_read(ea):
    '''Returns the indices of any operands that are being read from by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'r' in state)
@utils.multicase()
def ops_read():
    '''Return the operands that are being read from by the instruction at the current address.'''
    return ops_read(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_read(ea):
    '''Return the operands that are being read from by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_read(ea))

@utils.multicase()
def opsi_write():
    '''Returns the indices of the operands that are being written to by the instruction at the current address.'''
    return opsi_write(ui.current.address())
@utils.multicase(ea=types.integer)
def opsi_write(ea):
    '''Returns the indices of the operands that are being written to by the instruction at the address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'w' in state)
@utils.multicase()
def ops_write():
    '''Return the operands that are being written to by the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_write(ea):
    '''Return the operands that are being written to by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_write(ea))

@utils.multicase()
def opsi_constant():
    '''Return the indices of any operands in the current instruction that are constants.'''
    return opsi_constant(ui.current.address())
@utils.multicase(ea=types.integer)
def opsi_constant(ea):
    '''Return the indices of any operands in the instruction at `ea` that are constants.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, value in enumerate(ops_value(ea)) if isinstance(value, types.integer))
opsi_const = utils.alias(opsi_constant)
@utils.multicase()
def ops_constant():
    '''Return the operands that are being written to by the instruction at the current address.'''
    return ops_constant(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_constant(ea):
    '''Return the operands that are being written to by the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_constant(ea))
ops_const = utils.alias(ops_constant)

@utils.multicase()
def opsi_register(**modifiers):
    '''Returns the index of each operand in the instruction at the current address which uses a register.'''
    return opsi_register(ui.current.address(), **modifiers)
@utils.multicase(ea=types.integer)
def opsi_register(ea, **modifiers):
    '''Returns the index of each operand in the instruction at the address `ea` which uses a register.'''
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    fregisterQ = utils.fcompose(op, utils.fcondition(utils.finstance(interface.symbol_t))(utils.fcompose(utils.fattribute('symbols'), functools.partial(map, utils.finstance(interface.register_t)), any), utils.fconstant(False)))
    return tuple(filter(functools.partial(fregisterQ, ea), iterops(ea)))
@utils.multicase(reg=(types.string, interface.register_t))
def opsi_register(reg, *regs, **modifiers):
    '''Returns the index of each operand in the instruction at the current address that uses `reg` or any one of the registers in `regs`.'''
    return opsi_register(ui.current.address(), reg, *regs, **modifiers)
@utils.multicase(ea=types.integer, reg=(types.string, interface.register_t))
def opsi_register(ea, reg, *regs, **modifiers):
    """Returns the index of each operand in the instruction at address `ea` that uses `reg` or any one of the registers in `regs`.

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    uses = interface.regmatch.use( (reg,) + regs )
    return tuple(filter(functools.partial(uses, ea), iterops(ea)))
opsi_regi = opsi_reg = opsi_regs = opsi_registers = utils.alias(opsi_register)

@utils.multicase()
def ops_register(**modifiers):
    '''Returns each register operand in the instruction at the current address.'''
    return ops_register(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_register(ea, **modifiers):
    '''Returns each register operand in the instruction at the current address.'''
    return tuple(op(ea, index) for index in opsi_register(ea, **modifiers))
@utils.multicase(reg=(types.string, interface.register_t))
def ops_register(reg, *regs, **modifiers):
    '''Returns each register operand in the instruction at the current address that is `reg` or any one of the registers in `regs`.'''
    return ops_register(ui.current.address(), reg, *regs, **modifiers)
@utils.multicase(ea=types.integer, reg=(types.string, interface.register_t))
def ops_register(ea, reg, *regs, **modifiers):
    """Returns each register operand in the instruction at the address `ea` that is `reg` or any one of the registers in `regs`.'''

    If the keyword `write` is true, then only return the result if it's writing to the register.
    """
    return tuple(op(ea, index) for index in opsi_register(ea, reg, *regs, **modifiers))
ops_reg = ops_regs = ops_registers = utils.alias(ops_register)

## functions vs a specific operand of an insn
@utils.multicase(opnum=types.integer)
def op_repr(opnum):
    '''Return the string representation of the operand `opnum` for the current instruction.'''
    return op_repr(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_repr(reference):
    '''Return the string representation of the given operand `reference`.'''
    address, opnum, _ = reference
    return op_repr(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_repr(ea, opnum):
    '''Return the string representation of the operand `opnum` for the instruction at address `ea`.'''
    insn = at(ea)
    oppr = idaapi.ua_outop2 if idaapi.__version__ < 7.0 else idaapi.print_operand
    outop = utils.fcompose(idaapi.ua_outop2, idaapi.tag_remove) if idaapi.__version__ < 7.0 else utils.fcompose(idaapi.print_operand, idaapi.tag_remove)
    try:
        res = outop(insn.ea, opnum) or "{:s}".format(op(insn.ea, opnum))
    except:
        logging.warning(u"{:s}({:#x}, {:d}) : Unable to strip tags from operand \"{:s}\". Returning the result from {:s} instead.".format('.'.join([__name__, 'op_repr']), ea, opnum, utils.string.escape(oppr(insn.ea, opnum), '"'), '.'.join([__name__, 'op'])))
        return u"{!s}".format(op(insn.ea, opnum))
    return utils.string.of(res)

@utils.multicase(opnum=types.integer)
def op_state(opnum):
    '''Returns the modification state for the operand `opnum` belonging to the current instruction.'''
    return op_state(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_state(reference):
    '''Returns the modification state for the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_state(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

# we needed an adjective, but "read" is a verb and a noun. this should be thought of in its noun form.
@utils.multicase(opnum=types.integer)
def op_read(opnum):
    '''Return whether the operand `opnum` belonging to the current instruction is only being read from.'''
    return op_read(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_read(reference):
    '''Return whether the operand pointed to by `reference` is only being read from.'''
    address, opnum, _ = reference
    return op_read(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_read(ea, opnum):
    '''Return whether the operand `opnum` belonging to the instruction at the address `ea` is only being read from.'''
    return 'r' in op_state(ea, opnum)
op_used = utils.alias(op_read)          # XXX: read/modified or used/modified?

@utils.multicase(opnum=types.integer)
def op_modified(opnum):
    '''Return whether the operand `opnum` belonging to the current instruction is being modified (written to).'''
    return op_modified(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_modified(reference):
    '''Return whether the operand pointed to by `reference` is being modified (written to).'''
    address, opnum, _ = reference
    return op_modified(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_modified(ea, opnum):
    '''Return whether the operand `opnum` belonging to the instruction at the address `ea` is being modified (written to).'''
    return 'w' in op_state(ea, opnum)
op_written = op_write = utils.alias(op_modified)        # XXX: these aliases are needed because our opposite is `op_read`

@utils.multicase(opnum=types.integer)
def op_size(opnum):
    '''Return the size of the operand `opnum` for the current instruction.'''
    return op_size(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_size(reference):
    '''Return the size for the given operand `reference`.'''
    address, opnum, _ = reference
    return op_size(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_size(ea, opnum):
    '''Return the size of the operand `opnum` for the instruction at address `ea`.'''
    get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
    get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

    res = operand(ea, opnum)
    return 0 if res.type == idaapi.o_void else get_dtype_size(get_dtype_attribute(res))
@utils.multicase(opnum=types.integer)
def op_bits(opnum):
    '''Return the number of bits for the operand `opnum` belonging to the current instruction.'''
    return 8 * op_size(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_bits(reference):
    '''Return the number of bits for the given operand `reference`.'''
    return 8 * op_size(reference)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_bits(ea, opnum):
    '''Return the number of bits for the operand `opnum` belonging to the instruction at address `ea`.'''
    return 8 * op_size(ea, opnum)

@utils.multicase(opnum=types.integer)
def op_decoder(opnum):
    '''Return the name of the decoder used to decode operand `opnum` for the current instruction.'''
    return op_decoder(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_decoder(reference):
    '''Return the name of the decoder used to decode the given operand `reference`.'''
    address, opnum, _ = reference
    return op_decoder(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_decoder(ea, opnum):
    """Return the name of the decoder used to decode the operand `opnum` for the instruction at address `ea`.

    The string that is returned is dependent on the processor module used by the database.
    """
    res = operand(ea, opnum)
    return catalog.operand.type(res)

@utils.multicase(opnum=types.integer)
def op_type(opnum):
    '''Return the pythonic type of the operand `opnum` for the current instruction.'''
    return op_type(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_type(reference):
    '''Return the pythonic type for the given operand `reference`.'''
    address, opnum, _ = reference
    return op_type(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_type(ea, opnum):
    '''Return the pythonic type of the operand `opnum` for the instruction at address `ea`.'''
    op, opsize = operand(ea, opnum), op_size(ea, opnum)

    # if our operand is not a register, then we can use the operand type.
    if op.type not in {idaapi.o_reg}:
        return catalog.operand.ptype(op), opsize

    # now we have the register and we only decode the instruction with its
    # operand and then we can verify that its operand size matches.
    insn = at(ea)
    regtype, size = catalog.operand.decode(insn, op).type
    if size != opsize:
        logging.info(u"{:s}.op_type({:#x}, {:d}) : Returning the operand size ({:d}) as it is different from the register size ({:d}).".format(__name__, ea, opnum, opsize, size))
    return regtype, opsize
opt = utils.alias(op_type)

@utils.multicase(opnum=types.integer)
def op(opnum):
    '''Decode the operand `opnum` for the current instruction.'''
    return op(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op(reference):
    '''Decode the operand for the given `reference`.'''
    address, opnum, _ = reference
    return op(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op(ea, opnum):
    '''Decode the operand `opnum` for the instruction at address `ea`.'''
    insn, res = at(ea), operand(ea, opnum)
    return catalog.operand.decode(insn, res)
op_value = utils.alias(op)

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
@utils.multicase(opnum=types.integer)
def op_segment(opnum):
    '''Return the segment register used by the operand `opnum` for the current instruction.'''
    return op_segment(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_segment(reference):
    '''Return the segment register for the given operand `reference`.'''
    address, opnum, _ = reference
    return op_segment(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_segment(ea, opnum):
    '''Return the segment register for the operand `opnum` belonging to the instruction at address `ea`.'''
    op = operand(ea, opnum)
    segrg  = (op.specval & 0xffff0000) >> 16
    segsel = (op.specval & 0x0000ffff) >> 0
    if segrg:
        return architecture.by_index(segrg)
    #raise NotImplementedError("{:s}.op_segment({:#x}, {:d}) : Unable to determine the segment register for the specified operand number. {!r} was returned.".format(__name__, ea, opnum, segrg))
    return None
# FIXME: maybe use idaapi.op_seg(*args) to apply a segment to an operand?

@utils.multicase(opnum=types.integer)
def op_number(opnum):
    '''Set the type for operand `opnum` at the current instruction to a number and return it.'''
    return op_number(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_number(reference):
    '''Set the type for the operand pointed to by `reference` to a number and return it.'''
    address, opnum, _ = reference
    return op_number(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_character(opnum):
    '''Set the type for operand `opnum` at the current instruction to a character and return it.'''
    return op_character(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_character(reference):
    '''Set the type for the operand pointed to by `reference` to a character and return it.'''
    address, opnum, _ = reference
    return op_character(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_binary(opnum):
    '''Set the type for operand `opnum` at the current instruction to binary and return it.'''
    return op_binary(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_binary(reference):
    '''Set the type for the operand pointed to by `reference` to binary and return it.'''
    address, opnum, _ = reference
    return op_binary(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_octal(opnum):
    '''Set the type for operand `opnum` at the current instruction to octal and return it.'''
    return op_octal(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_octal(reference):
    '''Set the type for the operand pointed to by `reference` to octal and return it.'''
    address, opnum, _ = reference
    return op_octal(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_decimal(opnum):
    '''Set the type for operand `opnum` at the current instruction to decimal and return it.'''
    return op_decimal(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_decimal(reference):
    '''Set the type for the operand pointed to by `reference` to decimal and return it.'''
    address, opnum, _ = reference
    return op_decimal(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_hexadecimal(opnum):
    '''Set the type for operand `opnum` at the current instruction to hexadecimal and return it.'''
    return op_hexadecimal(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_hexadecimal(reference):
    '''Set the type for the operand pointed to by `reference` to hexadecimal and return it.'''
    address, opnum, _ = reference
    return op_hexadecimal(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_float(opnum):
    '''Set the type for operand `opnum` at the current instruction to floating-point and return it.'''
    return op_float(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_float(reference):
    '''Set the type for the operand pointed to by `reference` to floating-point and return it.'''
    address, opnum, _ = reference
    return op_float(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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

@utils.multicase(opnum=types.integer)
def op_stackvar(opnum):
    '''Set the type for operand `opnum` at the current instruction to a stack variable and return it.'''
    return op_stackvar(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_stackvar(reference):
    '''Set the type for the operand pointed to by `reference` to a stack variable and return it.'''
    address, opnum, _ = reference
    return op_stackvar(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_stackvar(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to a stack variable and return it.'''
    if not function.has(ea):
        raise E.FunctionNotFoundError(u"{:s}.op_stackvar({:#x}, {:d}) : The specified address ({:#x}) is not within a function.".format(__name__, ea, opnum, ea))

    ok = idaapi.op_stkvar(ea, opnum)
    if not ok:
        raise E.DisassemblerError(u"{:s}.op_stackvar({:#x}, {:d}) : Unable to set operand {:d} to a stack variable.".format(__name__, ea, opnum, opnum))

    # Now that it's set, call into op_structure to return it.
    return op_structure(ea, opnum)
op_stack = op_stkvar = utils.alias(op_stackvar)

@utils.multicase(opnum=types.integer)
def op_structure(opnum):
    '''Return the structure and members for operand `opnum` at the current instruction.'''
    return op_structure(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_structure(reference):
    '''Return the structure and members for the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structure(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_structure(ea, opnum):
    '''Return the structure and members for the operand `opnum` at the instruction `ea`.'''
    F, insn, op, ri = database.type.flags(ea), at(ea), operand(ea, opnum), interface.address.refinfo(ea, opnum)

    # Start out by checking if the operand is a stack variable, because
    # we'll need to handle it differently if so.
    if idaapi.is_stkvar(F, opnum) and function.has(insn.ea):
        fn = function.by(insn.ea)

        # Now we can ask IDA what's up with it.
        res = idaapi.get_stkvar(insn, op, op.addr)
        if not res:
            raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}) : The call to `idaapi.get_stkvar({!r}, {!r}, {:+#x})` returned an invalid stack variable.".format(__name__, ea, opnum, insn, op, value))
        mptr, actval = res

        # First we grab our frame, and then find the starting member by its id.
        frame = function.frame(fn)
        member = frame.members.by_identifier(mptr.id)

        # Use the real offset of the member so that we can figure out which
        # members of the structure are actually part of the path.
        path, delta = member.parent.members.__walk_to_realoffset__(actval)

        # If we got a list as a result, then we encountered an array which
        # requires us to return a list and include the offset.
        if isinstance(path, types.list):
            return path + [delta]

        # Otherwise it's just a regular path, and we need to determine whether
        # to include the offset in the result or not.
        results = tuple(path)
        if delta > 0:
            return results + (delta,)
        return tuple(results) if len(results) > 1 else results[0]

    # Otherwise, we check if our operand is not a structure offset, but pointing
    # to memory by having a reference. If it is then we'll need to figure the field
    # being referenced by calculating the offset into structure ourselves.
    elif not idaapi.is_stroff(F, opnum) and ri:
        value = op_reference(ea, opnum)
        address = database.address.head(value)
        t, count = database.type.array(address)
        offset = value - address

        # Verify that the type as the given address is a structure
        if not isinstance(t, structure.structure_t):
            raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is not pointing to a structure.".format(__name__, ea, opnum, opnum))

        # FIXME: check if the operand contains any member xrefs, because
        #        if it doesn't then we don't actually need a path.

        # Figure out the index and the real offset into the structure,
        # and then hand them off to the walk_to_realoffset method. From
        # this value, we calculate the array member offset and then
        # process it to get the actual path to return.
        index, byte = divmod(offset, t.size)
        path, realdelta = t.members.__walk_to_realoffset__(byte)
        delta = index * t.size + realdelta

        # If we received a list, then we can just return it with the delta.
        if isinstance(path, types.list) or count > 1:
            return [item for item in path] + [delta]

        # Figure out whether we need to include the offset in the result.
        results = tuple(path)
        if delta > 0:
            return results + (delta,)
        return tuple(results) if len(results) > 1 else results[0]

    # If it doesn't have a reference, then there's absolutely nothing we can do.
    elif not idaapi.is_stroff(F, opnum):
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Unable to identify the structure referenced by operand {:d} with flags ({:#x}).".format(__name__, ea, opnum, opnum, F))

    # First we'll get the operand value and then collect all of the IDs in
    # our path along with the delta that was applied. This way we can calculate
    # exactly which members were used for the path that we plan on returning.
    value = idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr)

    # FIXME: inverted or negated operands are currently not being supported.

    delta, tids = interface.node.get_stroff_path(insn.ea, opnum)
    logging.debug(u"{:s}.op_structure({:#x}, {:d}) : Processing {:d} members ({:s}) from path that was returned from `{:s}`.".format(__name__, ea, opnum, len(tids), ', '.join("{:#x}".format(mid) for mid in tids), "{!s}({:#x}, {:d})".format('.'.join(getattr(interface.node.get_stroff_path, attribute) for attribute in ['__module__', '__name__']), insn.ea, opnum)))

    # If we're a single tid, and the sum of the offset and the delta is
    # the same as the size, then the operand is using sizeof and we can leave.
    if len(tids) == 1 and sum([value, delta]) == structure.__instance__(tids[0]).size:
        return structure.__instance__(tids[0])

    # Next we'll gather the data references for the operand and key them
    # by their sptr id. This is because I can't figure out any other way
    # to get _exactly_ what's being displayed.
    displayed = {}
    for mid in filter(interface.node.is_identifier, interface.xref.of_data(insn.ea)):

        # Simple enough. If it's not a member identifier, then skip it.
        item = idaapi.get_member_by_id(mid)
        if item is None:
            continue

        # Okay, we should now have the member and its owner. We'll only be
        # looking them up by the sptr identifier, so that's all we want.
        mptr, _, sptr = item
        if operator.contains(displayed, sptr.id):
            logging.debug(u"{:s}.op_structure({:#x}, {:d}) : Found more than one reference for a member ({:#x}) belonging to the same structure ({:#x}).".format(__name__, ea, opnum, mptr.id, sptr.id))
        displayed[sptr.id] = mptr

    # Now we can grab our path from the tids that we extracted from the
    # operand. For the sake of debugging, we'll just log the full path.
    path = interface.strpath.of_tids(value + delta, tids)
    logging.info(u"{:s}.op_structure({:#x}, {:d}) : Resolved the path ({:d} elements) for the instruction operand to {:s}.".format(__name__, ea, opnum, len(path), interface.strpath.fullname(path)))

    # Now we can create a calculator for the starting offset from the
    # operand, and proceed to convert the path into a list of results.
    calculator = interface.strpath.calculate(0)
    result, position, leftover = [], builtins.next(calculator), 0
    for sptr, mptr, offset in path:

        # Start out by finding the exact structure that was resolved,
        # and then use it to find the exact member being referenced.
        st = structure.__instance__(sptr.id, offset=position)
        if mptr:
            member = st.members.by_identifier(mptr.id)
            offset = member.realoffset

        # If there wasn't a member, then there's at least a member
        # that's being displayed. So, we can figure out which one is
        # being displayed by the operand (via dref) and use that one.
        elif operator.contains(displayed, sptr.id):
            mptr = displayed[sptr.id]
            member, offset = st.members.by_identifier(mptr.id), offset

        # If it's not referenced at all, then we're in a very weird
        # situation and it absolutely has got to be the structure size.
        else:
            member, offset = st, 0

        # Now that we figured out the right item that's being displayed,
        # update our position using its realoffset, keep track of our
        # carried value, and then add them member before continuing.
        position, leftover = calculator.send((sptr, None, member.realoffset)), sum([leftover, offset])
        result.append(member)

    # Now that we have the carried bytes (leftover) of the path, we can
    # just subtract it from the operand value to get the displayed one.
    realoffset = value - leftover

    # Now we need to do one last tricky thing to remain backwards compatible
    # with the previous implementation. That is that we need to figure out
    # whether there's an array being referenced in one of our elements.
    if any(isinstance(member.type, types.list) for member in result if isinstance(member, structure.member_t)):
        return result + [realoffset]

    # Otherwise we've just collected a regular member path. So we need to
    # determine whether to include the offset in the result or not.
    results = tuple(result)
    if realoffset:
        return results + (realoffset,)
    return results if len(results) > 1 else results[0]

## current address and opnum with variable-length path
@utils.multicase(opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structure(opnum, structure, *path):
    '''Apply the specified `structure` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, [item for item in itertools.chain([structure], path)])
@utils.multicase(opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structure(opnum, member, *path):
    '''Apply the specified `member` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, [item for item in itertools.chain([member], path)])

## address and opnum with variable-length path
@utils.multicase(ea=types.integer, opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structure(ea, opnum, structure, *path):
    '''Apply the specified `structure` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    return op_structure(ea, opnum, [item for item in itertools.chain([structure], path)])
@utils.multicase(ea=types.integer, opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structure(ea, opnum, member, *path):
    '''Apply the specified `member` to the instruction operand `opnum` at the address `ea`.'''
    return op_structure(ea, opnum, [item for item in itertools.chain([member], path)])

## operand reference with variable-length path
@utils.multicase(reference=interface.opref_t, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structure(reference, structure, *path):
    '''Apply the specified `structure` along with the members in `path` to the operand pointed to by `reference`.'''
    return op_structure(reference, [item for item in itertools.chain([structure], path)])
@utils.multicase(reference=interface.opref_t, member=(structure.member_t, idaapi.member_t))
def op_structure(reference, member, *path):
    '''Apply the specified `member` along with the members in `path` to the instruction operand pointed to by `reference`.'''
    return op_structure(reference, [item for item in itertools.chain([member], path)])

## all variations that take a tuple/list to apply to a given operand.
@utils.multicase(reference=interface.opref_t, path=types.ordered)
def op_structure(reference, path):
    '''Apply the structure members in `path` to the instruction operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structure(address, opnum, path)
@utils.multicase(ea=types.integer, opnum=types.integer, path=types.ordered)
def op_structure(ea, opnum, path):
    '''Apply the structure members in `path` to the instruction operand `opnum` at the address `ea`.'''
    items = [item for item in path]
    member = items.pop(0) if len(items) else ''
    if isinstance(member, types.string):
        sptr, fullpath = structure.by(member).ptr, items
    elif isinstance(member, idaapi.struc_t):
        sptr, fullpath = structure.by(member.id), items
    elif isinstance(member, structure.structure_t):
        sptr, fullpath = member.ptr, items
    elif isinstance(member, idaapi.member_t):
        _,_, sptr = idaapi.get_member_by_id(member.id)
        if not interface.node.is_identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(member.id))
        fullpath = itertools.chain([member], items)
    elif isinstance(member, structure.member_t):
        sptr, fullpath = member.parent.ptr, itertools.chain([member], items)
    else:
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:d}, {!r}) : Unable to determine the structure from the provided path due to the first item being of an unsupported type ({!s}).".format(__name__, ea, opnum, path, member.__class__))
    return op_structure(ea, opnum, sptr, [item for item in fullpath])
@utils.multicase(ea=types.integer, opnum=types.integer, sptr=idaapi.struc_t, path=types.ordered)
def op_structure(ea, opnum, sptr, path):
    '''Apply the structure identified by `sptr` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The requested address ({:#x}) is not defined as a code type.".format(__name__, ea, opnum, sptr.id, path, ea))

    # Convert the path to a list, and then validate it before we use it.
    path, accepted = [item for item in path], (idaapi.member_t, structure.member_t, types.string, types.integer)
    if any(not isinstance(item, accepted) for item in path):
        index, item = next((index, item) for index, item in enumerate(path) if not isinstance(item, accepted))
        raise E.InvalidParameterError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The path member at index {:d} has a type ({!s}) that is not supported.".format(__name__, ea, opnum, sptr.id, path, index, item.__class__))

    # Grab information about our instruction and operand so that we can decode
    # it to get the structure offset to use.
    insn, op = at(ea), operand(ea, opnum)

    # If the operand type is not a valid type, then raise an exception so that
    # we don't accidentally apply a structure to an invalid operand type.
    if op.type not in {idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ, idaapi.o_imm}:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : Unable to apply structure path to the operand ({:d}) for the instruction at {:#x} due to its type ({:d}).".format(__name__, ea, opnum, sptr.id, path, opnum, insn.ea, op.type))

    # Now we need to decode our operand and stash it so that we can later
    # use it to calculate the delta between it and the actual member offset
    # to use when traversing the structure path. We try every possible attribute
    # from our decoders until we find one. Otherwise, we bail.
    res = catalog.operand.decode(insn, op)
    if isinstance(res, types.integer):
        value = res
    elif any(hasattr(res, attribute) for attribute in ['offset', 'Offset', 'address']):
        value = res.offset if hasattr(res, 'offset') else res.Offset if hasattr(res, 'Offset') else res.address
    else:
        raise E.UnsupportedCapability(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : An unexpected type ({!s}) was decoded from the operand ({:d}) for the instruction at {:#x}).".format(__name__, ea, opnum, sptr.id, path, value.__class__, opnum, insn.ea))

    # First we use the path the user gave us to figure out the suggested path. This
    # should give us the suggestion and its expected delta that we can use for warnings.
    st = structure.__instance__(sptr.id)
    userdelta, userpath = interface.strpath.suggest(sptr, path)

    # Precalculate a description of the path to make our error messages look good.
    path_description = []
    for sptr, mptr, offset in userpath:
        sname = utils.string.of(idaapi.get_struc_name(sptr.id))
        mname = utils.string.of(idaapi.get_member_name(mptr.id)) if mptr else ''
        fullname = '.'.join([sname, mname] if mname else [sname])
        path_description.append("{:s}{:+#x}".format(fullname, offset) if offset or mname else fullname)

    logging.info(u"{:s}.op_structure({:#x}, {:d}, {:#x}, [{:s}]) : The user suggested the path {:s} with a delta of {:+#x} for the given value ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), interface.strpath.fullname(userpath), userdelta, value))

    # If the suggested path has only 1 element, no members, and the sum of the delta
    # and the value matches the structure size, then this is simply the structure size.
    if len(userpath) == 1 and all(mptr is None for _, mptr, _ in userpath) and userdelta + value == st.size:
        realdelta, realpath = 0, userpath

    # Now we can calculate the path to the value that the user is trying to suggest
    # a path for. We don't really need the delta, but we can use it to determine
    # the path that the user stopped at with the path that we'll actually apply.
    else:
        realdelta, realpath = interface.strpath.guide(value, st.ptr, userpath)

    logging.info(u"{:s}.op_structure({:#x}, {:d}, {:#x}, [{:s}]) : The determined (real) path was {:s} with a delta of {:+#x} for the given value ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), interface.strpath.fullname(realpath), realdelta, value))

    # Now if the userdelta and realdelta are different, then either the path they
    # suggested to us is wrong (user > real) or we ended up having to complete
    # their path for them (user < real).
    if userdelta != realdelta:
        delta = realdelta - userdelta
        Flogging = logging.debug if userdelta < realdelta else logging.info
        Fdescription = "incomplete ({:#x} < {:#x})".format if userdelta < realdelta else "incorrect ({:#x} > {:#x})".format
        action = 'resolving additional members' if userdelta < realdelta else 'adjusting suggested members'

        # FIXME: We should probably refactor the previous logic so that way we can
        #        render the suggested members that were ignored or the any of the
        #        members that needed to be resolved.
        Flogging(u"{:s}.op_structure({:#x}, {:d}, {:#x}, [{:s}]) : The suggested path was {:s} and required {:+#x} bytes ({:s}) to reach the operand target value ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), Fdescription(userdelta, realdelta), delta, action, value))

    # Finally we can convert our realpath into a tid_array that we will apply.
    items = interface.strpath.to_tids(realpath)
    tid, length = idaapi.tid_array(len(items)), len(items)
    for index in range(length):
        tid[index] = items[index]

    # Now we can apply our tid_array to the operand and then return what
    # we just applied to the user using the other op_structure case.
    if not idaapi.op_stroff(insn.ea if idaapi.__version__ < 7.0 else insn, opnum, tid.cast(), length, 0):
        raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : Unable to apply the resolved structure path ({:s}) to the operand ({:d}) at the specified address ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), ', '.join(map("{:#x}".format, items)), opnum, insn.ea))
    return op_structure(insn.ea, opnum)
op_struc = op_struct = utils.alias(op_structure)

# Just some aliases for reading from the current location
@utils.multicase(opnum=types.integer)
def op_structurepath(opnum):
    '''Return the structure and members for operand `opnum` at the current instruction.'''
    return op_structurepath(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_structurepath(reference):
    '''Return the structure and members for the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structurepath(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_structurepath(ea, opnum):
    '''Return the structure and members for the operand `opnum` at the instruction `ea`.'''
    F, insn, op, ri = database.type.flags(ea), at(ea), operand(ea, opnum), interface.address.refinfo(ea, opnum)

    # If it's a stack variable, then this is also the wrong API and we should be
    # using the op_structure function. Log it and continue onto the right one.
    if idaapi.is_stkvar(F, opnum) and function.has(insn.ea):
        logging.info(u"{:s}.op_structurepath({:#x}, {:d}) : Using the `{:s}` function instead to return the path for a stack variable operand.".format(__name__, ea, opnum, '.'.join([getattr(op_structure, attribute) for attribute in ['__module__', '__name__'] if hasattr(op_structure, attribute)])))
        return op_structure(ea, opnum)

    # If it's a memory address, then this is the wrong API and we should be using
    # the op_structure function. Log something, and then chain to the correct one.
    elif not idaapi.is_stroff(F, opnum) and ri:
        logging.info(u"{:s}.op_structurepath({:#x}, {:d}) : Using the `{:s}` function instead to return the path for a reference.".format(__name__, ea, opnum, '.'.join([getattr(op_structure, attribute) for attribute in ['__module__', '__name__'] if hasattr(op_structure, attribute)])))
        return op_structure(ea, opnum)

    # If it wasn't a stack variable, then check that the operand is actually a
    # structure offset. If it isn't, then bail because we have no idea what to do.
    elif not idaapi.is_stroff(F, opnum):
        raise E.MissingTypeOrAttribute(u"{:s}.op_structurepath({:#x}, {:d}) : Unable to identify the structure referenced by operand {:d} with flags ({:#x}).".format(__name__, ea, opnum, opnum, F))

    # Start out by collecting the operand value, the delta and the tids from the
    # chosen operand and grab its sptr so that we can figure out what path was applied.
    value = idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr)

    delta, tids = interface.node.get_stroff_path(insn.ea, opnum)
    logging.debug(u"{:s}.op_structurepath({:#x}, {:d}) : Processing {:d} members ({:s}) from path that was returned from `{:s}`.".format(__name__, ea, opnum, len(tids), ', '.join("{:#x}".format(mid) for mid in tids), "{!s}({:#x}, {:d})".format('.'.join(getattr(interface.node.get_stroff_path, attribute) for attribute in ['__module__', '__name__']), insn.ea, opnum)))

    sid, target = tids[0], value + delta
    sptr = idaapi.get_struc(sid)

    # Before we do anything, we need to figure out exactly what the leftover
    # bytes are after properly resolving our path for the operand and delta.
    # To do this, we resolve for our target address using strpath.of_tids to
    # resolve each individual member and store it in our path.
    path = []
    calculator = interface.strpath.calculate(0)
    resolver = interface.strpath.resolve(path.append, sptr, target)

    position = builtins.next(calculator)
    try:
        sptr, candidates, carry = builtins.next(resolver)
        for owner, mptr, offset in interface.strpath.of_tids(target, tids):
            assert owner.id == sptr.id
            position = calculator.send((owner, mptr, offset))
            sptr, candidates, carry = resolver.send((mptr, carry))

        resolver.send((None, None))
        raise E.DisassemblerError(u"{:s}.op_structurepath({:#x}, {:d}) : Expected path to have been resolved at offset {:#x} of index {:d} with {:s}.".format(__name__, ea, opnum, builtins.next(calculator), len(path), interface.strpath.format(owner, mptr)))

    # If we're done resolving, then save our position for calculating the delta later.
    except (StopIteration, E.MemberNotFoundError):
        position = builtins.next(calculator)

    finally:
        resolver.close(), calculator.close()
        logging.info(u"{:s}.op_structurepath({:#x}, {:d}) : Resolved the path ({:d} elements) for the specified instruction operand to {:s}.".format(__name__, ea, opnum, len(path), interface.strpath.fullname(path)))

    # Now we have the correct resolved path with each offset in it being correct. We
    # need to translate it by our carried value and then we can determine the correct
    # offset for each member of the path that we'll return.
    calculator = interface.strpath.calculate(value + (carry - target))
    result, position = [], builtins.next(calculator)
    for sptr, mptr, offset in path:
        st = structure.__instance__(sptr.id, offset=position)
        item = st.members.by_identifier(mptr.id) if mptr else st
        result.append(item)
        position = calculator.send((sptr, mptr, offset))

    # If we did not figure out any path, then this is likely a sizeof(structure)
    # operand. So, we return the structure and whatever value was carried.
    if not result:
        return structure.__instance__(sptr.id), carry

    # Just like the op_structure implementation, we need to figure out if
    # there's an array being referenced to convert our result to a list.
    elif any(isinstance(member.type, types.list) for member in result if isinstance(member, structure.member_t)):
        return result + [carry]

    # Otherwise it's just a path with the carried offset, so we check the
    # carryied offset for non-zero in case we need to return it.
    results = tuple(result)
    if carry:
        return results + (carry,)
    return results if len(results) > 1 else results[0]

## current address and opnum with variable-length path
@utils.multicase(opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structurepath(opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ui.current.address(), opnum, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structurepath(opnum, member, *path, **delta):
    '''Apply the specified `member` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ui.current.address(), opnum, [item for item in itertools.chain([member], path, deltapath)])

## address and opnum with variable-length path
@utils.multicase(ea=types.integer, opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structurepath(ea, opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ea, opnum, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(ea=types.integer, opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structurepath(ea, opnum, member, *path, **delta):
    '''Apply the specified `member` to the instruction operand `opnum` at the address `ea`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ea, opnum, [item for item in itertools.chain([member], path, deltapath)])

## operand reference with variable-length path
@utils.multicase(reference=interface.opref_t, structure=(structure.structure_t, idaapi.struc_t, types.string))
def op_structurepath(reference, structure, *path, **delta):
    '''Apply the specified `structure` along with the members in `path` to the operand pointed to by `reference`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(reference, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(reference=interface.opref_t, member=(structure.member_t, idaapi.member_t))
def op_structurepath(reference, member, *path, **delta):
    '''Apply the specified `member` along with the members in `path` to the instruction operand pointed to by `reference`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(reference, [item for item in itertools.chain([member], path, deltapath)])

## all variations that take a tuple/list to apply to a given operand.
@utils.multicase(reference=interface.opref_t, path=types.ordered)
def op_structurepath(reference, path):
    '''Apply the structure members in `path` to the instruction operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structurepath(address, opnum, path)
@utils.multicase(ea=types.integer, opnum=types.integer, path=types.ordered)
def op_structurepath(ea, opnum, path):
    '''Apply the structure members in `path` to the instruction operand `opnum` at the address `ea`.'''
    items = [item for item in path]
    member = items.pop(0) if len(items) else ''
    if isinstance(member, types.string):
        sptr, fullpath = structure.by(member).ptr, items
    elif isinstance(member, idaapi.struc_t):
        sptr, fullpath = structure.by(member.id), items
    elif isinstance(member, structure.structure_t):
        sptr, fullpath = member.ptr, items
    elif isinstance(member, idaapi.member_t):
        _,_, sptr = idaapi.get_member_by_id(member.id)
        if not interface.node.is_identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(member.id))
        fullpath = itertools.chain([member], items)
    elif isinstance(member, structure.member_t):
        sptr, fullpath = member.parent.ptr, itertools.chain([member], items)
    else:
        raise E.InvalidParameterError(u"{:s}.op_structurepath({:#x}, {:d}, {!r}) : Unable to determine the structure from the provided path due to the first item being of an unsupported type ({!s}).".format(__name__, ea, opnum, path, member.__class__))
    return op_structurepath(ea, opnum, sptr, [item for item in fullpath])

@utils.multicase(ea=types.integer, opnum=types.integer, structure=structure.structure_t, path=types.ordered)
def op_structurepath(ea, opnum, structure, path):
    '''Apply the specified `structure` along with the members in `path` to the to the instruction operand `opnum` at the address `ea`.'''
    return op_structurepath(ea, opnum, structure.ptr, path)
@utils.multicase(ea=types.integer, opnum=types.integer, sptr=idaapi.struc_t, path=types.ordered)
def op_structurepath(ea, opnum, sptr, path):
    '''Apply the structure identified by `sptr` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise E.InvalidTypeOrValueError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, {!r}) : The requested address ({:#x}) is not defined as a code type.".format(__name__, ea, opnum, sptr.id, path, ea))

    # Convert the path to a list, and then validate it before we use it.
    path, accepted = [item for item in path], (idaapi.member_t, structure.member_t, types.string, types.integer)
    if any(not isinstance(item, accepted) for item in path):
        index, item = next((index, item) for index, item in enumerate(path) if not isinstance(item, accepted))
        raise E.InvalidParameterError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, {!r}) : The path member at index {:d} has a type ({!s}) that is not supported.".format(__name__, ea, opnum, sptr.id, path, index, item.__class__))

    # Grab information about our instruction and operand so that we can decode
    # it to get the structure offset to use.
    insn, op = at(ea), operand(ea, opnum)

    # If the operand type is not a valid type, then raise an exception so that
    # we don't accidentally apply a structure to an invalid operand type.
    if op.type not in {idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ, idaapi.o_imm}:
        raise E.MissingTypeOrAttribute(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, {!r}) : Unable to apply structure path to the operand ({:d}) for the instruction at {:#x} due to its type ({:d}).".format(__name__, ea, opnum, sptr.id, path, opnum, insn.ea, op.type))

    # Similar to op_structure, we first need to figure out the path that the user
    # has suggested to us to apply to the operand and we calculate our goal.
    st = structure.__instance__(sptr.id)
    usergoal, userpath = interface.strpath.suggest(st.ptr, path)

    # Precalculate a description of the path to make our logging events look good.
    path_description = []
    for sptr, mptr, offset in userpath:
        sname = utils.string.of(idaapi.get_struc_name(sptr.id))
        mname = utils.string.of(idaapi.get_member_name(mptr.id)) if mptr else ''
        fullname = '.'.join([sname, mname] if mname else [sname])
        path_description.append("{:s}{:+#x}".format(fullname, offset) if offset or mname else fullname)

    # We're looking for the "exact" path which should always be within the bounds
    # of the structure so we'll simply flail around for its value.
    calculator = interface.strpath.calculate(0, operator.truth)
    resolver = interface.strpath.resolve(calculator.send, st.ptr, usergoal)
    flailer = interface.strpath.flail(userpath)
    builtins.next(calculator), builtins.next(flailer)

    sptr, candidates, carry = builtins.next(resolver)
    try:
        while candidates:
            owner, choice, offset = flailer.send((sptr, candidates, carry))
            sptr, candidates, carry = resolver.send((choice, offset))

    except (StopIteration, E.MemberNotFoundError):
        pass

    finally:
        flailer.close()

    # Now we can simply choose the default members and at the end we should have both
    # the goal delta that we'll be able to traverse the suggestions with.
    try:
        while True:
            sptr, candidates, carry = resolver.send((None, carry))

    except (StopIteration, E.MemberNotFoundError):
        pass

    finally:
        resolver.close()
        goaldelta = builtins.next(calculator)
        calculator.close()

    # If our realdelta is different from our userdelta, then the user's path
    # didn't actually resolve completely and we need to let them know.
    if usergoal != goaldelta:
        Flogging = logging.debug if usergoal < goaldelta else logging.warning
        Fdescription = "incomplete ({:#x} < {:#x})".format if usergoal < goaldelta else "incorrect ({:#x} > {:#x})".format
        action = 'of members were added' if usergoal < goaldelta else 'of the last members were temporarily removed'
        Flogging(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, [{:s}]) : The suggested path was {:s} and {:+#x} bytes {:s} before calculating the real path.".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), Fdescription(usergoal, goaldelta), goaldelta - usergoal, action))

    # Finally we can really flail for the exact member the user wanted using the
    # delta that we're using as our goal and then choose the defaults for the rest.
    realpath = []
    calculator = interface.strpath.calculate(0, realpath.append)
    resolver = interface.strpath.resolve(calculator.send, st.ptr, goaldelta)
    flailer = interface.strpath.flail(userpath)
    realdelta, _ = builtins.next(calculator), builtins.next(flailer)

    sptr, candidates, carry = builtins.next(resolver)
    try:
        while True:
            owner, choice, offset = flailer.send((sptr, candidates, carry))
            sptr, candidates, carry = resolver.send((choice, carry))

    except (StopIteration, E.MemberNotFoundError):
        pass

    finally:
        flailer.close()

    try:
        while True:
            sptr, candidates, carry = resolver.send((None, carry))

    except (StopIteration, E.MemberNotFoundError):
        pass

    finally:
        resolver.close()
        realdelta = builtins.next(calculator)
        calculator.close()

    # If there was no path that we were able to calculate, then the user gave us
    # a single-element path that doesn't point to the first member they requested.
    # So, we deal by using the busted path that they gave us because it should have
    # a structure with the member + offset that they're aiming for anyways.
    if not realpath and len(userpath) == 1:
        realpath[:] = userpath

    # If we hit this case, then the logic described in the previous comment is
    # completely busted and I have no idea what this is supposed to be doing.
    elif not realpath:
        raise E.InvalidParameterError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, [{:s}]) : Unable to apply the path to the operand ({:d}) of the specified address ({:#x}) as the given path does not point to a specific member.".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), opnum, insn.ea))

    # Very last thing to do is to calculate the delta for the path with our
    # value, and then we can apply the whole thing to the operand.
    base = usergoal - goaldelta
    delta = realdelta - idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr)
    items = interface.strpath.to_tids(realpath)
    tid, length = idaapi.tid_array(len(items)), len(items)
    for index in range(length):
        tid[index] = items[index]

    # Only thing that's left to do is apply the tids that we collected along with
    # the delta that we calculated from the user's input to the desired operand.
    if not idaapi.op_stroff(insn.ea if idaapi.__version__ < 7.0 else insn, opnum, tid.cast(), length, base + delta):
        raise E.DisassemblerError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, [{:s}]) : Unable to apply the resolved structure path ({:s}) and delta ({:+#x}) to the operand ({:d}) at the specified address ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), ', '.join(map("{:#x}".format, items)), base + delta, opnum, insn.ea))

    # And then we can call into our other case to return what we just applied.
    return op_structurepath(insn.ea, opnum)
op_strucpath = op_strpath = utils.alias(op_structurepath)

@utils.multicase(opnum=types.integer)
def op_enumeration(opnum):
    '''Return the enumeration member id for the operand `opnum` belonging to the current instruction.'''
    return op_enumeration(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_enumeration(reference):
    '''Return the enumeration member id for the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_enumeration(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
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
    op = operand(ea, opnum)
    value, bits, signed = op.value if op.type in {idaapi.o_imm} else op.addr, op_bits(ea, opnum), interface.node.alt_opinverted(ea, opnum)

    # FIXME: recalculate the operand value if the operand is negated (~)

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
            return tuple(res) if len(res) > 1 else res[0]
        return res[0]

    # If we did get something but we missed a value for one of the masks,
    # then this result is incomplete, but still okay to return.
    elif res:
        if enumeration.bitfield(eid):
            return tuple(res) if len(res) > 1 else res[0]
        return res[0]

    # Otherwise, we didn't find anything and there was an error trying to
    # get an enumeration member. This is worth an exception for the caller
    # to figure out what to do with.
    raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:d}) : Unable to get any members for the enumeration ({:#x}) at operand {:d}.".format(__name__, ea, opnum, eid, opnum))
@utils.multicase(opnum=types.integer, name=types.string)
@utils.string.decorate_arguments('name')
def op_enumeration(opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the current instruction.'''
    return op_enumeration(ui.current.address(), opnum, enumeration.by(name))
@utils.multicase(reference=interface.opref_t)
def op_enumeration(reference, name_or_id):
    '''Apply the enumeration `name_or_id` to the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_enumeration(address, opnum, name_or_id)
@utils.multicase(ea=types.integer, opnum=types.integer, name=types.string)
@utils.string.decorate_arguments('name')
def op_enumeration(ea, opnum, name):
    '''Apply the enumeration `name` to operand `opnum` for the instruction at `ea`.'''
    return op_enumeration(ea, opnum, enumeration.by(name))
@utils.multicase(ea=types.integer, opnum=types.integer, id=(types.integer, types.ordered))
def op_enumeration(ea, opnum, id):
    '''Apply the enumeration `id` to operand `opnum` of the instruction at `ea`.'''
    if opnum >= len(operands(ea)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_enumeration({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    ok = idaapi.op_enum(ea, opnum, *id) if isinstance(id, types.ordered) else idaapi.op_enum(ea, opnum, id, 0)
    if not ok:
        eid, serial = id if isinstance(id, types.ordered) else (id, 0)
        raise E.DisassemblerError(u"{:s}.op_enumeration({:#x}, {:d}, {:#x}) : Unable to set operand {:d} for instruction ({:#x}) to enumeration {:#x} (serial {:d}).".format(__name__, ea, opnum, eid, opnum, ea, eid, serial))
    return op_enumeration(ea, opnum)
op_enum = utils.alias(op_enumeration)

@utils.multicase(opnum=types.integer)
def op_string(opnum):
    '''Return the string type of operand `opnum` for the current instruction.'''
    return op_string(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_string(reference):
    '''Return the string type (``idaapi.STRTYPE_``) of the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_string(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_string(ea, opnum):
    '''Return the string type (``idaapi.STRTYPE_``) of operand `opnum` for the instruction at `ea`.'''
    F = database.type.flags(ea)
    if F & (idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI) == 0:
        raise E.MissingTypeOrAttribute(u"{:s}.op_string({:#x}, {:d}) : Operand {:d} does not contain a literate string.".format(__name__, ea, opnum, opnum))

    res = opinfo(ea, opnum)
    if res is None:
        raise E.DisassemblerError(u"{:s}.op_string({:#x}, {:d}) : Unable to get `idaapi.opinfo_t` for operand {:d} with flags {:#x}.".format(__name__, ea, opnum, opnum, F))

    return res.strtype
@utils.multicase(reference=interface.opref_t, strtype=types.integer)
def op_string(reference, strtype):
    '''Set the string type used by operand pointed to by `reference` to `strtype`.'''
    address, opnum, _ = reference
    return op_string(address, opnum, strtype)
@utils.multicase(ea=types.integer, opnum=types.integer, strtype=types.integer)
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

# XXX: these functions are pretty much deprecated in favor of interface.address.refinfo.
@utils.multicase()
def ops_refinfo():
    '''Returns the ``idaapi.refinfo_t`` for the instruction at the current address.'''
    return interface.address.refinfo(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_refinfo(ea):
    '''Returns the ``idaapi.refinfo_t`` for the instruction at the address `ea`.'''
    return interface.address.refinfo(ea)
@utils.multicase(opnum=types.integer)
def op_refinfo(opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the instruction at the current address.'''
    return interface.address.refinfo(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_refinfo(reference):
    '''Return the ``idaapi.refinfo_t`` for the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return interface.address.refinfo(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_refinfo(ea, opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    return interface.address.refinfo(ea, opnum)

@utils.multicase(opnum=types.integer)
def op_reference(opnum):
    '''Return the address being referenced by the operand `opnum` belonging to the instruction at the current address.'''
    return op_reference(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_reference(reference):
    '''Return the address being referenced by the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_reference(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_reference(ea, opnum):
    '''Return the address being referenced by the operand `opnum` belonging to the instruction at the address `ea`.'''
    insn, ops = at(ea), operands(ea)
    if not(opnum < len(ops)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_reference({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Grab the operand and its reference if it it actually has one. We'll use this
    # to figure out exactly what address is being referenced by the operand.
    op, ri = ops[opnum], interface.address.refinfo(ea, opnum)
    if ri:
        target, base, value = idaapi.ea_pointer(), idaapi.ea_pointer(), op.value if op.type in {idaapi.o_imm} else op.addr

        # Try and calculate the reference for the operand value. If we couldn't, then we simply treat the value as-is.
        if not idaapi.calc_reference_data(target.cast(), base.cast(), ea, ri, value):
            logging.debug(u"{:s}.op_reference({:#x}, {:d}) : The disassembler could not calculate the target for the reference ({:d}) at address {:#x}.".format(__name__, ea, opnum, ri.flags & idaapi.REFINFO_TYPE, ea))
            return value
        return target.value()

        # If we actually wanted to, we could use the reference information to figure
        # out the actual offset to the data that is being referenced.
        base, target = (item.value() for item in [base, target])
        if base:
            base, offset = base, target - base
            return base + offset

        # If we weren't given the base address, then we're supposed to figure it out ourselves.
        seg = idaapi.getseg(ea)
        if seg is None:
            raise E.SegmentNotFoundError(u"{:s}.op_reference({:#x}, {:d}) : Unable to locate segment containing the specified instruction address ({:#x}).".format(__name__, ea, ea))

        imagebase, segbase = idaapi.get_imagebase(), idaapi.get_segm_base(seg)
        base, offset = imagebase, seg.start_ea - imagebase
        return base + offset

    # Otherwise, we need to use the default reference type. Unless the user changed
    # the default reference type, this should always result in returning the immediate.
    ri = idaapi.refinfo_t()
    ri.set_type(idaapi.get_default_reftype(ea))
    if op.type not in {idaapi.o_mem, idaapi.o_near, idaapi.o_far}:
        raise E.DisassemblerError(u"{:s}.op_reference({:#x}, {:d}) : Unable to get the reference information from the operand type ({:d}) at the specified operand ({:d}) belonging to the address {:#x}.".format(__name__, ea, opnum, op.type, opnum, ea))

    # If the target base can't be calculated, then we need to use the imagebase.
    res = idaapi.calc_target(ea, op.addr, ri)
    return op.addr if res == idaapi.BADADDR else res
op_ref = utils.alias(op_reference)

@utils.multicase(opnum=types.integer)
def op_references(opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the current instruction.'''
    return op_references(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_references(reference):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_references(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_references(ea, opnum):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the operand `opnum` for the instruction at `ea`.'''
    insn, ops = at(ea), operands(ea)
    if not(opnum < len(ops)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_references({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Start out by doing sanity check so that we can determine whether
    # the operand is referencing a local or a global. We grab both the
    # operand info any the result from idaapi.op_adds_xrefs in order to
    # distinguish the "type" of xrefs that are associated with an operand.
    # This way we can distinguish structure members, enumeration members,
    # locals, globals, etc.
    F = database.type.flags(insn.ea)
    info, has_xrefs = opinfo(insn.ea, opnum), idaapi.op_adds_xrefs(F, opnum)

    # If we have xrefs but no type information, then this operand has to
    # be pointing to a local stack variable that is stored in the frame.
    # This means that we need to be inside a function so that we can
    # grab its frame and search through it.
    if has_xrefs and info is None:
        fn = idaapi.get_func(insn.ea)
        if fn is None:
            raise E.FunctionNotFoundError(u"{:s}.op_references({:#x}, {:d}) : Unable to locate function for address {:#x}.".format(__name__, ea, opnum, insn.ea))

        # Use IDAPython's api to calculate the structure offset into the
        # function's frame using the instruction operand.
        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, insn.ea if idaapi.__version__ < 7.0 else insn, opnum)

        # For sanity, we're going to grab the actual value of the operand
        # and use it to verify that the result from IDAPython is correct.
        op = operand(insn.ea, opnum)
        sval = interface.sval_t(op.addr).value

        # Now that we have the instruction operand's value, we can use
        # it with IDAPython to check if it's actually a frame member.
        res = idaapi.get_stkvar(op, sval) if idaapi.__version__ < 7.0 else idaapi.get_stkvar(insn, op, sval)
        if res is None:
            raise E.DisassemblerError(u"{:s}.op_references({:#x}, {:d}) : The instruction operand's value ({:#x}) does not appear to point to a frame variable at the same offset ({:#x}).".format(__name__, ea, opnum, sval.value, stkofs_))

        # Now we have the actual frame member and the offset into the
        # frame, and we can use it to validate against our expectation.
        member, stkofs = res
        if stkofs != stkofs_:
            logging.warning(u"{:s}.op_references({:#x}, {:d}) : The stack variable offset ({:#x}) for the instruction operand does not match what was expected ({:#x}).".format(__name__, ea, opnum, stkofs, stkofs_))

        # Now we can collect all the operand references to the operand and we just
        # need to transform it into a list of interface.opref_t before returning it.
        # FIXME: the type for an LEA instruction should include an '&' in the
        #        reftype_t, but in this case we explicitly trust the type.
        return [ interface.opref_t(ea, opnum, interface.access_t(xtype, 0)) for ea, opnum, xtype in interface.xref.frame(fn, member) ]

    # If we have xrefs and the operand has information associated with it, then
    # we need to check if the type-id is an enumeration. If so, then the user is
    # looking for references to an enumeration member. We start by grabbing both
    # id for the enumeration and its member.
    elif has_xrefs and info and enumeration.has(info.tid):
        eid, mid = info.tid, op_enumeration(insn.ea, opnum)
        NALT_ENUM0, NALT_ENUM1 = (getattr(idaapi, name, 0xb + idx) for idx, name in enumerate(['NALT_ENUM0', 'NALT_ENUM1']))

        # Now we check to see if it has any xrefs that point directly to the id
        # of the member. If there aren't any then there's nothing to do here.
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mid, idaapi.XREF_ALL)]
        if not refs:
            fullname = '.'.join([enumeration.name(eid), enumeration.member.name(mid)])
            logging.warning(u"{:s}.op_references({:#x}, {:d}) : No references were found for the enumeration member {:s} ({:#x}) at operand {:d} of the instruction at {:#x}.".format(__name__, ea, opnum, fullname, mid, opnum, insn.ea))
            return []

        # After gathering all the xrefs into a list, we'll need to transform
        # it into a list of internal.opref_t. In order to do that, we need to
        # figure out which operand the member is in for each address. During
        # this process, we also verify that the member is actually owned by
        # the enumeration we extracted from our original operand information.
        res, Fnetnode = [], idaapi.ea2node if hasattr(idaapi, 'ea2node') else utils.fidentity
        for ea, xiscode, xr in refs:
            ops = ((opnum, internal.netnode.alt.get(Fnetnode(ea), altidx)) for opnum, altidx in enumerate([NALT_ENUM0, NALT_ENUM1]) if internal.netnode.alt.has(Fnetnode(ea), altidx))
            ops = (opnum for opnum, mid in ops if enumeration.member.parent(mid) == eid)
            res.extend(interface.opref_t(ea, int(opnum), interface.access_t(xr, xiscode)) for opnum in ops)
        return res

    # If the operand adds xrefs, there's operand information, and the operand's
    # type identifier is defined, then this is a structure. We don't actually
    # have to test the operand information in detail because for some reason
    # there's absolutely nothing in it.
    elif has_xrefs and info and info.tid != idaapi.BADADDR:
        NSUP_STROFF0, NSUP_STROFF1 = (getattr(idaapi, name, 0xf + idx) for idx, name in enumerate(['NSUP_STROFF0', 'NSUP_STROFF1']))
        op = ops[opnum]

        # First we need to get the structure path that IDA has stored at the
        # operand, and then get the operand's value. This is because IDA
        # isn't always guaranteed to return a proper path, and so we'll need
        # to calculate the offset ourselves.
        delta, items = interface.node.get_stroff_path(insn.ea, opnum)

        # Now we should have the path and delta that IDA is suggesting is
        # at the given operand, so we'll need to decode the operand's value
        # so that we can use it to find the proper path through the structure.
        res = catalog.operand.decode(insn, op)
        if isinstance(res, types.integer):
            offset = res
        elif any(hasattr(res, attribute) for attribute in ['offset', 'Offset', 'address']):
            offset = res.offset if hasattr(res, 'offset') else res.Offset if hasattr(res, 'Offset') else res.address
        else:
            raise E.UnsupportedCapability(u"{:s}.op_references({:#x}, {:d}) : An unexpected type ({!s}) was decoded from the operand ({:d}) for the instruction at {:#x}.".format(__name__, ea, opnum, res.__class__, opnum, insn.ea))

        # Hopefully that was it, now we should be able to figure out our path.
        _, items = interface.node.calculate_stroff_path(offset, items)

        # If we actually got some items, then we can assign it to members.
        if items:
            members = items

        # If we couldn't figure out the path, then we'll just fall back
        # to the op_structure implementation. This should give us the
        # members that are being used at the operand.
        else:
            res = op_structure(insn.ea, opnum)
            items = [item for item in res] if isinstance(res, types.ordered) else [res]
            items.pop(-1) if isinstance(items[-1], types.integer) else items

            # If the result is a structure, then this is either a reference
            # or a size. The easiest way to resolve this is to just grab
            # all the code references from the structure_t itself, and filter
            # them for any tuples.
            if len(items) == 1 and isinstance(items[0], structure.structure_t):
                return [item for item in items[0].refs() if isinstance(item, types.tuple)]

            # So, now we should have a list of structure.member_t and all
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
            items = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mptr.id, idaapi.XREF_ALL)]
            if not items:
                fullname = idaapi.get_member_fullname(mptr.id)
                logging.info(u"{:s}.op_references({:#x}, {:d}) : No references were found for structure member \"{:s}\".".format(__name__, ea, opnum, utils.string.escape(utils.string.of(fullname), '"')))
                continue

            # Update our set with all of the references that we found for the
            # current member, and then continue onto the next one.
            refs.update(items)

        # To verify that an xref is definitely referencing the path we care
        # about, we'll need to check the path for each operand belonging to
        # every xref. We're going to use the structure in our path along with
        # all of its members as a required constraint when filtering them.
        sptr, _ = members[0]
        required = {mptr.id for _, mptr in members}

        # Now we can iterate through all our references and gather any operands
        # as potential candidates that we'll filter later.
        result, Fnetnode = [], idaapi.ea2node if hasattr(idaapi, 'ea2node') else utils.fidentity
        for ea, xiscode, xr in sorted(refs, key=operator.itemgetter(0)):
            candidates = []

            # Start by gathering any structure candidates that may be referenced
            # by our structure path.
            for refopnum, supidx in enumerate([NSUP_STROFF0, NSUP_STROFF1]):
                if internal.netnode.sup.has(Fnetnode(ea), supidx):
                    delta, identifiers = interface.node.get_stroff_path(ea, refopnum)

                    # We'll need to rebuild the path to this member because again
                    # IDA does not guarantee the full path will be stored. So,
                    # extract the operand's value and use it to calculate all of
                    # the ids for the operand.
                    op = operand(ea, refopnum)
                    offset = idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr, 8 * op_size(ea, refopnum))
                    _, items = interface.node.calculate_stroff_path(offset + delta, identifiers)

                    # If this path does not even include our structure inside it,
                    # then we can just exclude it from our list of candidates.
                    if sptr.id not in {sptr.id for sptr, _ in items}:
                        continue

                    # Now we have the items, we need to grab their identifiers
                    # and then we can later test for them.
                    ids = [sptr.id for sptr, _ in items[:1]] + [mptr.id for _, mptr in items[:]]
                    candidates.append((refopnum, {id for id in ids}))
                continue

            # Next we need to check if there were any operands that actually
            # point to stack variables so we can figure out their path and
            # add them to our candidates list if necessary.
            for refopnum, op in enumerate(operands(ea)):
                if not idaapi.is_stkvar(database.type.flags(ea), refopnum):
                    continue

                # Use the instruction and the operand to figure out the
                # member id of the frame that we need to descend into.
                item = idaapi.get_stkvar(at(ea), op, op.value if op.type in {idaapi.o_imm} else op.addr)
                if item is None:
                    logging.warning(u"{:s}.op_references({:#x}, {:d}) : Error trying to get frame variable for the referenced operand ({:d}) of the instruction at {:#x}.".format(__name__, insn.ea, opnum, refopnum, ea))
                    continue
                mptr, actval = item
                offset = actval - mptr.soff

                # We have the mptr for the frame variable, so next we just need
                # to get the sptr for it, and use it get its members_t. This way
                # we can use the actual value to compose a path through it.
                msptr = idaapi.get_sptr(mptr)
                if msptr is None:
                    logging.warning(u"{:s}.op_references({:#x}, {:d}) : The frame variable for the operand ({:d}) in the instruction at {:#x} is not a structure.".format(__name__, insn.ea, opnum, refopnum, ea))
                    continue

                # Instantiate a structure_t in order to grab its members_t. From
                # this we can then use the actual value to carve a path straight
                # through the member.
                st = structure.__instance__(msptr.id)
                path, delta = st.members.__walk_to_realoffset__(offset)
                ids = [msptr.id] + [member.ptr.id for member in path]
                candidates.append((refopnum, {id for id in ids}))

            # If we didn't find any candidates, then that means this is a global
            # so we need to figure out which operand it is. We'll iterate through
            # all of them for this xref and filter it in one shot.
            if not candidates:
                for refopnum, op in enumerate(operands(ea)):
                    if op.type not in {idaapi.o_mem}:
                        continue

                    # Make sure that the operand is actually pointing to a
                    # structure. If it isn't, then this operand is not anything
                    # that we really care about.
                    if not database.type.is_structure(database.address.head(op.addr)):
                        continue

                    # Now we can trust the op_structure function to get all the
                    # members for the given operand. We'll need to homogenize the
                    # returned path, though, to a list of member_t.
                    path = op_structure(ea, refopnum)
                    items = [item for item in path] if isinstance(path, types.ordered) else [path]
                    items.pop(-1) if isinstance(items[-1], types.integer) else items

                    # Now we can grab all of the operand's ids and check them
                    # against our required ids before adding them to our results.
                    ids = {item.ptr.id for item in items}
                    if ids & required == required:
                        result.append(interface.opref_t(ea, int(refopnum), op_state(ea, refopnum)))
                    continue
                continue

            # Now that we've gathered all of the relevant operand numbers
            # and the structure ids for their paths, we need to do a final
            # pass of them to filter the operands to include references for.
            filtered = []
            for refopnum, ids in candidates:

                # Check that the list of required identifiers is within our
                # candidate identifiers. As each id is unique, this should
                # support the case where IDA doesn't store the full structure
                # offset path within the database.
                if ids & required == required:
                    filtered.append(refopnum)
                continue
            result.extend(interface.opref_t(ea, int(op), interface.access_t(xr, xiscode)) for op in filtered)
        return result

    # Anything else should be just a regular global reference or an immediate,
    # and to figure this out we just grab the operand's value and work it out
    # from there. The value at the supidx has some format which is documented
    # as "complex reference information". In some cases, I've seen the byte
    # 0x02 used to describe a pointer to a global that is within the second
    # segment. This might be worth noting in case we have to dig in there.

    # XXX: verify whether globals are supposed to add xrefs (has_xrefs) or not.

    attributes = ['NSUP_REF0', 'NSUP_REF1', 'NSUP_REF2', 'NSUP_REF3', 'NSUP_REF4', 'NSUP_REF5', 'NSUP_REF6', 'NSUP_REF7']
    indices = [9, 10, 11, 21, 22, 23, 33, 34]
    NSUP_REF0, NSUP_REF1, NSUP_REF2, NSUP_REF3, NSUP_REF4, NSUP_REF5, NSUP_REF6, NSUP_REF7 = (getattr(idaapi, name, supidx) for name, supidx in zip(attributes, indices))

    # We start by decoding the operand's value from the instruction. From
    # this, we should be able to get an immediate address, an offset, or
    # whatever. Once we get the right type, then we can start looking for
    # xrefs to it.
    res = catalog.operand.decode(insn, ops[opnum])
    if isinstance(res, types.integer):
        value = res
    elif any(hasattr(res, attribute) for attribute in ['offset', 'Offset', 'address']):
        value = res.offset if hasattr(res, 'offset') else res.Offset if hasattr(res, 'Offset') else res.address
    else:
        raise E.UnsupportedCapability(u"{:s}.op_references({:#x}, {:d}) : An unexpected type ({!s}) was decoded from the operand ({:d}) for the instruction at {:#x}.".format(__name__, ea, opnum, res.__class__, opnum, insn.ea))

    # Now we can try to get all the xrefs from the address or value that
    # we extracted. If we couldn't grab anything, then just warn the user
    # about it and return an empty list.
    refs = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(value, idaapi.XREF_ALL)]
    if not refs:
        logging.warning(u"{:s}.op_references({:#x}, {:d}) : The operand ({:d}) at the specified address ({:#x}) does not have any references.".format(__name__, insn.ea, opnum, opnum, insn.ea))
        return []

    # After gathering all of the references into our list, we need
    # to iterate through all of them to figure out exactly what kind
    # of data each reference is targetting.
    res = []
    for ea, xiscode, xr in refs:

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
            iterable = (interface.opref_t(ea, int(op), interface.access_t(xr, xiscode)) for op in ops)

        # If the address of the reference wasn't actually a code
        # type, then this is a data global which doesn't have an
        # operand for us to search through.
        else:
            ref = interface.ref_t(ea, interface.access_t(xr, xiscode))
            iterable = (item for item in [ref])
        res.extend(iterable)
    return res
op_refs = utils.alias(op_references)

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
    @utils.multicase(ea=types.integer)
    @classmethod
    def feature(cls, ea):
        '''Return the feature bitmask for the instruction at the address `ea`.'''
        if database.type.is_code(ea):
            return interface.instruction.feature(ea)
        return None
    @utils.multicase(ea=types.integer, mask=types.integer)
    @classmethod
    def feature(cls, ea, mask):
        '''Return the feature bitmask for the instruction at the address `ea` masked with `mask`.'''
        if database.type.is_code(ea):
            return interface.instruction.feature(ea) & idaapi.as_uint32(mask)
        return None

    @utils.multicase()
    @classmethod
    def is_sentinel(cls):
        '''Returns true if the current instruction is a sentinel-type instruction.'''
        return cls.is_sentinel(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_sentinel(cls, ea):
        '''Returns true if the instruction at `ea` is a sentinel-type instruction.'''
        ea = interface.address.inside(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_STOP)])
    sentinel = issentinel = sentinelQ = utils.alias(is_sentinel, 'type')

    @utils.multicase()
    @classmethod
    def is_return(cls):
        '''Returns true if the current instruction is a return-type instruction that exits its current frame.'''
        return cls.is_return(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_return(cls, ea):
        '''Returns true if the instruction at `ea` is a return-type instruction that exits the current frame.'''
        ea, Xcfilter = interface.address.inside(ea), {idaapi.get_item_end(ea)}

        # We check xrefs to make sure that IDA didn't detect that a constant
        # address was loaded into the stack or link register prior to returning.
        F, Xci, Xdi = (callable(ea) for callable in [cls.feature, interface.xref.of_code, interface.xref.of_data])
        Xc, Xd = ([item for item in X] for X in [(item for item in Xci if item not in Xcfilter), Xdi])

        # If it's a sentinel instruction, not a branch, and has no refs, then we're good.
        return cls.is_sentinel(ea) and not any([F & idaapi.CF_JUMP, Xc, Xd])
    ret = isreturn = returnQ = retQ = utils.alias(is_return, 'type')

    @utils.multicase()
    @classmethod
    def is_shift(cls):
        '''Returns true if the current instruction is a bit-shifting instruction.'''
        return cls.is_shift(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_shift(cls, ea):
        '''Returns true if the instruction at `ea` is a bit-shifting instruction.'''
        ea = interface.address.inside(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_SHFT)])
    shift = isshift = shiftQ = utils.alias(is_shift, 'type')

    @utils.multicase()
    @classmethod
    def is_branch(cls):
        '''Returns true if the current instruction is any kind of branch.'''
        return cls.is_branch(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_branch(cls, ea):
        '''Returns true if the instruction at `ea` is any kind of branch.'''
        ea, Xcfilter = interface.address.inside(ea), {idaapi.get_item_end(ea)}

        # We check code xrefs in case IDA figured out that this instruction
        # actually does branch to something and created a reference for it.
        F, Xci, Xdi = (callable(ea) for callable in [cls.feature, interface.xref.of_code, interface.xref.of_data])
        Xc, Xd = ([item for item in X] for X in [(item for item in Xci if item not in Xcfilter), Xdi])

        # If it's actual code, not a call or a shift (this flag is weird on intel), and is a jump
        # or it has an actual code reference that IDA detected, then we're a branch instruction.
        return database.type.is_code(ea) and all([not any([F & idaapi.CF_CALL, F & idaapi.CF_SHFT]), any([F & idaapi.CF_JUMP, Xc])])
    branch = isbranch = branchQ = utils.alias(is_branch, 'type')

    @utils.multicase()
    @classmethod
    def is_jmp(cls):
        '''Returns true if the current instruction is an immediate and indirect branch.'''
        return cls.is_jmp(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_jmp(cls, ea):
        '''Returns true if the instruction at `ea` is an immediate and indirect branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and all([cls.feature(ea, idaapi.CF_STOP)])
    jmp = isjmp = jmpQ = utils.alias(is_jmp, 'type')

    @utils.multicase()
    @classmethod
    def is_jxx(cls):
        '''Returns true if the current instruction is a conditional branch.'''
        return cls.is_jxx(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_jxx(cls, ea):
        '''Returns true if the instruction at `ea` is a conditional branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and not all([cls.feature(ea, idaapi.CF_STOP)])
    jxx = isjxx = jxxQ = utils.alias(is_jxx, 'type')

    @utils.multicase()
    @classmethod
    def is_jmpi(cls):
        '''Returns true if the instruction at the current address is an indirect branch.'''
        return cls.is_jmpi(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_jmpi(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect branch.'''
        ea = interface.address.inside(ea)
        return cls.is_branch(ea) and all([cls.feature(ea, idaapi.CF_JUMP)])
    jmpi = isjmpi = jmpiQ = utils.alias(is_jmpi, 'type')

    @utils.multicase()
    @classmethod
    def is_call(cls):
        '''Returns true if the current instruction is a call.'''
        return cls.is_call(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_call(cls, ea):
        '''Returns true if the instruction at `ea` is a call.'''
        ea = interface.address.inside(ea)
        if idaapi.__version__ < 7.0 and hasattr(idaapi, 'is_call_insn'):
            idaapi.decode_insn(ea)
            return idaapi.is_call_insn(ea)
        return database.type.is_code(ea) and all([cls.feature(ea, idaapi.CF_CALL)])
    call = iscall = callQ = utils.alias(is_call, 'type')

    @utils.multicase()
    @classmethod
    def is_calli(cls):
        '''Return true if the current instruction is an indirect call.'''
        return cls.is_calli(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def is_calli(cls, ea):
        '''Returns true if the instruction at `ea` is an indirect call.'''
        ea = interface.address.inside(ea)
        F = cls.feature(ea)
        return database.type.is_code(ea) and all([F & idaapi.CF_CALL, F & idaapi.CF_JUMP])
    calli = iscalli = calliQ = utils.alias(is_calli, 'type')

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
