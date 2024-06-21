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
    '''Return the length of the current instruction.'''
    return size(ui.current.address())
@utils.multicase(ea=types.integer)
def size(ea):
    '''Return the length of the instruction at address `ea`.'''
    return at(ea).size

@utils.multicase(opnum=types.integer)
def opinfo(opnum):
    '''Return the ``idaapi.opinfo_t`` of the operand `opnum` for the current instruction.'''
    return opinfo(ui.current.address(), opnum)
@utils.multicase(opnum=types.integer, info=idaapi.opinfo_t)
def opinfo(opnum, info, **flags):
    '''Set the operand information of the operand `opnum` for the current instruction to the ``idaapi.opinfo_t`` in `info`.'''
    return opinfo(ui.current.address(), opnum, info, **flags)
@utils.multicase(reference=interface.opref_t)
def opinfo(reference):
    '''Return the ``idaapi.opinfo_t`` for the given operand `reference`.'''
    address, opnum, _ = reference
    return opinfo(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def opinfo(ea, opnum):
    '''Return the ``idaapi.opinfo_t`` of the operand `opnum` for the instruction at address `ea`.'''
    info, flags = idaapi.opinfo_t(), interface.address.flags(ea)
    ok = idaapi.get_opinfo(ea, opnum, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, opnum, flags)
    return info if ok else None
@utils.multicase(reference=interface.opref_t, info=idaapi.opinfo_t)
def opinfo(reference, info, **flags):
    '''Set the operand information for the given operand `reference` to the ``idaapi.opinfo_t`` in `info`.'''
    address, opnum, _ = reference
    return opinfo(address, opnum, info, **flags)
@utils.multicase(ea=types.integer, opnum=types.integer, info=idaapi.opinfo_t)
def opinfo(ea, opnum, info, **flags):
    """Set the operand information of the operand `opnum` for the instruction at address `ea` to the ``idaapi.opinfo_t`` in `info`.

    If any `flags` have been specified, then also set the operand's flags to the provided value.
    """
    res, flags = opinfo(ea, opnum), flags['flags'] if 'flags' in flags else interface.address.flags(ea)
    if not idaapi.set_opinfo(ea, opnum, flags, info):
        raise E.DisassemblerError(u"{:s}.opinfo({:#x}, {:d}, {!s}) : Unable to set the operand info for operand {:d}.".format(__name__, ea, opnum, info, opnum))
    return res

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
def ops_access():
    '''Return the access type of each operand for the current instruction.'''
    return ops_access(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_access(ea):
    '''Return the access type of each operand for the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    return tuple(interface.instruction.access(ea))

@utils.multicase()
def ops_read():
    '''Return references to the operands that are being read by the current instruction.'''
    return ops_read(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_read(ea):
    '''Return references to the operands that are being read by the instruction at address `ea`.'''
    ops = interface.instruction.access(interface.address.inside(ea))
    return tuple(ref for ref in ops if 'r' in ref.access)

@utils.multicase()
def ops_modified():
    '''Return references to the operands that are being written to or modified by the current instruction.'''
    return ops_modified(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_modified(ea):
    '''Return references to the operands that are being written to or modified by the instruction at address `ea`.'''
    ops = interface.instruction.access(interface.address.inside(ea))
    return tuple(ref for ref in ops if 'w' in ref.access)
ops_write = ops_modify = utils.alias(ops_modified)

@utils.multicase()
def ops_immediate():
    '''Return references to the operands for the current instruction that are immediates.'''
    return ops_immediate(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_immediate(ea):
    '''Return references to the operands for the instruction at address `ea` that are immediates.'''
    ops = interface.instruction.access(interface.address.inside(ea))
    return tuple(ref for ref in ops if not any(bit in ref.access for bit in 'rw'))
ops_constant = ops_const = utils.alias(ops_immediate)

@utils.multicase()
def ops_register(**modifiers):
    '''Return references to the operands for the current instruction that are using registers.'''
    return ops_register(ui.current.address(), **modifiers)
@utils.multicase(ea=types.integer)
def ops_register(ea, **modifiers):
    '''Return references to the operands for the instruction at address `ea` that are using registers.'''
    ea = interface.address.inside(ea)
    matches = interface.regmatch(**modifiers)
    return tuple(ref for ref in matches(ea))
@utils.multicase(register=(types.string, interface.register_t))
def ops_register(register, *registers, **modifiers):
    '''Return references to the operands for the current instruction that are using `register` or the additional `registers`.'''
    return ops_register(ui.current.address(), register, *registers, **modifiers)
@utils.multicase(ea=types.integer, register=(types.string, interface.register_t))
def ops_register(ea, register, *registers, **modifiers):
    """Return references to the operands for the instruction at address `ea` that are using `register` or the additional `registers`.

    If the keyword `write` is true, then only return the result if it's writing to the register.
    If the keyword `read` is true, then only return the result if it's reading from the register.
    If the keyword `execute` is true, then only return the result if it's executing with the register.
    """
    ea = interface.address.inside(ea)
    matches = interface.regmatch(*itertools.chain([register], registers), **modifiers)
    return tuple(ref for ref in matches(ea))
ops_reg = utils.alias(ops_register)

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
    outop = utils.fcompose(idaapi.ua_outop2, utils.fdefault(''), idaapi.tag_remove) if idaapi.__version__ < 7.0 else utils.fcompose(idaapi.print_operand, utils.fdefault(''), idaapi.tag_remove)
    res = outop(insn.ea, opnum) or "{:s}".format(op(insn.ea, opnum))
    return utils.string.of(res)

@utils.multicase(opnum=types.integer)
def op_access(opnum):
    '''Return the access type of the operand `opnum` for the current instruction.'''
    return op_access(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_access(reference):
    '''Return the access type for the given operand `reference`.'''
    address, opnum, _ = reference
    return op_access(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_access(ea, opnum):
    """Return the access type of the operand `opnum` for the instruction at address `ea`.

    The returned state is composed of "&", "r", "w", or "x" depending on whether
    the operand is being used as an address, read from, written to, or executed.
    """
    ops = tuple(interface.instruction.access(interface.address.inside(ea)))
    if opnum >= len(ops):
        raise E.InvalidTypeOrValueError(u"{:s}.op_access({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(ops), ea))
    return ops[opnum]

@utils.multicase(opnum=types.integer)
def op_used(opnum):
    '''Return true if the operand `opnum` for the current instruction is being used (non-modified).'''
    return op_used(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_used(reference):
    '''Return true if the given operand `reference` is being used (non-modified).'''
    address, opnum, _ = reference
    return op_used(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_used(ea, opnum):
    '''Return true if the operand `opnum` for the instruction at address `ea` is being used (non-modified).'''
    return True if interface.instruction.uses_operand(ea, opnum) else False

@utils.multicase(opnum=types.integer)
def op_modified(opnum):
    '''Return true if operand `opnum` for the current instruction is being changed (modified).'''
    return op_modified(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_modified(reference):
    '''Return true if the given operand `reference` is being changed (modified).'''
    address, opnum, _ = reference
    return op_modified(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_modified(ea, opnum):
    '''Return true if the operand `opnum` for the instruction at address `ea` is being changed (modiied).'''
    return True if interface.instruction.changes_operand(ea, opnum) else False

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
def opt(opnum):
    '''Return the pythonic type of the operand `opnum` for the current instruction.'''
    return opt(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def opt(reference):
    '''Return the pythonic type for the given operand `reference`.'''
    address, opnum, _ = reference
    return opt(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def opt(ea, opnum):
    '''Return the pythonic type of the operand `opnum` for the instruction at address `ea`.'''
    op, opsize = operand(ea, opnum), op_size(ea, opnum)

    # If we got a branch of some kind, then we need to promote the type
    # because we always maintain that you can only branch to pointers.
    if any([interface.instruction.is_branch(ea), interface.instruction.is_call(ea)]):
        return internal.types.type, opsize

    # if our operand is a register, then we decode the instruction with
    # its operand to verify the operand size before returning the regtype.
    elif op.type == idaapi.o_reg:
        insn = at(ea)
        regtype, size = catalog.operand.decode(insn, op).type
        if size != opsize:
            logging.info(u"{:s}.opt({:#x}, {:d}) : Returning the decoded operand size ({:d}) as it is different from the register size ({:d}).".format(__name__, ea, opnum, opsize, size))
        return regtype, opsize

    # Otherwise we can just trust that the operand type is correct.
    return catalog.operand.ptype(op), opsize
op_type = utils.alias(opt)

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
    t, signed = idaapi.num_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
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
    t, signed = idaapi.char_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
        raise E.DisassemblerError(u"{:s}.op_character({:#x}, {:d}) : Unable to set the type of operand {:d} to a character.".format(__name__, ea, opnum, opnum))

    # Extract the operand's op_t and its size so that we can figure out
    # its maximum value. we'll use this to transform the value as necessary.
    res, size = operand(ea, opnum), op_size(ea, opnum)
    bits, maximum = 8 * size, pow(2, 8 * size)

    # If this is an immediate value, then we can treat it normally.
    if res.type in {idaapi.o_imm}:
        integer = res.value & (maximum - 1)
        result = 0 if integer == 0 else (integer - maximum) if signed else integer

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
    return bytes(bytearray(reversed(bytearray(octets + [0] * size)[:size])))
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
    t, signed = idaapi.bin_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
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
    t, signed = idaapi.oct_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
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
    t, signed = idaapi.dec_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
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
    t, signed = idaapi.hex_flag(), idaapi.is_invsign(ea, interface.address.flags(ea), opnum)
    if not idaapi.set_op_type(ea, t, opnum):
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
    if not idaapi.set_op_type(ea, t, opnum):
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
    '''Set the type for the operand `opnum` at the current instruction to a stack variable and return it.'''
    return op_stackvar(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_stackvar(reference):
    '''Set the type for the operand given by `reference` to a stack variable and return it.'''
    address, opnum, _ = reference
    return op_stackvar(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_stackvar(ea, opnum):
    '''Set the type for operand `opnum` belonging to the instruction at `ea` to a stack variable and return it.'''
    if not function.has(ea):
        raise E.FunctionNotFoundError(u"{:s}.op_stackvar({:#x}, {:d}) : The specified address ({:#x}) is not within a function.".format(__name__, ea, opnum, ea))

    if not idaapi.op_stkvar(ea, opnum):
        raise E.DisassemblerError(u"{:s}.op_stackvar({:#x}, {:d}) : Unable to set operand {:d} to a stack variable.".format(__name__, ea, opnum, opnum))

    # Now that it's set, call into op_structure to return it.
    return op_structure(ea, opnum)
op_stack = op_stkvar = utils.alias(op_stackvar)

@utils.multicase(opnum=types.integer)
def op_structure(opnum):
    '''Return the structure and members pointed to by the operand `opnum` for the current instruction.'''
    return op_structure(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_structure(reference):
    '''Return the structure and members pointed to by the given operand `reference`.'''
    address, opnum, _ = reference
    return op_structure(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_structure(ea, opnum):
    '''Return the structure and members pointed to by the operand `opnum` for the instruction at address `ea`.'''
    FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
    F, insn, op, ri = interface.address.flags(ea), at(ea), operand(ea, opnum), interface.address.refinfo(ea, opnum)

    # Start out by checking if the operand is a stack variable, because
    # we'll need to handle it differently if so.
    if idaapi.is_stkvar(F, opnum) and interface.function.has(insn.ea):
        fn = interface.function.by(insn.ea)

        # Now we can ask the disassembler what's up with it.
        res = idaapi.get_stkvar(insn, op, op.addr)
        if not res:
            raise E.DisassemblerError(u"{:s}.op_structure({:#x}, {:d}) : The call to `idaapi.get_stkvar({!r}, {!r}, {:+#x})` returned an invalid stack variable.".format(__name__, ea, opnum, insn, op, op.addr))
        mptr, actval = res

        # First we grab our frame, and then find the starting member by its id.
        frame = idaapi.get_frame(interface.range.start(fn))
        mowner, mindex, mptr = internal.structure.members.by_identifier(frame, mptr)
        framebase = interface.function.frame_offset(fn)

        # Iterate through all of the members searching for the actual operand value.
        path, is_array, total = [], False, 0
        for realoffset, packed in internal.structure.members.at(mowner, actval):
            mowner, mindex, mptr = packed

            # We use the total so that offsets from the path match what's displayed by the disassembler.
            # Essentially, the sum of the delta and the last path member should match the operand.
            member = internal.structure.new(mowner.id, framebase + total).members[mindex]
            path.append(member)

            # Check if any of the members are an array, because we promote to a list if so.
            msize, melement = internal.structure.member.size(mptr), internal.structure.member.element(mptr)
            is_array, total = is_array if is_array else melement < msize, total + (0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff)

        # Calculate the delta using the difference of the delta
        # from the path and the actual value of the operand.
        delta = actval - total

        # If our result is an array, then we need to return a list and include the offset.
        if is_array:
            return [item for item in itertools.chain(path, [delta])]

        # Otherwise it's just a regular path, and we need to determine whether
        # to include the offset in the result or not.
        if delta > 0:
            return tuple(item for item in itertools.chain(path, [delta]))
        return tuple(path) if len(path) > 1 else path[0]

    # Otherwise, we check if our operand is not a structure offset, but pointing
    # to memory by having a reference. If it is then we'll need to figure out the
    # field being referenced by calculating the offset into structure ourselves.
    elif not idaapi.is_stroff(F, opnum):
        value = op_reference(ea, opnum)
        address = interface.address.head(value)
        flags = interface.address.flags(address)

        # Extract the type from the given address and then use its size to
        # calculate the actual member offset that the operand is pointing at.
        info, offset, element = idaapi.opinfo_t(), value - address, interface.address.element(address, flags)
        index, bytes = divmod(offset, element)
        ok = idaapi.get_opinfo(address, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, address, idaapi.OPND_ALL, flags)

        # Verify that the type as the given address is a structure
        if idaapi.as_uint32(flags & idaapi.DT_TYPE) not in {FF_STRUCT}:
            raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is not referencing an address ({:#x}) containing the required flags ({:#x}) for a structure.".format(__name__, ea, opnum, opnum, address, flags))
        elif not ok:
            raise E.MissingTypeOrAttribute(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is not referencing an address ({:#x}) containing the necessary information for a structure.".format(__name__, ea, opnum, opnum, address))
        elif not idaapi.get_struc(info.tid):
            raise E.StructureNotFoundError(u"{:s}.op_structure({:#x}, {:d}) : Operand {:d} is referencing an identifier ({:#x}) that is not a structure.".format(__name__, ea, opnum, opnum, info.tid))
        sptr = idaapi.get_struc(info.tid)

        # FIXME: check if the operand contains any member xrefs, because
        #        if it doesn't then we don't actually need a path.

        # Iterate through the structure members looking for actual member offset.
        total, path, is_array = 0, [], interface.address.size(address) // element > 1
        for _, packed in internal.structure.members.at(sptr, bytes):
            mowner, mindex, mptr = packed

            # Here, we use the total so that the offsets for the entire path correlate to what
            # the disassembler displays. This works, except for when the disassembler is wrong.
            member = internal.structure.new(mowner.id, address + total).members[mindex]
            path.append(member)

            # Check if any of the members are an array, because we promote to a list if so.
            msize, melement = internal.structure.member.size(mptr), internal.structure.member.element(mptr)
            is_array, total = is_array if is_array else melement < msize, total + (0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff)

        # Calculate the delta based on the length of the path. The sum of the offset for the
        # very last member with the delta should result in the operand address. It's also
        # worth noting that the disassembler doesn't always display the correct member.
        delta = value - (address + total)

        # If we encountered an element that's an array, then we
        # return the path as a list with the delta attached to it.
        if is_array:
            return [item for item in itertools.chain(path, [delta])]

        # Figure out whether we need to include the offset in the result.
        if delta > 0:
            return tuple(item for item in itertools.chain(path, [delta]))
        return tuple(path) if len(path) > 1 else path[0]

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
    if len(tids) == 1 and sum([value, delta]) == structure.size(tids[0]):
        return structure.by_identifier(tids[0])

    # Next we'll gather the data references for the operand and key them
    # by their sptr id. This is because I can't figure out any other way
    # to get _exactly_ what's being displayed.
    displayed = {}
    for mid in filter(interface.node.identifier, interface.xref.of_data(insn.ea)):

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
        owner = internal.structure.new(sptr.id, position)

        # Start out by finding the exact structure that was resolved,
        # and then use it to find the exact member being referenced.
        if mptr:
            mindex = internal.structure.members.index(sptr, mptr)
            moffset = 0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff
            member, offset = internal.structure.member_t(owner, mindex), mptr.soff

        # If there wasn't a member, then there's at least a member
        # that's being displayed. So, we can figure out which one is
        # being displayed by the operand (via dref) and use that one.
        elif operator.contains(displayed, sptr.id):
            mptr, mindex = displayed[sptr.id], internal.structure.members.index(sptr, displayed[sptr.id])
            moffset = 0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff
            member, offset = internal.structure.member_t(owner, mindex), offset

        # If it's not referenced at all, then we're in a very weird
        # situation and it absolutely has got to be the structure size.
        else:
            member, offset, moffset = owner, 0, 0

        # Now that we figured out the right item that's being displayed,
        # update our position using its realoffset, keep track of our
        # carried value, and then add them member before continuing.
        position, leftover = calculator.send((sptr, None, moffset)), leftover + offset
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
@utils.multicase(opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
def op_structure(opnum, structure, *path):
    '''Apply the specified `structure` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, [item for item in itertools.chain([structure], path)])
@utils.multicase(opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structure(opnum, member, *path):
    '''Apply the specified `member` along with any members in `path` to the instruction operand `opnum` at the current address.'''
    return op_structure(ui.current.address(), opnum, [item for item in itertools.chain([member], path)])

## address and opnum with variable-length path
@utils.multicase(ea=types.integer, opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
def op_structure(ea, opnum, structure, *path):
    '''Apply the specified `structure` along with the members in `path` to the instruction operand `opnum` at the address `ea`.'''
    return op_structure(ea, opnum, [item for item in itertools.chain([structure], path)])
@utils.multicase(ea=types.integer, opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structure(ea, opnum, member, *path):
    '''Apply the specified `member` to the instruction operand `opnum` at the address `ea`.'''
    return op_structure(ea, opnum, [item for item in itertools.chain([member], path)])

## operand reference with variable-length path
@utils.multicase(reference=interface.opref_t, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
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
    if isinstance(member, (types.string, idaapi.tinfo_t)):
        sptr, fullpath = structure.by(member).ptr, items
    elif isinstance(member, idaapi.struc_t):
        sptr, fullpath = structure.by(member.id), items
    elif isinstance(member, structure.structure_t):
        sptr, fullpath = member.ptr, items
    elif isinstance(member, idaapi.member_t):
        _,_, sptr = idaapi.get_member_by_id(member.id)
        if not interface.node.identifier(sptr.id):
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
    if interface.address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
        raise E.InvalidTypeOrValueError(u"{:s}.op_structure({:#x}, {:d}, {:#x}, {!r}) : The requested address ({:#x}) is not defined as a code type.".format(__name__, ea, opnum, sptr.id, path, ea))

    # Convert the path to a list, and then validate it before we use it.
    path, accepted = [item for item in path], (idaapi.member_t, structure.member_t, types.string, types.integer)
    if any(not isinstance(item, accepted) for item in path if not hasattr(item, '__int__')):
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
    st = structure.by_identifier(sptr.id)
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
        display_members = False

    # Now we can calculate the path to the value that the user is trying to suggest
    # a path for. We don't really need the delta, but we can use it to determine
    # the path that the user stopped at with the path that we'll actually apply.
    else:
        realdelta, realpath = interface.strpath.guide(value, st.ptr, userpath)
        display_members = not(userdelta + value) and any(mptr for _, mptr, _ in userpath)

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
    interface.node.aflags(ea, idaapi.AFL_ZSTROFF, idaapi.AFL_ZSTROFF if display_members else 0)
    return op_structure(insn.ea, opnum)
op_struc = op_struct = utils.alias(op_structure)

# Just some aliases for reading from the current location
@utils.multicase(opnum=types.integer)
def op_structurepath(opnum):
    '''Return the structure and members applied to the operand `opnum` for the current instruction.'''
    return op_structurepath(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_structurepath(reference):
    '''Return the structure and members applied to the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structurepath(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_structurepath(ea, opnum):
    '''Return the structure and members applied to the operand `opnum` for the instruction at address `ea`.'''
    FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
    F, insn, op, ri = interface.address.flags(ea), at(ea), operand(ea, opnum), interface.address.refinfo(ea, opnum)

    # If it's a stack variable, then we need to know its function before doing anything.
    if idaapi.is_stkvar(F, opnum) and function.has(insn.ea):
        fn = interface.function.by(insn.ea)

        # Then we can demand that the disassembler tells us its mptr and offset.
        res = idaapi.get_stkvar(insn, op, op.addr)
        if not res:
            raise E.DisassemblerError(u"{:s}.op_structurepath({:#x}, {:d}) : The call to `idaapi.get_stkvar({!r}, {!r}, {:+#x})` returned an invalid stack variable.".format(__name__, ea, opnum, insn, op, op.addr))
        mptr, actval = res

        # Then we'll grab its frame along with everything related to the member.
        frame = idaapi.get_frame(interface.range.start(fn))
        mowner, mindex, mptr = internal.structure.members.by_identifier(frame, mptr)
        framebase = interface.function.frame_offset(fn)

        # Traverse through each member for the actual value, and collect the full path.
        path, is_array, realoffset, moffset = [], False, 0, 0
        for realoffset, packed in internal.structure.members.at(mowner, actval):
            mowner, mindex, mptr = packed

            # Now we create a new structure at the real offset and grab the member by its index.
            member = internal.structure.new(mowner.id, framebase + realoffset).members[mindex]
            path.append(member)

            # Check if any of the members are an array, because we promote to a list if so.
            msize, melement = internal.structure.member.size(mptr), internal.structure.member.element(mptr)
            is_array, moffset = is_array if is_array else melement < msize, 0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff

        # Calculate the delta based on the member location and the last member from the path.
        delta = actval - (realoffset + moffset)

        # We didn't need to adjust the path due to the frame already being a structure. We still
        # have to determine whether the path contains an array, though. Also, since each member
        # should have an adjusted offset, we can exclude a non-zero delta from the result.
        Fmake_ordered = builtins.list if is_array else builtins.tuple
        if delta > 0:
            return Fmake_ordered(item for item in itertools.chain(path, [delta]))
        return Fmake_ordered(path) if len(path) > 1 else path[0]

    # If it's a memory address, then we need to verify that that the operand points to a
    # structure. If it is, then we need to figure out the exact field being referenced.
    elif not idaapi.is_stroff(F, opnum):
        value = op_reference(ea, opnum)
        address = interface.address.head(value)
        flags = interface.address.flags(address)

        # Extract the type that is being referenced along with its size and operand
        # information. We will be using this to calculate the correct path to use.
        offset, element = value - address, interface.address.element(address, flags)
        index, bytes = divmod(offset, element)
        info, count, base = idaapi.opinfo_t(), interface.address.size(address) // element, index * element
        ok = idaapi.get_opinfo(address, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, address, idaapi.OPND_ALL, flags)

        # Check that the address being pointed to is actually a structure of some sort.
        if idaapi.as_uint32(flags & idaapi.DT_TYPE) not in {FF_STRUCT}:
            raise E.MissingTypeOrAttribute(u"{:s}.op_structurepath({:#x}, {:d}) : Operand {:d} is not referencing an address ({:#x}) containing the required flags ({:#x}) for a structure.".format(__name__, ea, opnum, opnum, address, flags))
        elif not ok:
            raise E.MissingTypeOrAttribute(u"{:s}.op_structurepath({:#x}, {:d}) : Operand {:d} is not referencing an address ({:#x}) containing the necessary information for a structure.".format(__name__, ea, opnum, opnum, address))
        elif not idaapi.get_struc(info.tid):
            raise E.StructureNotFoundError(u"{:s}.op_structurepath({:#x}, {:d}) : Operand {:d} is referencing an identifier ({:#x}) that is not a structure.".format(__name__, ea, opnum, opnum, info.tid))
        sptr = idaapi.get_struc(info.tid)

        # Now we'll use everything we gathered to determine the path using the real
        # offset into the structure. Each member of the path should be translated
        # to the correct address representing the index that was actually selected.
        path, is_array, moffset = [], False, 0
        for realoffset, packed in internal.structure.members.at(sptr, bytes):
            mowner, mindex, mptr = packed

            # We're using the real offset so that each structure starts at the correct
            # address. This way each path member has a real address that can be used.
            member = internal.structure.new(mowner.id, address + base + realoffset).members[mindex]
            path.append(member)

            # Check if any of the members are an array, because we promote to a list if so.
            msize, melement = internal.structure.member.size(mptr), internal.structure.member.element(mptr)
            is_array, moffset = is_array if is_array else melement < msize, 0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff

        # Calculate the delta using the adjustment we made for the array and the last element.
        delta = offset - (base + moffset)

        # Now we need to figure out whether to return an array or a regular path. This is a
        # structure path, so the indices should already be resolved and represented by the
        # offset for each member. This means we can exclude the non-zero delta for either one.
        Fmake_ordered = builtins.list if is_array else builtins.tuple
        if delta > 0:
            return Fmake_ordered(item for item in itertools.chain(path, [delta]))
        return Fmake_ordered(path) if len(path) > 1 else path[0]

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
    path, members = [], interface.strpath.of_tids(target, tids)
    calculator = interface.strpath.calculate(0)
    resolver = interface.strpath.resolve(path.append, sptr, target)

    position = builtins.next(calculator)
    try:
        sptr, candidates, carry = builtins.next(resolver)
        for owner, mptr, offset in members:
            assert owner.id == sptr.id
            sptr, candidates, carry = resolver.send((mptr, carry))
            position = calculator.send((owner, mptr, offset))

        resolver.send((None, None))
        raise E.DisassemblerError(u"{:s}.op_structurepath({:#x}, {:d}) : Expected path to have been resolved at offset {:#x} of index {:d} with {:s}.".format(__name__, ea, opnum, builtins.next(calculator), len(path), interface.strpath.format(owner, mptr)))

    # If we're done resolving, then save our position for calculating the path members.
    except StopIteration:
        position = builtins.next(calculator)
        base = value - carry - position

    # If we failed to resolve the path, then our operand does not reference the structure
    # and we can't trust the resolved path at all whatsoever. First check to see if it's
    # a sizeof(), and then recalculate the entire path explicitly trusting the tid array.
    except E.MemberNotFoundError as e:
        size = idaapi.get_struc_size(sid)

        # If we failed to resolve the path, our position and delta are 0, and the value
        # is the same as our structure size, then this is definitely a sizeof(structure)
        # and we return the structure with its size as a special-case.
        if 0 == position == delta and target == size:
            return structure.by_identifier(sptr.id), size

        # Otherwise we're oob of the structure and will need to guide to the field
        # displayed by the disassembler. Then we can do our maths with the new position.
        calculator = interface.strpath.calculate(0); builtins.next(calculator)
        [calculator.send((sptr, mptr, offset)) for (sptr, mptr, offset) in members]
        position, path = interface.strpath.guide(builtins.next(calculator) % size, idaapi.get_struc(sid), members)

        # We need two calcuations, the first one which is the target offset,
        # and relative to our guided position, and the base offset which'll be
        # used to calculate the position of each member in the returend path.
        carry = target - position
        base =  value - delta - position

    finally:
        resolver.close(), calculator.close()
        logging.info(u"{:s}.op_structurepath({:#x}, {:d}) : Resolved the path ({:d} elements) for the specified instruction operand to {:s}.".format(__name__, ea, opnum, len(path), interface.strpath.fullname(path)))

    # Now we have resolved a correct path and we only need to convert
    # it into a list of members. We can also use our base to calculate
    # the location of each member that is being returned in said list.
    calculator = interface.strpath.calculate(base)
    result, position = [], builtins.next(calculator)
    for sptr, mptr, offset in path:
        st = structure.by_identifier(sptr.id, offset=position)
        item = st.members.by_identifier(mptr.id) if mptr else st
        result.append(item)
        position = calculator.send((sptr, mptr, offset))

    # Just like the op_structure implementation, we need to figure out if
    # there's an array being referenced to convert our result to a list.
    if any(isinstance(member.type, types.list) for member in result if isinstance(member, structure.member_t)):
        return result + [carry]

    # Otherwise it's just a path with the carried offset, so we check the
    # carryied offset for non-zero in case we need to return it.
    results = tuple(result)
    if carry:
        return results + (carry,)
    return results if len(results) > 1 else results[0]

## current address and opnum with variable-length path
@utils.multicase(opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
def op_structurepath(opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with any members in `path` directly to the operand `opnum` of the instruction at the current address.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ui.current.address(), opnum, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structurepath(opnum, member, *path, **delta):
    '''Apply the specified `member` along with any members in `path` directly to the operand `opnum` of the instruction at the current address.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ui.current.address(), opnum, [item for item in itertools.chain([member], path, deltapath)])

## address and opnum with variable-length path
@utils.multicase(ea=types.integer, opnum=types.integer, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
def op_structurepath(ea, opnum, structure, *path, **delta):
    '''Apply the specified `structure` along with the members in `path` directly to the operand `opnum` of the instruction at address `ea`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ea, opnum, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(ea=types.integer, opnum=types.integer, member=(structure.member_t, idaapi.member_t))
def op_structurepath(ea, opnum, member, *path, **delta):
    '''Apply the specified `member` directly to the operand `opnum` of the instruction at address `ea`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(ea, opnum, [item for item in itertools.chain([member], path, deltapath)])

## operand reference with variable-length path
@utils.multicase(reference=interface.opref_t, structure=(structure.structure_t, idaapi.struc_t, types.string, idaapi.tinfo_t))
def op_structurepath(reference, structure, *path, **delta):
    '''Apply the specified `structure` along with the members in `path` directly to the operand pointed to by `reference`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(reference, [item for item in itertools.chain([structure], path, deltapath)])
@utils.multicase(reference=interface.opref_t, member=(structure.member_t, idaapi.member_t))
def op_structurepath(reference, member, *path, **delta):
    '''Apply the specified `member` along with the members in `path` relative to the operand pointed to by `reference`.'''
    deltapath = [delta.pop('delta', 0)] if delta else []
    return op_structurepath(reference, [item for item in itertools.chain([member], path, deltapath)])

## all variations that take a tuple/list to apply to a given operand.
@utils.multicase(reference=interface.opref_t, path=types.ordered)
def op_structurepath(reference, path):
    '''Apply the structure members in `path` directly to the operand pointed to by `reference`.'''
    address, opnum, _ = reference
    return op_structurepath(address, opnum, path)
@utils.multicase(ea=types.integer, opnum=types.integer, path=types.ordered)
def op_structurepath(ea, opnum, path):
    '''Apply the structure members in `path` directly to the operand `opnum` of the instruction at address `ea`.'''
    items = [item for item in path]
    member = items.pop(0) if len(items) else ''
    if isinstance(member, (types.string, idaapi.tinfo_t)):
        sptr, fullpath = structure.by(member).ptr, items
    elif isinstance(member, idaapi.struc_t):
        sptr, fullpath = structure.by(member.id), items
    elif isinstance(member, structure.structure_t):
        sptr, fullpath = member.ptr, items
    elif isinstance(member, idaapi.member_t):
        _,_, sptr = idaapi.get_member_by_id(member.id)
        if not interface.node.identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(member.id))
        fullpath = itertools.chain([member], items)
    elif isinstance(member, structure.member_t):
        sptr, fullpath = member.parent.ptr, itertools.chain([member], items)
    else:
        raise E.InvalidParameterError(u"{:s}.op_structurepath({:#x}, {:d}, {!r}) : Unable to determine the structure from the provided path due to the first item being of an unsupported type ({!s}).".format(__name__, ea, opnum, path, member.__class__))
    return op_structurepath(ea, opnum, sptr, [item for item in fullpath])

@utils.multicase(ea=types.integer, opnum=types.integer, structure=structure.structure_t, path=types.ordered)
def op_structurepath(ea, opnum, structure, path):
    '''Apply the specified `structure` along with the members in `path` directly to the operand `opnum` of the instruction at address `ea`.'''
    return op_structurepath(ea, opnum, structure.ptr, path)
@utils.multicase(ea=types.integer, opnum=types.integer, sptr=idaapi.struc_t, path=types.ordered)
def op_structurepath(ea, opnum, sptr, path):
    '''Apply the structure identified by `sptr` along with the members in `path` directly to the operand `opnum` of the instruction at address `ea`.'''
    ea = interface.address.inside(ea)
    if interface.address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
        raise E.InvalidTypeOrValueError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, {!r}) : The requested address ({:#x}) is not defined as a code type.".format(__name__, ea, opnum, sptr.id, path, ea))

    # Convert the path to a list, and then validate it before we use it.
    path, accepted = [item for item in path], (idaapi.member_t, structure.member_t, types.string, types.integer)
    if any(not isinstance(item, accepted) for item in path if not hasattr(item, '__int__')):
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
    st = structure.by_identifier(sptr.id)
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

    # Very last thing to do is to figure out the operands for op_stroff. We first need
    # to convert the path to a tid_array, and then we'll need to know the delta to use.
    items = interface.strpath.to_tids(realpath)
    tid, length = idaapi.tid_array(len(items)), len(items)
    for index in range(length):
        tid[index] = items[index]

    # We now calc the diff between our expected and the user's delta. We've already warned
    # them about it, so this ensures those missing members still get included in the operand.
    base = usergoal - goaldelta

    # Now we need a delta to use. If we avoid adjusting the realdelta using the operand, then the
    # user's path would appear relative to the operand. But since we now support integer-likes, we
    # perform the calculation as the user can just adjust the calculation for that capability.
    delta = realdelta - idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr)
    display_members = False if base + delta else True

    # XXX: The purpose of excluding the operand from the realdelta was when the user knows that
    #      a register is pointing at a specific field and wants all future references to be
    #      relative to it. This avoids them having to calculate it themselves. However, as these
    #      op_structure functions allow integer-like path members, the user can simply include
    #      the operand in their path for the operand to appear relative to a structure field.
    #      That's the purpose of the prior delta being assigned and this line being commented.
    #delta = realdelta

    # Only thing that's left to do is apply the tids that we collected along with
    # the delta that we calculated from the user's path to the desired operand.
    if not idaapi.op_stroff(insn.ea if idaapi.__version__ < 7.0 else insn, opnum, tid.cast(), length, base + delta):
        raise E.DisassemblerError(u"{:s}.op_structurepath({:#x}, {:d}, {:#x}, [{:s}]) : Unable to apply the resolved structure path ({:s}) and delta ({:+#x}) to the operand ({:d}) at the specified address ({:#x}).".format(__name__, ea, opnum, st.ptr.id, ', '.join(path_description), ', '.join(map("{:#x}".format, items)), base + delta, opnum, insn.ea))
    interface.node.aflags(ea, idaapi.AFL_ZSTROFF, idaapi.AFL_ZSTROFF if display_members else 0)

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
    F = interface.address.flags(ea)
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
    F = interface.address.flags(ea)
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
    info, F = idaapi.opinfo_t(), interface.address.flags(ea)

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
    '''Return the ``idaapi.refinfo_t`` for the current instruction.'''
    return interface.address.refinfo(ui.current.address())
@utils.multicase(ea=types.integer)
def ops_refinfo(ea):
    '''Return the ``idaapi.refinfo_t`` for the instruction at address `ea`.'''
    return interface.address.refinfo(ea)
@utils.multicase(opnum=types.integer)
def op_refinfo(opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the current instruction.'''
    return interface.address.refinfo(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_refinfo(reference):
    '''Return the ``idaapi.refinfo_t`` for the given operand `reference`.'''
    address, opnum, _ = reference
    return interface.address.refinfo(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_refinfo(ea, opnum):
    '''Return the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
    return interface.address.refinfo(ea, opnum)

@utils.multicase(opnum=types.integer)
def op_reference(opnum):
    '''Set the type for operand `opnum` at the current instruction to an offset and return its target address.'''
    return op_reference(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_reference(reference):
    '''Set the type for the given operand `reference` to an offset and return its target address.'''
    address, opnum, _ = reference
    return op_reference(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_reference(ea, opnum):
    '''Set the type for operand `opnum` of the instruction at address `ea` to an offset and return its target address.'''
    insn = interface.instruction.at(ea)
    operands = interface.instruction.operands(insn.ea)
    if not(0 <= opnum < len(operands)):
        message = 'invalid' if opnum < 0 else "larger than the number of operands ({:d})".format(len(operands))
        raise E.IndexOutOfBoundsError(u"{:s}.op_reference({:#x}, {:d}) : The specified operand number ({:d}) is {:s} for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, message, insn.ea))

    # If there's already a refinfo_t for the operand number, then we don't want
    # to change anything. So we'll simply use it as-is to return the target.
    operand, refinfo = operands[opnum], interface.address.refinfo(insn.ea, opnum)
    if refinfo:
        return interface.instruction.reference(insn.ea, operand.n, refinfo)

    # We need to check the operand type here because idaapi.op_offset_ex seems
    # to always return success, even if the operand type is a register. So to
    # avoid applying a reference to an operand that doesn't make sense, we bail.
    elif operand.type not in {idaapi.o_mem, idaapi.o_near, idaapi.o_far, idaapi.o_imm, idaapi.o_displ, idaapi.o_phrase}:
        raise E.InvalidTypeOrValueError(u"{:s}.op_reference({:#x}, {:d}) : Unable to modify the operand ({:d}) for the instruction at address {:#x} due to the operand being an unsupported type ({:d}).".format(__name__, ea, opnum, operand.n, insn.ea, operand.type))

    # Otherwise, we're going to need to use the default to figure it out
    # ourselves, apply it to the operand, and then we can return it.
    refinfo = idaapi.refinfo_t()
    refinfo.set_type(idaapi.get_default_reftype(insn.ea))
    refinfo.target = idaapi.BADADDR
    if not idaapi.op_offset_ex(insn.ea, operand.n, refinfo):
        raise E.DisassemblerError(u"{:s}.op_reference({:#x}, {:d}) : Unable to change the operand ({:d}) for the specified instruction ({:#x}) to a reference.".format(__name__, ea, opnum, operand.n, ea))
    return interface.instruction.reference(insn.ea, operand.n, refinfo)
@utils.multicase(ea=types.integer, opnum=types.integer, refinfo=idaapi.refinfo_t)
def op_reference(ea, opnum, refinfo):
    '''Set the type for operand `opnum` of the instruction at address `ea` to an offset with the given `refinfo` and return its target address.'''
    insn = interface.instruction.at(ea)
    iterable = ((attribute, getattr(refinfo, attribute)) for attribute in ['base', 'target'])
    refinfo_attributes = [(attribute, value) for attribute, value in iterable if value != idaapi.BADADDR]

    # Check the operand number is actually valid.
    operands = interface.instruction.operands(insn.ea)
    if not(0 <= opnum < len(operands)):
        descr = "{:s}(flags={:#x}, tdelta={:+#x}{:s})".format(utils.pycompat.fullname(refinfo), refinfo.flags, refinfo.tdelta, ", {:s}".format(', '.join("{:s}={:#x}".format(attribute, value) for attribute, value in refinfo_attributes)) if refinfo_attributes else '')
        message = 'invalid' if opnum < 0 else "larger than the number of operands ({:d})".format(len(operands))
        raise E.IndexOutOfBoundsError(u"{:s}.op_reference({:#x}, {:d}, {:s}) : The specified operand number ({:d}) is {:s} for the instruction at address {:#x}.".format(__name__, ea, opnum, descr, opnum, message, insn.ea))

    # Make sure the operand type is something that actually makes sense.
    operand = operands[opnum]
    if operand.type not in {idaapi.o_mem, idaapi.o_near, idaapi.o_far, idaapi.o_imm, idaapi.o_displ, idaapi.o_phrase}:
        descr = "{:s}(flags={:#x}, tdelta={:+#x}{:s})".format(utils.pycompat.fullname(refinfo), refinfo.flags, refinfo.tdelta, ", {:s}".format(', '.join("{:s}={:#x}".format(attribute, value) for attribute, value in refinfo_attributes)) if refinfo_attributes else '')
        raise E.InvalidTypeOrValueError(u"{:s}.op_reference({:#x}, {:d}, {:s}) : Unable to modify the operand ({:d}) for the instruction at address {:#x} due to the operand being an unsupported type ({:d}).".format(__name__, ea, opnum, descr, operand.n, insn.ea, operand.type))

    # Now we can try to apply the refinfo_t we were given and return the operand value using it.
    if not idaapi.op_offset_ex(insn.ea, operand.n, refinfo):
        descr = "{:s}(flags={:#x}, tdelta={:+#x}{:s})".format(utils.pycompat.fullname(refinfo), refinfo.flags, refinfo.tdelta, ", {:s}".format(', '.join("{:s}={:#x}".format(attribute, value) for attribute, value in refinfo_attributes)) if refinfo_attributes else '')
        raise E.DisassemblerError(u"{:s}.op_reference({:#x}, {:d}, {:s}) : Unable to change the operand ({:d}) for the specified instruction ({:#x}) to a reference.".format(__name__, ea, opnum, operand.n, insn.ea))
    return interface.instruction.reference(insn.ea, operand.n, refinfo)
op_ref = utils.alias(op_reference)

@utils.multicase(opnum=types.integer)
def op_references(opnum):
    '''Return the `(address, opnum, type)` of each location that references the target of the operand `opnum` for the current instruction.'''
    return op_references(ui.current.address(), opnum)
@utils.multicase(reference=interface.opref_t)
def op_references(reference):
    '''Return the `(address, opnum, type)` of each location that references the target of the given operand `reference`.'''
    address, opnum, _ = reference
    return op_references(address, opnum)
@utils.multicase(ea=types.integer, opnum=types.integer)
def op_references(ea, opnum):
    '''Return the `(address, opnum, type)` of each location that references the target of operand `opnum` for the instruction at `ea`.'''
    insn, ops = at(ea), operands(ea)
    if not(opnum < len(ops)):
        raise E.InvalidTypeOrValueError(u"{:s}.op_references({:#x}, {:d}) : The specified operand number ({:d}) is larger than the number of operands ({:d}) for the instruction at address {:#x}.".format(__name__, ea, opnum, opnum, len(operands(ea)), ea))

    # Start out by doing sanity check so that we can determine whether
    # the operand is referencing a local or a global. We grab both the
    # operand info any the result from idaapi.op_adds_xrefs in order to
    # distinguish the "type" of xrefs that are associated with an operand.
    # This way we can distinguish structure members, enumeration members,
    # locals, globals, etc.
    F = interface.address.flags(insn.ea)
    info, has_xrefs, accesses = opinfo(insn.ea, opnum), idaapi.op_adds_xrefs(F, opnum), tuple(ref.access for ref in interface.instruction.access(insn.ea))

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
        # FIXME: the access for an LEA instruction should include an '&', but if we
        #        trust insn_t.itype instead of op_t.type, then we'd probably need to
        #        maintain their semantics in the processor module instead of interface.
        return [ interface.opref_t(ea, opnum, accesses[opnum]) for ea, opnum, xtype in interface.xref.frame(fn, member) ]

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
                if not idaapi.is_stkvar(interface.address.flags(ea), refopnum):
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

                # Carve a path through the members that overlap with the offset.
                path, moffset, realoffset = [], 0, 0
                for realoffset, packed in internal.structure.members.at(mowner, offset):
                    mowner, mindex, mptr = packed
                    path.append((mowner, mptr))
                    moffset = 0 if mptr.flsg & idaapi.MF_UNIMEM else mptr.soff

                delta = offset - (realoffset + moffset)

                # Now that we have all the members in the path, we go through and
                # collect all of their identifiers as a filter for the candidates.
                ids = [msptr.id] + [mptr.id for mowner, mptr in path]
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
                    if interface.address.flags(interface.address.head(op.addr), idaapi.DT_TYPE) != (idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU):
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
                        result.append(interface.opref_t(ea, int(refopnum), accesses[refopnum]))
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
        if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:

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
        > print( instruction.type.is_jcc(ea) )
        > print( instruction.type.is_call(ea) )
        > print( instruction.type.is_branch(ea) )

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the instruction code (processor-specific) for the instruction at the current address.'''
        ea = interface.address.inside(ui.current.address())
        insn = interface.instruction.at(ea)
        return insn.itype
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea):
        '''Return the instruction code (processor-specific) for the instruction at address `ea`.'''
        ea = interface.address.inside(ea)
        insn = interface.instruction.at(ea)
        return insn.itype

    @utils.multicase()
    @classmethod
    def feature(cls):
        '''Return the feature bitmask of the current instruction.'''
        return cls.feature(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def feature(cls, ea):
        '''Return the feature bitmask of the instruction at address `ea`.'''
        ea = interface.address.inside(ea)
        return interface.instruction.feature(ea) if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE else None
    @utils.multicase(ea=types.integer, mask=types.integer)
    @classmethod
    def feature(cls, ea, mask):
        '''Return the feature bitmask of the instruction at the address `ea` masked with `mask`.'''
        ea = interface.address.inside(ea)
        return interface.instruction.feature(ea) & idaapi.as_uint32(mask) if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE else None

    @utils.multicase()
    @classmethod
    def sentinel(cls):
        '''Return true if the current instruction is a sentinel instruction.'''
        return cls.sentinel(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def sentinel(cls, ea):
        '''Return true if the instruction at address `ea` is a sentinel instruction.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_sentinel(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def sentinel(cls, bounds):
        '''Return true if the basic block at the given `bounds` will stop execution when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_sentinel(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def sentinel(cls, bb):
        '''Return true if the basic block `bb` will stop execution when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_sentinel(ea)
    is_sentinel = utils.alias(sentinel, 'type')

    @utils.multicase()
    @classmethod
    def leave(cls):
        '''Return true if the current instruction will return from a function when executed.'''
        return cls.leave(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def leave(cls, ea):
        '''Return true if the instruction at address `ea` will return from a function when executed.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_return(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def leave(cls, bounds):
        '''Return true if the basic block at the given `bounds` will return from a function when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_return(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def leave(cls, bb):
        '''Return true if the basic block `bb` will return from a function when executed.'''
        if bb.type in {interface.fc_block_type_t.fcb_ret, interface.fc_block_type_t.fcb_cndret}:
            return True
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_return(ea)
    is_return = exit = utils.alias(leave, 'type')

    @utils.multicase()
    @classmethod
    def shift(cls):
        '''Return true if the current instruction is a bit-shifting instruction.'''
        return cls.shift(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def shift(cls, ea):
        '''Return true if the instruction at address `ea` is a bit-shifting instruction.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_shift(ea)
    is_shift = utils.alias(shift, 'type')

    @utils.multicase()
    @classmethod
    def branch(cls):
        '''Return true if the current instruction is a type of branch.'''
        return cls.branch(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def branch(cls, ea):
        '''Return true if the instruction at address `ea` is a type of branch.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_branch(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def branch(cls, bounds):
        '''Return true if the basic block at the given `bounds` will branch to another block when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_branch(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def branch(cls, bb):
        '''Return true if the basic block `bb` will branch to another block when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_branch(ea)
    is_branch = utils.alias(branch, 'type')

    @utils.multicase()
    @classmethod
    def unconditional(cls):
        '''Return true if the current instruction is an unconditional branch.'''
        return cls.unconditional(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def unconditional(cls, ea):
        '''Return true if the instruction at address `ea` is an unconditional branch.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_unconditional(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def unconditional(cls, bounds):
        '''Return true if the basic block at the given `bounds` will branch unconditionally when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_unconditional(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def unconditional(cls, bb):
        '''Return true if the basic block `bb` will branch unconditionally when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_unconditional(ea)
    is_jmp = jmp = utils.alias(unconditional, 'type')

    @utils.multicase()
    @classmethod
    def conditional(cls):
        '''Return true if the current instruction is a conditional branch.'''
        return cls.conditional(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def conditional(cls, ea):
        '''Return true if the instruction at address `ea` is a conditional branch.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_conditional(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def conditional(cls, bounds):
        '''Return true if the basic block at the given `bounds` will branch conditionally when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_conditional(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def conditional(cls, bb):
        '''Return true if the basic block `bb` will branch conditionally when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_conditional(ea)
    jcc = is_jcc = is_jxx = utils.alias(conditional, 'type')

    @utils.multicase()
    @classmethod
    def unconditionali(cls):
        '''Return true if the current instruction is an unconditional (indirect) branch.'''
        return cls.unconditionali(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def unconditionali(cls, ea):
        '''Return true if the instruction at address `ea` is an unconditional (indirect) branch.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_indirect(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def unconditionali(cls, bounds):
        '''Return true if the basic block at the given `bounds` will branch unconditionally (indirect) when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_indirect(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def unconditionali(cls, bb):
        '''Return true if the basic block `bb` will branch unconditionally (indirect) when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_indirect(ea)
    jmpi = is_jmpi = utils.alias(unconditionali, 'type')

    @utils.multicase()
    @classmethod
    def enter(cls):
        '''Return true if the current instruction will enter a function (direct) when executed.'''
        return cls.enter(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def enter(cls, ea):
        '''Return true if the instruction at address `ea` will enter a function (direct) when executed.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_call(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def enter(cls, bounds):
        '''Return true if the basic block at the given `bounds` will enter a function (direct) when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_call(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def enter(cls, bb):
        '''Return true if the basic block `bb` will enter a function (direct) when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_call(ea)
    is_call = call = link = is_link = utils.alias(enter, 'type')

    @utils.multicase()
    @classmethod
    def enteri(cls):
        '''Return true if the current instruction will enter a function (indirect) when executed.'''
        return cls.enteri(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def enteri(cls, ea):
        '''Return true if the instruction at address `ea` will enter a function (indirect) when executed.'''
        ea = interface.address.inside(ea)
        return interface.instruction.is_calli(ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def enteri(cls, bounds):
        '''Return true if the basic block at the given `bounds` will enter a function (indirect) when executed.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)
        return interface.instruction.is_calli(ea)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def enteri(cls, bb):
        '''Return true if the basic block `bb` will enter a function (indirect) when executed.'''
        left, right = interface.range.bounds(bb)
        ea = idaapi.get_item_head(right - 1)
        if not any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch]):
            ea = next((ea for ea in interface.address.items(left, right) if any(F(ea) for F in [interface.instruction.is_call, interface.instruction.is_sentinel, interface.instruction.is_branch])), ea)
        return interface.instruction.is_calli(ea)
    is_calli = calli = linki = is_linki = utils.alias(enteri, 'type')

t = type    # XXX: ns alias

feature = utils.alias(type.feature, 'type')
is_return = returns = utils.alias(type.leave, 'type')
is_shift = utils.alias(type.shift, 'type')
is_branch = utils.alias(type.branch, 'type')
is_jmp = utils.alias(type.unconditional, 'type')
is_jxx = is_jcc = utils.alias(type.conditional, 'type')
is_jmpi = utils.alias(type.unconditionali, 'type')
is_call = utils.alias(type.enter, 'type')
is_calli = utils.alias(type.enteri, 'type')
