"""
Instructions

generic tools for working in the context of an instruction.
"""

import six
from six.moves import builtins

import functools, operator, itertools, types
import logging, collections

import database, function
import structure, enumeration
import ui, internal
from internal import utils, interface

import idaapi

## register lookups and types
class register_t(interface.symbol_t):
    '''A register type.'''

    @property
    def symbols(self):
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
    def dtype(self):
        '''Returns the IDA dtype of the register.'''
        return self.__dtype__
    @property
    def size(self):
        '''Returns the size of the register.'''
        return self.__size__
    @property
    def position(self):
        '''Returns the binary offset into the full register where it begins at.'''
        return self.__position__

    def __str__(self):
        return self.architecture.prefix + self.name

    def __repr__(self):
        try:
            dt, = [name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi, name) == self.dtype]
        except ValueError:
            dt = 'unknown'
        cls = self.__class__
        return "<{:s}({:d},{:s}) {!r} {:d}:{:+d}>".format('.'.join((__name__,'register',cls.__name__)), self.id, dt, self.name, self.position, self.size)
        #return "{:s} {:s} {:d}:{:+d}".format(self.__class__, dt, self.position, self.size, dt)

    def __eq__(self, other):
        if isinstance(other, basestring):
            return self.name.lower() == other.lower()
        elif isinstance(other, register_t):
            return self is other
        elif hasattr(other, '__eq__'):  # XXX: i fucking hate python
            return other.__eq__(self)
        return other is self

    def __ne__(self, other):
        return not (self == other)

    def __contains__(self, other):
        '''Returns True if the ``other`` register is a sub-register of ``self``.'''
        return other in six.viewvalues(self.__children__)

    def subsetQ(self, other):
        '''Returns True if the ``other`` register is a part of ``self``.'''
        def collect(node):
            res = set([node])
            [res.update(collect(n)) for n in six.itervalues(node.__children__)]
            return res
        return other in self.alias or other in collect(self)

    def supersetQ(self, other):
        '''Returns `True` if the ``other`` register is a superset of ``self``.'''
        res, pos = set(), self
        while pos is not None:
            res.add(pos)
            pos = pos.__parent__
        return other in self.alias or other in res

    def relatedQ(self, other):
        '''Returns `True` if the ``other`` register affects ``self`` when it's modified'''
        return self.supersetQ(other) or self.subsetQ(other)

class map_t(object):
    __slots__ = ('__state__',)
    def __init__(self):
        object.__setattr__(self, '__state__', {})

    def __getattr__(self, name):
        if name.startswith('__'):
            return getattr(self.__class__, name)
        res = self.__state__
        return res[name]

    def __setattr__(self, name, register):
        res = self.__state__
        return res.__setitem__(name, register)

    def __contains__(self, name):
        return name in self.__state__

    def __repr__(self):
        return "{:s} {!r}".format(self.__class__, self.__state__)

class architecture_t(object):
    """Base class to represent how IDA maps the registers and types returned from an operand to a register that's uniquely identifiable by the user.

    This is necessary as for some architectures IDA will not include all the register names and thus will use the same register-index to represent two registers that are of different types. As an example, on the Intel processor module the `al` and `ax` regs are returned in the operand as an index to the "ax" string. Similarly on the 64-bit version of the processor module, all of the registers `ax`, `eax`, and `rax` have the same index.
    """
    __slots__ = ('__register__', '__cache__',)
    r = register = property(fget=lambda s: s.__register__)

    def __init__(self, **cache):
        """Instantiate an `architecture_t` object which represents the registers available to an architecture.
        If ``cache`` is defined, then use the specified dictionary to map an ida (register-name, register-dtype) to a string containing the commonly recognized register-name.
        """
        self.__register__, self.__cache__ = map_t(), cache.get('cache', {})

    def new(self, name, bits, idaname=None, **kwargs):
        '''Add a register to the architecture's cache.'''

        # older
        if idaapi.__version__ < 7.0:
            dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
        # newer
        else:
            dtype_by_size = idaapi.get_dtyp_by_size

        dtype = next((kwargs[n] for n in ('dtyp', 'dtype', 'type') if n in kwargs), idaapi.dt_bitfield if bits == 1 else dtype_by_size(bits // 8))
        #dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        namespace = dict(register_t.__dict__)
        namespace.update({'__name__':name, '__parent__':None, '__children__':{}, '__dtype__':dtype, '__position__':0, '__size__':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', set())
        namespace['architecture'] = self
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name, dtype] = name
        return res

    def child(self, parent, name, position, bits, idaname=None, **kwargs):
        '''Add a child-register to the architecture's cache.'''

        # older
        if idaapi.__version__ < 7.0:
            dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
        # newer
        else:
            dtype_by_size = idaapi.get_dtyp_by_size

        dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        namespace = dict(register_t.__dict__)
        namespace.update({'__name__':name, '__parent__':parent, '__children__':{}, '__dtype__':dtyp, '__position__':position, '__size__':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', set())
        namespace['architecture'] = self
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name, dtyp] = name
        parent.__children__[position] = res
        return res

    def by_index(self, index):
        """Lookup a register according to its ``index``.
        Size is the default that's set according to the IDA version.
        """
        res = idaapi.ph.regnames[index]
        return self.by_name(res)
    byIndex = utils.alias(by_index, 'architecture')
    def by_indextype(self, index, dtyp):
        """Lookup a register according to its ``index`` and ``dtyp``.
        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res, dtyp]
        return getattr(self.__register__, name)
    byIndexType = utils.alias(by_indextype, 'architecture')
    def by_name(self, name):
        '''Lookup a register according to its ``name``.'''
        if any(name.startswith(prefix) for prefix in ('%', '$')):        # at&t, mips
            return getattr(self.__register__, name[1:].lower())
        if name.lower() in self.__register__:
            return getattr(self.__register__, name.lower())
        return getattr(self.__register__, name)
    byName = utils.alias(by_name, 'architecture')
    def by_indexsize(self, index, size):
        '''Lookup a register according to its ``index`` and ``size``.'''
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtyp_by_size
        dtyp = dtype_by_size(size)
        return self.by_indextype(index, dtyp)
    def promote(self, register, size=None):
        '''Promote the specified ``register`` to its next larger ``size``.'''
        parent = utils.fcompose(operator.attrgetter('__parent__'), utils.box, functools.partial(filter, None), iter, next)
        try:
            if size is None:
                return parent(register)
            return register if register.size == size else self.promote(parent(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise LookupError("{:s}.promote({:s}{:s}) : Unable to find register to promote to.".format('.'.join((__name__,cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))
    def demote(self, register, size=None):
        '''Demote the specified ``register`` to its next smaller ``size``.'''
        childitems = utils.fcompose(operator.attrgetter('__children__'), operator.methodcaller('iteritems'))
        firstchild = utils.fcompose(childitems, functools.partial(sorted, key=operator.itemgetter(0)), iter, next, operator.itemgetter(1))
        try:
            if size is None:
                return firstchild(register)
            return register if register.size == size else self.demote(firstchild(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise LookupError("{:s}.demote({:s}{:s}) : Unable to find register to demote to.".format('.'.join((__name__,cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))

## operand types
class __optype__(object):
    '''Registration/Lookup table for all the different operand type decoders in an architecture.'''
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
    def decode(cls, ea, op, processor=None):
        res = cls.lookup(op.type, processor=processor)
        return res(ea, op)

    @classmethod
    def type(cls, op, processor=None):
        res = cls.lookup(op.type, processor=processor)
        return res.__name__

    @classmethod
    def size(cls, op, processor=None):
        return idaapi.get_dtyp_size(op.dtyp)

## general functions
@utils.multicase()
def at():
    '''Returns the `idaapi.insn_t` instance at the current address.'''
    return at(ui.current.address())
@utils.multicase(ea=six.integer_types)
def at(ea):
    '''Returns the `idaapi.insn_t` instance at the address ``ea``.'''
    ea = interface.address.inside(ea)
    if not database.is_code(ea):
        raise TypeError("{:s}.at({:#x}) : Unable to decode a non-instruction at specified address.".format(__name__, ea))
    length = idaapi.decode_insn(ea)
    if idaapi.__version__ < 7.0:
        return idaapi.cmd.copy()

    tmp = idaapi.insn_t()
    tmp.assign(idaapi.cmd)
    return tmp
get = utils.alias(at)

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
    if database.is_code(ea):
        return at(ea).get_canon_feature()
    return None

@utils.multicase()
def mnemonic():
    '''Returns the mnemonic of an instruction at the current address.'''
    return mnemonic(ui.current.address())
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
    ea = interface.address.inside(ea)
    res = operand(ea, None)
    return len(res)

@utils.multicase()
def ops_repr():
    '''Returns a tuple of the `op_repr` of all the operands for the instruction at the current address.'''
    return ops_repr(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_repr(ea):
    '''Returns a tuple of the `op_repr` of all the operands for the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_repr, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))

@utils.multicase()
def ops_value():
    '''Returns a tuple of all the operands for the instruction at the current address.'''
    return ops_value(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_value(ea):
    '''Returns a tuple of all the operands for the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_value, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))
ops = utils.alias(ops_value)

@utils.multicase()
def ops_size():
    '''Returns a tuple with all the sizes of each operand for the instruction at the current address.'''
    return ops_size(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_size(ea):
    '''Returns a tuple with all the sizes of each operand for the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    f = utils.fcompose(functools.partial(operand, ea), operator.attrgetter('dtyp'), idaapi.get_dtyp_size, int)
    return tuple(map(f, six.moves.range(ops_count(ea))))

@utils.multicase()
def ops_type():
    '''Returns a tuple of the types for all the operands in the instruction at the current address.'''
    return ops_type(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_type(ea):
    '''Returns a tuple of the types for all the operands in the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    f = functools.partial(op_type, ea)
    return tuple(map(f, six.moves.range(ops_count(ea))))
opts = utils.alias(ops_type)

@utils.multicase()
def ops_state():
    '''Returns a tuple of the state `(r, w, rw)` of all the operands for the instruction at the current address.'''
    return ops_state(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_state(ea):
    '''Returns a tuple of the state `(r, w, rw)` of all the operands for the instruction at address ``ea``.'''
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
def ops_read(ea):
    '''Returns the indices of any operands that are being read from by the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    return tuple(i for i, s in enumerate(ops_state(ea)) if 'r' in s)

@utils.multicase()
def ops_write():
    '''Returns the indices of the operands that are being written to by the instruction at the current address.'''
    return ops_write(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_write(ea):
    '''Returns the indices of the operands that are being written to by the instruction at the address ``ea``.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, state in enumerate(ops_state(ea)) if 'w' in state)

@utils.multicase()
def ops_constant():
    '''Return the indices of any operands in the current instruction that are constants.'''
    return ops_constant(ui.current.address())
@utils.multicase(ea=six.integer_types)
def ops_constant(ea):
    '''Return the indices of any operands in the instruction at ``ea`` that are constants.'''
    ea = interface.address.inside(ea)
    return tuple(opnum for opnum, value in enumerate(ops_value(ea)) if isinstance(value, six.integer_types))
ops_const = utils.alias(ops_constant)

@utils.multicase(reg=(basestring, register_t))
def ops_register(reg, *regs, **modifiers):
    """Yields the index of each operand in the instruction at the current address which touches one of the registers identified by ``regs``.
    If the keyword ``write`` is True, then only return the result if it's writing to the register.
    """
    return ops_register(ui.current.address(), reg, *regs, **modifiers)
@utils.multicase(reg=(basestring, register_t))
def ops_register(ea, reg, *regs, **modifiers):
    """Yields the index of each operand in the instruction at address ``ea`` that touches one of the registers identified by ``regs``.
    If the keyword ``write`` is True, then only return the result if it's writing to the register.
    """
    ea = interface.address.inside(ea)
    iterops = interface.regmatch.modifier(**modifiers)
    uses = interface.regmatch.use( (reg,) + regs )
    return tuple(filter(functools.partial(uses, ea), iterops(ea)))
ops_reg = ops_regs = utils.alias(ops_register)

## functions vs a specific operand of an insn
@utils.multicase()
def operand():
    '''Returns all the `idaapi.op_t` instances of the instruction at the current address.'''
    return operand(ui.current.address(), None)
@utils.multicase(none=types.NoneType)
def operand(none):
    """Returns all the `idaapi.op_t` instances of the instruction at the current address.
    (Not really intended to be used. Please use the zero-argument version.))
    """
    return operand(ui.current.address(), None)
@utils.multicase(n=six.integer_types)
def operand(n):
    '''Returns the ``n``th operand of the instruction at the current address as an `idaapi.op_t`.'''
    return operand(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def operand(ea, none):
    '''Returns all of the operands of the instruction at the address ``ea`` as a tuple of `idaapi.op_t` instances.'''
    insn = at(ea)
    res = itertools.takewhile(utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), insn.Operands)
    if idaapi.__version__ < 7.0:
        return tuple(op.copy() for op in res)
    res = ((idaapi.op_t(), op) for op in res)
    return tuple([n.assign(op), n][1] for n, op in res)

@utils.multicase(ea=six.integer_types, n=six.integer_types)
def operand(ea, n):
    '''Returns the ``n``th operand of the instruction at the address ``ea`` as an `idaapi.op_t`.'''
    insn = at(ea)
    if idaapi.__version__ < 7.0:
        return insn.Operands[n].copy()
    res = idaapi.op_t()
    res.assign(insn.Operands[n])
    return res

@utils.multicase(n=six.integer_types)
def op_repr(n):
    '''Returns the ``n``th operand of the instruction at the current address in a printable form.'''
    return op_repr(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_repr(ea, n):
    '''Returns the ``n``th operand of the instruction at the address ``ea`` in a printable form.'''
    insn = at(ea)
    oppr = idaapi.ua_outop2 if idaapi.__version__ < 7.0 else idaapi.print_operand
    outop = utils.fcompose(idaapi.ua_outop2, idaapi.tag_remove) if idaapi.__version__ < 7.0 else utils.fcompose(idaapi.print_operand, idaapi.tag_remove)
    try:
        res = outop(insn.ea, n) or "{:s}".format(op_value(insn.ea, n))
    except ValueError, e:
        logging.warn("{:s}({:#x}, {:d}) : Unable to strip tags from operand. Returning the result from {:s} instead. : {!r}".format('.'.join((__name__,'op_repr')), ea, n, '.'.join((__name__,'op_value')), oppr(insn.ea, n)))
        return "{:s}".format(op_value(insn.ea, n))
    return res

@utils.multicase(n=six.integer_types)
def op_state(n):
    '''Returns the state `(r, w, rw)` for the ``n``th operand of the instruction at the current address.'''
    return op_state(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_state(ea, n):
    '''Returns the state `(r, w, rw)` for the ``n``th operand of the instruction at address ``ea``.'''
    f = feature(ea)
    r, w = f&ops_state.read[n], f&ops_state.write[n]
    return (r and 'r' or '') + (w and 'w' or '')

@utils.multicase(n=six.integer_types)
def op_size(n):
    '''Returns the size for the ``n``th operand of the current instruction.'''
    return op_size(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_size(ea, n):
    '''Returns the size for the ``n``th operand of the instruction at the address ``ea``.'''
    res = operand(ea, n)
    return 0 if res.type == idaapi.o_void else idaapi.get_dtyp_size(res.dtyp)
@utils.multicase(n=six.integer_types)
def op_bits(n):
    '''Returns the size (in bits) for the ``n``th operand of the current instruction.'''
    return 8 * op_size(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_bits(ea, n):
    '''Returns the size (in bits) for the ``n``th operand of the instruction at the address ``ea``.'''
    return 8 * op_size(ea, n)

@utils.multicase(n=six.integer_types)
def op_type(n):
    '''Returns the type of the ``n``th operand as a string for the instruction at the current address.'''
    return op_type(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_type(ea, n):
    """Returns the type of the ``n``th operand as a string for the instruction at the address ``ea``.
    Some of the types returned are: imm, reg, phrase, or addr
    """
    res = operand(ea, n)
    return __optype__.type(res)
opt = utils.alias(op_type)

@utils.multicase(n=six.integer_types)
def op_decode(n):
    '''Returns the value of the ``n``th operand for the current instruction in byte form if possible.'''
    raise NotImplementedError
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_decode(ea, n):
    '''Returns the value of the ``n``th operand for the instruction at address ``ea`` in byte form if possible.'''
    raise NotImplementedError

@utils.multicase(n=six.integer_types)
def op_value(n):
    '''Returns the value for the ``n``th operand of the current instruction.'''
    return op_value(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_value(ea, n):
    """Returns the value for the ``n``th operand of the instruction at the address ``ea``.

    The formats are based on the operand type as emitted by the `ins.op_type` function:
    imm -> integer
    reg -> register name
    addr -> address
    phrase -> (offset, base-register name, index-register name, scale)
    """
    res = operand(ea, n)
    return __optype__.decode(ea, res)
op = op_decode = utils.alias(op_value)

### tag:intel
## FIXME: deprecate this, and somehow associate the segment register with the operand for the intel arch
@utils.multicase(n=six.integer_types)
def op_segment(n):
    '''Returns the segment register used by the ``n``th operand of the instruction at the current address.'''
    return op_segment(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_segment(ea, n):
    '''Returns the segment register used by the ``n``th operand of the instruction at the address ``ea``.'''
    op = operand(ea, n)
    segment  = (op.specval & 0xffff0000) >> 16
    selector = (op.specval & 0x0000ffff) >> 0
    if segment:
        global architecture
        return architecture.by_index(segment)
    #raise NotImplementedError("{:s}.op_segment({:#x}, {:d}) : Unable to determine the segment register for specified operand number. : {!r}".format(__name__, ea, n, segment))
    return None

@utils.multicase(opnum=six.integer_types)
def op_structure(opnum):
    '''Return the structures that operand ``opnum`` at the current instruction points to.'''
    return op_structure(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_structure(ea, opnum):
    '''Return the structures that operand ``opnum`` at instruction ``ea`` points to.'''
    ti, fl, op = idaapi.opinfo_t(), database.type.flags(ea), operand(ea, opnum)
    if all(fl & ff != ff for ff in {idaapi.FF_STRUCT, idaapi.FF_0STRO, idaapi.FF_1STRO}):
        raise TypeError("{:s}.op_structure({:#x}, {:#x}) : Operand {:d} does not contain a structure.".format(__name__, ea, opnum, opnum))

    # pathvar = idaapi.tid_array(length)
    # idaapi.get_stroff_path(ea, opnum, pathvar.cast(), delta)
    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if not res:
        raise TypeError("{:s}.op_structure({:#x}, {:#x}) : Operand {:d} does not contain a structure.".format(__name__, ea, opnum, opnum))

    # get the path and the delta
    delta, path = res.path.delta, [res.path.ids[idx] for idx in six.moves.range(res.path.len)]
    value = op.addr if op.type in {idaapi.o_displ, idaapi.o_phrase} else op.value

    # if it's a single path, then convert it to a multiple entry path
    if len(path) == 1:
        # get the member offset of the operand
        st = structure.by(path[0])
        m = st.by(value)
        path = [st.id, m.id]

    # collect all the path members
    moff, st = 0, structure.by(path.pop(0))
    res = [st]
    for pid in path:
        st = st.by_identifier(pid)
        res.append(st)
        moff, st = moff + st.offset, st.type

    ofs = delta - moff + value
    return tuple(res + [ofs]) if ofs > 0 else tuple(res)
@utils.multicase(opnum=six.integer_types, structure=(structure.structure_t, structure.member_t))
def op_structure(opnum, structure, **delta):
    """Apply the specified ``structure`` to the instruction operand ``opnum`` at the current address.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return op_structure(ui.current.address(), opnum, [structure], **delta)
@utils.multicase(opnum=six.integer_types, id=six.integer_types)
def op_structure(opnum, id, **delta):
    """Apply the structure identified by ``id`` to the instruction operand ``opnum`` at the current address.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return op_structure(ui.current.address(), opnum, id, **delta)
@utils.multicase(opnum=six.integer_types, path=(types.TupleType, types.ListType))
def op_structure(opnum, path, **delta):
    """Apply the structure members in ``path`` to the instruction operand ``opnum`` at the current address.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return op_structure(ui.current.address(), opnum, path, **delta)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, structure=(structure.structure_t, structure.member_t))
def op_structure(ea, opnum, structure, **delta):
    """Apply the specified ``structure`` to the instruction operand ``opnum`` at the address ``ea``.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return op_structure(ea, opnum, structure.id, **delta)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=six.integer_types)
def op_structure(ea, opnum, id, **delta):
    """Apply the structure identified by ``id`` to the instruction operand ``opnum`` at the address ``ea``.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise TypeError("{:s}.op_structure({:#x}, {:#x}, {:#x}, delta={:d}) : Item type at requested address is not code.".format(__name__, ea, opnum, id, delta.get('delta', 0)))
    # FIXME: allow one to specify more than one field for tid_array

    sptr, name = idaapi.get_struc(id), idaapi.get_member_fullname(id)
    if sptr is not None:
        sid, mid = sptr.id, 0
    elif name is not None:
        fn = idaapi.get_member_fullname(id)
        sptr = idaapi.get_member_struc(name)
        sid, mid = sptr.id, id
    else:
        raise LookupError("{:s}.op_structure({:#x}, {:#x}, {:#x}, delta={:d}) : Unable to locate the structure member for the specified id.".format(__name__, ea, opnum, id, delta.get('delta', 0)))

    st = structure.by(sid)
    m = st.by_identifier(mid)
    return op_structure(ea, opnum, [st, m], **delta)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, path=(types.TupleType, types.ListType))
def op_structure(ea, opnum, path, **delta):
    """Apply the structure members in ``path`` to the instruction operand ``opnum`` at the address ``ea``.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise TypeError("{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : Item type at requested address is not code.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # validate the path
    if len(path) == 0:
        raise ValueError("{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : No structure members were specified.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    if any(not isinstance(m, (structure.structure_t, structure.member_t, basestring)+six.integer_types) for m in path):
        raise ValueError("{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : A member of an invalid type was specified.".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # ensure the path begins with a structure.structure_t
    if isinstance(path[0], structure.member_t):
        path[0:0] = [path[0].owner]

    # crop elements to valid ones in case the delta is specified at the end
    res = list(itertools.takewhile(lambda t: not isinstance(t, six.integer_types), path))
    if len(res) < len(path):
        res.append(path[len(res)])

    if len(res) < len(path):
        logging.warn("{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : Cropping path down to {:d} elements due to invalid types being used to specify the structure path.".format(__name__, ea, opnum, path, delta.get('delta', 0), len(path) - len(res) + 1))
    path = res[:]

    # if the delta is in the path, move it into the delta kwarg
    if isinstance(path[-1], six.integer_types):
        delta['delta'] = delta.get('delta', 0) + path.pop(-1)

    # figure out the structure that this all starts with
    sptr, path = path[0].ptr, list(path)

    # collect each member resolving them to an id
    moff, tids = 0, []
    for item in path[1:]:
        if isinstance(item, basestring):
            m = idaapi.get_member_by_name(sptr, item)
        elif isinstance(item, structure.member_t):
            m = item.ptr
        else:
            raise NotImplementedError
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
        logging.warn("{:s}.op_structure({:#x}, {:#x}, {!r}, delta={:d}) : There was an error trying to determine the path for the list of members (not all members were pointing to structures).".format(__name__, ea, opnum, path, delta.get('delta', 0)))

    # build the list of member ids and prefix it with a structure id
    length = len(tids) + 1
    tid = idaapi.tid_array(length)
    tid[0] = sptr.id
    for i, id in enumerate(tids):
        tid[i + 1] = id

    # figure out the real position (ida handles this actually)
    # value = operand(ea, opnum).value if op_type(ea, opnum) == 'immediate' else operand(ea, opnum).addr
    ofs = moff + delta.get('delta', 0)

    # now we can finally apply the path to the specified operand
    ok = idaapi.op_stroff(ea, opnum, tid.cast(), length, ofs)
    #ok = idaapi.set_stroff_path(ea, opnum, tid.cast(), length, moff - ofs)

    return ok
op_struct = utils.alias(op_structure)

@utils.multicase(opnum=six.integer_types)
def op_enumeration(opnum):
    return op_enumeration(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_enumeration(ea, opnum):
    '''Return the id of the enumeration used by operand ``opnum`` of the instruction at ``ea``.'''
    ti, fl = idaapi.opinfo_t(), database.type.flags(ea)
    if all(fl & n == 0 for n in (idaapi.FF_0ENUM, idaapi.FF_1ENUM)):
        raise TypeError("{:s}.op_enumeration({:#x}, {:#x}) : Operand {:d} does not contain an enumeration.".format(__name__, ea, opnum, opnum))

    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if res is None:
        raise TypeError("{:s}.op_enumeration({:#x}, {:#x}) : Unable to get operand info for operand {:d}.".format(__name__, ea, opnum, opnum))

    return enumeration.by(res.ec.tid), res.ec.serial if res.ec.serial > 0 else enumeration.by(res.ec.tid)
@utils.multicase(opnum=six.integer_types, name=basestring)
def op_enumeration(opnum, name):
    '''Apply the enumeration ``name`` to operand ``opnum`` of the current instruction.'''
    return op_enumeration(ui.current.address(), opnum, enumeration.by(name))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, name=basestring)
def op_enumeration(ea, opnum, name):
    '''Apply the enumeration ``name`` to operand ``opnum`` of the instruction at ``ea``.'''
    return op_enumeration(ea, opnum, enumeration.by(name))
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=six.integer_types+(types.TupleType,))
def op_enumeration(ea, opnum, id):
    '''Apply the enumeration ``id`` to operand ``opnum`` of the instruction at ``ea``.'''
    return idaapi.op_enum(ea, opnum, *id) if isinstance(id, types.TupleType) else idaapi.op_enum(ea, opnum, id, 0)
op_enum = utils.alias(op_structure)

@utils.multicase(opnum=six.integer_types)
def op_string(opnum):
    return op_string(ui.current.address(), opnum)
@utils.multicase(ea=six.integer_types, opnum=six.integer_types)
def op_string(ea, opnum):
    '''Return the string type (STRTYPE_) of the string used by operand ``opnum`` of the instruction at ``ea``.'''
    ti, fl = idaapi.opinfo_t(), database.type.flags(ea)
    if fl & idaapi.STRLIT == 0:
        raise TypeError("{:s}.op_string({:#x}, {:#x}) : Operand {:d} does not contain an enumeration.".format(__name__, ea, opnum, opnum))

    res = idaapi.get_opinfo(ea, opnum, fl, ti)
    if res is None:
        raise TypeError("{:s}.op_string({:#x}, {:#x}) : Unable to get operand info for operand {:d}.".format(__name__, ea, opnum, opnum))

    return res.strtype
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, strtype=six.integer_types)
def op_string(ea, opnum, strtype):
    '''Set the string type used by operand ``opnum`` of the instruction at ``ea`` to ``strtype``.'''
    res, fl = idaapi.opinfo_t(), database.type.flags(ea)

    fl |= idaapi.FF_STRLIT
    res.strtype = strtype

    ok = idaapi.set_opinfo(ea, opnum, fl, res)

    # FIXME: verify that set_opinfo was actually applied by checking via get_opinfo
    return ok

## flags
# idaapi.set_typeinfo(ea, opnum, flags, ti)
# idaapi.get_typeinfo(ea, opnum, &flags, &buf)

# idaapi.set_op_type(ea, type, opnum)
# idaapi.typeflag(ea, &oldflag, type, opnum)

## lvars
# def op_type(ea, n)
#    '''Apply the specified type to a stack variable'''
#    py_op = operand(ea,n)
#    py_v = py_op.addr
#    py_t = idc.ParseType("type string", flags)[1]
#    py_name = "stack variable name"
#    idaapi.apply_type_to_stkarg(py_op, py_v, py_t, py_name)

@utils.multicase(n=six.integer_types)
def op_refs(n):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the ``n``th operand of the current instruction.'''
    return op_refs(ui.current.address(), n)
@utils.multicase(ea=six.integer_types, n=six.integer_types)
def op_refs(ea, n):
    '''Returns the `(address, opnum, type)` of all the instructions that reference the ``n``th operand of the instruction at ``ea``.'''
    fn = idaapi.get_func(ea)
    if fn is None:
        raise LookupError("{:s}.op_refs({:#x}, {:d}) : Unable to locate function for address. : {:#x}".format(__name__, ea, n, ea))
    inst = at(ea)

    # sanity: returns whether the operand has a local or global xref
    F = database.type.flags(inst.ea)
    ok = idaapi.op_adds_xrefs(F, n) ## FIXME: on tag:arm, this returns T for some operands

    # FIXME: gots to be a better way to determine operand representation
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(inst.ea, n, F, ti)

    # FIXME: this is incorrect on ARM for the 2nd op in `ADD R7, SP, #0x430+lv_dest_41c`
    # stkvar
    if ok and res is None:
        stkofs_ = idaapi.calc_stkvar_struc_offset(fn, inst.ea if idaapi.__version__ < 7.0 else inst, n)
        # check that the stkofs_ from get_stkvar and calc_stkvar are the same
        op = operand(inst.ea, n)

        res = interface.sval_t(op.addr).value
        if idaapi.__version__ < 7.0:
            member, stkofs = idaapi.get_stkvar(op, res)
        else:
            member, stkofs = idaapi.get_stkvar(inst, op, res)

        if stkofs != stkofs_:
            logging.warn("{:s}.op_refs({:#x}, {:d}) : Stack offsets for instruction operand do not match. : {:#x} != {:#x}".format(__name__, inst.ea, n, stkofs, stkofs_))

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
            ok = idaapi.get_stroff_path(inst.ea, n, pathvar.cast(), delta.cast())
        else:
            ok = idaapi.get_stroff_path(pathvar.cast(), delta.cast(), inst.ea, n)
        if not ok:
            raise LookupError("{:s}.op_refs({:#x}, {:d}) : Unable to get structure id for operand.".format(__name__, inst.ea, n))

        # get the structure offset and then figure its member
        addr = operator.attrgetter('value' if idaapi.__version__ < 7.0 else 'addr')     # FIXME: this will be incorrect for an offsetted struct
        memofs = addr(operand(inst.ea, n))

        st = idaapi.get_struc(pathvar[0])
        if st is None:
            raise LookupError("{:s}.op_refs({:#x}, {:d}) : Unable to get structure for id. : {:#x}".format(__name__, inst.ea, n, pathvar[0]))

        mem = idaapi.get_member(st, memofs)
        if mem is None:
            raise LookupError("{:s}.op_refs({:#x}, {:d}) : Unable to find member for offset in structure {:#x}. : {:#x}".format(__name__, inst.ea, n, st.id, memofs))

        # extract the references
        x = idaapi.xrefblk_t()

        if not x.first_to(mem.id, 0):
            logging.warn("{:s}.op_refs({:#x}, {:d}) : No references found to struct member {:s}.".format(__name__, inst.ea, n, mem.fullname))

        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # now figure out the operands if there are any
        res = []
        for ea, _, t in refs:
            ops = ((idx, internal.netnode.sup.get(ea, 0xf+idx)) for idx in six.moves.range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf+idx) is not None)
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
        raise NotImplementedError

    # FIXME: is this supposed to execute if ok == T? or not?
    # global
    else:
        # anything that's just a reference is a single-byte supval at index 0x9+opnum
        # 9 -- '\x02' -- offset to segment 2
        gid = operand(inst.ea, n).value if operand(inst.ea, n).type in {idaapi.o_imm} else operand(inst.ea, n).addr
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
@utils.multicase()
def is_return(): return is_return(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_return(ea):
    '''Returns `True` if the instruction at ``ea`` is a return-type instruction.'''
    ea = interface.address.inside(ea)
    returnQ = lambda ea: feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP

    # Older versions of IDA required idaapi.cmd to be populated for is_ret_insn to work.
    if hasattr(idaapi, 'is_ret_insn'):
        idaapi.decode_insn(ea)
        returnQ = idaapi.is_ret_insn

    return database.is_code(ea) and returnQ(ea)
isReturn = returnQ = retQ = utils.alias(is_return)

@utils.multicase()
def is_shift(): return is_shift(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_shift(ea):
    '''Returns `True` if the instruction at ``ea`` is a bit-shifting instruction.'''
    ea = interface.address.inside(ea)
    return database.is_code(ea) and feature(ea) & idaapi.CF_SHFT == idaapi.CF_SHFT
isShift = shiftQ = utils.alias(is_shift)

@utils.multicase()
def is_branch(): return is_branch(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_branch(ea):
    '''Returns `True` if the instruction at ``ea`` is a branch instruction.'''
    ea = interface.address.inside(ea)
    return database.is_code(ea) and is_jmp(ea) or is_jxx(ea) or is_jmpi(ea)
isBranch = branchQ = utils.alias(is_branch)

@utils.multicase()
def is_jmp(): return is_jmp(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jmp(ea):
    '''Returns `True` if the instruction at ``ea`` is a jmp (both immediate and indirect) instruction.'''
    ea = interface.address.inside(ea)

    F, X = feature(ea), interface.xiterate(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)
    return database.is_code(ea) and (F & idaapi.CF_CALL != idaapi.CF_CALL) and (F & idaapi.CF_STOP == idaapi.CF_STOP) and len(list(X)) == 1 and not is_return(ea)
isJmp = JmpQ = jmpQ = utils.alias(is_jmp)

@utils.multicase()
def is_jxx(): return is_jxx(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jxx(ea):
    '''Returns `True` if the instruction at ``ea`` is a conditional branch.'''
    ea = interface.address.inside(ea)

    F, X = feature(ea), interface.xiterate(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)
    return database.is_code(ea) and all((F&x != x) for x in {idaapi.CF_CALL, idaapi.CF_STOP}) and len(list(X)) > 1
isJxx = JxxQ = jxxQ = utils.alias(is_jxx)

@utils.multicase()
def is_jmpi(): return is_jmpi(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_jmpi(ea):
    '''Returns `True` if the instruction at ``ea`` is an indirect branch.'''
    ea = interface.address.inside(ea)
    F = feature(ea)
    return database.is_code(ea) and (F & idaapi.CF_CALL != idaapi.CF_CALL) and (F & idaapi.CF_JUMP == idaapi.CF_JUMP)
isJmpi = JmpiQ = jmpiQ = utils.alias(is_jmpi)

@utils.multicase()
def is_call(): return is_call(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_call(ea):
    '''Returns `True` if the instruction at ``ea`` is a call instruction.'''
    ea = interface.address.inside(ea)
    if hasattr(idaapi, 'is_call_insn'):
        idaapi.decode_insn(ea)
        return idaapi.is_call_insn(ea)

    F = feature(ea)
    return database.is_code(ea) and (feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL)
isCall = callQ = utils.alias(is_call)

@utils.multicase()
def is_calli(): return is_calli(ui.current.address())
@utils.multicase(ea=six.integer_types)
def is_calli(ea):
    '''Returns `True` if the instruction at ``ea`` is an indirect call instruction.'''
    ea = interface.address.inside(ea)
    F = feature(ea)
    return is_call(ea) and all(F&x == x for x in {idaapi.CF_CALL, idaapi.CF_JUMP})

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

## operand type registration
## XXX: This namespace is deleted after each method has been assigned to their lookup table
class operand_types:
    """Namespace containing all of the operand type handlers.
    """
    @__optype__.define(idaapi.PLFM_386, idaapi.o_void)
    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_void)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_void)
    def void(ea, op):
        '''An `idaapi.o_void` operand...which is nothing.'''
        return ()

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_reg)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_reg)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_reg)
    def register(ea, op):
        '''Return the operand as a `register_t`.'''
        global architecture
        dtype_by_size = utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtyp_by_size
        if op.type in {idaapi.o_reg}:
            res, dt = op.reg, dtype_by_size(database.config.bits()//8)
            return architecture.by_indextype(res, op.dtyp)
        optype = "{:s}({:d})".format('idaapi.o_reg', idaapi.o_reg)
        raise TypeError("{:s}.register(...) : {:s} : Invalid operand type. : {:d}".format('.'.join((__name__, 'operand_types')), s_optype, op.type))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_imm)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_imm)
    def immediate(ea, op):
        '''Return the operand as an integer.'''
        if op.type in {idaapi.o_imm, idaapi.o_phrase}:
            bits = idaapi.get_dtyp_size(op.dtyp) * 8

            # figure out the sign flag
            sf, res = 2 ** (bits - 1), op.value

            # if op.value has its sign inverted, then signify it otherwise just use it
            return -2 ** bits + res if interface.node.alt_opinverted(ea, op.n) else res & (2 ** bits - 1)
        optype = "{:s}({:d})".format('idaapi.o_imm', idaapi.o_imm)
        raise TypeError("{:s}.immediate(...) : {:s} : Invalid operand type. : {:d}".format('.'.join((__name__, 'operand_types')), optype, op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_far)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_near)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_near)
    def memory(ea, op):
        '''Return the `operand.addr` field from an operand.'''
        if op.type in {idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ}:
            seg, sel = (op.specval & 0xffff0000) >> 16, (op.specval & 0x0000ffff) >> 0
            return op.addr
        optype = map(utils.unbox("{:s}({:d})".format), [('idaapi.o_far', idaapi.o_far), ('idaapi.o_near', idaapi.o_near)])
        raise TypeError("{:s}.address(...) : {:s}, {:s} : Invalid operand type. : {:d}".format('.'.join((__name__, 'operand_types')), optype[0], optype[1], op.type))

    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec0)
    def trregister(ea, op):
        '''trreg'''
        raise NotImplementedError
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec1)
    def dbregister(ea, op):
        '''dbreg'''
        raise NotImplementedError
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec2)
    def crregister(ea, op):
        '''crreg'''
        raise NotImplementedError
        return getattr(reg, "cr{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec3)
    def fpregister(ea, op):
        '''fpreg'''
        return getattr(reg, "st{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec4)
    def mmxregister(ea, op):
        '''mmxreg'''
        return getattr(reg, "mmx{:d}".format(op.reg)).id
    @__optype__.define(idaapi.PLFM_386, idaapi.o_idpspec5)
    def xmmregister(ea, op):
        '''xmmreg'''
        return getattr(reg, "xmm{:d}".format(op.reg)).id

    @__optype__.define(idaapi.PLFM_386, idaapi.o_mem)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_displ)
    @__optype__.define(idaapi.PLFM_386, idaapi.o_phrase)
    def phrase(ea, op):
        """Returns an operand as a `(offset, basereg, indexreg, scale)` tuple."""
        F1, F2 = op.specflag1, op.specflag2
        if op.type in {idaapi.o_displ, idaapi.o_phrase}:
            if F1 == 0:
                base = op.reg
                index = None

            elif F1 == 1:
                base = (F2 & 0x07) >> 0
                index = (F2 & 0x38) >> 3

            else:
                optype = map(utils.unbox("{:s}({:d})".format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
                raise TypeError("{:s}.phrase(...) : {:s}, {:s}, {:s} : Unable to determine the operand format for op.type {:d} : {:#x}".format(__name__, optype[0], optype[1], optype[2], op.type, F1))

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
            if F1 == 0:
                base = None
                index = None

            elif F1 == 1:
                base = None
                index = (F2 & 0x38) >> 3

            else:
                optype = map(utils.unbox("{:s}({:d})".format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
                raise TypeError("{:s}.phrase(...) : {:s} : Unable to determine the operand format for op.type {:d} : {:#x}".format(__name__, optype[0], optype[1], optype[2], op.type, F1))
            offset = op.addr

        else:
            optype = map(utils.unbox("{:s}({:d})".format), [('idaapi.o_mem', idaapi.o_mem), ('idaapi.o_displ', idaapi.o_displ), ('idaapi.o_phrase', idaapi.o_phrase)])
            raise TypeError("{:s}.phrase(...) : {:s}, {:s}, {:s} : Invalid operand type. : {:d}".format(__name__, optype[0], optype[1], optype[2], op.type))

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
        return intelop.OffsetBaseIndexScale(*res)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_phrase)
    def phrase(ea, op):
        global architecture
        Rn, Rm = architecture.by_index(op.reg), architecture.by_index(op.specflag1)
        return armop.phrase(Rn, Rm)

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_displ)
    def disp(ea, op):
        '''Convert an arm operand into an `armop.disp` tuple `(register, offset)`.'''
        global architecture
        Rn = architecture.by_index(op.reg)
        return armop.disp(Rn, long(op.addr))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_mem)
    def memory(ea, op):
        '''Convert an arm operand into an `armop.mem` tuple `(address, dereferenced-value)`.'''
        # get the address and the operand size
        addr, size = op.addr, idaapi.get_dtyp_size(op.dtyp)
        maxval = 1<<size*8

        # dereference the address and return its integer.
        res = idaapi.get_many_bytes(addr, size) or ''
        res = reversed(res) if database.config.byteorder() == 'little' else iter(res)
        res = reduce(lambda agg, n: (agg*0x100)|n, six.iterbytes(res), 0)
        sf = bool(res & maxval>>1)

        return armop.mem(long(addr), long(res-maxval) if sf else long(res))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec0)
    def flex(ea, op):
        '''Convert an arm operand into an `arm.flexop` tuple `(register, type, immediate)`.'''
        # tag:arm, this is a register with a shift-op applied
        global architecture
        Rn = architecture.by_index(op.reg)
        shift = 0   # FIXME: find out where the shift-type is stored
        return armop.flex(Rn, int(shift), int(op.value))

    @__optype__.define(idaapi.PLFM_ARM, idaapi.o_idpspec1)
    def list(ea, op):
        '''Convert a bitmask of a registers into an `armop.list`.'''
        # op.specval -- a bitmask specifying which registers are included
        global architecture
        res, n = [], op.specval
        for i in six.moves.range(16):
            if n & 1:
                res.append(architecture.by_index(i))
            n >>= 1
        return armop.list(set(res))

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_displ)
    def phrase(ea, op):
        global architecture
        rt, imm = architecture.by_index(op.reg), op.addr
        return mipsop.phrase(rt, imm)

    @__optype__.define(idaapi.PLFM_MIPS, idaapi.o_idpspec1)
    def coprocessor(ea, op):
        return mipsop.coproc(op.reg)
del(operand_types)

## intel operands
class intelop:
    class SegmentOffset(interface.namedtypedtuple, interface.symbol_t):
        _fields = ('segment', 'offset')
        _types = ((types.NoneType, register_t), six.integer_types)

        @property
        def symbols(self):
            s, _ = self
            if s is not None: yield s
    SO = SegmentOffset

    class SegmentOffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an intel operand `(offset, base, index, scale)`.
        Within the tuple, `base` and `index` are registers.
        """
        _fields = ('segment', 'offset', 'base', 'index', 'scale')
        _types = ((types.NoneType, register_t), six.integer_types, (types.NoneType, register_t), (types.NoneType, register_t), six.integer_types)

        @property
        def symbols(self):
            s, _, b, i, _ = self
            if s is not None: yield s
            if b is not None: yield b
            if i is not None: yield i
    SOBIS = SegmentOffsetBaseIndexScale

    class OffsetBaseIndexScale(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an intel operand `(offset, base, index, scale)`.
        Within the tuple, `base` and `index` are registers.
        """
        _fields = ('offset', 'base', 'index', 'scale')
        _types = (six.integer_types, (types.NoneType, register_t), (types.NoneType, register_t), six.integer_types)

        @property
        def symbols(self):
            _, b, i, _ = self
            if b is not None: yield b
            if i is not None: yield i
    OBIS = OffsetBaseIndexScale

## arm operands
class armop:
    class flex(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an arm flexible-operand `(Rn, shift, n)`.
        A flexible operand is an operation that allows the architecture to apply
        a binary shift or rotation to the value of a register.
        """
        _fields = ('Rn', 'shift', 'n')
        _types = (register_t, six.integer_types, six.integer_types)

        register = property(fget=operator.itemgetter(0))
        t = type = property(fget=operator.itemgetter(1))
        imm = immediate = property(fget=operator.itemgetter(2))

        @property
        def symbols(self):
            r, _, _ = self
            yield r

    class list(interface.namedtypedtuple, interface.symbol_t):
        """A tuple containing an arm register list `(reglist,)`.
        `reglist` contains a set of `register_t` which can be used to test membership.
        """
        _fields = ('reglist',)
        _types = (set,)

        @property
        def symbols(self):
            res, = self
            for r in res: yield r

    class disp(interface.namedtypedtuple, interface.symbol_t):
        '''A tuple for an arm operand containing the `(Rn, Offset)`.'''
        _fields = ('Rn', 'offset')
        _types = (register_t, six.integer_types)

        register = property(fget=operator.itemgetter(0))
        offset = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            r, _ = self
            yield r

    class phrase(interface.namedtypedtuple, interface.symbol_t):
        '''A tuple for an arm operand containing the `(Rn, Rm)`.'''
        _fields = ('Rn', 'Rm')
        _types = (register_t, register_t)

        register = property(fget=operator.itemgetter(0))
        offset = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            r, _ = self
            yield r

    class mem(interface.namedtypedtuple, interface.symbol_t):
        """A tuple for an arm memory operand containing the `(address, value)`.
        `address` contains the actual value that's stored within the operand.
        `value` contains the dereferenced value at the operand's address.
        """
        _fields = ('address', 'value')
        _types = (six.integer_types, six.integer_types)

        @property
        def symbols(self):
            raise StopIteration
            yield   # so that this function is still treated as a generator

## mips operands
class mipsop:
    class phrase(interface.namedtypedtuple, interface.symbol_t):
        '''A tuple for an arm operand containing the `(Rn, Offset)`.'''
        _fields = ('rt', 'imm')
        _types = (register_t, six.integer_types)

        register = property(fget=operator.itemgetter(0))
        immediate = property(fget=operator.itemgetter(1))

        @property
        def symbols(self):
            r, _ = self
            yield r

    @staticmethod
    def coproc(regnum):
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
class Intel(architecture_t):
    """An implementation of the Intel architecture.
    This can be used to locate registers that are of a specific size
    or are related to another set of registers.
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

class AArch32(architecture_t):
    """An implementation of the AArch32 architecture.
    This class is used to locate registers by name, index, or size.
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

class Mips(architecture_t):
    """An implementation of the Mips architecture.
    This class is used to locate registers by name, index, or size.
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
def __newprc__(id):
    plfm, m = idaapi.ph.id, __import__('sys').modules[__name__]
    if plfm == idaapi.PLFM_386:     # id == 15
        res = Intel()
    elif plfm == idaapi.PLFM_ARM:   # id == 1
        res = AArch32()
    elif plfm == idaapi.PLFM_MIPS:
        res = Mips()
    else:
        logging.warn("{:s} : IDP_Hooks.newprc({:d}) : {:d} : Unknown processor type. instruction module might not work properly.".format(__name__, id, plfm))
        return
    m.architecture, m.register = res, res.r
    m.arch, m.reg = m.architecture, m.register
__newprc__(0)

def __ev_newprc__(pnum, keep_cfg):
    return __newprc__(pnum)

### an intermediary representation for operands/operations
# FIXME: the following IR (heh) is entirely dependant on the intel architecture, replace it or remove it
OOBIS = collections.namedtuple('OpOffsetBaseIndexScale', ('op', 'offset', 'base', 'index', 'scale'))

## tag:intel
class ir_op:
    """Returns an operand as a parseable intermediary representation"""
    class __base__(object):
        def __init__(self, size=0):
            self.__size = size
        name = property(fget=lambda s: s.__class__.__name__)
        size = property(fget=lambda s: s.__size)
        def str(self):
            return "{:s}({:d})".format(self.name, self.size)
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
            return isinstance(self, other) if isinstance(other, builtins.type) else super(object, self) == other
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
        'immediate':    {'r' : ir_op.value,   'w' : ir_op.assign,   'rw' : ir_op.modify,      '' : ir_op.value},
        'memory':       {'r' : ir_op.load,    'w' : ir_op.store,    'rw' : ir_op.loadstore,   '' : ir_op.unknown},
        'phrase':       {'r' : ir_op.load,    'w' : ir_op.store,    'rw' : ir_op.loadstore,   '' : ir_op.unknown},
        'register':     {'r' : ir_op.value,   'w' : ir_op.assign,   'rw' : ir_op.modify,      '' : ir_op.unknown},
    }

    @utils.multicase(opnum=six.integer_types)
    @classmethod
    def op(cls, opnum): return cls.op(ui.current.address(), opnum)
    @utils.multicase(ea=six.integer_types, opnum=six.integer_types)
    @classmethod
    def op(cls, ea, opnum):
        """Returns an operand as a tuple.

        (store, immediate, register, index, scale)
        (load, immediate, register, index, scale)
        (value, immediate, register, index, scale)
        (assign, immediate, register, index, scale)
        """
        op, state = operand(ea, opnum), op_state(ea, opnum)
        t, sz = __optype__.lookup(op.type), __optype__.size(op)
        operation = cls.table[t.__name__][state]

        # if mnemonic is lea, then demote it from a memory operation
        # FIXME: i _really_ don't like this hack.
        if mnem(ea).upper() == 'LEA':
            if operation == ir_op.load:
                operation = ir_op.value
            elif operation == ir_op.store:
                operation = ir_op.assign
            else:
                operation = operation

        if t.__name__ == 'phrase':
            imm, base, index, scale = t(op)
        elif t.__name__ in {'immediate', 'memory'}:
            imm, base, index, scale = t(op), None, None, None
        else:
            imm, base, index, scale = None, t(op), None, None

        if operation == ir_op.load:
            sz = database.config.bits() // 8

        global architecture
        base = None if base is None else base if isinstance(base, register_t) else architecture.by_indexsize(base, size=sz)
        index = None if index is None else index if isinstance(base, register_t) else architecture.by_indexsize(index, size=sz)

        return OOBIS(operation(__optype__.size(op)), *(imm, base, index, scale))

    @utils.multicase()
    @classmethod
    def instruction(cls): return cls.instruction(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def instruction(cls, ea):
        result = []
        for opnum in six.moves.range(ops_count(ea)):
            operation, offset, base, index, scale = cls.op(ea,  opnum)
            sz = operation.size
            if operation == ir_op.modify:
                result.append(OOBIS(ir_op.assign(sz), offset, base, index, scale))
                result.append(OOBIS(ir_op.value(sz), offset, base, index, scale))
            elif operation == ir_op.loadstore:
                result.append(OOBIS(ir_op.load(sz), offset, base, index, scale))
                result.append(OOBIS(ir_op.store(sz), offset, base, index, scale))
            else:
                result.append(OOBIS(operation, offset, base, index, scale))
            continue

        # if mnemonic is stack-related, then add the other implicit operation
        # FIXME: ...and another pretty bad hack to figure out how to remove
        global register, architecture
        sp, sz = register.sp.id, database.config.bits()/8
        if mnem(ea).upper() == 'PUSH':
            result.append(OOBIS(ir_op.store(sz), 0, architecture.by_indexsize(sp, size=sz), 0, 1))
        elif mnem(ea).upper() == 'POP':
            result.append(OOBIS(ir_op.load(sz), 0, architecture.by_indexsize(sp, size=sz), 0, 1))
        elif mnem(ea).upper().startswith('RET'):
            if len(result) > 0:
                result.append(OOBIS(ir_op.modify(sz), 0, architecture.by_indexsize(sp, size=sz), 0, 1))
            result.append(OOBIS(ir_op.load(sz), 0, architecture.by_indexsize(sp, size=sz), 0, 1))
        elif mnem(ea).upper() == 'CALL':
            result.append(OOBIS(ir_op.store(sz), 0, architecture.by_indexsize(sp, size=sz), 0, 1))

        return mnem(ea), result
    at = utils.alias(instruction, 'ir')

    @utils.multicase()
    @classmethod
    def value(cls): return cls.value(ui.current.address())
    @utils.multicase()
    @classmethod
    def value(cls, ea):
        _, res = cls.at(ea)
        value = [v for v in res if v.op == 'value']
        return value

    @utils.multicase()
    @classmethod
    def store(cls): return cls.store(ui.current.address())
    @utils.multicase()
    @classmethod
    def store(cls, ea):
        _, res = cls.at(ea)
        store = [v for v in res if v.op == 'store']
        return store

    @utils.multicase()
    @classmethod
    def load(cls): return cls.load(ui.current.address())
    @utils.multicase()
    @classmethod
    def load(cls, ea):
        _, res = cls.at(ea)
        load = [v for v in res if v.op == 'load']
        return load

    @utils.multicase()
    @classmethod
    def assign(cls): return cls.assign(ui.current.address())
    @utils.multicase()
    @classmethod
    def assign(cls, ea):
        _, res = cls.at(ea)
        assign = [v for v in res if v.op == 'assign']
        return assign
