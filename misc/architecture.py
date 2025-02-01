r"""
Architectures module (internal)

This module contains class definitions that are used to track the operand
information for the processors that are currently supported by this plugin.
The contents of this module are not intended to be exposed directly to the
user, as instead the module is staged by the loader so that processor modules
can use this module's provided functionality to register any requirements
that are necessary to support the comprehension of that processor's instructions
and the decoding of its operands. The plugin then uses the information that
was registered for each processor module when detecting the processor used
in a database in order to switch to the correct architecture if the processor
has been properly registered and made available for usage.
"""

import functools, operator, itertools, logging, six
import builtins, math, bisect
import idaapi, internal
from internal import interface, utils, types

class map_t(object):
    """
    An object used for mapping attribute names to an object. This
    is used for dynamically representing each of the registers
    that available for a given architecture.
    """
    __slots__ = ('__state__',)
    def __init__(self):
        object.__setattr__(self, '__state__', {})

    def __getattr__(self, name):
        if name.startswith('__'):
            return getattr(self.__class__, name)
        res = self.__state__
        if name in res:
            return res[name]
        raise AttributeError(name)

    def __setattr__(self, name, register):
        cls, res = self.__class__, self.__state__
        if not isinstance(register, interface.register_t):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.__setattr__({!r}, {!r}) : Refusing to assign an invalid type ({!s}) to the current architecture as the \"{:s}\" register.".format('.'.join([cls.__module__, cls.__name__]), name, register, register.__class__, internal.utils.string.escape(name, '"')))
        elif name in res and hash(res[name]) != hash(register):
            raise internal.exceptions.DuplicateItemError(u"{:s}.__setattr__({!r}, {!r}) : Refusing to assign an alternative register ({!r}) to the current architecture as \"{:s}\" due to it having already been defined.".format('.'.join([cls.__module__, cls.__name__]), name, register, register, internal.utils.string.escape(name, '"')))
        return res.__setitem__(name, register)

    def __delattr__(self, name):
        cls, res = self.__class__, self.__state__
        raise internal.exceptions.UnsupportedCapability(u"{:s}.__delattr__({!r}) : Refusing to remove the \"{:s}\" register from the current architecture.".format('.'.join([cls.__module__, cls.__name__]), name, internal.utils.string.escape(name, '"')))

    def __contains__(self, name):
        return name in self.__state__

    def __repr__(self):

        # Given a register, traverse its parents until we get to a root node.
        Froot = lambda item: Froot(item.__parent__) if item.__parent__ else item

        # Gather all the children from a given root yielding each item
        # along with it's height inside the tree.
        def Fgather(root, height=0):
            yield height, root
            for position, type in sorted(root.__children__, key=operator.itemgetter(0)):
                child = root.__children__[position, type]
                for h, node in Fgather(child, height + 1):
                    yield h, node
                continue
            return

        # Build a sparse matrix and a height table for each member of a tree.
        def Fheights(root):
            matrix, heights = {}, {}
            for height, node in Fgather(root):
                row = matrix.setdefault(height, {})

                assert not operator.contains(row, node.id)
                row[node.__position__, node.__ptype__] = node

                assert not operator.contains(heights, node.id)
                heights[node] = height
            return matrix, heights

        # Given a list of the root registers, iterate through each one
        # and yield the heights of each element in their tree so that
        # we can sort and display them in some reasonable format.
        def Fiterate(registers):
            for root in map(Froot, registers):
                matrix, items = Fheights(root)
                yield root, matrix, items
            return

        # Needed some way to sort alphanumeric registers somehow.
        def alphanumerickey(item):
            if item.isalpha():
                return (item,)
            runs, iterable = [ch.isdigit() for ch in item], iter(item)
            consumeguide = [(isnumeric, len([item for item in items])) for isnumeric, items in itertools.groupby(runs, bool)]
            parts = []
            for numeric, length in consumeguide:
                part = ''.join(item for _, item in zip(range(length), iterable))
                if numeric:
                    parts.append(int(part))
                else:
                    parts.append(part)
                continue
            return tuple(parts)

        # First we collect the unique roots of all our registers, and then
        # we sort them by name before we group related registers together.
        registers = {Froot(reg) for _, reg in self.__state__.items()}
        roots = [reg for reg in sorted(registers, key=utils.fcompose(operator.attrgetter('name'), alphanumerickey))]

        # Now we need to group our registers together, and then flatten
        # them into essentially an euclidean coordinate to render it.
        results = []
        for root, matrix, regs in Fiterate(roots):
            lines = []
            for height in sorted(matrix):
                items = [(position, reg) for (position, _), reg in matrix[height].items()]
                items = [item for item in sorted(items, key=operator.itemgetter(0))]
                grouped = (map(operator.itemgetter(1), items) for _, items in itertools.groupby(items, key=operator.itemgetter(0)))
                iterable = ([(index, item) for item in items] for index, items in enumerate(grouped))
                lines.extend((height, index, item) for index, item in itertools.chain(*iterable))

            # Figure out the largest register name, and add padding along
            # with other ascii-shit to make it look like it's aligned.
            largest = max(map(len, map("{!s}".format, regs))) if regs else 0
            for height, index, reg in lines:
                reg_s = "{!s}".format(reg)
                results.append(r"{:s} : {:>{:d}s}{:s}{!r}".format("{:>{:d}s}".format(reg_s, 1 + largest) if height else "{:<{:d}s}".format(reg_s, 1 + largest), '\\_' if height else '', 2 * height, '__' * index, reg))
            continue
        return '\n'.join(itertools.chain(["{!s}".format(self.__class__)], results))

    ## Serialization
    def __getnewargs__(self):
        return ()

    def __getstate__(self):
        return {name : register for name, register in self.__state__.items()}

    def __setstate__(self, state):
        validated = {name.replace('.', '_') : register for name, register in state.items()}
        object.__setattr__(self, '__state__', validated)

class architecture_t(object):
    """
    Base class to represent how IDA maps the registers and types
    returned from an operand to a register that's uniquely
    identifiable by the user.

    This is necessary as for some architectures IDA will not include all
    the register names in the processor resulting in the same register
    index being used to represent two registers that are of different
    types. As an example, on the Intel processor module both the `%al`
    and `%ax` registers in an operand are actually returned as an index
    to the "ax" string and it is up to us to figure out which one it is.

    Similarly on the 64-bit version of the same processor module, all
    of the registers `%ax`, `%eax`, and `%rax` use the very same index.
    """
    __slots__ = ('__register__', '__cache__',)

    @property
    def register(self):
        '''A property that can be used to access any of the registers available for the architecture.'''
        return self.__register__
    reg = register

    def __init__(self, **cache):
        """Instantiate an ``architecture_t`` object which represents the registers available on an architecture.

        If `cache` is defined, then use the specified dictionary to map
        an IDA register's `(name, dtype)` to a string containing the
        more commonly recognized register name.
        """
        self.__register__, self.__cache__ = map_t(), cache.get('cache', {})

    def __getinitargs__(self): return
    def __getstate__(self): return

    @classmethod
    def __get_dtype_by_size__(cls, type, bits):
        '''Return the disassembler data type (``idaapi.dt_*``) for the specified number of `bits` and `type`.'''
        dtype_size, dtype_by_size = (idaapi.get_dtyp_size(op.dtyp), internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)) if idaapi.__version__ < 7.0 else (idaapi.get_dtype_size, idaapi.get_dtype_by_size)

        # normally we'd just use get_dtype_by_size to map the size to its dtype, but this is
        # actually borked in the disassembler for both tbyte and packreal (10 bytes each). So,
        # we generate tables for looking it up...one for integers, and another for floats.
        borked_dtype_integer = {dtype_size(dtype) : dtype for dtype in {idaapi.dt_tbyte}}
        borked_dtype_float = {dtype_size(dtype) : dtype for dtype in {getattr(idaapi, 'dt_half', idaapi.dt_word), idaapi.dt_float, idaapi.dt_double, idaapi.dt_packreal}}

        # add "long double", but only if it has a different size than the others.
        borked_dtype_float.setdefault(dtype_size(idaapi.dt_ldbl), idaapi.dt_ldbl)

        # now we just figure out which type, and then use it to select the correct table.
        # then we can fetch the dtype from a table or fall back to get_dtype_by_size.
        borked = borked_dtype_float if type is types.float else borked_dtype_integer
        return idaapi.dt_bitfild if bits < 8 else borked.get(bits // 8, dtype_by_size(bits // 8))

    def new(self, name, bits, idaname=None, **kwargs):
        """Add a new register with the given `name` and `bits` to the current architecture's register cache.

        If `idaname` is a string, then use it to identify the disassembler register instead of `name`.
        """
        key = name if idaname is None else idaname

        # now we just figure out which ptype, and then we can use it to
        # determine the dtype if we weren't given one explicitly.
        ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)
        dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), self.__get_dtype_by_size__(ptype, bits))

        # check if the key has already been registered in the cache.
        if (key, dtype) in self.__cache__ or key in self.__cache__:
            cls, realname_description = self.__class__, '' if idaname is None else " for \"{:s}\"".format(internal.utils.string.escape(idaname, '"')) if isinstance(idaname, internal.types.string) else " ({:d})".format(idaname)
            raise internal.exceptions.DuplicateItemError(u"{:s}.new({!r}, {:d}, {!r}{:s}) : Unable to create the \"{:s}\" register{:s} with dtype {:d} as there is one that already exists.".format('.'.join([cls.__module__, cls.__name__]), name, bits, idaname, ", {:s}".format(internal.utils.string.kwargs(kwargs)) if kwargs else '', internal.utils.string.escape(name, '"'), realname_description, dtype))

        # now we can come up with the namespace and create the register.
        namespace = {key : value for key, value in interface.register_t.__dict__.items()}
        namespace.update({'__name__':name, '__parent__':None, '__children__':{}, '__dtype__':dtype, '__position__':0, '__size__':bits, '__ptype__':ptype})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self

        # create the register and assign it into our namespace.
        res = type(name, (interface.register_t,), namespace)()
        self.__register__.__state__[name] = res

        # now we need to update the cache so that the register name can be looked up. we
        # register the default key also so that grabbing the name gives us the root register.
        self.__cache__[key, dtype] = self.__cache__[key] = name
        return res

    def child(self, parent, name, position, bits, idaname=None, **kwargs):
        """Add a register with the specified `name`, `position`, and `bits` to the architecture cache as a child of the given `parent` register.

        If `idaname` is a string, then use it to identify the disassembler register instead of `name`.
        """
        assert(isinstance(parent, interface.register_t))

        # grab the type from the parameter if it exists, and then try to
        # calculate the dtype with it if we weren't given one explicitly.
        ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)
        dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), self.__get_dtype_by_size__(ptype, bits))

        # confirm that the key hasn't already beeen used to register something else.
        key = name if idaname is None else idaname
        if (key, dtype) in self.__cache__:
            cls, realname_description = self.__class__, '' if idaname is None else " for \"{:s}\"".format(internal.utils.string.escape(idaname, '"')) if isinstance(idaname, internal.types.string) else " ({:d})".format(idaname)
            raise internal.exceptions.DuplicateItemError(u"{:s}.child({!s}, {!r}, {:d}, {:d}, {!r}{:s}) : Unable to create the \"{:s}\" register{:s} with dtype {:d} as there is one that already exists.".format('.'.join([cls.__module__, cls.__name__]), parent, name, position, bits, idaname, ", {:s}".format(internal.utils.string.kwargs(kwargs)) if kwargs else '', internal.utils.string.escape(name, '"'), realname_description, dtype))

        # populate the namespace for the child register, and then use it.
        namespace = {key : value for key, value in interface.register_t.__dict__.items() }
        namespace.update({'__name__':name, '__parent__':parent, '__children__':{}, '__dtype__':dtype, '__position__':position, '__size__':bits, '__ptype__':ptype})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self

        # create the child register, add it to our namespace, and update its parent
        # to reference it so that we can traverse downard from the parent to it.
        res = type(name, (interface.register_t,), namespace)()
        self.__register__.__state__[name] = res
        parent.__children__[position, ptype] = res

        # we now need to register the child into the cache. we conditionally register the
        # default key so that we don't overwrite a root register that may already exist.
        self.__cache__[key, dtype] = name
        self.__cache__.setdefault(key, name)

        # we also update the cache with any parent registers that are above us. if the
        # parent is a real-register, then update the cache with us being relative to it.
        if parent.realname is not None:
            self.__cache__.setdefault((parent.realname, dtype), name)

        # otherwise our parent is a pseudo-register (and our current register isn't), so
        # we need to update the cache so that the parent register is relative to us.
        elif idaname is not None:
            self.__cache__.setdefault((idaname, parent.dtype), parent.name)
        return res

    def pseudoregister(self, name, bits, pseudo_t, idaname=None, **kwargs):
        """Add a new pseudo-register of the specified `name` and `bits` to the architecture's register cache using the class `pseudo_t`.

        If `idaname` is a string, then use it to identify the disassembler register instead of `name`.
        """
        dt_bitfield, dtype_by_size = idaapi.dt_bitfild, internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        ptype = builtins.next((kwargs.pop(item) for item in ['ptype'] if item in kwargs), int)
        dtype = builtins.next((kwargs.pop(item) for item in ['dtyp', 'dtype', 'type'] if item in kwargs), self.__get_dtype_by_size__(ptype, bits))

        # check if the key has already been registered in the cache.
        key = name if idaname is None else idaname
        if (key, dtype) in self.__cache__ or key in self.__cache__:
            cls = self.__class__
            raise internal.exceptions.DuplicateItemError(u"{:s}.pseudo({!r}, {:d}, {!s}{:s}) : Unable to create the \"{:s}\" pseudo-register with dtype {:d} as there is one that already exists.".format('.'.join([cls.__module__, cls.__name__]), name, bits, pseudo_t, ", {:s}".format(internal.utils.string.kwargs(kwargs)) if kwargs else '', internal.utils.string.escape(name, '"'), dtype))

        # prepare the register's namespace for attachment.
        namespace = {key : value for key, value in pseudo_t.__dict__.items() }
        namespace.update({'__name__': name, '__parent__': None, '__children__': {}, '__dtype__': dtype, '__position__': 0, '__size__': bits, '__ptype__': ptype})
        namespace['realname'] = None
        namespace['alias'] = kwargs.pop('alias', {item for item in []})
        namespace['architecture'] = self

        res = type(name, (pseudo_t,), namespace)(**kwargs)
        self.__register__.__state__[name] = res
        self.__cache__[key, dtype] = self.__cache__[key] = name
        return res

    def by_index(self, index):
        """Return a register from the given architecture by its `index`.

        The default size is based on the architecture that IDA is using.
        """
        res = idaapi.ph.regnames[index]
        return self.by_name(res)
    byindex = internal.utils.alias(by_index)

    def by_indextype(self, index, dtype):
        """Return a register from the given architecture by its `index` and `dtype`.

        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res, dtype]
        return getattr(self.__register__, name)
    byindextype = internal.utils.alias(by_indextype)

    def by_name(self, name):
        '''Return a register from the given architecture by its `name`.'''
        key = name[1:].lower() if name.startswith(('%', '$', '@')) else name.lower()    # at&t, mips, windbg
        if key in self.__register__ or hasattr(self.__register__, key):
            name = key
        elif key in self.__cache__:
            name = self.__cache__[key]
        else:
            cls = self.__class__
            raise internal.exceptions.RegisterNotFoundError(u"{:s}.by_name({!r}) : Unable to find a register with the given name \"{:s}\".".format('.'.join([cls.__module__, cls.__name__]), name, internal.utils.string.escape(name, '"')))
        return getattr(self.__register__, name)
    byname = internal.utils.alias(by_name)

    def by_indexsize(self, index, size):
        '''Return a register from the given architecture by its `index` and `size`.'''
        ptype = self.by_index(index).__ptype__
        dtype = self.__get_dtype_by_size__(ptype, 8 * size)
        return self.by_indextype(index, dtype)
    byindexsize = internal.utils.alias(by_indexsize)

    @utils.multicase(name=types.string)
    def by(self, name):
        '''Return a register from the given architecture by its `name`.'''
        return self.by_name(name)
    @utils.multicase(index=types.integer)
    def by(self, index):
        '''Return a register from the given architecture by its `index`.'''
        return self.by_index(index)
    @utils.multicase(index=types.integer, size=types.integer)
    def by(self, index, size):
        '''Return a register from the given architecture by its `index` and `size`.'''
        return self.by_indexsize(index, size)
    @utils.multicase(register=interface.register_t)
    def by(self, register):
        '''Return the specified `register` from the given architecture.'''
        cls = self.__class__

        # If it's a regular register, then we can trust its id and type.
        if isinstance(register.realname, types.string):
            return self.by_indextype(register.id, register.dtype)

        # If it's a uarchitecture register, then we need to use its size
        # to convert it in order to get to the actual register index.
        elif isinstance(register.realname, types.integer) and hasattr(idaapi, 'mreg2reg'):
            ridx = idaapi.mreg2reg(register.id, register.size)
            return self.by_indextype(ridx, register.dtype)

        raise internal.exceptions.RegisterNotFoundError(u"{:s}.by({!s}) : Unable to find the specified register ({!s}).".format('.'.join([cls.__module__, cls.__name__]), register, register))
    @utils.multicase(register=interface.register_t, size=types.integer)
    def by(self, register, size):
        '''Return the specified `register` from the given architecture by its `size`.'''
        dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        dtype = dtype_by_size(size)

        # If it's a regular register, then we can trust its id and type.
        if isinstance(register.realname, types.string):
            return self.by_indextype(register.id, dtype)

        # If it's a uarchitecture register, then we need to
        # convert it to get to the actual register index.
        elif isinstance(register.realname, types.integer) and hasattr(idaapi, 'mreg2reg'):
            ridx = idaapi.mreg2reg(register.id, size)
            return self.by_indextype(ridx, dtype)

        cls = self.__class__
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.by({!s}, {:d}) : Unable to find the specified register ({!s}) in the given size ({:d}).".format('.'.join([cls.__module__, cls.__name__]), register, size, register, size))

    @utils.multicase(name=types.string)
    def has(self, name):
        '''Return true if a register with the given `name` exists within the architecture.'''
        key = name[1:].lower() if name.startswith(('%', '$', '@')) else name.lower()    # at&t, mips, windbg
        return key in self.__cache__ or key in self.__register__ or hasattr(self.__register__, key)
    @utils.multicase(index=types.integer)
    def has(self, index):
        '''Return true if a register at the given `index` exists within the architecture.'''
        names = idaapi.ph.regnames
        return 0 <= index < len(names)
    @utils.multicase(register=interface.register_t)
    def has(self, register):
        '''Return true if the specified `register` exists within the architecture.'''

        # If it's a regular register, then we can trust its id as the index.
        # However, if it's a uarchitecture register, then we need to use the
        # API to get the index. Afterwards we can just recurse for the result.
        if isinstance(register.realname, types.string):
            ridx = register.id
        elif isinstance(register.realname, types.integer) and hasattr(idaapi, 'mreg2reg'):
            ridx = idaapi.mreg2reg(register.id, register.size)
        else:
            ridx = -1
        return self.has(ridx)

    def promote(self, register, bits=None):
        '''Promote the specified `register` to its next larger size as specified by `bits`.'''
        parent = internal.utils.fcompose(operator.attrgetter('__parent__'), (lambda *items: items), functools.partial(filter, None), iter, next)
        try:
            if bits is None:
                return parent(register)
            return register if register.bits == bits else self.promote(parent(register), bits=bits)
        except StopIteration: pass
        cls = self.__class__
        if bits is None:
            raise internal.exceptions.RegisterNotFoundError(u"{:s}.promote({!s}{:s}) : Unable to promote the specified register ({!s}) to a size larger than {!r}.".format('.'.join([cls.__module__, cls.__name__]), register, '' if bits is None else ", bits={:d}".format(bits), register, register))
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.promote({!s}{:s}) : Unable to find a register of the required number of bits ({:d}) to promote {!r}.".format('.'.join([cls.__module__, cls.__name__]), register, '' if bits is None else ", bits={:d}".format(bits), bits, register))

    def demote(self, register, bits=None, type=None):
        '''Demote the specified `register` to its next smaller size as specified by `bits`.'''
        childitems = internal.utils.fcompose(operator.attrgetter('__children__'), operator.methodcaller('items'))
        firsttype = internal.utils.fcompose(childitems, lambda items: ((key, value) for key, value in items if key[1] == type), iter, next, operator.itemgetter(1))
        firstchild = internal.utils.fcompose(childitems, functools.partial(sorted, key=internal.utils.fcompose(operator.itemgetter(0), operator.itemgetter(0))), iter, next, operator.itemgetter(1))
        try:
            if bits is None:
                return firstchild(register)
            return register if register.bits == bits else self.demote(firstchild(register), bits=bits)
        except StopIteration: pass
        cls = self.__class__
        if bits is None:
            raise internal.exceptions.RegisterNotFoundError(u"{:s}.demote({!s}{:s}) : Unable to demote the specified register ({!s}) to a size smaller than {!r}.".format('.'.join([cls.__module__, cls.__name__]), register, '' if bits is None else ", bits={:d}".format(bits), register, register))
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.demote({!s}{:s}) : Unable to find a register of the required number of bits ({:d}) to demote {!r}.".format('.'.join([cls.__module__, cls.__name__]), register, '' if bits is None else ", bits={:d}".format(bits), bits, register))

## Hex-Rays (decompiler) architecture
try:
    import ida_hexrays

# If we couldn't import the "ida_hexrays" module, then we can only assume
# that Hex-Rays isn't available for us to actually use.
except ImportError:
    logging.debug(u"{:s} : Ignoring the Hex-Rays (decompiler) microcode architecture due to a missing \"{:s}\" module.".format(__name__, 'ida_hexrays'))

# Use the architecture_t class we defined as a base class for the ucode
# architecture in order to support the micro-registers from Hex-Rays.
else:
    class uarchitecture_t(architecture_t):
        """
        An implementation of all the registers available for the Hex-Rays
        microarchitecture that is part of its decompiler.

        Similar to the generally available architectures, this class keeps track
        of the relationships between registers allowing one to promote or demote
        a register to the different sizes that may be available. The registers
        within this class are typically represented by an index which is considered
        a micro-index (midx). This allows the decompiler to better identify the
        part of a register that is actually being modified by a micro-instruction.

        The architecture that is created is actually based on the architecture
        that is currently selected and can be changed by simply providing the
        architecture instance as the first parameter to this class' constructor.

        Some of the methods within this class may return a tuple that is of the
        `partialregister_t` type. The semantics of this type is exactly how it
        sounds and intends to represent a portion of a complete register.
        """

        # 0..7: condition codes
        # 8..n: all processor registers (including fpu registers, if necessary) this range may also include temporary registers used during the initial microcode generation
        # n.. : so called kernel registers; they are used during optimization see is_kreg()
        prefix = ''

        @utils.require_attribute(ida_hexrays, 'rlist_t')
        @utils.multicase(rlist=getattr(ida_hexrays, 'rlist_t', object))
        def by_rlist(self, rlist):
            '''Yield each register (partial and complete) that is represented by the ``ida_hexrays.rlist_t`` specified in `rlist`.'''
            return self.by_rlist([item for item in rlist])
        @utils.multicase(bitset=types.ordered)
        def by_rlist(self, bitset):
            '''Yield each register (partial and complete) that is represented by the indices specified in `bitset`.'''
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
            byteset = [item for item in bitset]

            # iterate through all of our contiguous points in the interval.
            offset = 0
            for _, points in itertools.groupby(enumerate(byteset), utils.funpack(operator.sub)):
                points = [n for n in map(operator.itemgetter(1), points)]
                logging.debug(u"bitset {:+d} : found {:d} contiguous points in rlist: {!s}".format(offset, len(points), points))

                run = points[:]
                while run:
                    result = self.by_partial(run[0], len(run))
                    size = result.size
                    logging.debug(u"bitset {:+d} : decoded {:d} run as {!s} : {!r} : left {!r}".format(offset, size, result, run[:size], run[size:]))
                    yield result
                    slice, run[:] = run[:size], run[size:]
                offset += len(points)
            return
        @utils.require_attribute(ida_hexrays, 'vivl_t')
        @utils.multicase(vivl=getattr(ida_hexrays, 'vivl_t', object))
        def by_interval(self, vivl):
            '''Yield each register (partial and complete) that is represented by ``ida_hexrays.vivl_t`` specified as `vivl`.'''
            voffset, vtype, vsize = vivl.off, vivl.type, vivl.size

            # if we're a stack offset, then we simply return the location for our interval.
            # we pretty much expect the caller to convert this to a location_t.
            if vtype in {ida_hexrays.mop_S}:
                yield interface.location_t(voffset, vsize)

            # if it's not a register, then we bail since we don't know what type it is.
            elif vtype not in {ida_hexrays.mop_r}:
                cls = self.__class__
                raise internal.exceptions.InvalidTypeOrValueError("{:s}.by_interval({!s}) : Unable to process an interval of an unknown type ({:d}) with the offset ({:d}) and size ({:+d}).".format('.'.join([__name__, cls.__name__]), vivl, vtype, voffset, vsize))

            # otherwise, this is a value interval and we need to continue to yield registers
            # until we meet the expected size.
            else:
                size = 0
                while size < vsize:
                    item = self.by_partial(voffset + size, vsize - size)
                    yield item
                    size += item.size
                return
            return

        @utils.multicase(register=(types.string, interface.register_t), size=types.integer)
        def by_partial(self, register, size):
            '''Return a `register_t` or `partialregister_t` for the given `register` up to the maximum `size`.'''
            reg = self.by(name)
            return self.by_partial(reg.realname, size)
        @utils.multicase(index=types.integer, size=types.integer)
        def by_partial(self, index, size):
            '''Return a `register_t` or `partialregister_t` for the register at the specified `index` up to the maximum `size`.'''
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
            midx, maximum, dtype = index, size, dtype_by_size(size)

            # define a closure that yields all of the available promotions for a register.
            def mreg_promotions(midx):
                if not self.has(midx):
                    return
                mreg = self.by_index(midx)
                while mreg.__parent__ and mreg.realname is not None:
                    yield mreg
                    mreg = mreg.__parent__
                if mreg.realname:
                    yield mreg
                return

            # return the size for each mreg within the architecture. these sizes are the
            # candidates that we'll be trying to match with. specifically, we only return
            # sizes for the correct mreg index.
            def mreg_candidates(midx):
                def verify(midx, promotions):
                    name = None
                    for mreg in promotions:
                        res = ida_hexrays.get_mreg_name(midx, mreg.size)
                        if res != name and '^' not in res:
                            name = res
                            yield mreg.size
                        continue
                    return
                iterable = verify(midx, mreg_promotions(midx))
                return [size for size in iterable]

            # scan backwards until we get to a real register
            def mreg_scan(midx):
                Fpredicate = lambda string: '^' in string
                shift = next(-idx for idx in itertools.count() if not Fpredicate(ida_hexrays.get_mreg_name(-idx + midx, 1)))
                return midx + shift

            # now we can begin the actual logic. we shortcut things here by checking if
            # we got an exact match. if so, then we're good to go and can just return it.
            candidates = [size for size in mreg_candidates(midx)]
            if any(size == maximum for size in candidates):
                try:
                    result = self.by_indextype(midx, dtype)
                except (internal.exceptions.RegisterNotFoundError, KeyError):
                    result = interface.partialregister_t(self.by_index(midx), 0, 8 * maximum)
                return result

            # otherwise, we need to seek backwards from our index to find the "real" register
            # that the index is part of and that we're able to actually promote.
            mregindex, res = mreg_scan(midx), midx
            while any('^' in ida_hexrays.get_mreg_name(mregindex, mreg.size) for mreg in mreg_promotions(mregindex)):
                if res == mregindex:
                    mregindex, res = mreg_scan(res - 1), mregindex
                else:
                    mregindex, res = mreg_scan(res), mregindex
                continue

            # now we have the actual register (mregindex), we use it to calculate the offset
            # into the register that we'll need to use and then figure out what's the largest
            # possible size that we'll be able to promote to.
            offset = midx - mregindex
            candidates = [size for size in mreg_candidates(mregindex)]
            selected = [size for size in candidates if size <= maximum]
            if len(selected):
                goal = offset + maximum
                index = bisect.bisect_left(selected, goal)
                size = selected[min(index, len(selected) - 1)]

                try:
                    result = self.by_indexsize(mregindex, size)
                    assert result.size == size

                # FIXME: we found a register, but couldn't find a size. the only time this happens
                #        is because our register size from the architecture does not match hexrays
                #        mreg size. so, we deal with this by treating as a partialregister_t.
                except (internal.exceptions.RegisterNotFoundError, KeyError):
                    result = self.by_index(mregindex)
                    return result

            # if we couldn't find any candidates to promote to, then there wasn't even a register
            # that matched the desired size which makes this a partial register.
            else:
                result = self.by_index(mregindex)
                assert maximum < result.size

            # collect all of our available promotions looking for a register size that is larger
            # than our offset that could fit it.
            promotions = [mreg.size for mreg in mreg_promotions(mregindex) if offset < mreg.size and mreg.realname == mregindex and mreg.size <= max(candidates)]
            if promotions and result.size < offset + maximum:
                index = bisect.bisect_left(promotions, offset + maximum)
                size = promotions[index] if index < len(promotions) else promotions[-1]
                try:
                    result = self.promote(result, 8 * size)

                # if we couldn't promote the register to the desired size, then use whatever
                # register index it was that we actually received.
                except internal.exceptions.RegisterNotFoundError:
                    return result

            # finally we use the offset to calcuate the real size of the result and then return it.
            realsize = min(result.size - offset, offset + maximum)
            return interface.partialregister_t(result, 8 * offset, 8 * realsize) if any([offset, realsize < result.size]) else result

        @utils.multicase(name=types.string)
        def has(self, name):
            '''Return whether the architecture contains a microregister with the specified `name`.'''
            return super(uarchitecture_t, self).has(identifier)
        @utils.multicase(index=types.integer)
        def has(self, index):
            '''Return whether the architecture contains a microregister with the specified `index`.'''
            return index in self.__cache__

        def by_index(self, index):
            '''Return the (complete) microregister for the given `index`.'''
            res = self.__cache__[index]
            if hasattr(self.__register__, res):
                return getattr(self.__register__, res)
            return IndexError(index)
        byindex = internal.utils.alias(by_index)

        def by_indextype(self, index, dtype):
            '''Return the (complete) microregister for the given `index` and `dtype`.'''
            name = self.__cache__[index, dtype]
            return self.by_name(name)
        byindextype = internal.utils.alias(by_indextype)

        def by_indexsize(self, index, size):
            '''Return the (complete or partial) microregister for the given `index` and `size`.'''
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
            dtype = dtype_by_size(size)

            # if the register exists in the cache, then we can return the whole thing.
            if (index, dtype) in self.__cache__:
                return self.by_indextype(index, dtype)

            # otherwise, this is a part of a uregister and we need to return that.
            return self.by_partial(index, size)
        byindexsize = internal.utils.alias(by_indexsize)

        def __init__(self, architecture, **cache):
            self.__owner__ = owner = architecture
            self.prefix = getattr(owner, 'prefix', '')
            super(uarchitecture_t, self).__init__()
            getitem, setitem = self.__register__.__getattr__, self.__register__.__setattr__

            # check to see if the hexrays microcode api is actually available.
            if not all(hasattr(ida_hexrays, name) for name in ['reg2mreg', 'mreg2reg', 'get_mreg_name', 'is_kreg']):
                cls = self.__class__
                raise internal.exceptions.UnsupportedCapability("{:s} : Unable to instantiate architecture due to the microcode api for the Hex-Rays decompiler being unavailable.".format('.'.join([__name__, cls.__name__])))

            # do some trickery to figure out what our largest contiguous register size is.
            midx = ida_hexrays.reg2mreg(0)
            bits = 32 if ida_hexrays.mreg2reg(midx, 8) < 0 else 64
            # FIXME: is it safe to assume that the reg at index 0 is always sizable?

            # some tools for dealing with a tree of registers on intel. i'm probably shooting
            # myself in the foot here as i'm not sure if uregs are in an actual tree on all archs.
            Froot = lambda item: Froot(item.__parent__) if item.__parent__ else item
            def Fgather(root, height=0):
                yield height, root
                for position, type in sorted(root.__children__, key=operator.itemgetter(0)):
                    child = root.__children__[position, type]
                    for h, node in Fgather(child, height + 1):
                        yield h, node
                    continue
                return

            def Fheights(root):
                matrix, heights = {}, {}
                for height, node in Fgather(root):
                    row = matrix.setdefault(height, {})

                    assert not operator.contains(row, node.id)
                    row[node.__position__, node.__ptype__] = node

                    assert not operator.contains(heights, node.id)
                    heights[node] = height
                return matrix, heights

            # start by counting exactly how many regs we have available which we
            # can do by taking from an infinite range until is_kreg() is true.
            iterable = itertools.dropwhile(utils.fcompose(ida_hexrays.is_kreg, operator.not_), itertools.count(0))
            count = next(iterable)

            # first we do the non-architecture registers like temporary and kregs. neither
            # of these should need to be stored as a tree since they're only temporary and
            # should only be used as an intermediary before storing to a concrete register.
            powers = range(1 + math.trunc(math.log2(bits // 8)))
            pow2 = utils.fcompose(functools.partial(pow, 2), math.trunc)

            # grab the temporary registers and iterate through all of them to add each one.
            mlist = idaapi.get_temp_regs()
            assert mlist.mem.count() == 0

            for midx in mlist.reg:
                for width in map(pow2, powers):
                    name = ida_hexrays.get_mreg_name(midx, width)
                    mreg = self.new(name, 8 * width, idaname=midx, ptype=int)
                    setitem(name, mreg)
                continue

            # now we just need to do a few kernel registers so that the user can access
            # them if they actually need to.
            for midx in map(functools.partial(operator.add, count), range(0x10)):
                for width in map(pow2, powers):
                    name = ida_hexrays.get_mreg_name(midx, width)
                    mreg = self.new(name, 8 * width, idaname=midx, ptype=int)
                    setitem(name, mreg)
                continue

            # now we need to build our index of all the mregs. we need to do the condition
            # codes (1-8) first, because they're required to exist. these can overlap with
            # concrete storage, so any logic that follows this should end up fixing it.
            mregindex = {}
            for midx in range(8):
                name = idaapi.get_mreg_name(midx, 1)

                # if our next mreg is part of ours (cc on intel), then scan for the size.
                if idaapi.get_mreg_name(midx + 1, 1).startswith(name):
                    size = next(idx for idx in itertools.count(1) if '^' not in ida_hexrays.get_mreg_name(+idx + midx, 1))
                    setitem(name, self.new(name, 8 * size, idaname=midx, ptype=int))

                # otherwise, each flag is just a byte in size and we can add it.
                else:
                    setitem(name, self.new(name, 8, idaname=midx, ptype=int))
                continue
            # XXX: should we ensure these _all_ become part of the flags register on intel?

            # now we'll scan the entire mregspace for all other variable-byte registers
            # that "we" know about, but hexrays doesn't. (heh)
            iterable = ((ida_hexrays.get_mreg_name(midx, 1), midx) for midx in range(count))
            iterable = ((name, midx) for name, midx in iterable if ida_hexrays.get_mreg_name(midx, bits // 8).lower() == name.lower())
            iterable = ((owner.by_name(name), midx) for name, midx in iterable if owner.has(name))
            mregindex.update({reg : midx for reg, midx in iterable if idaapi.reg2mreg(reg.id) < 0})

            for reg, midx in mregindex.items():
                logging.debug(u"seeded index for register {!r} with uregister {:d}".format(reg, midx))

            # firstly, we iterate through all of the registers so we can use their
            # realname in an index. afterwards, we then build another index of all
            # of the concrete registers that are available for the architecture.
            registers = {reg.name if reg.realname is None else reg.realname : reg for _, reg in architecture.register.__state__.items()}
            for idx, name in enumerate(idaapi.ph.regnames):
                reg, midx = registers[name], ida_hexrays.reg2mreg(idx)
                if 0 > midx:
                    logging.debug(u"skipping register {:d} during collection : {!r}".format(idx, reg))
                else:
                    mregindex[reg] = midx
                continue

            # now we need all of the roots for each mreg in mregindex
            available = {reg for reg in mregindex}
            results, roots = {}, {item for item in map(Froot, mregindex)}
            for root in roots:
                matrix, heights = Fheights(root)
                assert (root,) == tuple(matrix[0].values())
                common = available & {node for node in heights}
                used = sorted({heights[reg] for reg in common})
                assert used

                # create all nodes that do not have an mreg. however, we still need to figure out
                # which realname that these registers are associated with since hexrays wants a size.
                midx = mregindex[root] if root in mregindex else mregindex.get(registers[root.realname or root.name], -1)
                head = results[root] = self.new(root.name, root.bits, idaname=root.realname if midx < 0 else midx, ptype=root.__ptype__, dtype=root.__dtype__)
                for hidx in range(1, used[0]):
                    for (position, ptype), reg in matrix[hidx].items():
                        assert(reg not in mregindex)
                        dreg = registers[reg.name if reg.realname is None else reg.realname]
                        midx = mregindex.get(dreg, -1)
                        parent = results[reg.__parent__]
                        results[reg] = self.child(parent, reg.name, position, reg.bits, idaname=midx, ptype=reg.__ptype__, dtype=reg.__dtype__)
                    continue
                used.pop(0) if used[0] in {0} else used

                # that should give us all our dependencies, and now we just need to go
                # through and assign the ones that actually have an mreg associated with them.
                for hidx in used:
                    for (position, ptype), reg in matrix[hidx].items():
                        midx = mregindex[reg] if reg in mregindex else mregindex.get(registers[reg.name if reg.realname is None else reg.realname], -1)
                        parent = results[reg.__parent__]
                        if midx < 0:
                            logging.debug(u"skipping register {!r} ({!s}) due to there being no corresponding uregister ({:d})".format(reg, ptype, midx))
                        results[reg] = self.child(parent, reg.name, position, reg.bits, idaname=reg.realname if midx < 0 else midx, ptype=reg.__ptype__, dtype=reg.__dtype__)
                    continue
                continue

            # that should be literally all of the registers we inherited from our owner,
            # so the only thing left to really do is to attach them to our register state.
            assert len({ureg.name for _, ureg in results.items()}) == len(results)
            [ setitem(ureg.name, ureg) for _, ureg in results.items() ]

        @utils.multicase(string=types.string)
        def by(self, string):
            '''Return the (complete) microregister identified by the name specified in `string`.'''
            return self.by_name(string)
        @utils.multicase(integer=types.integer)
        def by(self, integer):
            '''Return the (complete) microregister identified by the index specfied in `integer`.'''
            return self.by_index(integer)
        @utils.multicase(register=interface.register_t)
        def by(self, register):
            '''Return the (complete) microregister that represents the specified `register`.'''
            return self.by(register, register.size)
        @utils.multicase(register=interface.register_t, size=types.integer)
        def by(self, register, size):
            '''Return the (complete) microregister for the specified `size` based on the given `register`.'''
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
            dtype = dtype_by_size(size)

            if isinstance(register.realname, types.string):
                realname = ida_hexrays.reg2mreg(register.id)
                return self.by_indextype(realname, dtype)

            # If we were given a uarchitecture register, then just scale it up
            # according to whatever the requested size is.
            elif isinstance(register.realname, types.integer):
                ridx = ida_hexrays.mreg2reg(register.id, size)
                realname = idaapi.ph.regnames[ridx]
                basereg = self.by_name(realname)
                realname = basereg.id
                return self.by_indextype(realname, dtype)

            # If we're too small, then promote it as far as we can.
            elif register.size < size:
                return self.promote(register, 8 * size)

            # Otherwise we have a matching register, or the smallest one available.
            return register

        def new(self, name, bits, idaname=None, **kwargs):
            '''Add a new uregister to the current architecture's register cache overwriting the old one if it already exists.'''
            key = name if idaname is None else idaname

            # similar to our parent, architecture_t.new, we need the dtype for registration.
            ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)
            dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), self.__get_dtype_by_size__(ptype, bits))

            # now we can check the cache, remove any registers that exist, and chain to the parent.
            [self.__cache__.pop(item) for item in [(key, dtype), key] if item in self.__cache__]
            res = super(uarchitecture_t, self).new(name, bits, idaname, **kwargs)

            # last thing to do is to ensure its registered in the cache. we overwrite any
            # previous instances with the new register due to the way they get created.
            self.__cache__[key, dtype] = self.__cache__[key] = name
            return res

        def child(self, parent, name, position, bits, idaname=None, **kwargs):
            '''Add a new child uregister to the current architecture's register cache overwriting the old one if it already exists.'''
            key = name if idaname is None else idaname

            # here we do the same dance as architecture_t.child in order to get the dtype for registration.
            ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)
            dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), self.__get_dtype_by_size__(ptype, bits))

            # go through the cache removing any other registers so that we can chain to the parent method.
            [self.__cache__.pop(item) for item in [(key, dtype), key] if item in self.__cache__]
            res = super(uarchitecture_t, self).child(parent, name, position, bits, idaname, **kwargs)

            # all we need to do is to ensure its registered. uregisters are pretty much
            # guaranteed to be unique since we use their index. so we overwrite everything.
            self.__cache__[key, dtype] = self.__cache__[key] = name
            return res

    logging.debug(u"{:s} : Successfully defined Hex-Rays (decompiler) microcode architecture.".format(__name__))

class operands(object):
    """
    This object is a registration table for the operand type decoders
    that are available for each processor. Once the operands have
    been registered by a processor module, this object can then be
    used to look up information about an operand according to its
    processor and operand type.
    """
    def __init__(self):
        self.cache = {}

    def define(self, processor, type, ptype=None):
        '''Register the operand decoder for the specfied `processor` and `type`'''
        def registered_decoder(fn):
            res = processor, type
            self.cache.setdefault(res, (fn, ptype))
            return fn
        return registered_decoder

    __call__ = internal.utils.alias(define, 'operands')

    def lookup(self, type, processor=None):
        '''Lookup the operand decoder and type for a specific `type` and `processor`.'''
        try: Fdecoder, ptype = self.cache[processor or idaapi.ph.id, type]
        except KeyError: Fdecoder, ptype = self.cache[0, type]
        return Fdecoder, ptype

    def decode(self, insn, op, processor=None):
        '''Using the specified `processor`, decode the operand `op` for the specified instruction `insn`.'''
        F, _ = self.lookup(op.type, processor=processor)
        return F(insn, op)

    def type(self, op, processor=None):
        '''Return the operand decoder type's name for the specified `processor` and `op`.'''
        F, _ = self.lookup(op.type, processor=processor)
        return F.__name__

    def ptype(self, op, processor=None):
        '''Return the pythonic type for the specified `processor` and `op`.'''
        _, t = self.lookup(op.type, processor=processor)
        return t

    def size(self, op, processor=None):
        '''Return the size of the operand identified by `op` for the specified `processor`.'''
        if idaapi.__version__ < 7.0:
            return idaapi.get_dtyp_size(op.dtyp)
        return idaapi.get_dtype_size(op.dtype)

class processors(object):
    """
    This object is a registration table for the processors that can be loaded
    when a database has been either created or opened by the user. Once the
    object has been instantiated, each processor implementation is then
    responsible for registering itself with this object. After the processor
    implementation has been registered, this object will initialize the processor
    state when the disassembler has figured out which processor it wants to use.
    """

    def __init__(self):
        self.cache = {}

    def register(self, processor):
        """Register a callable for the specified `processor` that returns an ``interface.architecture_t``.

        Each registered callable gets inserted to the front of a list and is called with
        the processor id that is detected by the disassembler. If the callable returns an
        an ``interface.architecture_t`` then it will be used. If ``None`` is returned by
        the callable, then the next registered callable will be tried until none are left.
        """
        def registered_architecture(callable):
            self.cache.setdefault(processor, []).insert(0, callable)
        return registered_architecture

    __call__ = internal.utils.alias(register, 'processors')

    def unregister(self, processor):
        '''Unregister the callable at the end of the queue for the specified `processor`.'''
        if self.cache.get(processor, []):
            return self.cache[processor].pop()
        cls = self.__class__
        return internal.exceptions.ItemNotFoundError("{:s}.unregister({:d}) : No architectures are registered for the processor with the specified id ({:d}).".format('.'.join([__name__, cls.__name__]), processor, processor))

    def choose(self, processor):
        '''Return a new instance of the architecture for the specified `processor` along with its description.'''
        for callable in self.cache.get(processor, []):
            res = callable(processor)
            if res:
                description = internal.utils.pycompat.function.documentation(callable)
                return res, description
            continue
        return

class module(object):
    """
    This is a utility namespace that maintains references to the different
    processor-specific objects that are provided by the plugin. This
    is intended to be used by the loader to provide a module representing
    the currently chosen architecture and expose tools that may be used
    internally by the plugin.
    """
    __slots__ = {'__processor__', '__operand__', '__update__', '__lazyattributes__', '__attributes__'}
    def __init__(self, update, **constructors):
        self.__processor__ = processors()
        self.__operand__ = operands()
        self.__update__ = update

        # the following is a hack that allows us to attach arbitrary objects to
        # this class as an attribute by providing the constructor for it.
        self.__lazyattributes__ = constructors
        self.__attributes__ = {}

    def __getattr__(self, attribute):
        if attribute in self.__attributes__:
            return self.__attributes__[attribute]

        # If the attribute wasn't cached, but we have a constructor for it, then
        # call it (if it's callable) and assign the new instance to our cache.
        elif attribute in self.__lazyattributes__:
            cons = self.__lazyattributes__[attribute]
            res = cons() if callable(cons) else cons
            self.__attributes__[attribute] = res
            return res

        cls = self.__class__
        raise AttributeError("{!r} object has no attribute {!r}".format(cls.__name__, attribute))

    @property
    def processor(self):
        '''Return the processor registration table.'''
        return self.__processor__

    @property
    def operand(self):
        '''Return the operand registration table.'''
        return self.__operand__

    @property
    def update(self):
        '''Return a callable that will be called when a processor has been determined by this object.'''
        return self.__update__
    @update.setter
    def update(self, callable):
        '''Modify the callable that will be executed when a processor has been determined by this object.'''
        self.__update__ = callable

    def nw_newprc(self, nw_code, is_old_database):
        pnum = idaapi.ph_get_id()
        return self.newprc(pnum)

    def ev_newprc(self, pnum, keep_cfg):
        return self.newprc(pnum)

    def newprc(self, id):
        """
        Determine the architecture from the current processor and use it to initialize
        the globals (``architecture`` and ``register``) within this module.
        """
        plfm = idaapi.ph.id

        # We need to explicitly fetch the processor id since not all versions of IDA
        # give us the correct processor id in our parameter.
        result = self.processor.choose(plfm)
        if result is None:
            cls = self.__class__
            logging.warning(u"{:s}.newprc({:d}) : Unsupported processor type {:d} was specified. Tools that use the instruction module might not work properly.".format('.'.join([__name__, cls.__name__]), id, plfm))
            return

        # Unpack the instance and our documentation from the result and log it.
        instance, description = result
        logging.warning(u"Detected processor module : {:s} ({:d})".format(description, plfm))

        # Now we have a new instance of the architecture and can simply swap it
        # into the proxy object with the callable we were instantiated with and
        # inject it into the "instruction" module for backwards compatibility.
        instance = self.update(instance)
        self.inject(instance)

    def inject(self, instance):
        '''Inject the chosen `instance` into the necessary modules for compatibility.'''
        res, m = instance, __import__('instruction')

        # if the instruction module has a hook function defined, then just dispatch
        # directly into it so that we don't interfere with logic that still exists.
        if hasattr(m, '__newprc__'):
            return m.__newprc__(idaapi.ph.id)

        # assign our required globals
        m.architecture, m.register = res, res.register

        # assign some aliases so that it's much shorter to type
        m.arch, m.reg = m.architecture, m.register

# Last thing to do is to update the name for the class so the documentation looks okay.
module.__name__ = 'architecture'
