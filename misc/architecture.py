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

import functools, operator, itertools, logging, six, builtins
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
        res = self.__state__
        return res.__setitem__(name, register)

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

    def new(self, name, bits, idaname=None, **kwargs):
        '''Add a new register to the current architecture's register cache.'''

        # older
        if idaapi.__version__ < 7.0:
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
            dt_bitfield = idaapi.dt_bitfild
        # newer
        else:
            dtype_by_size = idaapi.get_dtype_by_size
            dt_bitfield = idaapi.dt_bitfild

        #dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), dt_bitfield if bits == 1 else dtype_by_size(bits // 8))
        ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)

        namespace = {key : value for key, value in interface.register_t.__dict__.items()}
        namespace.update({'__name__':name, '__parent__':None, '__children__':{}, '__dtype__':dtype, '__position__':0, '__size__':bits, '__ptype__':ptype})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self
        res = type(name, (interface.register_t,), namespace)()
        self.__register__.__state__[name] = res
        key = name if idaname is None else idaname
        self.__cache__[key, dtype] = self.__cache__[key] = name
        return res

    def child(self, parent, name, position, bits, idaname=None, **kwargs):
        '''Add a new child register to the architecture's register cache.'''

        # older
        if idaapi.__version__ < 7.0:
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
            dt_bitfield = idaapi.dt_bitfild
        # newer
        else:
            dtype_by_size = idaapi.get_dtype_by_size
            dt_bitfield = idaapi.dt_bitfild

        dtype = builtins.next((kwargs[item] for item in ['dtyp', 'dtype', 'type'] if item in kwargs), dt_bitfield if bits == 1 else dtype_by_size(bits // 8))
        #dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        ptype = builtins.next((kwargs[item] for item in ['ptype'] if item in kwargs), int)

        namespace = {key : value for key, value in interface.register_t.__dict__.items() }
        namespace.update({'__name__':name, '__parent__':parent, '__children__':{}, '__dtype__':dtype, '__position__':position, '__size__':bits, '__ptype__':ptype})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self
        res = type(name, (interface.register_t,), namespace)()
        self.__register__.__state__[name] = res
        key = name if idaname is None else idaname
        self.__cache__[key, dtype] = self.__cache__[key] = name
        parent.__children__[position, ptype] = res
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
        dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        dtype = dtype_by_size(size)
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
    __slots__ = {'__processor__', '__operand__', '__update__'}
    def __init__(self, update):
        self.__processor__ = processors()
        self.__operand__ = operands()
        self.__update__ = update

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
