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

import logging
import idaapi, internal

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
