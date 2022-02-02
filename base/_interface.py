"""
Interface module (internal)

This module wraps a number of features provided by IDA so that it can be
dumbed down a bit. This module is used internally and thus doesn't provide
anything that a user should use. Nonetheless, we document this for curious
individuals to attempt to understand this craziness.
"""

import six, builtins
import sys, logging, contextlib
import functools, operator, itertools, types
import collections, heapq, traceback, ctypes, math
import unicodedata as _unicodedata, string as _string, array as _array

import ui, internal
import idaapi

class typemap(object):
    """
    This namespace provides bidirectional conversion from IDA's types
    to something more pythonic. This namespace is actually pretty
    magical in that it dumbs down IDA's types for humans without
    needing a reference.

    Normally IDA defines types as flags and enumerations which require
    a user to know the correct ones in order to infer information about
    it. Although they can still do this, it's a lot more reasonable if
    we convert them into some weird python-like syntax.

    The syntax for types is fairly straight forward if one is familiar
    with the names that python exposes. Essentially the base type is
    a tuple of the format `(type, size)`. If `size` is not specified,
    then the size will be assumed to be the default word size for the
    current database. The `type` field is then any one of the python
    types such as ``int``, ``chr``, ``str``, ``float``, ``type``, or
    ``None``.

    These types have the following meanings:

        ``int`` or ``long`` - an integral
        ``chr`` - a character
        ``unichr`` - a wide-character
        ``str`` or ``unicode`` - a string or a character
        ``float`` - a floating point number
        ``type`` - a pointer
        ``None`` - alignment

    This can result in the describing of an IDA type and its size
    using a much simpler interface. Some examples can be:

        `int` - An integer with the default size
        `(int, 2)` - a 16-bit integer
        `(chr, 3)` - a 3-byte string
        `(type, 4)` - a 32-bit pointer
        `(float, 4)` - a 16-bit floating point (ieee754 single)
        `(None, 16)` - aligned to 16 bytes

    If an array needs to be represented, then one can simply wrap
    their type within a list. A few examples of this follows:

        `[int, 4]` - a 4 element array of default sized integers
        `[chr, 9]` - a 4 element array of characters
        `[unichr, 9]` - a 4 element array of wide-characters
        `[(int, 2), 3]` - a 3 element array of 16-bit integers
        `[(float, 8), 4]` - a 4 element array of 64-bit floating point numbers.
        `[type, 6]` - a 6 element array of pointers

    These types are commonly associated with members of structures
    and thus can be used to quickly read or apply a type to a
    field within a structure.
    """

    FF_MASKSIZE = idaapi.as_uint32(idaapi.DT_TYPE)  # Mask that select's the flag's size
    FF_MASK = FF_MASKSIZE | 0xfff00000              # Mask that select's the flag's repr

    # FIXME: In some cases FF_nOFF (where n is 0 or 1) does not actually
    #        get auto-treated as an pointer by ida. Instead, it appears to
    #        only get marked as an "offset" and rendered as an integer.

    # FIXME: Figure out how to update this to use/create an idaapi.tinfo_t()
    #        and also still remain backwards-compatible with the older idaapi.opinfo_t()

    ## IDA 6.95 types
    if idaapi.__version__ < 7.0:
        integermap = {
            1:(idaapi.byteflag(), -1),  2:(idaapi.wordflag(), -1),  3:(idaapi.tribyteflag(), -1),
            4:(idaapi.dwrdflag(), -1),  8:(idaapi.qwrdflag(), -1), 10:(idaapi.tbytflag(), -1),
            16:(idaapi.owrdflag(), -1),
        }
        if hasattr(idaapi, 'ywrdflag'):
            integermap[32] = getattr(idaapi, 'ywrdflag')(), -1

        decimalmap = {
             4:(idaapi.floatflag(), -1),     8:(idaapi.doubleflag(), -1),
            10:(idaapi.packrealflag(), -1), 12:(idaapi.packrealflag(), -1),
        }

        stringmap = {
            chr:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            str:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
        }

        if hasattr(builtins, 'unichr'):
            stringmap.setdefault(builtins.unichr, (idaapi.asciflag(), idaapi.ASCSTR_UNICODE))
        if hasattr(builtins, 'unicode'):
            stringmap.setdefault(builtins.unicode, (idaapi.asciflag(), idaapi.ASCSTR_UNICODE))

        ptrmap = { sz : (idaapi.offflag() | flg, tid) for sz, (flg, tid) in integermap.items() }
        nonemap = { None :(idaapi.alignflag(), -1) }

    ## IDA 7.0 types
    else:
        integermap = {
            1:(idaapi.byte_flag(), -1),  2:(idaapi.word_flag(), -1),
            4:(idaapi.dword_flag(), -1),  8:(idaapi.qword_flag(), -1), 10:(idaapi.tbyte_flag(), -1),
            16:(idaapi.oword_flag(), -1),
        }
        if hasattr(idaapi, 'yword_flag'):
            integermap[32] = getattr(idaapi, 'yword_flag')(), -1

        decimalmap = {
             4:(idaapi.float_flag(), -1),     8:(idaapi.double_flag(), -1),
            10:(idaapi.packreal_flag(), -1), 12:(idaapi.packreal_flag(), -1),
        }

        stringmap = {
            chr:(idaapi.strlit_flag(), idaapi.STRTYPE_C),
            str:(idaapi.strlit_flag(), idaapi.STRTYPE_C),
        }
        if hasattr(builtins, 'unichr'):
            stringmap.setdefault(builtins.unichr, (idaapi.strlit_flag(), idaapi.STRTYPE_C_16))
        if hasattr(builtins, 'unicode'):
            stringmap.setdefault(builtins.unicode, (idaapi.strlit_flag(), idaapi.STRTYPE_C_16))

        ptrmap = { sz : (idaapi.off_flag() | flg, tid) for sz, (flg, tid) in integermap.items() }
        nonemap = { None :(idaapi.align_flag(), -1) }

    # Generate the lookup table for looking up the correct tables for a given type.
    typemap = {
        int:integermap, float:decimalmap,
        str:stringmap, chr:stringmap,
        type:ptrmap, None:nonemap,
    }
    if hasattr(builtins, 'long'): typemap.setdefault(builtins.long, integermap)
    if hasattr(builtins, 'unicode'): typemap.setdefault(builtins.unicode, stringmap)
    if hasattr(builtins, 'unichr'): typemap.setdefault(builtins.unichr, stringmap)

    # Invert our lookup tables so that we can find the correct python types for
    # the IDAPython flags that are defined.
    inverted = {}
    for s, (f, _) in integermap.items():
        inverted[f & FF_MASKSIZE] = (int, s)
    for s, (f, _) in decimalmap.items():
        inverted[f & FF_MASKSIZE] = (float, s)
    for s, (f, _) in stringmap.items():
        inverted[f & FF_MASKSIZE] = (str, s)
    for s, (f, _) in ptrmap.items():
        inverted[f & FF_MASK] = (type, s)
    del f

    # FIXME: this is a hack for dealing with structures that
    #        have the flag set but aren't actually structures..
    inverted[idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU] = (int, 1)

    # Assign the default values for the processor that was selected for the database.
    @classmethod
    def __newprc__(cls, pnum):
        info = idaapi.get_inf_structure()
        bits = 64 if info.is_64bit() else 32 if info.is_32bit() else None
        if bits is None: return

        typemap.integermap[None] = typemap.integermap[bits // 8]
        typemap.decimalmap[None] = typemap.decimalmap[bits // 8]
        typemap.ptrmap[None] = typemap.ptrmap[bits // 8]
        typemap.stringmap[None] = typemap.stringmap[str]

    @classmethod
    def __ev_newprc__(cls, pnum, keep_cfg):
        return cls.__newprc__(pnum)

    @classmethod
    def __nw_newprc__(cls, nw_code, is_old_database):
        pnum = idaapi.ph_get_id()
        return cls.__newprc__(pnum)

    @classmethod
    def dissolve(cls, flag, typeid, size):
        '''Convert the specified `flag`, `typeid`, and `size` into a pythonic type.'''
        structure = sys.modules.get('structure', __import__('structure'))
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        dt = flag & cls.FF_MASKSIZE
        sf = -1 if flag & idaapi.FF_SIGN == idaapi.FF_SIGN else +1

        # Check if the dtype is a structure and our type-id is an integer so that we
        # figure out the structure's size. We also do an explicit check if the type-id
        # is a structure because in some cases, IDA will forget to set the FF_STRUCT
        # flag but still assign the structure type-id to a union member.
        if (dt == FF_STRUCT and isinstance(typeid, six.integer_types)) or (typeid is not None and structure.has(typeid)):
            # FIXME: figure out how to fix this recursive module dependency
            t = structure.by_identifier(typeid)
            sz = t.size
            return t if sz == size else [t, size // sz]

        # Verify that we actually have the datatype mapped and that we can look it up.
        if dt not in cls.inverted:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.dissolve({!r}, {!r}, {!r}) : Unable to locate a pythonic type that matches the specified flag.".format('.'.join([__name__, cls.__name__]), dt, typeid, size))

        # Now that we know the datatype exists, extract the actual type and the
        # type's size from the inverted map that we previously created.
        t, sz = cls.inverted[dt]

        # If the datatype size is not an integer, then we need to calculate the
        # size ourselves using the size parameter we were given and the element
        # size of the datatype that we extracted from the flags.
        if not isinstance(sz, six.integer_types):
            count = size // idaapi.get_data_elsize(idaapi.BADADDR, dt, idaapi.opinfo_t())
            return [t, count] if count > 1 else t

        # If the size matches the datatype size, then this is a single element
        # which we represent with a tuple composed of the python type, and the
        # actual byte size of the datatype.
        elif sz == size:
            return t, sz * sf

        # At this point, the size does not match the datatype size which means
        # that this is an array where each element is using the datatype. So,
        # we need to return a list where the first element is the datatype with
        # the element size, and the second element is the length of the array.
        return [(t, sz * sf), size // sz]

    @classmethod
    def resolve(cls, pythonType):
        '''Convert the provided `pythonType` into IDA's `(flag, typeid, size)`.'''
        structure = sys.modules.get('structure', __import__('structure'))
        struc_flag = idaapi.struflag if idaapi.__version__ < 7.0 else idaapi.stru_flag

        sz, count = None, 1

        # If we were given a pythonic-type that's a tuple, then we know that this
        # is actually an atomic type that has its flag within our typemap. We'll
        # first use the type the user gave us to find the actual table containg
        # the sizes we want to look up, and then we extract the flag and typeid
        # from the table that we determined.
        if isinstance(pythonType, ().__class__):
            (t, sz), count = pythonType, 1
            table = cls.typemap[t]
            flag, typeid = table[abs(sz) if t in {int, getattr(builtins, 'long', int), float, type} else t]

        # If we were given a pythonic-type that's a list, then we know that this
        # is an array of some kind. We extract the count from the second element
        # of the list, but then we'll need to recurse into ourselves in order to
        # figure out the actual flag, type-id, and size of the type that we were
        # given by the first element of the list.
        elif isinstance(pythonType, [].__class__):
            res, count = pythonType
            flag, typeid, sz = cls.resolve(res)

        # If our pythonic-type is an actual structure_t, then obviously this
        # type is representing a structure. We know how to create the structure
        # flag, but we'll need to extract the type-id and the structure's size
        # from the properties of the structure that we were given.
        elif isinstance(pythonType, structure.structure_t):
            flag, typeid, sz = struc_flag(), pythonType.id, pythonType.size

        # If our pythonic-type is an idaapi.struc_t, then we need to do
        # pretty much the exact same thing that we did for the structure_t
        # and extract both its type-id and size.
        elif isinstance(pythonType, idaapi.struc_t):
            flag, typeid, sz = struc_flag(), pythonType.id, idaapi.get_struc_size(pythonType)

        # Anything else should be the default value that we're going to have to
        # look up. We start by using the type to figure out the correct table,
        # and then we grab the flags and type-id from the None key for the
        # pythonType. This should give us the default type information for the
        # current database and architecture.
        else:
            table = cls.typemap[pythonType]
            flag, typeid = table[None]

            # Construct an opinfo_t with the type-id that was returned, and then
            # calculate the correct size for the value returned by our table.
            opinfo, typeid = idaapi.opinfo_t(), idaapi.BADADDR if typeid < 0 else typeid
            opinfo.tid = typeid
            return flag, typeid, idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo)

        # Now we can return the flags, type-id, and the total size that IDAPython
        # uses when describing a type. We also check if our size is negative
        # because then we'll need to update the flags with the FF_SIGN flag in
        # order to describe the correct type requested by the user.
        typeid = idaapi.BADADDR if typeid < 0 else typeid
        return flag | (idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz) * count

class prioritybase(object):
    result = type('result', (object,), {})
    CONTINUE = type('continue', (result,), {})()
    STOP = type('stop', (result,), {})()

    def __init__(self):
        self.__cache__ = collections.defaultdict(list)
        self.__disabled = {item for item in []}
        self.__traceback = {}

    def __iter__(self):
        '''Return the id of each target that is hooked by this object.'''
        for target in self.__cache__:
            yield target
        return

    def __formatter__(self, target):
        raise NotImplementedError

    def connect(self, target):
        if target in self.__cache__:
            logging.warning(u"{:s}.connect({!r}) : Unable to connect to {:s} due to being already connected.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
            return False
        self.__cache__[target]
        return True

    def disconnect(self, target):
        if target in self.__cache__:
            if len(self.__cache__[target]):
                logging.warning(u"{:s}.disconnect({!r}) : Unable to disconnect from {:s} due to items still in cache.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
                return False
            self.__cache__.pop(target, None)
            return True
        logging.warning(u"{:s}.disconnect({!r}) : Unable to disconnect from {:s} due to not being connected.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
        raise False

    def hook(self):
        '''Physically connect all of the hooks controlled by this class.'''
        notok = False

        # Just iterate through each target and connect a closure for it
        for target in self.__cache__:
            ok = self.connect(target, self.apply(target))
            if not ok:
                logging.warning(u"{:s}.hook() : Error trying to connect to the specified {:s}.".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target)))
                notok = True
            continue
        return not notok

    def unhook(self):
        '''Physically disconnect all of the hooks controlled by this class.'''
        notok = False

        # Simply disconnect everything
        for target in self.__cache__:
            ok = self.disconnect(target)
            if not ok:
                logging.warning(u"{:s}.unhook() : Error trying to disconnect from the specified {:s}.".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target)))
                notok = True
            continue
        return not notok

    @property
    def available(self):
        '''Return all of the available targets that can be either enabled or disabled.'''
        return {item for item in self.__cache__}
    @property
    def disabled(self):
        '''Return all of the available targets that are currently disabled.'''
        return {item for item in self.__disabled}
    @property
    def enabled(self):
        '''Return all of the available targets that are currently enabled.'''
        return self.available - self.disabled

    def __repr__(self):
        cls = self.__class__

        # Extract the parameters from a function. This is just a
        # wrapper around utils.multicase.ex_args so we can extract
        # the names.
        def parameters(func):
            args, defaults, (star, starstar) = internal.utils.multicase.ex_args(func)
            for item in args:
                yield "{:s}={!s}".format(item, defaults[item]) if item in defaults else item
            if star:
                yield "*{:s}".format(star)
            if starstar:
                yield "**{:s}".format(starstar)
            return

        # Render the callable as something readable.
        def repr_callable(object, pycompat=internal.utils.pycompat):

            # If a method is passed to us, then we need to extract all
            # of the relevant components that describe it.
            if isinstance(object, (types.MethodType, staticmethod, classmethod)):
                cls = pycompat.method.self(object)
                func = pycompat.method.function(object)
                module, name = func.__module__, pycompat.function.name(func)
                iterable = parameters(func)
                None if isinstance(object, staticmethod) else next(iterable)
                return '.'.join([module, cls.__name__, name]), tuple(iterable)

            # If our object is a function-type, then it's easy to grab.
            elif isinstance(object, types.FunctionType):
                module, name = object.__module__, pycompat.function.name(object)
                iterable = parameters(object)
                return '.'.join([module, name]), tuple(iterable)

            # If it's still callable, then this is likely a class.
            elif callable(object):
                symbols, module, name = object.__dict__, object.__module__, object.__name__
                cons = symbols.get('__init__', symbols.get('__new__', None))
                iterable = parameters(cons) if cons else []
                next(iterable)
                return '.'.join([module, name]), tuple(iterable)

            # Otherwise, we have no idea what it is...
            return "{!r}".format(object), None

        # Unpack a prioritytuple into its components so we can describe it.
        def repr_prioritytuple(tuple):
            priority, callable = tuple
            name, args = repr_callable(callable)
            return priority, name, args

        # If there aren't any targets available, then return immediately.
        if not self.available:
            return '\n'.join(["{!s}".format(cls), "...No targets are being used...".format(cls)])

        alignment_enabled = max(len(self.__formatter__(target)) for target in self.enabled) if self.enabled else 0
        alignment_disabled = max(len("{:s} (disabled)".format(self.__formatter__(target))) for target in self.disabled) if self.disabled else 0
        res = ["{!s}".format(cls)]

        # First gather all our enabled hooks.
        for target in sorted(self.enabled):
            items = self.__cache__[target]
            hooks = sorted([(priority, callable) for priority, callable in items], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format(self.__formatter__(target), alignment_enabled, ' '.join(items) if items else '...nothing attached...'))

        # Now we can append all the disabled ones.
        for target in sorted(self.disabled):
            items = self.__cache__[target]
            hooks = sorted([(priority, callable) for priority, callable in items], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format("{:s} (disabled)".format(self.__formatter__(target)), alignment_disabled, ' '.join(items) if items else '...nothing attached...'))

        # And then return it to the caller.
        return '\n'.join(res)

    def enable(self, target):
        '''Enable any callables for the specified `target` that has been previously disabled.'''
        if target not in self.__disabled:
            cls = self.__class__
            logging.fatal(u"{:s}.enable({!r}) : The requested {:s} is not disabled. Currently disabled hooks are: {:s}.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "{{{:s}}}".format(', '.join(map("{!r}".format, self.__disabled)))))
            return False

        # Always explicitly do what we're told...
        self.__disabled.discard(target)

        # But if there were no entries in the cache, then warn the user about it.
        if not len(self.__cache__[target]):
            logging.warning(u"{:s}.enable({!r}) : The requested {:s} does not have any hooks attached to it.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target)))
            return False
        return True

    def disable(self, target):
        '''Disable execution of all the callables for the specified `target`.'''
        cls = self.__class__
        if target not in self.__cache__:
            logging.fatal(u"{:s}.disable({!r}) : The requested {:s} does not exist. Available hooks are: {:s}.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "{{{:s}}}".format(', '.join(map("{!r}".format, self.__cache__)))))
            return False
        if target in self.__disabled:
            logging.warning(u"{:s}.disable({!r}) : {:s} has already been disabled. Currently disabled hooks are: {:s}.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "{{{:s}}}".format(', '.join(map("{!r}".format, self.__disabled)))))
            return False
        self.__disabled.add(target)
        return True

    def add(self, target, callable, priority):
        '''Add the `callable` to our queue for the specified `target` with the provided `priority`.'''

        # connect to the requested target if possible
        if target not in self.__cache__:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, six.integer_types) else "{!r}".format
            raise NameError(u"{:s}.add({!r}, {!s}, priority={:s}) : Unable to connect to the specified {:s}.".format('.'.join([__name__, cls.__name__]), target, callable, format(priority), self.__formatter__(target)))

        # discard any callables already attached to the specified target
        self.discard(target, callable)

        # add the callable to our priority queue
        queue = self.__cache__[target]
        heapq.heappush(queue, internal.utils.priority_tuple(priority, callable))

        # preserve a backtrace so we can track where our callable is at
        self.__traceback[(target, callable)] = traceback.extract_stack()[:-1]
        return True

    def get(self, target):
        '''Return all of the callables that are attached to the specified `target`.'''
        res = self.__cache__[target]
        return tuple(callable for _, callable in res)

    def pop(self, target, index):
        '''Pop the item at the specified `index` from the given `target`.'''
        if target not in self.__cache__:
            cls, format = self.__class__, "{:d}".format if isinstance(index, six.integer_types) else "{!r}".format
            raise NameError(u"{:s}.pop({!r}, {:d}) : Unable to connect to the specified target ({:s}).".format('.'.join([__name__, cls.__name__]), target, format(index), self.__formatter__(target)))
        state = []

        # Iterate through the cache for the specified target and collect
        # each callable so we can figure out which one to remove.
        for (priority, F) in self.__cache__[target][:]:
            state.append((priority, F))

        # Pop off the result the user requested, and then combine our
        # state back into the cache we took it from.
        item = state.pop(index)
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # Otherwise our target is now empty and we need to disable it.
        else:
            self.__cache__[target][:] = []
            self.__disabled.add(target)

        # Now we can return whatever it was they removed.
        priority, result = item
        return result

    def discard(self, target, callable):
        '''Discard the `callable` from our priority queue for the specified `target`.'''
        if target not in self.__cache__:
            return False
        state = []

        # Filter through our cache for the specified target, and collect
        # each callable except for the one the user provided.
        found = 0
        for index, (priority, F) in enumerate(self.__cache__[target][:]):
            if F == callable:
                found += 1
                continue
            state.append((priority, F))

        # If we aggregated some items, then replace our cache with everything
        # except for the item the user discarded.
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # Otherwise we found nothing and we should just disable the target.
        else:
            self.__cache__[target][:] = []
            self.__disabled.add(target)

        return True if found else False

    def remove(self, target, priority):
        '''Remove the first callable from the specified `target` that has the provided `priority`.'''
        if target not in self.__cache__:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, six.integer_types) else "{!r}".format
            raise NameError(u"{:s}.remove({!r}, {:s}) : Unable to connect to the specified target ({:s}).".format('.'.join([__name__, cls.__name__]), target, format(priority), self.__formatter__(target)))
        state, table = [], {}

        # Iterate through our cache for the specified target and save
        # both the state and the index of every single priority.
        for index, (priority, F) in enumerate(self.__cache__[target][:]):
            state.append((priority, F))
            table.setdefault(priority, []).append(index)

        # Before we do anything, we need to ping the priority we're searching for
        # in the table and then we grab the first index for the given priority.
        if priority not in table:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, six.integer_types) else "{!r}".format
            raise NameError(u"{:s}.remove({!r}, {:s}) : Unable to locate a callable with the requested priority ({:+d}).".format('.'.join([__name__, cls.__name__]), target, format(priority), format(priority)))
        index = table[priority].pop(0)

        # We now can pop the index directly out of the state. Afterwards, we
        # need to shove our state back into the cache for the target.
        item = state.pop(index)
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # If our state is empty, then we go ahead and disable the target.
        # cache and then discard the the target.
        else:
            self.__cache__[target][:] = []
            self.__disabled.add(target)

        # We have an item that we can now return.
        priority, result = item
        return result

    def apply(self, target):
        '''Return a closure that will execute all of the hooks for the specified `target`.'''

        ## Define the closure that we'll hand off to connect
        def closure(*parameters):
            if target not in self.__cache__ or target in self.__disabled:
                return

            # Iterate through our priorityqueue extracting each callable and
            # executing it with the parameters we received
            hookq = self.__cache__[target][:]
            for priority, callable in heapq.nsmallest(len(hookq), hookq, key=operator.attrgetter('priority')):
                logging.debug(u"{:s}.closure({:s}) : Dispatching parameters ({:s}) to callback ({!s}) with priority ({:+d})".format('.'.join([__name__, self.__class__.__name__]), ', '.join(map("{!r}".format, parameters)), ', '.join(map("{!r}".format, parameters)), callable, priority))

                try:
                    result = callable(*parameters)

                # if we caught an exception, then inform the user about it and stop processing our queue
                except:
                    cls = self.__class__
                    bt = traceback.format_list(self.__traceback[target, callable])
                    current = str().join(traceback.format_exception(*sys.exc_info()))

                    format = functools.partial(u"{:s}.callback({:s}) : {:s}".format, '.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)))
                    logging.fatal(format(u"Callback for {:s} with priority ({:+d}) raised an exception while executing {!s}".format(self.__formatter__(target), priority, callable)))
                    logging.warning(format(u"Traceback ({:s} was hooked at)".format(self.__formatter__(target))))
                    [ logging.warning(format(item)) for item in str().join(bt).split('\n') ]
                    [ logging.warning(format(item)) for item in current.split('\n') ]

                    result = self.STOP

                if not isinstance(result, self.result) or result == self.CONTINUE:
                    continue

                elif result == self.STOP:
                    break

                cls = self.__class__
                raise TypeError(u"{:s}.callback({:s}) : Unable to determine the result ({!r}) returned from callable ({!s}).".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)), result, callable))
            return

        # That's it!
        return closure

class priorityhook(prioritybase):
    """
    Helper class for allowing one to apply a number of hooks to the
    different hook points within IDA.
    """
    def __init__(self, hooktype):
        '''Construct an instance of a priority hook with the specified IDA hook type which can be one of ``idaapi.*_Hooks``.'''
        super(priorityhook, self).__init__()

        # construct a new class definition, but do it dynamically for SWIG
        res = { name for name in hooktype.__dict__ if not name.startswith('__') and name not in {'hook', 'unhook'} }
        cls = type(hooktype.__name__, (hooktype, ), { name : self.__make_dummy_method(name) for name in res })

        # now we can finally use it
        self.__type__ = cls
        self.object = self.__type__()

    @staticmethod
    def __make_dummy_method(name):
        '''Generate a method that calls the super method specified by `name`.'''
        def method(self, *parameters, **keywords):
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(*parameters, **keywords)

        def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
            cls = self.__class__
            if value_type == idaapi.IDPOPT_STR:     # string constant (char*)
                res = idaapi.uchar_array(1 + len(value))
                for index, item in enumerate(bytearray(value + b'\0')):
                    res[index] = item
                pvalue = res
            elif value_type == idaapi.IDPOPT_NUM:   # number (uval_t*)
                res = idaapi.uvalvec_t()
                res.push_back(value)
                pvalue = res
            elif value_type == idaapi.IDPOPT_BIT:   # bit, yes/no (int*)
                res = idaapi.intvec_t()
                res.push_back(value)
                pvalue = res
            elif value_type == idaapi.IDPOPT_FLT:   # float, yes/no (double*)
                # FIXME: is there a proper way to get a double* type?
                res = idaapi.uint64vec_t()
                res.push_back(internal.utils.float_to_integer(value, 52, 11, 1))
                pvalue = res
            elif value_type == idaapi.IDPOPT_I64:   # 64bit number (int64*)
                res = idaapi.int64vec_t()
                res.push_back(value)
                pvalue = res
            else:
                raise ValueError(u"ev_set_idp_options_hook({!r}, {:d}, {:d}, {!s}) : Unknown value_type ({:d}) passed to ev_set_idp_options hook".format(keyword, value_type, value, idb_loaded, value_type))
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(keyword, value_type, pvalue, idb_loaded)

        def segm_deleted(self, start_ea, end_ea, flags):
            # /home/user/idapro-7.6/python/3/ida_idp.py:5189 # expected 4, got 3
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(start_ea, end_ea, flags)

        def bookmark_changed(self, index, pos, desc, operation):
            # /home/user/idapro-7.6/python/3/ida_idp.py:5801 # expected 5, got 4
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(index, pos, desc, operation)

        def compiler_changed(self, adjust_inf_fields):
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(adjust_inf_fields)

        def renamed(self, ea, new_name, local_name, old_name):
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(ea, new_name, local_name or None, old_name)

        def saved(self, path):
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, name)
            return supermethod(path)

        # patch-methods because SWIG+IDAPython is fucking stupid and Ilfak keeps
        # changing the damned hook parameters in the supermethod without updating
        # the dispatchers of the hook.

        if idaapi.__version__ >= 7.5:
            if name in {'ev_set_idp_options'}:
                return ev_set_idp_options

        if idaapi.__version__ >= 7.6:
            if name in {'compiler_changed'}:
                return compiler_changed
            elif name in {'renamed'}:
                return renamed
            elif name in {'saved'}:
                return saved
            elif name in {'bookmark_changed'}:
                return bookmark_changed

        if idaapi.__version__ >= 7.7:
            if name in {'segm_deleted'}:
                return segm_deleted

        return method

    def __formatter__(self, name):
        cls = self.__type__
        return '.'.join([cls.__name__, name])

    def __hook(self):
        if not self.object.hook():
            cls = self.__class__
            logging.debug(u"{:s}.hook(...) : Unable to hook with object ({!r}).".format('.'.join([__name__, cls.__name__]), self.object))
            return False
        return True

    def __unhook(self):
        if not self.object.unhook():
            cls = self.__class__
            logging.debug(u"{:s}.unhook(...) : Error trying to unhook object ({!r}).".format('.'.join([__name__, cls.__name__]), self.object))
            return False
        return True

    @contextlib.contextmanager
    def __context__(self):
        try:
            yield self.object.unhook()
        finally:
            self.object.hook()
        return

    def hook(self):
        '''Physically connect all of the hooks managed by this class.'''
        ok = super(priorityhook, self).hook()
        return ok and self.__hook()

    def unhook(self):
        '''Physically disconnect all of the hooks managed by this class.'''
        ok = self.__unhook()
        return ok and super(priorityhook, self).unhook()

    def connect(self, name, callable):
        '''Connect the hook `callable` to the specified `name`.'''
        if not hasattr(self.__type__, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError(u"{:s}.connect({!r}) : Unable to connect to the specified hook due to the method ({:s}) being unavailable.".format('.'.join([__name__, cls.__name__]), name, method))

        # if the name attribute already exists, then we're already connected.
        if name in self.available:
            return True

        # create a closure that calls our callable, and its supermethod
        supermethod = self.__make_dummy_method(name)
        def closure(instance, *args, **kwargs):
            callable(*args, **kwargs)
            return supermethod(instance, *args, **kwargs)

        # unhook, assign our new method, and then re-hook
        with self.__context__():
            method = internal.utils.pycompat.method.new(closure, self.object, self.__type__)
            setattr(self.object, name, method)
        return super(priorityhook, self).connect(name)

    def disconnect(self, name):
        '''Disconnect the hook from the specified `name`.'''
        def closure(instance, *parameters):
            supermethod = getattr(super(cls, instance), name)
            return supermethod(*parameters)

        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError(u"{:s}.disconnect({!r}, {!s}) : Unable to disconnect from the specified hook ({:s}).".format('.'.join([__name__, cls.__name__]), name, callable, method))

        method = internal.utils.pycompat.method.new(closure, self.object, self.__type__)
        setattr(self.object, name, method)
        return super(priorityhook, self).disconnect(name)

    def add(self, target, callable, priority):
        '''Add the `callable` to the queue for the specified `target` with the provided `priority`.'''
        if target in self.available:
            return super(priorityhook, self).add(target, callable, priority)

        # Try and connect to the target with a closure that will handle all its hooks.
        ok = self.connect(target, self.apply(target))
        if not ok:
            raise ValueError(u"{:s}.add({!r}, {!s}, {:+d}) : Unable to connect the specified hook ({:s}).".format('.'.join([__name__, cls.__name__]), name, callable, method))

        # We should've connected, so all that's left is to enable the hook.
        ok = super(priorityhook, self).add(target, callable, priority)
        return ok and self.enable(target)

    def discard(self, name, callable):
        '''Discard the specified `callable` from hooking the event `name`.'''
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError(u"{:s}.discard({!r}, {!s}) : Unable to discard method for hook as the specified hook ({:s}) is unavailable.".format('.'.join([__name__, cls.__name__]), name, callable, method))
        return super(priorityhook, self).discard(name, callable)

    def apply(self, name):
        '''Apply the currently registered callables to the event `name`.'''
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError(u"{:s}.apply({!r}) : Unable to apply the specified hook due to the method ({:s}) being unavailable.".format('.'.join([__name__, cls.__name__]), name, method))
        return super(priorityhook, self).apply(name)

    def __repr__(self):
        hObject = self.object
        hType = hObject.__class__
        hName = hType.__name__
        if not self.available:
            return "Callables currently attached to {:s}: {:s}".format(hName, 'No hooks are attached.')
        res, items = "Callables currently attached to {:s}:".format(hName), super(priorityhook, self).__repr__().split('\n')
        return '\n'.join([res] + items[1:])

class prioritynotification(prioritybase):
    """
    Helper class for allowing one to apply an arbitrary number of hooks to the
    different notification points within IDA.
    """
    def __init__(self):
        super(prioritynotification, self).__init__()
        self.hook()
        self.__lookup = { getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('NW_') }

    def __formatter__(self, notification):
        name = self.__lookup.get(notification, '')
        return "{:s}({:#x})".format(name, notification) if name else "{:#x}".format(notification)

    def connect(self, notification, closure):
        '''Connect to the specified `notification` in order to execute any callables provided by the user.'''
        ok = idaapi.notify_when(notification, closure)
        return ok and super(prioritynotification, self).connect(notification)

    def disconnect(self, notification):
        '''Disconnect from the specified `notification` so that nothing will execute.'''
        def closure(*parameters):
            return True
        ok = idaapi.notify_when(notification | idaapi.NW_REMOVE, closure)
        return ok and super(prioritynotification, self).disconnect(notification)

    def add(self, notification, callable, priority):
        '''Add the `callable` to the queue for the specified `notification` with the provided `priority`.'''
        if notification in self.available:
            return super(prioritynotification, self).add(notification, callable, priority)

        # Notifications are always connected and enabled.
        ok = self.connect(notification, self.apply(notification))
        if not ok:
            raise ValueError(u"{:s}.add({!r}, {!s}, {:+d}) : Unable to connect the specified hook ({:s}).".format('.'.join([__name__, cls.__name__]), name, callable, method))

        # Add the callable to our connected notification.
        ok = super(prioritynotification, self).add(notification, callable, priority)
        return ok and self.enable(notification)

    def apply(self, notification):
        '''Return a closure that will execute all of the hooks for the specified `notification`.'''
        if notification not in {idaapi.NW_INITIDA, idaapi.NW_TERMIDA, idaapi.NW_OPENIDB, idaapi.NW_CLOSEIDB}:
            cls = self.__class__
            raise ValueError(u"{:s}.apply({:#x}): Unable to apply the specified notification ({:#x}) due to the value being invalid.".format('.'.join([__name__, cls.__name__]), notification, notification))

        return super(prioritynotification, self).apply(notification)

    def __repr__(self):
        if not self.available:
            return "Callables currently attached to notifications: {:s}".format('No hooks are attached.')
        res, items = 'Callables currently attached to notifications:', super(prioritynotification, self).__repr__().split('\n')
        return '\n'.join([res] + items[1:])

class address(object):
    """
    This namespace provides tools that assist with correcting
    arguments that a user will provide to a function. This includes
    things such as verifying that an argument references an address
    within the database, is pointing to the "head" or "tail" of an
    address, etc.

    This is needed because some APIs that IDAPython exposes tend to
    be crashy when you give it a bogus address. This way parameters
    can be corrected before they're passed to an API that may crash
    IDA.
    """
    @classmethod
    def pframe(cls):
        '''Return the python frame that was called from the main thread.'''
        res = fr = sys._getframe()
        while fr.f_back and fr.f_code.co_name != '<module>':
            res = fr
            fr = fr.f_back
        return res

    @classmethod
    def __bounds__(cls):
        if idaapi.__version__ < 7.2:
            info = idaapi.get_inf_structure()
            min, max = info.minEA, info.maxEA
        else:
            min, max = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
        return min, max

    @classmethod
    def __within__(cls, ea):
        l, r = cls.__bounds__()
        return l <= ea < r

    @classmethod
    def __head1__(cls, ea, **silent):
        '''Adjusts `ea` so that it is pointing to the beginning of an item.'''
        entryframe = cls.pframe()
        logF = logging.warning if not silent.get('silent', False) else logging.debug

        res = idaapi.get_item_head(ea)
        if ea != res:
            logF("{:s} : Specified address {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, res))
        return res
    @classmethod
    def __head2__(cls, start, end, **silent):
        '''Adjusts both `start` and `end` so that each are pointing to the beginning of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warning if not silent.get('silent', False) else logging.debug

        res_start, res_end = idaapi.get_item_head(start), idaapi.get_item_head(end)
        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logF("{:s} : Starting address of {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, res_start))
        if res_end != end:
            logF("{:s} : Ending address of {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, end, res_end))
        return res_start, res_end
    @classmethod
    def head(cls, *args, **silent):
        '''Adjusts the specified addresses so that they point to the beginning of their specified items.'''
        if len(args) > 1:
            return cls.__head2__(*args, **silent)
        return cls.__head1__(*args, **silent)

    @classmethod
    def __tail1__(cls, ea, **silent):
        '''Adjusts `ea` so that it is pointing to the end of an item.'''
        entryframe = cls.pframe()
        logF = logging.warning if not silent.get('silent', False) else logging.debug

        res = idaapi.get_item_end(ea)
        if ea != res:
            logF("{:s} : Specified address {:#x} not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, res))
        return res
    @classmethod
    def __tail2__(cls, start, end, **silent):
        '''Adjusts both `start` and `end` so that each are pointing to the end of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warning if not silent.get('silent', False) else logging.debug

        res_start, res_end = idaapi.get_item_end(start), idaapi.get_item_end(end)
        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logF("{:s} : Starting address of {:#x} is not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, res_start))
        if res_end != end:
            logF("{:s} : Ending address of {:#x} is not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, end, res_end))
        return res_start, res_end
    @classmethod
    def tail(cls, *args, **silent):
        '''Adjusts the specified addresses so that they point to the end of their specified items.'''
        if len(args) > 1:
            return cls.__tail2__(*args, **silent)
        return cls.__tail1__(*args, **silent)

    @classmethod
    def __inside1__(cls, ea):
        '''Check that `ea` is within the database and adjust it to point to the beginning of its item.'''
        entryframe = cls.pframe()

        if not isinstance(ea, six.integer_types):
            raise internal.exceptions.InvalidParameterError(u"{:s} : The specified address {!r} is not an integral type ({!r}).".format(entryframe.f_code.co_name, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise internal.exceptions.InvalidParameterError(u"{:s} : An invalid address ({:#x}) was specified.".format(entryframe.f_code.co_name, ea))

        res = cls.within(ea)
        return cls.head(res, silent=True)
    @classmethod
    def __inside2__(cls, start, end):
        '''Check that both `start` and `end` are within the database and adjust them to point at their specified range.'''

        entryframe = cls.pframe()
        start, end = cls.within(start, end)
        if not isinstance(start, six.integer_types) or not isinstance(end, six.integer_types):
            raise internal.exceptions.InvalidParameterError(u"{:s} : The specified addresses ({!r}, {!r}) are not integral types ({!r}, {!r}).".format(entryframe.f_code.co_name, start, end, start.__class__, end.__class__))
        return cls.head(start, silent=True), cls.tail(end, silent=True) - 1
    @classmethod
    def inside(cls, *args):
        '''Check the specified addresses are within the database and adjust so that they point to their item or range.'''
        if len(args) > 1:
            return cls.__inside2__(*args)
        return cls.__inside1__(*args)

    @classmethod
    def __within1__(cls, ea):
        '''Check that `ea` is within the database.'''
        entryframe = cls.pframe()

        if not isinstance(ea, six.integer_types):
            raise internal.exceptions.InvalidParameterError(u"{:s} : The specified address {!r} is not an integral type ({!r}).".format(entryframe.f_code.co_name, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise internal.exceptions.InvalidParameterError(u"{:s} : An invalid address {:#x} was specified.".format(entryframe.f_code.co_name, ea))

        if not cls.__within__(ea):
            l, r = cls.__bounds__()
            raise internal.exceptions.OutOfBoundsError(u"{:s} : The specified address {:#x} is not within the bounds of the database ({:#x}<>{:#x}).".format(entryframe.f_code.co_name, ea, l, r))
        return ea
    @classmethod
    def __within2__(cls, start, end):
        '''Check that both `start` and `end` are within the database.'''
        entryframe = cls.pframe()

        if not isinstance(start, six.integer_types) or not isinstance(end, six.integer_types):
            raise internal.exceptions.InvalidParameterError(u"{:s} : The specified addresses ({!r}, {!r}) are not integral types ({!r}, {!r}).".format(entryframe.f_code.co_name, start, end, start.__class__, end.__class__))

        # If the start and end are matching, then we don't need to fit the bounds.
        if any(not cls.__within__(ea) for ea in [start, end if start == end else end - 1]):
            l, r = cls.__bounds__()
            raise internal.exceptions.OutOfBoundsError(u"{:s} : The specified range ({:#x}<>{:#x}) is not within the bounds of the database ({:#x}<>{:#x}).".format(entryframe.f_code.co_name, start, end, l, r))
        return start, end
    @classmethod
    def within(cls, *args):
        '''Check that the specified addresses are within the database.'''
        if len(args) > 1:
            return cls.__within2__(*args)
        return cls.__within1__(*args)

class range(object):
    """
    This namespace provides tools that assist with interacting with IDA 6.x's
    ``idaapi.area_t``, or IDA 7.x's ``idaapi.range_t`` in a generic manner
    without needing to know which version of IDA is being used or if the IDA
    6.95 compatibility layer is enabled.
    """

    # Define some classmethods for accessing area_t attributes in versions of IDA
    # prior to IDA 7.0.
    @classmethod
    def start_6x(cls, area):
        '''Return the "startEA" attribute of the specified `area`.'''
        return area.startEA
    @classmethod
    def end_6x(cls, area):
        '''Return the "endEA" attribute of the specified `area`.'''
        return area.endEA

    # Now we can do it for versions of IDA 7.0 and newer..
    @classmethod
    def start_7x(cls, area):
        '''Return the "startEA" attribute of the specified `area`.'''
        return area.start_ea
    @classmethod
    def end_7x(cls, area):
        '''Return the "end_ea" attribute of the specified `area`.'''
        return area.end_ea

    # Assign them based on the IDA version and add some aliases for it.
    start, end = (start_6x, end_6x) if idaapi.__version__ < 7.0 else (start_7x, end_7x)
    left, right, stop = start, end, end
    del(start_6x)
    del(end_6x)
    del(start_7x)
    del(end_7x)

    @classmethod
    def unpack(cls, area):
        '''Unpack the boundaries of the specified `area` as a tuple.'''
        return cls.start(area), cls.end(area)

    @classmethod
    def bounds(cls, area):
        '''Return the boundaries of the specified `area` as a ``bounds_t``.'''
        res = cls.unpack(area)
        return bounds_t(*res)

    @classmethod
    def within(cls, ea, area):
        '''Return whether the address `ea` is contained by the specified `area`.'''
        left, right = cls.unpack(area)
        return left <= ea < right
    contains = internal.utils.alias(within, 'range')

    @classmethod
    def size(cls, area):
        '''Return the size of the specified `area` by returning the difference of its boundaries.'''
        left, right = cls.unpack(area)
        return right - left

class node(object):
    """
    This namespace contains a number of methods that extract information
    from some of the undocumented structures that IDA stores within
    netnodes for various addresses in a database.

    XXX: Hopefully these are correct!
    """
    @staticmethod
    def is_identifier(identifier):
        '''Return truth if the specified `identifier` is valid.'''
        parameters = 2 * [identifier]
        if any(F(id) for F, id in zip([idaapi.get_struc, idaapi.get_member_by_id], parameters)):
            return True
        iterable = (F(id) for F, id in zip([idaapi.get_enum_idx, idaapi.get_enum_member_enum], parameters))
        return not all(map(functools.partial(operator.eq, idaapi.BADADDR), iterable))

    @internal.utils.multicase(sup=bytes)
    @classmethod
    def sup_functype(cls, sup, *supfields):
        """Given a supval, return the pointer size, model, calling convention, return type, and a tuple composed of the argument stack size and the arguments for a function.

        These bytes are typically found in a supval[0x3000] of a function.
        """
        res, ti = [], idaapi.tinfo_t()
        if not ti.deserialize(None, sup, *itertools.chain(supfields, [None] * (2 - min(2, len(supfields))))):
            raise internal.exceptions.DisassemblerError(u"{:s}.sup_functype(\"{!s}\") : Unable to deserialize the type information that was received.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # Fetch the pointer size and the model from the realtype byte.
        if not ti.is_func():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.sup_functype(\"{!s}\") : The type that was received ({!s}) was not a function type.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), ti))
        byte = ti.get_realtype()
        ptrsize, model = byte & idaapi.CM_MASK, byte & idaapi.CM_M_MASK
        res += [ptrsize, model]

        # Now we can get the calling convention and append the return type.
        ftd = idaapi.func_type_data_t()
        if not ti.get_func_details(ftd):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.sup_functype(\"{!s}\") : Unable to get the function's details from the received type information.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))
        byte = ftd.cc
        cc, spoiled_count = byte & idaapi.CM_CC_MASK, byte & ~idaapi.CM_CC_MASK
        res += [cc, ftd.rettype]

        # If the argument locations have been calculated, then we can add
        # them to our results. For sanity, we first validate that the number
        # of arguments corresponds to the number of elements in our ftd array.
        if ftd.flags & idaapi.FTI_ARGLOCS:
            number = ti.get_nargs()
            if number != len(ftd):
                raise internal.exceptions.AssertionError(u"{:s}.sup_functype(\"{!s}\") : The number of arguments for the function type ({:d}) does not match the number of arguments that were returned ({:d}).".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), number, len(ftd)))

            # To grab the arguments, we need to figure out the count because our arguments
            # will be a tuple composed of the (name, type, comment) for each one.
            arguments = []
            for index in builtins.range(ti.get_nargs()):
                item = ftd[index]
                typename, typeinfo, typecomment = item.name, item.type, item.cmt
                arguments.append(typeinfo if not len(supfields) else (typeinfo, typename) if len(supfields) == 1 else (typeinfo, typename, typecomment))

            # Include the size for the arguments on the stack along with the
            # arguments that we just extracted.argument size along with the arguments.
            arglocs = ftd.stkargs, arguments

        # If the argument locations weren't calculated, then the next element we
        # append is the size of the stack that is allocated to the arguments.
        else:
            arglocs = ftd.stkargs
        res += [arglocs]

        # Now we can return everything that we've collected from the type.
        return tuple(res)
    @internal.utils.multicase(sup=bytes, ptrsize=(None.__class__, six.integer_types), model=(None.__class__, six.integer_types), cc=(None.__class__, six.integer_types), rettype=(None.__class__, idaapi.tinfo_t), arglocs=(None.__class__, builtins.list, builtins.tuple))
    @classmethod
    def sup_functype(cls, sup, ptrsize, model, cc, rettype, arglocs):
        '''Given the old supval, re-encode any of the given parameters into it whilst ignoring the parameters that are specified as ``None``.'''

        # First decode the type information that we were given since we're going
        # to use it to reconstruct the supval.
        res, ti = bytearray(), idaapi.tinfo_t()
        if not ti.deserialize(None, sup, None):
            raise internal.exceptions.DisassemblerError(u"{:s}.sup_functype(\"{!s}\", ...) : Unable to deserialize the type information that was received.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # If it's not a function, then refuse to process it.
        if not ti.is_func():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.sup_functype(\"{!s}\", ...) : The type that was received ({!s}) was not a function type.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), ti))

        # Grab the extra function details so that we can sort out the caling
        # convention and types.
        ftd = idaapi.func_type_data_t()
        if not ti.get_func_details(ftd):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.sup_functype(\"{!s}\", ...) : Unable to get the function's details from the received type information.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # Verify that our arglocs were calculated and the number matches our type.
        if ftd.flags & idaapi.FTI_ARGLOCS:
            number = ti.get_nargs()
            if number != len(ftd):
                raise internal.exceptions.AssertionError(u"{:s}.sup_functype(\"{!s}\", ...) : The number of arguments for the function type ({:d}) does not match the number of arguments that were returned ({:d}).".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), number, len(ftd)))

        # Start out by grabbing the first byte and compose it from the ptrsize and model.
        obyte = ti.get_realtype()
        nptrsize = obyte & idaapi.CM_MASK if ptrsize is None else ptrsize & idaapi.CM_MASK
        nmodel = obyte & idaapi.CM_M_MASK if model is None else model & idaapi.CM_M_MASK
        res.append(nptrsize | nmodel)

        # Next we compose the calling convention. We need to extract the count
        # from the old byte since the user should be giving us a straight-up
        # calling convention to use.
        obyte = ftd.cc
        ncc = obyte & idaapi.CM_CC_MASK if cc is None else cc & idaapi.CM_CC_MASK
        nspoiled_count = obyte & ~idaapi.CM_CC_MASK
        res.append(ncc | nspoiled_count)

        # Next in our queue is the serialized return type.
        otype = ftd.rettype
        nbytes, _, _ = otype.serialize() if rettype is None else rettype.serialize()
        res.extend(bytearray(nbytes))

        # The last thing we need to do is to figure out our arguments. First we'll
        # check if the user gave us any. If not, then we'll just use the previously
        # used arguments from the idaapi.tinfo_t. We start with the old length,
        # and then we serialize everything into our result.
        if arglocs is None:
            ocount = len(ftd)
            res.append(1 + ocount)

            # Now we can iterate through all of them and serialize each one
            # so that we can extend our result with it.
            for index in builtins.range(ocount):
                funcarg = ftd[index]
                obytes, _, _ = funcarg.type.serialize()
                res.extend(bytearray(obytes))

            # That was it, so we can append our null-byte because we're done.
            res.append(0)

        # Otherwise the user gave us some new arguments to use which we'll need
        # to serialize in order to extend our result. First we'll need to check
        # if we were given a tuple, because if we were then this is a tuple
        # composed of the argument stack size and our actual argument list.
        else:
            _, arglocs = arglocs if isinstance(arglocs, tuple) else (0, arglocs)

            # Now that we have our real list of arguments, we can start by
            # appending the number of arguments that we were given.
            ncount = len(arglocs)
            res.append(1 + ncount)

            # Next we iterate through each of them in order to serialize each
            # one so that we can extend our result with it.
            for index, argloc in builtins.enumerate(arglocs):
                nbytes, _, _ = argloc.serialize()
                res.extend(bytearray(nbytes))

            # Last thing to do is append our null byte.
            res.append(0)

        # We're returning a supval here, so we need to convert our bytearray
        # back to bytes in order for it to be usable.
        return builtins.bytes(res)

    @staticmethod
    def sup_opstruct(sup, bit64Q):
        """Given a supval, return a tuple of the delta and a list of the encoded structure/field ids.

        This string is typically found in a supval[0xF+opnum] of the instruction.
        """
        le = functools.partial(functools.reduce, lambda agg, by: (agg * 0x100) | by)
        Fidentifier = getattr(idaapi, 'node2ea', internal.utils.fidentity)

        # jspelman. he's everywhere.
        ror = lambda n, shift, bits: (n>>shift) | ((n & pow(2, shift) - 1) << (bits - shift))

        # 16-bit
        # 0001 9ac1 -- _SYSTEMTIME

        # 32-bit
        # 0001 50
        # 0002 5051
        # 0001 c0006e92 -- ULARGE_INTEGER
        # 0002 c0006e92 c0006e98 -- ULARGE_INTEGER.quadpart
        # 0002 c0006e92 c0006e97 -- ULARGE_INTEGER.u.lowpart
        # 0002 c0006e92 c0006e96 -- ULARGE_INTEGER.s0.lowpart
        # (x ^ 0x3f000000)

        def id32(sup):
            iterable = (item for item in bytearray(sup))

            # First consume the offset (FIXME: we only support 2 bytes for now...)
            by = builtins.next(iterable)
            if le([by]) & 0x80:
                offset = le([by] + [builtins.next(iterable)])
                offset ^= 0x8000
            else:
                offset = 0

            count, rest = le([builtins.next(iterable)]), [item for item in iterable]
            itemsize = len(rest) // count

            iterable = (item for item in rest)
            chunks = [item for item in zip(*(itemsize * [iterable]))]

            if itemsize == 1:
                return offset, [0xff000000 | le(item) for item in chunks]

            elif itemsize == 2:
                return offset, [0xff000000 | 0x8000 ^ le(item) for item in chunks]

            elif itemsize == 4:
                #res = map(le, chunks)
                #res = map(functools.partial(operator.xor, 0x3f000000), res)
                return offset, [0x3f000000 ^ le(item) for item in chunks]

            raise internal.exceptions.SizeMismatchError(u"{:s}.sup_opstruct(\"{:s}\") -> id32 : An unsupported itemsize ({:d}) was discovered while trying to decode {:d} chunks at offset {:#x}. These chunks are {!r}.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), itemsize, count, offset, [bytes().join(item) for item in chunks]))

        # 64-bit
        # 000002 c000888e00 c000889900 -- KEVENT.Header.anonymous_0.anonymous_0.Type
        # 000002 c000888e00 c000889a00 -- KEVENT.Header.anonymous_0.Lock
        # 000001 c000888e00        -- KEVENT.Header.anonymous_0
        # 000001 c002bdc400
        # ff0000000000088e -- KEVENT
        # ff0000000000088f -- DISPATCHER_HEADER
        # ff00000000000890 -- _DISPATCHER_HEADER::*F98
        # ff00000000000891 -- _DISPATCHER_HEADER::*F98*0C
        # (x ^ 0xc0000000ff) ror 8

        def id64(sup):
            iterable = (item for item in bytearray(sup))

            # First consume the offset (FIXME: we only support 2 bytes for now...)
            by = builtins.next(iterable)
            if le([by]) & 0x80:
                offset = le([by] + [builtins.next(iterable)])
                offset ^= 0x8000
            else:
                offset = 0

            # Now we can grab our length
            length = le([builtins.next(iterable), builtins.next(iterable)])
            rest = [item for item in iterable]

            if len(rest) % 3 == 0:
                count, mask = 3, 0x8000ff

            elif len(rest) % 5 == 0:
                count, mask = 5, 0xc0000000ff

            else:
                raise NotImplementedError(u"{:s}.sup_opstruct(\"{:s}\") -> id64 : Error decoding supval from parameter.".format('.'.join([__name__, node.__name__]), rest))

            iterable = (item for item in rest)
            chunks = [item for item in zip(*(count * [iterable]))]

            #length = le(chunks.pop(0))
            if len(chunks) != length:
                raise internal.exceptions.SizeMismatchError(u"{:s}.sup_opstruct(\"{:s}\") -> id64 : Number of chunks ({:d}) does not match the extracted length ({:d}). These chunks are {!r}.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), len(chunks), length, [bytes().join(item) for item in chunks]))
            res = map(le, chunks)
            res = map(functools.partial(operator.xor, mask), res)
            return offset, [ror(item, 8, 64) for item in res]

        offset, items = id64(sup) if bit64Q else id32(sup)
        return offset, [Fidentifier(item) for item in items]

    @internal.utils.multicase(ea=six.integer_types)
    @classmethod
    def aflags(cls, ea):
        '''Return the additional flags for the instruction at the address `ea`.'''
        NALT_AFLAGS = getattr(idaapi, 'NALT_AFLAGS', 8)
        if hasattr(idaapi, 'get_aflags'):
            return idaapi.get_aflags(ea)
        return internal.netnode.alt.get(idaapi.ea2node(ea) if hasattr(idaapi, 'ea2node') else ea, NALT_AFLAGS)
    @internal.utils.multicase(ea=six.integer_types, mask=six.integer_types)
    @classmethod
    def aflags(cls, ea, mask):
        '''Return the additional flags for the instruction at the address `ea` masked with the integer provided by `mask`.'''
        return cls.aflags(ea) & mask
    @internal.utils.multicase(ea=six.integer_types, mask=six.integer_types, value=six.integer_types)
    @classmethod
    def aflags(cls, ea, mask, value):
        '''Set the additional flags for the instruction at address `ea` using the provided `mask` and `value`.'''
        NALT_AFLAGS = getattr(idaapi, 'NALT_AFLAGS', 8)
        result, flags = cls.aflags(ea, ~mask), value & mask
        if hasattr(idaapi, 'set_aflags'):
            return idaapi.set_aflags(ea, result | flags)
        return internal.netnode.alt.set(idaapi.ea2node(ea) if hasattr(idaapi, 'ea2node') else ea, NALT_AFLAGS, result | flags)

    @classmethod
    def alt_opinverted(cls, ea, opnum):
        '''Return whether the operand `opnum` at the address `ea` has its sign inverted or not.'''
        AFL_SIGN0, AFL_SIGN1 = 0x100000, 0x200000

        # Verify that we were given an operand number that has been tested before,
        # and log it if we haven't. Although it's likely that IDA will consider
        # all of the operands that follow the second operand as inverted once the
        # inversion has been applied by the user, we log this just to be safe and
        # let the user know that we're making an assumption here.
        if opnum not in {0, 1, 2}:
            result = cls.aflags(ea)
            logging.info(u"{:s}.alt_opinverted({:#x}, {:d}) : Fetching the inversion state for the operand ({:d}) of the instruction at {:#x} has not been tested (aflags={:#x}).".format('.'.join([__name__, cls.__name__]), ea, opnum, opnum, ea, result))

        # Grab the altval containing the additional flags for the given address
        # masked with the bits that we plan on checking.
        else:
            result = cls.aflags(ea, AFL_SIGN0 | AFL_SIGN1)

        # Now we just need to figure out which flag we need to use for the
        # operand that was chosen, and then we can check its mask.
        flag = AFL_SIGN1 if opnum else AFL_SIGN0
        return result & flag == flag

    @classmethod
    def alt_opnegated(cls, ea, opnum):
        '''Return whether the operand `opnum` at the address `ea` has its value negated or not.'''
        AFL_BNOT0, AFL_BNOT1 = 0x100, 0x200
        AFL_BNOTX = AFL_BNOT0 | AFL_BNOT1

        # Verify that we were given an operand number that has been tested before,
        # and if not then log it. Although it's totally plausible that the negation
        # of the second operand will affect all of the other operands that follow
        # it when the negation is applied by the user, we do this log just to be
        # safe and let the user know that we're making an assumption.
        if opnum not in {0, 1, 2}:
            result = cls.aflags(ea)
            logging.info(u"{:s}.alt_opnegated({:#x}, {:d}) : Fetching the negation state for the operand ({:d}) of the instruction at {:#x} has not been tested (aflags={:#x}).".format('.'.join([__name__, cls.__name__]), ea, opnum, opnum, ea, result))

        # Grab the altval containing the additional flags for the given address
        # masked with the bits that we want to check.
        else:
            result = cls.aflags(ea, AFL_BNOT0 | AFL_BNOT1)

        # Similar to the alt_opinverted function, we just need to figure out
        # the flag to use for the operand number that was chosen so that we
        # check its the aflags against the correct mask.
        flag = AFL_BNOT1 if opnum else AFL_BNOT0
        return result & flag == flag

def tuplename(*names):
    '''Given a tuple as a name, return a single name joined by "_" characters.'''
    iterable = ("{:x}".format(abs(item)) if isinstance(item, six.integer_types) else item for item in names)
    return '_'.join(iterable)

# copied mostly from the collections.namedtuple template
class namedtypedtuple(tuple):
    """
    A named tuple with actual type checking.
    """
    _fields = ()
    _types = ()

    def __new__(cls, *args):
        '''Construct a new instance of a tuple using the specified `args`.'''
        res = args[:]
        for n, t, x in zip(cls._fields, cls._types, args):
            if not isinstance(x, t):
                field_name = n.encode('utf8') if sys.version_info.major < 3 and isinstance(n, unicode) else n
                raise TypeError("Unexpected type ({!r}) for field {:s} should be {!r}.".format(type(x), field_name, t))
            continue
        return tuple.__new__(cls, res)

    @classmethod
    def _make(cls, iterable, cons=tuple.__new__, len=len):
        """Make a tuple using the values specified in `iterable`.

        If `cons` is specified as a callable, then use it to construct the type.
        If `len` is specified as a callable, then use it to return the length.
        """
        result = cons(cls, iterable)
        if len(result) != len(cls._fields):
            raise TypeError("Expected {:d} arguments, got {:d}.".format(len(cls._fields), len(result)))
        for n, t, x in zip(cls._fields, cls._types, result):
            if not isinstance(x, t):
                field_name = n.encode('utf8') if sys.version_info.major < 3 and isinstance(n, unicode) else n
                raise TypeError("Unexpected type ({!r} for field {:s} should be {!r}.".format(type(x), field_name, t))
            continue
        return result

    @classmethod
    def _type(cls, name):
        '''Return the type for the field `name`.'''
        res = (t for n, t in zip(cls._fields, cls._types) if n == name)
        try:
            result = builtins.next(res)
        except StopIteration:
            raise NameError("Unable to locate the type for an unknown field {!r}.".format(name))
        return result

    def __getattribute__(self, name):
        try:
            # honor the ._fields first
            fields = object.__getattribute__(self, '_fields')
            items = [item.lower() for item in fields]
            F = operator.itemgetter(items.index(name.lower()))
        except (IndexError, ValueError):
            F = lambda self: object.__getattribute__(self, name)
        return F(self)

    def __repr__(self):
        cls = self.__class__
        res = ("{!s}={!s}".format(internal.utils.string.escape(name, ''), value) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    def _replace(self, **fields):
        '''Assign the specified `fields` to the fields within the tuple.'''
        fc = fields.copy()
        result = self._make(map(fc.pop, self._fields, self))
        if fc:
            cls = self.__class__
            logging.warning(u"{:s}._replace({:s}) : Unable to assign unknown field names ({:s}) to tuple.".format('.'.join([__name__, cls.__name__]), internal.utils.string.kwargs(fields), '{' + ', '.join(map(internal.utils.string.repr, fc)) + '}'))
        return result
    def _asdict(self): return collections.OrderedDict(zip(self._fields, self))
    def __getnewargs__(self): return tuple(self)
    def __getstate__(self): return

class symbol_t(object):
    """
    An object that is used to describe something that is symbolic in nature
    and has semantics that depend on symbolic values.

    This can be used to weakly describe an expression which allows for
    a user to then enumerate any symbolic parts.
    """
    def __hash__(self):
        cls, res = self.__class__, id(self)
        return hash(cls, res)

    @property
    def symbols(self):
        '''Must be implemented by each sub-class: Return a generator that returns each symbol described by `self`.'''
        raise internal.exceptions.MissingMethodError

class register_t(symbol_t):
    """
    An object representing a particular register as part of an architecture.
    This allows a user to determine the register's name, size, and allows
    for comparison to other registers.
    """

    def __hash__(self):
        items = self.id, self.dtype, self.position, self.size
        return hash(items)

    @property
    def symbols(self):
        '''A register is technically a symbol, so we yield ourself.'''
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
        '''Returns the binary offset into the full register which owns it.'''
        return self.__position__

    def __str__(self):
        '''Return the architecture's register prefix concatenated to the register's name.'''
        prefix = self.architecture.prefix if hasattr(self, 'architecture') else ''
        return prefix + self.name

    def __repr__(self):
        try:
            dt, = [name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi, name) == self.dtype]
        except (AttributeError, ValueError):
            dt = 'unknown'
        cls = register_t
        return "<class '{:s}' index={:d} dtype={:s} name='{!s}' position={:d}{:+d}>".format(cls.__name__, self.id, dt, internal.utils.string.escape(self.name, '\''), self.position, self.size)

    def __eq__(self, other):
        if isinstance(other, six.string_types):
            return self.name.lower() == other.lower()
        elif isinstance(other, register_t):
            return self is other
        elif hasattr(other, '__eq__'):  # XXX: i fucking hate python
            return other.__eq__(self)
        return other is self

    def __ne__(self, other):
        return not (self == other)

    def __contains__(self, other):
        '''Returns True if the `other` register is a sub-part of `self`.'''
        viewvalues = {item for item in self.__children__.values()}
        return other in viewvalues

    def subsetQ(self, other):
        '''Returns true if the `other` register is a part of `self`.'''
        def collect(node):
            res = {node}
            [res.update(collect(item)) for item in node.__children__.values()]
            return res
        return other in self.alias or other in collect(self)

    def supersetQ(self, other):
        '''Returns true if the `other` register actually contains `self`.'''
        res, pos = {item for item in []}, self
        while pos is not None:
            res.add(pos)
            pos = pos.__parent__
        return other in self.alias or other in res

    def relatedQ(self, other):
        '''Returns true if both `other` and `self` affect each other when one is modified.'''
        return self.supersetQ(other) or self.subsetQ(other)

class regmatch(object):
    """
    This namespace is used to assist with doing register matching
    against instructions. This simplifies the interface for register
    matching so that one can specify whether any number of registers
    are written to or read from.
    """
    def __new__(cls, *regs, **modifiers):
        '''Construct a closure that can be used for matching instruction using the specified `regs` and `modifiers`.'''
        if not regs:
            args = ', '.join(map(internal.utils.string.escape, regs))
            mods = internal.utils.string.kwargs(modifiers)
            raise internal.exceptions.InvalidParameterError(u"{:s}({:s}{:s}) : The specified registers are empty.".format('.'.join([__name__, cls.__name__]), args, (', '+mods) if mods else ''))
        use, iterops = cls.use(regs), cls.modifier(**modifiers)
        def match(ea):
            return any(map(functools.partial(use, ea), iterops(ea)))
        return match

    @classmethod
    def use(cls, regs):
        '''Return a closure that checks if an address and opnum uses the specified `regs`.'''
        _instruction = sys.modules.get('instruction', __import__('instruction'))

        # convert any regs that are strings into their correct object type
        regs = { _instruction.architecture.by_name(r) if isinstance(r, six.string_types) else r for r in regs }

        # returns an iterable of bools that returns whether r is a subset of any of the registers in `regs`.
        match = lambda r, regs=regs: any(map(r.relatedQ, regs))

        # returns true if the operand at the specified address is related to one of the registers in `regs`.
        def uses_register(ea, opnum):
            val = _instruction.op(ea, opnum)
            if isinstance(val, symbol_t):
                return any(map(match, val.symbols))
            return False

        return uses_register

    @classmethod
    def modifier(cls, **modifiers):
        '''Return a closure iterates through all the operands in an address that use the specified `modifiers`.'''
        _instruction = sys.modules.get('instruction', __import__('instruction'))

        # by default, grab all operand indexes
        iterops = internal.utils.fcompose(_instruction.ops_count, builtins.range, sorted)

        # if `read` is specified, then only grab operand indexes that are read from
        if modifiers.get('read', False):
            iterops = _instruction.opsi_read

        # if `write` is specified that only grab operand indexes that are written to
        if modifiers.get('write', False):
            iterops = _instruction.opsi_write
        return iterops

## figure out the boundaries of sval_t
if idaapi.BADADDR == 0xffffffff:
    sval_t = ctypes.c_long
elif idaapi.BADADDR == 0xffffffffffffffff:
    sval_t = ctypes.c_longlong
else:
    sval_t = ctypes.c_int
    logging.fatal(u"{:s} : Unable to determine size of idaapi.BADADDR in order to determine boundaries of sval_t. Setting default size to {:d}-bits. The value of idaapi.BADADDR is {!r}.".format(__name__, ctypes.sizeof(sval_t), idaapi.BADADDR))

#Ref_Types = {
#    0 : 'Data_Unknown', 1 : 'Data_Offset',
#    2 : 'Data_Write', 3 : 'Data_Read', 4 : 'Data_Text',
#    5  : 'Data_Informational',
#    16 : 'Code_Far_Call', 17 : 'Code_Near_Call',
#    18 : 'Code_Far_Jump', 19 : 'Code_Near_Jump',
#    20 : 'Code_User', 21 : 'Ordinary_Flow'
#}
class reftype_t(object):
    """
    An object representing a reference type that allows one to easily extract
    semantics using set membership. This type uses "rwx" from posix file
    permissions to simplify reference semantics. It is bests to treat this
    object as a string.

    When testing membership, "r" means read, "w" means write, and "x" means
    execute. This makes it very easy to test whether a reference is reading
    and executing something, or it's writing to its target.
    """

    if idaapi.__version__ < 7.0:
        __mapper__ = {
            0 : '',
            1 : '&r',
            2 : 'w', 3 : 'r'
        }
    else:
        __mapper__ = {
            idaapi.fl_CF : 'rx', idaapi.fl_CN : 'rx',
            idaapi.fl_JF : 'rx', idaapi.fl_JN : 'rx',
            idaapi.fl_F : 'rx',
            idaapi.dr_O : '&r', idaapi.dr_I : '&r',
            idaapi.dr_R : 'r', idaapi.dr_W : 'w',
            getattr(idaapi, 'fl_U', 0) : '',
        }
    __mapper__[31] = '*'        # code 31 used internally by ida-minsc

    def __operator__(self, F, item):
        cls = self.__class__
        if isinstance(item, cls):
            res = F(self.S, item.S)
        elif isinstance(item, six.integer_types):
            res = F(self.S, cls.of(item))
        else:
            res = F(self.S, item)
        return cls.of_action(str().join(res)) if isinstance(res, set) else res

    def __hash__(self):
        return hash(self.F)
    def __or__(self, other):
        return self.__operator__(operator.or_, other)
    def __and__(self, other):
        return self.__operator__(operator.and_, other)
    def __eq__(self, other):
        return self.__operator__(operator.eq, other)
    def __ne__(self, other):
        return self.__operator__(operator.ne, other)
    def __contains__(self, type):
        if isinstance(type, six.integer_types):
            res = self.F & type
        else:
            res = operator.contains(self.S, type.lower())
        return True if res else False
    def __getitem__(self, type):
        if isinstance(type, six.integer_types):
            res = self.F & type
        else:
            res = operator.contains(self.S, type.lower())
        return True if res else False

    def __iter__(self):
        for item in sorted(self.S):
            yield item
        return

    def __repr__(self):
        return "reftype_t({:s})".format(str().join(sorted(self.S)))

    def __init__(self, xrtype, iterable):
        '''Construct a ``reftype_t`` using `xrtype` and any semantics specified in `iterable`.'''
        self.F = xrtype
        self.S = { item for item in iterable }

    @classmethod
    def of_type(cls, xrtype):
        '''Convert an IDA reference type in `xrtype` to a ``reftype_t``.'''
        if not isinstance(xrtype, six.integer_types):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_type({!r}) : Refusing coercion of a non-integral {!s} into the necessary type ({!s}).".format('.'.join([__name__, cls.__name__]), xrtype, xrtype.__class__, 'xrtype'))
        items = cls.__mapper__.get(xrtype, '')
        iterable = (item for item in items)
        return cls(xrtype, iterable)
    of = of_type

    @classmethod
    def of_action(cls, state):
        '''Convert a ``reftype_t`` in `state` back into an IDA reference type.'''
        if state == '*':
            return cls(31, '*')     # code 31 used internally by ida-minsc
        elif state == 'rw':
            state = 'w'

        # Verify that the state we were given can be iterated through.
        try:
            (item for item in state)

        except TypeError:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_action({!r}) : Unable to coerce the provided state ({!r}) into a cross-reference type ({!s}).".format('.'.join([__name__, cls.__name__]), state, state, cls.__name__))

        # Search through our mapper for the correct contents of the reftype_t.
        res = { item for item in state }
        for F, t in cls.__mapper__.items():
            if { item for item in t } == res:
                return cls(F, res)
            continue
        resP = str().join(sorted(res))
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_action({!r}) : Unable to to coerce the requested state ({!r}) into a cross-reference type ({!s}).".format('.'.join([__name__, cls.__name__]), resP, resP, cls.__name__))

class ref_t(namedtypedtuple):
    """
    This tuple is used to represent references that include an operand number
    and has the format `(address, opnum, reftype_t)`. The operand number is
    optional as not all references will provide it.
    """
    _fields = ('address', 'opnum', 'reftype')
    _types = (six.integer_types, (six.integer_types, None.__class__), reftype_t)

    @property
    def ea(self):
        '''Return the address field that is associated with the reference.'''
        res, _, _ = self
        return res

    def __repr__(self):
        cls, fields = self.__class__, {'address'}
        res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

class opref_t(namedtypedtuple):
    """
    This tuple is used to represent references that include an operand number
    and has the format `(address, opnum, reftype_t)`.
    """
    _fields = ('address', 'opnum', 'reftype')
    _types = (six.integer_types, six.integer_types, reftype_t)

    @property
    def ea(self):
        '''Return the address field that is associated with the operand being referenced.'''
        res, _, _ = self
        return res

    def __repr__(self):
        cls, fields = self.__class__, {'address'}
        res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

# XXX: is .startea always guaranteed to point to an instruction that modifies
#      the switch's register? if so, then we can use this to calculate the
#      .range/.cases more accurately instead of them being based on .elbase.
class switch_t(object):
    """
    This object is a wrapper around the ``idaapi.switch_info_ex_t`` class and
    allows for easily querying the semantics of the different attributes that
    are exposed by the switch_info_ex_t. A number of methods are provided
    which allow one to enumerate the valid case numbers, the handlers for them
    and any tables associated with the switch.
    """
    def __init__(self, switch_info_ex):
        self.object = switch_info_ex
    def __len__(self):
        '''Return the total number of cases (including any default) handled by the switch.'''
        return len(self.range)
    @property
    def ea(self):
        '''Return the address at the beginning of the switch.'''
        return self.object.startea
    @property
    def branch_ea(self):
        '''Return the address of the branch table.'''
        return self.object.jumps
    @property
    def table_ea(self):
        '''Return the address of the case or index table.'''
        return self.object.lowcase
    @property
    def default(self):
        '''Return the address that handles the default case.'''
        return self.object.defjump
    @property
    def branch(self):
        '''Return the contents of the branch table.'''
        import database, instruction

        # if we're an indirect switch, then we can grab our length from
        # the jcases property.
        if self.indirectQ():
            ea, count = self.object.jumps, self.object.jcases
            items = database.get.array(ea, length=count)

        # otherwise, we'll need to use the ncases property for the count.
        else:
            ea, count = self.object.jumps, self.object.ncases
            items = database.get.array(ea, length=count)

        # check that the result is a proper array with a typecode.
        if not hasattr(items, 'typecode'):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.branch() : An invalid type ({!s}) was returned from the switch table at address {:#x}.".format(cls.__name__, items.__class__, ea))

        # last thing to do is to adjust each element from our items to
        # correspond to what's described by its refinfo_t.
        ri = instruction.ops_refinfo(ea)

        # the refinfo_t's flags determine whether we need to subtract or
        # add the value from the refinfo_t.base.
        f = operator.sub if ri.is_subtract() else operator.add

        # now that we know what type of operation the refinfo_t is, use
        # it to translate the array's values into database addresses, and
        # then we can return them to the caller.
        return [f(ri.base, item) for item in items]
    @property
    def index(self):
        '''Return the contents of the case or index table.'''
        import database

        # if we're not an indirect switch, then the index table is empty.
        if not self.indirectQ():
            return database.get.array(self.object.jumps, length=0)

        # otherwise, we can simply read the array and return it.
        ea, count = self.object.lowcase, self.object.ncases
        return database.get.array(ea, length=count)
    @property
    def register(self):
        '''Return the register that the switch is based on.'''
        import instruction
        ri, rt = (self.object.regnum, self.object.regdtyp) if idaapi.__version__ < 7.0 else (self.object.regnum, self.object.regdtype)
        return instruction.architecture.by_indextype(ri, rt)
    @property
    def base(self):
        '''Return the base value (lowest index of cases) of the switch.'''
        return self.object.ind_lowcase if self.object.is_indirect() else 0
    @property
    def count(self):
        '''Return the number of cases in the switch.'''
        return self.object.ncases
    def indirectQ(self):
        '''Return whether the switch is using an indirection table or not.'''
        return self.object.is_indirect()
    def subtractQ(self):
        '''Return whether the switch performs a translation (subtract) on the index.'''
        return self.object.is_subtract()
    def case(self, case):
        '''Return the handler for a particular `case`.'''
        # return the ea of the specified case number
        # FIXME: check that this works with a different .ind_lowcase
        if case < self.base or case >= self.count + self.base:
            cls = self.__class__
            raise internal.exceptions.IndexOutOfBoundsError(u"{:s}.case({:d}) : The specified case ({:d}) was out of bounds ({:#x}<>{:#x}).".format(cls.__name__, case, case, self.base, self.base+self.count - 1))
        idx = case - self.base
        if self.indirectQ():
            idx = self.index[idx]
        return self.branch[idx]
    def handler(self, ea):
        '''Return all the cases that are handled by the address `ea` as a tuple.'''
        return tuple(case for case in self.range if self.case(case) == ea)
    @property
    def cases(self):
        '''Return all of the non-default cases in the switch.'''
        import instruction
        F = lambda ea, dflt=self.default: (ea == dflt) or (instruction.type.is_jmp(ea) and instruction.op(ea, 0) == dflt)
        return tuple(idx for idx in builtins.range(self.base, self.base + self.count) if not F(self.case(idx)))
    @property
    def range(self):
        '''Return all of the possible cases for the switch.'''
        return tuple(builtins.range(self.base, self.base + self.count))
    def __str__(self):
        cls = self.__class__
        if self.indirectQ():
            return "<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} index[{:d}]:*{:#x} register:{!s}".format(cls.__name__, self.count, self.ea, self.default, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return "<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} register:{!s}".format(cls.__name__, self.count, self.ea, self.default, self.object.ncases, self.object.jumps, self.register)
    def __unicode__(self):
        cls = self.__class__
        if self.indirectQ():
            return u"<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} index[{:d}]:*{:#x} register:{!s}".format(cls.__name__, self.count, self.ea, self.default, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return u"<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} register:{!s}".format(cls.__name__, self.count, self.ea, self.default, self.object.ncases, self.object.jumps, self.register)
    def __repr__(self):
        return u"{!s}".format(self)

def xiterate(ea, start, next):
    '''Utility function for iterating through idaapi's xrefs from `start` to `end`.'''
    getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_flags

    addr = start(ea)
    while addr != idaapi.BADADDR:
        yield addr
        addr = next(ea, addr)
    return

def addressOfRuntimeOrStatic(func):
    """Used to determine if `func` is a statically linked address or a runtime-linked address.

    This returns a tuple of the format `(runtimeQ, address)` where
    `runtimeQ` is a boolean returning true if the symbol is linked
    during runtime.
    """
    import function
    try:
        fn = function.by(func)

    # otherwise, maybe it's an rtld symbol
    except internal.exceptions.FunctionNotFoundError as e:
        import database
        exc_info = sys.exc_info()

        # if func is not an address, then there ain't shit we can do
        if not isinstance(func, six.integer_types): six.reraise(*exc_info)

        # make sure that we're actually data
        if not database.type.is_data(func): six.reraise(*exc_info)

        # ensure that we're an import, otherwise throw original exception
        try:
            database.imports.at(func)
        except internal.exceptions.MissingTypeOrAttribute:
            six.reraise(*exc_info)

        # yep, we're an import
        return True, func

    # check if we're _not_ actually within a function (mis-defined external)
    ea = range.start(fn)
    if not function.within(ea):
        import database

        # ensure that we're an import, otherwise this is definitely not misdefined
        try:
            database.imports.at(ea)
        except internal.exceptions.MissingTypeOrAttribute:
            raise internal.exceptions.FunctionNotFoundError(u"addressOfRuntimeOrStatic({:#x}) : Unable to locate function by address.".format(ea))

        # ok, we found a mis-defined import
        return True, ea

    # nope, we're just a function
    return False, ea

## internal enumerations that idapython missed
class fc_block_type_t(object):
    """
    This namespace contains a number of internal enumerations for
    ``idaapi.FlowChart`` that were missed by IDAPython. This can
    be used for checking the type of the various elements within
    an ``idaapi.FlowChart``.
    """
    fcb_normal = 0  # normal block
    fcb_indjump = 1 # block ends with indirect jump
    fcb_ret = 2     # return block
    fcb_cndret = 3  # conditional return block
    fcb_noret = 4   # noreturn block
    fcb_enoret = 5  # external noreturn block (does not belong to the function)
    fcb_extern = 6  # external normal block
    fcb_error = 7   # block passes execution past the function end

class map_t(object):
    """
    An object used for mapping names to an object. This is used for
    representing the registers available for an architecture.
    """
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
        return "{!s} {:s}".format(self.__class__, internal.utils.string.repr(self.__state__))

class collect_t(object):
    """
    This type is used by coroutines in order to aggregate values
    that are yielded by coroutines. It implements the receiver
    part of a coroutine.
    """
    def __init__(self, cons, f):
        '''Constructs a type using `cons` as the constructor and a callable `f` used to coerce a value into the constructed type.'''
        self.__cons__, self.__agg__ = cons, f
        self.reset()

    def type(self):
        '''Return the constructor that is used for the state.'''
        return self.__cons__

    def reset(self):
        '''Reset the current state.'''
        self.__state__ = self.__cons__()
        return self

    def send(self, value):
        '''Given a `value`, aggregate it into the current state.'''
        f, state = self.__agg__, self.__state__
        self.__state__ = res = f(state, value)
        return res

    def get(self):
        '''Return the current state of the constructed type.'''
        return self.__state__

    def __repr__(self):
        t = self.__cons__
        return "{!s} {!s} -> {!r}".format(self.__class__, getattr(t, '__name__', t), self.__state__)

class architecture_t(object):
    """
    Base class to represent how IDA maps the registers and types
    returned from an operand to a register that's uniquely
    identifiable by the user.

    This is necessary as for some architectures IDA will not include all
    the register names and thus will use the same register index to
    represent two registers that are of different types. As an example,
    on the Intel processor module the `%al` and `%ax` regs are returned in
    the operand as an index to the "ax" string.

    Similarly on the 64-bit version of the processor module, all of the
    registers `%ax`, `%eax`, and `%rax` have the same index.
    """
    __slots__ = ('__register__', '__cache__',)
    r = register = property(fget=lambda s: s.__register__)

    def __init__(self, **cache):
        """Instantiate an ``architecture_t`` object which represents the registers available to an architecture.

        If `cache` is defined, then use the specified dictionary to map
        an IDA register's `(name, dtype)` to a string containing the
        more commonly recognized register name.
        """
        self.__register__, self.__cache__ = map_t(), cache.get('cache', {})

    def new(self, name, bits, idaname=None, **kwargs):
        '''Add a register to the architecture's cache.'''

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

        namespace = {key : value for key, value in register_t.__dict__.items()}
        namespace.update({'__name__':name, '__parent__':None, '__children__':{}, '__dtype__':dtype, '__position__':0, '__size__':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name, dtype] = name
        return res

    def child(self, parent, name, position, bits, idaname=None, **kwargs):
        '''Add a child register to the architecture's cache.'''

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
        namespace = {key : value for key, value in register_t.__dict__.items() }
        namespace.update({'__name__':name, '__parent__':parent, '__children__':{}, '__dtype__':dtype, '__position__':position, '__size__':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', {item for item in []})
        namespace['architecture'] = self
        res = type(name, (register_t,), namespace)()
        self.__register__.__state__[name] = res
        self.__cache__[idaname or name, dtype] = name
        parent.__children__[position] = res
        return res

    def by_index(self, index):
        """Lookup a register according to its `index`.

        The default size is based on the architecture that IDA is using.
        """
        res = idaapi.ph.regnames[index]
        return self.by_name(res)
    byindex = internal.utils.alias(by_index)

    def by_indextype(self, index, dtype):
        """Lookup a register according to its `index` and `dtype`.

        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res, dtype]
        return getattr(self.__register__, name)
    byindextype = internal.utils.alias(by_indextype)

    def by_name(self, name):
        '''Lookup a register according to its `name`.'''
        if any(name.startswith(prefix) for prefix in {'%', '$'}):        # at&t, mips
            return getattr(self.__register__, name[1:].lower())
        if name.lower() in self.__register__:
            return getattr(self.__register__, name.lower())
        return getattr(self.__register__, name)
    byname = internal.utils.alias(by_name)

    def by_indexsize(self, index, size):
        '''Lookup a register according to its `index` and `size`.'''
        dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        dtype = dtype_by_size(size)
        return self.by_indextype(index, dtype)
    byindexsize = internal.utils.alias(by_indexsize)

    def promote(self, register, size=None):
        '''Promote the specified `register` to its next larger `size`.'''
        parent = internal.utils.fcompose(operator.attrgetter('__parent__'), (lambda *items: items), functools.partial(filter, None), iter, next)
        try:
            if size is None:
                return parent(register)
            return register if register.size == size else self.promote(parent(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.promote({:s}{:s}) : Unable to determine the register to promote to.".format('.'.join([__name__, cls.__name__]), register, '' if size is None else ", size={:d}".format(size)))

    def demote(self, register, size=None):
        '''Demote the specified `register` to its next smaller `size`.'''
        childitems = internal.utils.fcompose(operator.attrgetter('__children__'), operator.methodcaller('items'))
        firstchild = internal.utils.fcompose(childitems, functools.partial(sorted, key=operator.itemgetter(0)), iter, next, operator.itemgetter(1))
        try:
            if size is None:
                return firstchild(register)
            return register if register.size == size else self.demote(firstchild(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.demote({:s}{:s}) : Unable to determine the register to demote to.".format('.'.join([__name__, cls.__name__]), register, '' if size is None else ", size={:d}".format(size)))

class bounds_t(namedtypedtuple):
    """
    This tuple is used to represent references that describe a bounds
    and has the format `(left, right)`.
    """
    _fields = ('left', 'right')
    _types = (six.integer_types, six.integer_types)

    def __new__(cls, *args, **kwargs):
        if len(args) == 2 and not kwargs:
            return super(bounds_t, cls).__new__(cls, *sorted(args))

        # create a mapping containing our individual fields given with our
        # arguments. the keyword parameters are given secondary priority to
        # any argument parameters.
        fields = {fld : item for fld, item in zip(cls._fields, args)}
        [ fields.setdefault(fld, kwargs.pop(fld)) for fld in cls._fields if fld in kwargs ]

        # if the size was provided, then we can use it to calculate the
        # right size of our boundaries.
        if all(item in fields for item in cls._fields) and 'size' in kwargs:
            raise TypeError("{!s}() got unexpected keyword argument{:s} {:s}".format(cls.__name__, '' if len(kwargs) == 1 else 's', ', '.join(map("'{!s}'".format, kwargs))))

        elif 'left' in fields and 'size' in kwargs:
            fields.setdefault('right', fields['left'] + kwargs.pop('size'))

        # at this point, we should have all our boundaries. it kwargs has
        # anything left in it or any required fields are not defined, then
        # raise an exception because invalid parameters were passed to us.
        if len(kwargs):
            raise TypeError("{!s}() got unexpected keyword argument{:s} {:s}".format(cls.__name__, '' if len(kwargs) == 1 else 's', ', '.join(map("'{!s}'".format, kwargs))))
        if any(item not in fields for item in cls._fields):
            available, required = ({item for item in items} for items in [fields, cls._fields])
            missing = required - available
            raise TypeError("{!s}() is missing required field{:s} {:s}".format(cls.__name__, '' if len(missing) == 1 else 's', ', '.join(map("'{!s}'".format, (item for item in cls._fields if item in missing)))))

        # now we can use our fields to construct our type properly.
        args = (fields[item] for item in cls._fields)
        return super(bounds_t, cls).__new__(cls, *sorted(args))

    @property
    def size(self):
        '''Return the size of the ``bounds_t``.'''
        left, right = self
        return right - left if left < right else left - right

    @property
    def top(self):
        '''Return the minimum address for the current boundary.'''
        left, right = self
        return min(left, right)

    @property
    def bottom(self):
        '''Return the maximum address for the current boundary.'''
        left, right = self
        return max(left, right)

    def range(self):
        '''Return the current boundary casted to a native ``idaapi.range_t`` type.'''
        left, right = self
        return idaapi.range_t(left, right)

    def translate(self, offset):
        '''Return an instance of the class with its boundaries translated by the provided `offset`.'''
        cls = self.__class__
        left, right = self
        return cls(offset + left, offset + right)

    def contains(self, ea):
        '''Return if the address `ea` is contained by the ``bounds_t``.'''
        left, right = self
        return left <= ea < right if left < right else right <= ea < left
    __contains__ = contains

    def __str__(self):
        cls = self.__class__
        items = ("{!s}={:#x}".format(internal.utils.string.escape(name, ''), value) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(items))

    def __unicode__(self):
        cls = self.__class__
        items = (u"{!s}={:#x}".format(internal.utils.string.escape(name, ''), value) for name, value in zip(self._fields, self))
        return u"{:s}({:s})".format(cls.__name__, u', '.join(items))

    def __repr__(self):
        return u"{!s}".format(self)
