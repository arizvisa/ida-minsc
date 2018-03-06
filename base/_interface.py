"""
Interface module (internal)

This module wraps a number of features provided by IDA so that it can be
dumbed down a bit. This module is used internally and thus doesn't provide
anything that a user should use. Nonetheless, we document this for curious
individuals to attempt to understand this craziness.
"""

import six
import sys, logging, contextlib
import functools, operator, itertools, types
import collections, heapq, traceback, ctypes
import unicodedata as _unicodedata, string as _string

import ui, internal
import idaapi

class typemap:
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
        `[(int, 2), 3]` - a 3 element array of 16-bit integers
        `[(float, 8), 4]` - a 4 element array of 64-bit floating point numbers.
        `[type, 6]` - a 6 element array of pointers

    These types are commonly associated with members of structures
    and thus can be used to quickly read or apply a type to a
    field within a structure.
    """

    FF_MASKSIZE = 0xf0000000    # Mask that select's the flag's size
    FF_MASK = 0xfff00000        # Mask that select's the flag's repr
    # FIXME: In some cases FF_nOFF (where n is 0 or 1) does not actually
    #        get auto-treated as an pointer by ida. Instead, it appears to
    #        only get marked as an "offset" and rendered as an integer.

    # FIXME: Figure out how to update this to use/create an idaapi.tinfo_t()
    #        and also still remain backwards-compatible with the older idaapi.opinfo_t()

    ## IDA 7.0 types
    if idaapi.__version__ >= 7.0:
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
            chr:(idaapi.strlit_flag(), 0),
            str:(idaapi.strlit_flag(), idaapi.STRTYPE_TERMCHR),
            unicode:(idaapi.strlit_flag(), idaapi.STRTYPE_C_16),
        }

        ptrmap = { sz : (idaapi.off_flag()|flg, tid) for sz, (flg, tid) in six.iteritems(integermap) }
        nonemap = { None :(idaapi.align_flag(), -1) }

    ## IDA 6.95 types
    else:
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
            chr:(idaapi.asciflag(), 0),
            str:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            unicode:(idaapi.asciflag(), idaapi.ASCSTR_UNICODE),
        }

        ptrmap = { sz : (idaapi.offflag()|flg, tid) for sz, (flg, tid) in six.iteritems(integermap) }
        nonemap = { None :(idaapi.alignflag(), -1) }

    # lookup table for type
    typemap = {
        int:integermap, long:integermap, float:decimalmap,
        str:stringmap, unicode:stringmap, chr:stringmap,
        type:ptrmap, None:nonemap,
    }

    # inverted lookup table
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

    # defaults
    @classmethod
    def __newprc__(cls, pnum):
        info = idaapi.get_inf_structure()
        bits = 64 if info.is_64bit() else 32 if info.is_32bit() else None
        if bits is None: return

        typemap.integermap[None] = typemap.integermap[bits/8]
        typemap.decimalmap[None] = typemap.decimalmap[bits/8]
        typemap.ptrmap[None] = typemap.ptrmap[bits/8]
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
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        dt = flag & cls.FF_MASKSIZE
        sf = -1 if flag & idaapi.FF_SIGN == idaapi.FF_SIGN else +1
        if dt == FF_STRUCT and isinstance(typeid, six.integer_types):
            # FIXME: figure out how to fix this recursive module dependency
            t = sys.modules.get('structure', __import__('structure')).by_identifier(typeid)
            sz = t.size
            return t if sz == size else [t, size // sz]
        if dt not in cls.inverted:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.dissolve({!r}, {!r}, {!r}) : Unable to locate a pythonic type that matches the specified flag.".format('.'.join(('internal', __name__, cls.__name__)), dt, typeid, size))

        t, sz = cls.inverted[dt]
        # if the type and size are the same, then it's a string or pointer type
        if not isinstance(sz, six.integer_types):
            count = size // idaapi.get_data_elsize(idaapi.BADADDR, dt, idaapi.opinfo_t())
            return [t, count] if count > 1 else t
        # if the size matches, then we assume it's a single element
        elif sz == size:
            return t, (sz*sf)
        # otherwise it's an array
        return [(t, sz*sf), size // sz]

    @classmethod
    def resolve(cls, pythonType):
        '''Convert the provided `pythonType` into IDA's `(flag, typeid, size)`.'''
        struc_flag = idaapi.struflag if idaapi.__version__ < 7.0 else idaapi.stru_flag

        sz, count = None, 1

        # figure out what format pythonType is in
        if isinstance(pythonType, ().__class__):
            (t, sz), count = pythonType, 1
            table = cls.typemap[t]
            flag, typeid = table[abs(sz) if t in {int, long, float, type} else t]

        # an array, which requires us to recurse...
        elif isinstance(pythonType, [].__class__):
            res, count = pythonType
            flag, typeid, sz = cls.resolve(res)

        # if it's a structure, pass it through.
        # FIXME: figure out how to fix this recursive module dependency
        elif isinstance(pythonType, sys.modules.get('structure', __import__('structure')).structure_t):
            flag, typeid, sz = struc_flag(), pythonType.id, pythonType.size

        # default size that we can lookup in the typemap table
        else:
            table = cls.typemap[pythonType]
            flag, typeid = table[None]

            typeid = idaapi.BADADDR if typeid < 0 else typeid
            opinfo = idaapi.opinfo_t()
            opinfo.tid = typeid
            return flag, typeid, idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo)

        typeid = idaapi.BADADDR if typeid < 0 else typeid
        return flag|(idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz)*count

@document.hidden
class prioritybase(object):
    result = type('result', (object,), {})
    CONTINUE = type('continue', (result,), {})()
    STOP = type('stop', (result,), {})()

    def __init__(self):
        self.__cache__ = collections.defaultdict(list)
        self.__disabled = set()
        self.__traceback = {}

    def __iter__(self):
        '''Return the id of each target that is hooked by this object.'''
        for target in self.__cache__:
            yield target
        return

    def __formatter__(self, target):
        raise NotImplementedError

    def connect(self, target, callable):
        raise NotImplementedError

    def disconnect(self, target):
        raise NotImplementedError

    def hook(self):
        '''Physically connect all of the hooks controlled by this class.'''
        notok = False

        # Just iterate through each target and connect a closure for it
        for target in self.__cache__.viewkeys():
            ok = self.connect(target, self.apply(target))
            if not ok:
                logging.warn(u"{:s}.cycle() : Error trying to connect to the specified {:s}.".format('.'.join(('internal', __name__, self.__class__.__name__)), self.__format__(target)))
                notok = True
            continue
        return not notok

    def unhook(self):
        '''Physically disconnect all of the hooks controlled by this class.'''
        notok = False

        # Simply disconnect everything
        for target in self.__cache__.viewkeys():
            ok = self.disconnect(target)
            if not ok:
                logging.warn(u"{:s}.cycle() : Error trying to disconnect from the specified {:s}.".format('.'.join(('internal', __name__, self.__class__.__name__)), self.__format__(target)))
                notok = True
            continue
        return not notok

    def enable(self, target):
        '''Enable any callables for the specified `target` that has been previously disabled.'''
        if target not in self.__disabled:
            cls = self.__class__
            logging.fatal(u"{:s}.enable({:#x}) : The requested {:s} is not disabled. Currently disabled hooks are: {:s}.".format('.'.join(('internal', __name__, cls.__name__)), target, self.__formatter__(target), "{{{:s}}}".format(', '.join(map("{:#x}".format, self.__disabled)))))
            return False
        self.__disabled.discard(target)
        return True

    def disable(self, target):
        '''Disable execution of all the callables for the specified `target`.'''
        cls = self.__class__
        if target not in self.__cache__:
            logging.fatal(u"{:s}.disable({!r}) : The requested {:s} does not exist. Available notifications are: {:s}.".format('.'.join(('internal', __name__, cls.__name__)), target, self.__formatter__(target), "{{{:s}}}".format(', '.join(map("{:#x}".format, self.__cache__.viewkeys())))))
            return False
        if target in self.__disabled:
            logging.warn(u"{:s}.disable({!r}) : {:s} has already been disabled. Currently disabled notifications are: {:s}.".format('.'.join(('internal', __name__, cls.__name__)), target, self.__formatter__(target).capitalize(), "{{{:s}}}".format(', '.join(map("{:#x}".format, self.__disabled)))))
            return False
        self.__disabled.add(target)
        return True

    def add(self, target, callable, priority):
        '''Add the `callable` to our queue for the specified `target` with the provided `priority`.'''

        # connect to the requested target if possible
        if target not in self.__cache__ and not self.connect(target, self.apply(target)):
            cls = self.__class__
            raise NameError(u"{:s}.add({:#x}, {!r}, priority={:d}) : Unable to connect to the specified {:s}.".format('.'.join(('internal', __name__, cls.__name__)), target, callable, priority, self.__formatter__(target)))

        # discard any callables already attached to the specified target
        self.discard(target, callable)

        # add the callable to our priority queue
        res = self.__cache__[target]
        heapq.heappush(self.__cache__[target], (priority, callable))

        # preserve a backtrace so we can track where our callable is at
        self.__traceback[(target, callable)] = traceback.extract_stack()[:-1]
        return True

    def get(self, target):
        '''Return all of the callables that are attached to the specified `target`.'''
        res = self.__cache__[target]
        return tuple(callable for _, callable in res)

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
            self.__cache__[target][:] = state

        # Otherwise we found nothing and we can remove the entire target
        # from our cache.
        else:
            self.__cache__.pop(target, [])

        return True if found else False

    def apply(self, target):
        '''Return a closure that will execute all of the hooks for the specified `target`.'''

        ## Define the closure that we'll hand off to connect
        def closure(*parameters):
            if target not in self.__cache__ or target in self.__disabled:
                return

            # Iterate through our priorityqueue extracting each callable and
            # executing it with the parameters we received
            hookq = self.__cache__[target][:]
            for priority, callable in heapq.nsmallest(len(hookq), hookq):
                logging.debug(u"{:s}.closure({:s}) : Dispatching parameters ({:s}) to callback ({:s}) with priority ({:+d})".format('.'.join(('internal', __name__, self.__class__.__name__)), ', '.join(map("{!r}".format, parameters)), ', '.join(map("{!r}".format, parameters)), callable, priority))

                try:
                    result = callable(*parameters)

                # if we caught an exception, then inform the user about it and stop processing our queue
                except:
                    cls = self.__class__
                    bt = traceback.format_list(self.__traceback[target, callable])
                    current = str().join(traceback.format_exception(*sys.exc_info()))

                    format = functools.partial(u"{:s}.callback({:s}) : {:s}".format, '.'.join(('internal', __name__, cls.__name__)), ', '.join(map("{!r}".format, parameters)))
                    logging.fatal(format(u"Callback for {:s} with priority ({:+d}) raised an exception while executing {!r}".format(self.__formatter__(target), priority, callable)))
                    logging.warn(format("Traceback ({:s} was hooked at)".format(self.__formatter__(target))))
                    [ logging.warn(format(item)) for item in str().join(bt).split('\n') ]
                    [ logging.warn(format(item)) for item in current.split('\n') ]

                    result = self.STOP

                if not isinstance(result, self.result) or result == self.CONTINUE:
                    continue

                elif result == self.STOP:
                    break

                cls = self.__class__
                raise TypeError("{:s}.callback({:s}) : Unable to determine the result ({!r}) returned from callable ({!r}).".format('.'.join(('internal', __name__, cls.__name__)), ', '.join(map("{!r}".format, parameters)), result, callable))
            return

        # That's it!
        return closure

@document.hidden
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
        return method

    def remove(self):
        '''Unhook the instance completely.'''
        return self.object.unhook()

    def __formatter__(self, name):
        return "\"{:s}.{:s}\"".format(self.__type__.__name__, name)

    def __hook(self):
        if not self.object.hook():
            cls = self.__class__
            logging.debug(u"{:s}.hook(...) : Unable to hook with object ({!r}).".format('.'.join(('internal', __name__, cls.__name__)), self.object))
            return False
        return True

    def __unhook(self):
        if not self.object.unhook():
            cls = self.__class__
            logging.debug(u"{:s}.unhook(...) : Error trying to unhook object ({!r}).".format('.'.join(('internal', __name__, cls.__name__)), self.object))
            return False
        return True

    @contextlib.contextmanager
    def __context__(self):
        try:
            yield self.object.unhook()
        finally:
            pass
        self.object.hook()

    def hook(self):
        '''Physically connect all of the hooks managed by this class.'''
        ok = super(priorityhook, self).hook()
        self.__hook()
        return ok

    def unhook(self):
        '''Physically disconnect all of the hooks managed by this class.'''
        self.__unhook()
        return super(priorityhook, self).unhook()

    def connect(self, name, callable):
        '''Connect the hook `callable` to the specified `name`.'''
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError("{:s}.connect({!r}) : Unable to connect to the specified hook due to the method ({:s}) being unavailable.".format('.'.join(('internal', __name__, cls.__name__)), name, method))

        # create a closure that calls our callable, and its supermethod
        supermethod = self.__make_dummy_method(name)
        def closure(instance, *args, **kwargs):
            callable(*args, **kwargs)
            return supermethod(instance, *args, **kwargs)

        # unhook, assign our new method, and then re-hook
        with self.__context__():
            method = types.MethodType(closure, self.object, self.__type__)
            setattr(self.object, name, method)
        return True

    def disconnect(self, name):
        '''Disconnect the hook from the specified `name`.'''
        def closure(instance, *parameters):
            supermethod = getattr(super(cls, instance), name)
            return supermethod(*parameters)
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError("{:s}.disconnect({!r}, {!r}) : Unable to disconnect from the specified hook ({:s}).".format('.'.join(('internal', __name__, cls.__name__)), name, callable, method))
        method = types.MethodType(closure, self.object, self.__type__)
        setattr(self.object, name, method)
        return True

    def discard(self, name, callable):
        '''Discard the specified `callable` from hooking the event `name`.'''
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError("{:s}.discard({!r}, {!r}) : Unable to discard method for hook as the specified hook ({:s}) is unavailable.".format('.'.join(('internal', __name__, cls.__name__)), name, callable, method))
        return super(priorityhook, self).discard(name, callable)

    def apply(self, name):
        '''Apply the currently registered callables to the event `name`.'''
        if not hasattr(self.object, name):
            cls, method = self.__class__, '.'.join([self.object.__class__.__name__, name])
            raise NameError("{:s}.apply({!r}) : Unable to apply the specified hook due to the method ({:s}) being unavailable.".format('.'.join(('internal', __name__, cls.__name__)), name, method))
        return super(priorityhook, self).apply(name)

@document.hidden
class prioritynotification(prioritybase):
    """
    Helper class for allowing one to apply an arbitrary number of hooks to the
    different notification points within IDA.
    """
    def __init__(self):
        super(prioritynotification, self).__init__()
        self.hook()

    def __formatter__(self, notification):
        return "notification ({:#x})".format(notification)

    def connect(self, notification, closure):
        '''Connect to the specified `notification` in order to execute any callables provided by the user.'''
        return idaapi.notify_when(notification, closure)

    def disconnect(self, notification):
        '''Disconnect from the specified `notification` so that nothing will execute.'''
        def closure(*parameters):
            return True
        return idaapi.notify_when(notification | idaapi.NW_REMOVE, closure)

    def apply(self, notification):
        '''Return a closure that will execute all of the hooks for the specified `notification`.'''
        if notification not in {idaapi.NW_INITIDA, idaapi.NW_TERMIDA, idaapi.NW_OPENIDB, idaapi.NW_CLOSEIDB}:
            cls = self.__class__
            raise ValueError("{:s}.apply({:#x}): Unable to apply the specified notification ({:#x}) due to the value being invalid.".format('.'.join(('internal', __name__, cls.__name__)), notification, notification))

        return super(prioritynotification, self).apply(notification)

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
        info = idaapi.get_inf_structure()
        return info.minEA, info.maxEA

    @classmethod
    def __within__(cls, ea):
        l, r = cls.__bounds__()
        return l <= ea < r

    @classmethod
    def __head1__(cls, ea, **silent):
        '''Adjusts `ea` so that it is pointing to the beginning of an item.'''
        entryframe = cls.pframe()
        logF = logging.warn if not silent.get('silent', False) else logging.debug

        res = idaapi.get_item_head(ea)
        if ea != res:
            logF("{:s} : Specified address {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, res))
        return res
    @classmethod
    def __head2__(cls, start, end, **silent):
        '''Adjusts both `start` and `end` so that each are pointing to the beginning of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warn if not silent.get('silent', False) else logging.debug

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
        logF = logging.warn if not silent.get('silent', False) else logging.debug

        res = idaapi.get_item_end(ea)
        if ea != res:
            logF("{:s} : Specified address {:#x} not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, res))
        return res
    @classmethod
    def __tail2__(cls, start, end, **silent):
        '''Adjusts both `start` and `end` so that each are pointing to the end of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warn if not silent.get('silent', False) else logging.debug

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

        # FIXME: off-by-one here, as end can be the size of the db.
        if any(not cls.__within__(ea) for ea in (start, end-1)):
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

    # Assign them based on the IDA version
    start, end = (start_6x, end_6x) if idaapi.__version__ < 7.0 else (start_7x, end_7x)

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
    def sup_functype(sup):
        """Given a supval, return the pointer size, model, and calling convention for a function.

        This string is typically found in a supval[0x3000] of a function.
        """
        res, iterable = [], iter(sup)
        onext = internal.utils.fcompose(next, six.byte2int)

        # pointer and model
        by = onext(iterable)
        if by & 0xf0:
            # FIXME: If this doesn't match, then this is a type that forwards to the real function type.
            raise internal.exceptions.UnsupportedCapability(u"{:s}.sup_functype(\"{!s}\") : Forwarded function prototypes are currently unsupported (current byte is {:#0{:d}x}).".format('.'.join(('internal', node.__name__)), sup.encode('hex'), by, 2 + 2))
        res.append( (by & idaapi.CM_MASK) )
        res.append( (by & idaapi.CM_M_MASK) )

        # calling convention
        by = onext(iterable)
        cc, count = by & idaapi.CM_CC_MASK, by & 0x0f
        if cc == idaapi.CM_CC_SPOILED:
            if count != 15:
                lookup = { getattr(idaapi, name) : "idaapi.{:s}".format(name) for name in dir(idaapi) if name.startswith('CM_CC_') }
                raise internal.exceptions.UnsupportedCapability(u"{:s}.sup_functype(\"{!s}\") : The calling convention {!s}({:d}) with a count ({:d}) not equal to {:d} is not supported (current byte is {:#0{:d}x}).".format('.'.join(('internal', node.__name__)), sup.encode('hex'), lookup[cc], cc, count, 15, by, 2 + 2))
            funcattr = onext(iterable)
            by = onext(iterable)
            res.append( (by & idaapi.CM_CC_MASK) )
        else:
            res.append(cc)

        # FIXME: terminate ahead of time because decoding the return type seemed more work than I desired to commit
        return tuple(res)

        # XXX: implement a parser for type_t in order to figure out idaapi.BT_COMPLEX types
        # return type_t
        data = six.next(iterable)
        base, flags, mods = six.byte2int(data) & idaapi.TYPE_BASE_MASK, six.byte2int(data) & idaapi.TYPE_FLAGS_MASK, six.byte2int(data) & idaapi.TYPE_MODIF_MASK
        if base == idaapi.BT_PTR:
            data+= six.next(iterable)
        elif base == idaapi.BT_COMPLEX and flags == 0x30:
            by = six.next(iterable)
            skip, data = six.byte2int(by), data + by
            while skip > 1:
                data+= six.next(iterable)
                skip -= 1
        elif base in {idaapi.BT_ARRAY, idaapi.BT_FUNC, idaapi.BT_COMPLEX, idaapi.BT_BITFIELD}:
            lookup = { getattr(idaapi, name) : "idaapi.{:s}".format(name) for name in dir(idaapi) if name.startswith('BT_') }
            if base == idaapi.BT_COMPLEX:
                raise internal.exceptions.UnsupportedCapability(u"{:s}.sup_functype(\"{!s}\") : Calling conventions that return an {!s}({:d}) where the flags ({:#x} are not equal to {:#x} are currently not supported. The flags and the modification flags ({:#x}) were extracted from the byte {:#{:d}x}.".format('.'.join(('internal', node.__name__)), sup.encode('hex'), lookup[base], base, flags, 0x30, mods, six.byte2int(data), 2+2))
            raise internal.exceptions.UnsupportedCapability(u"{:s}.sup_functype(\"{!s}\") : Calling conventions that return an {!s}({:d}) are currently not supported. The flags ({:#x}) and the modification flags ({:#x}) were extracted from the byte {:#{:d}x}.".format('.'.join(('internal', node.__name__)), sup.encode('hex'), lookup[base], base, flags, mods, six.byte2int(data), 2+2))

        # append the return type
        res.append(data)

        # append the number of arguments
        by = onext(iterable)
        res.append(by)

        # Everything else in the iterable is an array of type_t as found in "Type flags" in the SDK docs.
        ''.join(iterable)

        # now we can return the whole thing
        return tuple(res)

    @staticmethod
    def sup_opstruct(sup, bit64Q):
        """Given a supval, return the list of the encoded structure/field ids.

        This string is typically found in a supval[0xF+opnum] of the instruction.
        """
        le = internal.utils.fcompose(
            functools.partial(map, six.byte2int),
            functools.partial(reduce, lambda t, c: (t*0x100)|c)
        )
        ror = lambda n, shift, bits: (n>>shift) | ((n & 2**shift - 1) << (bits - shift))

        # 16-bit
        # 0001 9ac1 -- _SYSTEMTIME

        # 32-bit
        # 0001 c0006e92 -- ULARGE_INTEGER
        # 0002 c0006e92 c0006e98 -- ULARGE_INTEGER.quadpart
        # 0002 c0006e92 c0006e97 -- ULARGE_INTEGER.u.lowpart
        # 0002 c0006e92 c0006e96 -- ULARGE_INTEGER.s0.lowpart
        # (x ^ 0x3f000000)

        def id32(sup):
            count, res = le(sup[:2]), sup[2:]
            if len(res) == 2:
                if count > 1:
                    raise internal.exceptions.SizeMismatchError(u"{:s}.op_id(\"{:s}\") -> id32 : The count for the 16-bit identifier ({:d}) is larger than the expected count ({:d}).".format('.'.join(('internal', __name__)), sup.encode('hex'), count, 1))
                return (0xff000000 | 0x8000 ^ le(res),)

            chunks = zip(*((iter(res),) * 4))
            if len(chunks) != count:
                raise internal.exceptions.SizeMismatchError(u"{:s}.op_id(\"{:s}\") -> id32 : The number of chunks ({:d}) does not match the count ({:d}). These chunks are {!r}.".format('.'.join(('internal', __name__)), sup.encode('hex'), len(chunks), count, map(''.join, chunks)))
            res = map(le, chunks)
            res = map(functools.partial(operator.xor, 0x3f000000), res)
            return tuple(res)

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
            iterable = iter(sup)
            #chunks = zip(*((iter(sup),)*3))
            length = le((six.next(iterable), six.next(iterable), six.next(iterable)))
            chunks = zip(*((iterable,)*5))
            #length = le(chunks.pop(0))
            if len(chunks) != length:
                raise internal.exceptions.SizeMismatchError(u"{:s}.op_id(\"{:s}\") -> id64 : Number of chunks ({:d}) does not match the extracted length ({:d}). These chunks are {!r}.".format('.'.join(('internal', __name__)), sup.encode('hex'), len(chunks), length, map(''.join, chunks)))
            res = map(le, chunks)
            res = map(functools.partial(operator.xor, 0xc0000000ff), res)
            return tuple(ror(n, 8, 64) for n in res)

        return id64(sup) if bit64Q else id32(sup)

    @staticmethod
    def alt_opinverted(ea, opnum):
        '''Return whether the operand `opnum` at the address `ea` has its sign inverted or not.'''
        OP_REPR, INVERT_BIT = 8, 0x100000
        return internal.netnode.alt.get(ea, OP_REPR) & (INVERT_BIT << opnum) != 0

@document.hidden
def tuplename(*names):
    '''Given a tuple as a name, return a single name joined by "_" characters.'''
    res = ("{:x}".format(abs(n)) if isinstance(n, six.integer_types) else n for n in names)
    return '_'.join(res)

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
                raise TypeError("Unexpected type ({!r}) for field {:s} should be {!r}.".format(type(x), n.encode('utf8') if isinstance(n, unicode) else n, t))
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
                raise TypeError("Unexpected type ({!r} for field {:s} should be {!r}.".format(type(x), n.encode('utf8') if isinstance(n, unicode) else n, t))
            continue
        return result

    @classmethod
    def _type(cls, name):
        '''Return the type for the field `name`.'''
        res = (t for n, t in zip(cls._fields, cls._types) if n == name)
        try:
            result = six.next(res)
        except StopIteration:
            raise NameError("Unable to locate the type for an unknown field {!r}.".format(name))
        return result

    def __getattribute__(self, name):
        try:
            # honor the ._fields first
            res = object.__getattribute__(self, '_fields')
            res = map(operator.methodcaller('lower'), res)
            res = operator.itemgetter(res.index(name.lower()))
        except (IndexError, ValueError):
            res = lambda s: object.__getattribute__(s, name)
        return res(self)

    def __repr__(self):
        cls = self.__class__
        res = ("{!s}={!s}".format(internal.utils.string.escape(name, ''), internal.utils.string.repr(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    def _replace(self, **fields):
        '''Assign the specified `fields` to the fields within the tuple.'''
        fc = fields.copy()
        result = self._make(map(fc.pop, self._fields, self))
        if fc:
            cls = self.__class__
            logging.warn(u"{:s}._replace({:s}) : Unable to assign unknown field names ({:s}) to tuple.".format('.'.join(('internal', __name__, cls.__name__)), internal.utils.string.kwargs(fields), '{' + ', '.join(map(internal.utils.string.repr, six.viewkeys(fc))) + '}'))
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
        '''Returns True if the `other` register is a sub-part of `self`.'''
        return other in six.viewvalues(self.__children__)

    def subsetQ(self, other):
        '''Returns true if the `other` register is a part of `self`.'''
        def collect(node):
            res = set([node])
            [res.update(collect(n)) for n in six.itervalues(node.__children__)]
            return res
        return other in self.alias or other in collect(self)

    def supersetQ(self, other):
        '''Returns true if the `other` register actually contains `self`.'''
        res, pos = set(), self
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
            raise internal.exceptions.InvalidParameterError(u"{:s}({:s}{:s}) : The specified registers are empty.".format('.'.join(('internal', __name__, cls.__name__)), args, (', '+mods) if mods else ''))
        use, iterops = cls.use(regs), cls.modifier(**modifiers)
        def match(ea):
            return any(map(functools.partial(use, ea), iterops(ea)))
        return match

    @classmethod
    def use(cls, regs):
        '''Return a closure that checks if an address and opnum uses the specified `regs`.'''
        _instruction = sys.modules.get('instruction', __import__('instruction'))

        # convert any regs that are strings into their correct object type
        regs = { _instruction.architecture.by_name(r) if isinstance(r, basestring) else r for r in regs }

        # returns an iterable of bools that returns whether r is a subset of any of the registers in `regs`.
        match = lambda r, regs=regs: any(itertools.imap(r.relatedQ, regs))

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
        iterops = internal.utils.fcompose(_instruction.ops_count, six.moves.range, sorted)

        # if `read` is specified, then only grab operand indexes that are read from
        if modifiers.get('read', False):
            iterops = _instruction.ops_read

        # if `write` is specified that only grab operand indexes that are written to
        if modifiers.get('write', False):
            iterops = _instruction.ops_write
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
class ref_t(set):
    """
    An object representing a reference type that allows one to easily extract
    semantics using set membership. This type uses "rwx" from posix file
    permissions to simplify reference semantics. It is bests to treat this
    object as a string.

    When testing membership, "r" means read, "w" means write, and "x" means
    execute. This makes it very easy to test whether a reference is reading
    and executing something, or it's writing to its target.
    """

    F = 0

    if idaapi.__version__ < 7.0:
        __mapper__ = {
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
        }
    __mapper__[31] = '*'        # code 31 used internally by ida-minsc

    def __and__(self, type):
        return type in self

    def __str__(self):
        return str().join(sorted(self))
    def __repr__(self):
        return "ref_t({:s})".format(str().join(sorted(self)))

    def __init__(self, xrtype, iterable):
        '''Construct a ``ref_t`` using `xrtype` and any semantics specified in `iterable`.'''
        self.F = xrtype
        self.update(iterable)

    @classmethod
    def of(cls, xrtype):
        '''Convert an IDA reference type in `xrtype` to a ``ref_t``.'''
        res = cls.__mapper__.get(xrtype, '')
        return cls(xrtype, res)
    of_type = of

    @classmethod
    def of_state(cls, state):
        '''Convert a ``ref_t`` in `state` back into an IDA reference type.'''
        if state == '*':
            return cls(31, '*')     # code 31 used internally by ida-minsc
        elif state == 'rw':
            state = 'w'
        res = set(state)
        for F, t in six.iteritems(cls.__mapper__):
            if set(t) == res:
                return cls(F, str().join(sorted(res)))
            continue
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_state({!r}) : Unable to find the cross-reference type that matches requested state.".format('.'.join(('internal', __name__, cls.__name__)), str().join(sorted(res))))

@document.classdef
class AddressOpnumReftype(namedtypedtuple):
    """
    This tuple is used to represent references that include an operand number
    and has the format `(address, opnum, ref_t)`. The operand number is
    optional as not all references will provide it.
    """
    _fields = ('address', 'opnum', 'reftype')
    _types = (six.integer_types, (types.NoneType,) + six.integer_types, ref_t)
OREF = AddressOpnumReftype

# XXX: is .startea always guaranteed to point to an instruction that modifies
#      the switch's register? if so, then we can use this to calculate the
#      .range/.cases more accurately instead of them being based on .elbase.
@document.classdef
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
        import database
        if self.indirectQ():
            ea, count = self.object.jumps, self.object.jcases
            return database.get.array(ea, length=count)
        ea, count = self.object.jumps, self.object.ncases
        return database.get.array(ea, length=count)
    @property
    def index(self):
        '''Return the contents of the case or index table.'''
        import database
        if self.indirectQ():
            ea, count = self.object.lowcase, self.object.ncases
            return database.get.array(ea, length=count)
        return database.get.array(self.object.jumps, length=0)
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
        f = lambda ea, dflt=self.default: (ea == dflt) or (instruction.type.is_jmp(ea) and instruction.op(ea, 0) == dflt)
        return tuple(idx for idx in six.moves.range(self.base, self.base+self.count) if not f(self.case(idx)))
    @property
    def range(self):
        '''Return all of the possible cases for the switch.'''
        return tuple(six.moves.range(self.base, self.base+self.count))
    def __repr__(self):
        cls = self.__class__
        if self.indirectQ():
            return "<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} index[{:d}]:*{:#x} register:{:s}".format(cls.__name__, self.count, self.ea, self.default, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return "<class '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} register:{:s}".format(cls.__name__, self.count, self.ea, self.default, self.object.ncases, self.object.jumps, self.register)

@document.hidden
def xiterate(ea, start, next):
    '''Utility function for iterating through idaapi's xrefs from `start` to `end`.'''
    getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_flags
    ea = ea if getflags(ea) & idaapi.FF_DATA else idaapi.prev_head(ea, 0)

    addr = start(ea)
    while addr != idaapi.BADADDR:
        yield addr
        addr = next(ea, addr)
    return

@document.hidden
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
    except internal.exceptions.FunctionNotFoundError, e:
        import database
        exc_info = sys.exc_info()

        # if func is not an address, then there ain't shit we can do
        if not isinstance(func, six.integer_types): six.reraise(*exc_info)

        # make sure that we're actually data
        if not database.is_data(func): six.reraise(*exc_info)

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
            raise internal.exceptions.FunctionNotFoundError(u"{:s}.addressOfRuntimeOrStatic({#x}) : Unable to locate function by address.".format(cls.__name__, ea))

        # ok, we found a mis-defined import
        return True, func

    # nope, we're just a function
    return False, ea

## internal enumerations that idapython missed
class fc_block_type_t:
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
        return "{:s} {!s}".format(self.__class__, internal.utils.string.repr(self.__state__))

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
        return "{:s} {!s} -> {!r}".format(self.__class__, getattr(t, '__name__', t), self.__state__)

@document.classdef
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
        # newer
        else:
            dtype_by_size = idaapi.get_dtype_by_size

        #dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        dtype = six.next((kwargs[n] for n in ('dtyp', 'dtype', 'type') if n in kwargs), idaapi.dt_bitfield if bits == 1 else dtype_by_size(bits // 8))

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
        '''Add a child register to the architecture's cache.'''

        # older
        if idaapi.__version__ < 7.0:
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
        # newer
        else:
            dtype_by_size = idaapi.get_dtype_by_size

        dtype = six.next((kwargs[n] for n in ('dtyp', 'dtype', 'type') if n in kwargs), idaapi.dt_bitfield if bits == 1 else dtype_by_size(bits // 8))
        #dtyp = kwargs.get('dtyp', idaapi.dt_bitfild if bits == 1 else dtype_by_size(bits//8))
        namespace = dict(register_t.__dict__)
        namespace.update({'__name__':name, '__parent__':parent, '__children__':{}, '__dtype__':dtype, '__position__':position, '__size__':bits})
        namespace['realname'] = idaname
        namespace['alias'] = kwargs.get('alias', set())
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

    def by_indextype(self, index, dtype):
        """Lookup a register according to its `index` and `dtype`.

        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res, dtype]
        return getattr(self.__register__, name)

    def by_name(self, name):
        '''Lookup a register according to its `name`.'''
        if any(name.startswith(prefix) for prefix in ('%', '$')):        # at&t, mips
            return getattr(self.__register__, name[1:].lower())
        if name.lower() in self.__register__:
            return getattr(self.__register__, name.lower())
        return getattr(self.__register__, name)

    def by_indexsize(self, index, size):
        '''Lookup a register according to its `index` and `size`.'''
        dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtype_by_size
        dtype = dtype_by_size(size)
        return self.by_indextype(index, dtype)
    def promote(self, register, size=None):
        '''Promote the specified `register` to its next larger `size`.'''
        parent = internal.utils.fcompose(operator.attrgetter('__parent__'), internal.utils.fbox, functools.partial(filter, None), iter, next)
        try:
            if size is None:
                return parent(register)
            return register if register.size == size else self.promote(parent(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.promote({:s}{:s}) : Unable to determine the register to promote to.".format('.'.join(('internal', __name__, cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))
    def demote(self, register, size=None):
        '''Demote the specified `register` to its next smaller `size`.'''
        childitems = internal.utils.fcompose(operator.attrgetter('__children__'), operator.methodcaller('iteritems'))
        firstchild = internal.utils.fcompose(childitems, functools.partial(sorted, key=operator.itemgetter(0)), iter, next, operator.itemgetter(1))
        try:
            if size is None:
                return firstchild(register)
            return register if register.size == size else self.demote(firstchild(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise internal.exceptions.RegisterNotFoundError(u"{:s}.demote({:s}{:s}) : Unable to determine the register to demote to.".format('.'.join(('internal', __name__, cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))

@document.classdef
class bounds_t(namedtypedtuple):
    """
    This tuple is used to represent references that describe a bounds
    and has the format `(left, right)`.
    """
    _fields = ('left', 'right')
    _types = (six.integer_types, six.integer_types)

