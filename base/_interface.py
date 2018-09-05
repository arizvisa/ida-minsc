import six
import sys, logging
import functools, operator, itertools, types
import collections, heapq, traceback, ctypes

import ui, internal
import idaapi

class typemap:
    """
    Convert bidirectionally from a pythonic type into an idaapi type
    """

    FF_MASKSIZE = 0xf0000000    # Mask that select's the flag's size
    FF_MASK = 0xfff00000        # Mask that select's the flag's repr
    # FIXME: In some cases FF_nOFF (where n is 0 or 1) does not actually
    #        get auto-treated as an pointer by ida. Instead, it appears to
    #        only get marked as an "offset" and rendered as an integer.

    # FIXME: Figure out how to update this to use/create an idaapi.tinfo_t()
    #        and also still remain backwards-compatible with the older idaapi.opinfo_t()

    integermap = {
        1:(idaapi.byteflag(), -1),  2:(idaapi.wordflag(), -1),  3:(idaapi.tribyteflag(), -1),
        4:(idaapi.dwrdflag(), -1),  8:(idaapi.qwrdflag(), -1), 10:(idaapi.tbytflag(), -1),
        16:(idaapi.owrdflag(), -1),
    }
    if idaapi.__version__ >= 7.0:
        del integermap[3]
    if hasattr(idaapi, 'ywrdflag'): integermap[32] = getattr(idaapi, 'ywrdflag')(), -1

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
    inverted[idaapi.FF_STRU] = (int, 1)  # FIXME: hack for dealing with
                                        #   structures that have the flag set
                                        #   but aren't actually structures..

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
    def dissolve(cls, flag, typeid, size):
        dt = flag & cls.FF_MASKSIZE
        sf = -1 if flag & idaapi.FF_SIGN == idaapi.FF_SIGN else +1
        if dt == idaapi.FF_STRU and isinstance(typeid, six.integer_types):
            # FIXME: figure out how to fix this recursive module dependency
            t = sys.modules.get('structure', __import__('structure')).instance(typeid)
            sz = t.size
            return t if sz == size else [t, size // sz]
        if dt not in cls.inverted:
            logging.warn("{:s}.dissolve({!r}, {!r}, {!r}) : Unable to identify a pythonic type.".format('.'.join(('internal', __name__, cls.__name__)), dt, typeid, size))

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
        """Return ida's (flag, typeid, size) given the type (type, size) or (type/instance)
        (int, 4)     -- a dword
        [(int, 4), 8] -- an array of 8 dwords
        (str, 10)    -- an ascii string of 10 characters
        (int, 2)     -- a word
        [chr, 4]     -- an array of 4 characters
        """
        sz, count = None, 1
        # FIXME: figure out how to fix this recursive module dependency

        # figure out what format pythonType is in
        if isinstance(pythonType, ().__class__):
            (t, sz), count = pythonType, 1
            table = cls.typemap[t]
            flag, typeid = table[abs(sz) if t in {int, long, float, type} else t]

        elif isinstance(pythonType, [].__class__):
            # an array, which requires us to recurse...
            res, count = pythonType
            flag, typeid, sz = cls.resolve(res)

        elif isinstance(pythonType, sys.modules.get('structure', __import__('structure')).structure_t):
            # it's a structure, pass it through.
            flag, typeid, sz = idaapi.struflag(), pythonType.id, pythonType.size

        else:
            # default size that we can lookup in the typemap table
            table = cls.typemap[pythonType]
            flag, typeid = table[None]

            typeid = idaapi.BADADDR if typeid < 0 else typeid
            opinfo = idaapi.opinfo_t()
            opinfo.tid = typeid
            return flag, typeid, idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo)

        typeid = idaapi.BADADDR if typeid < 0 else typeid
        return flag|(idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz)*count

class priorityhook(object):
    '''Helper class for hooking different parts of IDA.'''
    result = type('result', (object,), {})
    CONTINUE = type('continue', (result,), {})()
    STOP = type('stop', (result,), {})()

    def __init__(self, hooktype, **exclude):
        exclusions = set(exclude.get('exclude', ()))
        self.__type__ = hooktype
        self.__cache = collections.defaultdict(list)
        self.object = self.cycle(self.__type__())
        self.__disabled = set()
        self.__traceback = {}

    def remove(self):
        '''Unhook the object completely.'''
        return self.object.unhook()

    def enable(self, name):
        '''Enable any hooks for the ``name`` event that have been previously disabled.'''
        if name not in self.__disabled:
            logging.fatal("{:s}.enable : Hook {:s} is not disabled. : {:s}".format('.'.join(('internal', __name__, cls.__name__)), '.'.join((self.__type__.__name__, name)), '{'+', '.join(self.__disabled)+'}'))
            return False
        self.__disabled.discard(name)
        return True
    def disable(self, name):
        '''Disable execution of all the hooks for the ``name`` event.'''
        if name not in self.__cache:
            logging.fatal("{:s}.disable : Hook {:s} does not exist. : {:s}".format('.'.join(('internal', __name__, cls.__name__)), '.'.join((self.__type__.__name__, name)), '{'+', '.join(self.__cache.viewkeys())+'}'))
            return False
        if name in self.__disabled:
            logging.warn("{:s}.disable : Hook {:s} has already been disabled. : {:s}".format('.'.join(('internal', __name__, cls.__name__)), '.'.join((self.__type__.__name__, name)), '{'+', '.join(self.__disabled)+'}'))
            return False
        self.__disabled.add(name)
        return True
    def __iter__(self):
        '''Return the name of each event that is hooked by this object.'''
        for name in self.__cache:
            yield name
        return

    def cycle(self, object=None):
        '''Cycle the hooks for this object with the idaapi.*_Hooks instance provided by ``object``.'''
        cls = self.__class__
        # uhook previous object
        ok = object.unhook()
        if not ok:
            logging.debug("{:s}.cycle : Error trying to unhook object. : {!r}".format('.'.join(('internal', __name__, cls.__name__)), object))

        namespace = { name : self._new_(name) for name in self.__cache.viewkeys() }
        res = type(object.__class__.__name__, (self.__type__,), namespace)
        object = res()

        ok = object.hook()
        if not ok:
            logging.debug("{:s}.cycle : Unable to hook with object. : {!r}".format('.'.join(('internal', __name__, cls.__name__)), object))
        return object

    def add(self, name, function, priority=50):
        '''Add a hook for the event ``name`` to call the requested ``function`` at the given ``priority (lower is prioritized).'''
        if name not in self.__cache:
            res = self._new_(name)
            setattr(self.object, name, res)
        self.discard(name, function)

        # add function to cache
        res = self.__cache[name]
        heapq.heappush(self.__cache[name], (priority, function))

        # save the backtrace in case function errors out
        self.__traceback[(name, function)] = traceback.extract_stack()[:-1]
        return True

    def get(self, name):
        '''Return all the functions that are hooking the event ``name``.'''
        res = self.__cache[name]
        return tuple(f for _, f in res)

    def discard(self, name, function):
        '''Discard the specified ``function`` from hooking the event ``name``.'''
        if not hasattr(self.object, name):
            cls = self.__class__
            raise AttributeError("{:s}.add({!r}, {!r}) : Unable to add a method to hooker for unknown method.".format('.'.join(('internal', __name__, cls.__name__)), name, function))
        if name not in self.__cache: return False

        res, found = [], 0
        for i, (p, f) in enumerate(self.__cache[name][:]):
            if f != function:
                res.append((p, f))
                continue
            found += 1

        if res: self.__cache[name][:] = res
        else: self.__cache.pop(name, [])

        return True if found else False

    def _new_(self, name):
        '''Overwrite the hook ``name`` with a priorityhook.'''
        if not hasattr(self.object, name):
            cls = self.__class__
            raise AttributeError("{:s}._new_({!r}) : Unable to create a hook for unknown method.".format('.'.join(('internal', __name__, cls.__name__)), name))

        def method(hookinstance, *args):
            if name in self.__cache and name not in self.__disabled:
                hookq = self.__cache[name][:]

                for _, func in heapq.nsmallest(len(hookq), hookq):
                    try:
                        res = func(*args)
                    except:
                        cls = self.__class__
                        message = functools.partial("{:s}.callback : {:s}".format, '.'.join(('internal', __name__, cls.__name__)))

                        logging.fatal("{:s}.callback : Callback for {:s} raised an exception.".format('.'.join(('internal', __name__, cls.__name__)), '.'.join((self.__type__.__name__, name))))
                        res = map(message, traceback.format_exception(*sys.exc_info()))
                        map(logging.fatal, res)

                        logging.warn("{:s}.callback : Hook originated from -> ".format('.'.join(('internal', __name__, cls.__name__))))
                        res = map(message, traceback.format_list(self.__traceback[name, func]))
                        map(logging.warn, res)

                        res = self.STOP

                    if not isinstance(res, self.result) or res == self.CONTINUE:
                        continue
                    elif res == self.STOP:
                        break
                    cls = self.__class__
                    raise TypeError("{:s}.callback : Unable to determine result type. : {!r}".format('.'.join(('internal', __name__, cls.__name__)), res))

            supermethod = getattr(super(hookinstance.__class__, hookinstance), name)
            return supermethod(*args)
        return types.MethodType(method, self.object, self.object.__class__)

class address(object):
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
        # Ensures that ``ea`` is pointing to a valid address
        entryframe = cls.pframe()
        logF = logging.warn if not silent.get('silent', False) else logging.debug

        res = idaapi.get_item_head(ea)
        if ea != res:
            logF("{:s} : Specified address {:#x} not aligned to the beginning of an item. Setting the argument to {:#x}.".format(entryframe.f_code.co_name, ea, res))
        return res
    @classmethod
    def __head2__(cls, start, end, **silent):
        # Ensures that both ``start`` and ``end`` are pointing to valid addresses
        entryframe = cls.pframe()
        logF = logging.warn if not silent.get('silent', False) else logging.debug

        res_start, res_end = idaapi.get_item_head(start), idaapi.get_item_head(end)
        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logF("{:s} : Starting address of {:#x} not aligned to the beginning of an item. Setting the argument to {:#x}.".format(entryframe.f_code.co_name, start, res_start))
        if res_end != end:
            logF("{:s} : Ending address of {:#x} not aligned to the beginning of an item. Setting the argument to {:#x}.".format(entryframe.f_code.co_name, end, res_end))
        return res_start, res_end
    @classmethod
    def head(cls, *args, **silent):
        if len(args) > 1:
            return cls.__head2__(*args, **silent)
        return cls.__head1__(*args, **silent)

    @classmethod
    def __inside1__(cls, ea):
        # Ensures that ``ea`` is within the database and pointing at a valid address
        entryframe = cls.pframe()

        if not isinstance(ea, six.integer_types):
            raise TypeError("{:s} : Specified address is not of the correct type. : {!r} -> {!r}".format(entryframe.f_code.co_name, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise StandardError("{:s} : An invalid address ({:#x}) was specified.".format(entryframe.f_code.co_name, ea))

        res = cls.within(ea)
        return cls.head(res, silent=True)
    @classmethod
    def __inside2__(cls, start, end):
        # Ensures that both ``start`` and ``end`` are within the database and pointing at a valid address

        entryframe = cls.pframe()
        start, end = cls.within(start, end)
        if not isinstance(start, six.integer_types) or not isinstance(end, six.integer_types):
            raise TypeError("{:s} : Specified addresses are not of the correct type. : ({!r}, {!r}) -> ({!r}, {!r})".format(entryframe.f_code.co_name, start, end, start.__class__, end.__class__))
        return cls.head(start, end, silent=True)
    @classmethod
    def inside(cls, *args):
        if len(args) > 1:
            return cls.__inside2__(*args)
        return cls.__inside1__(*args)

    @classmethod
    def __within1__(cls, ea):
        # Ensures that ``ea`` is within the database
        entryframe = cls.pframe()

        if not isinstance(ea, six.integer_types):
            raise TypeError("{:s} : Specified address is not of the correct type. : {!r} -> {!r}".format(entryframe.f_code.co_name, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise StandardError("{:s} : An invalid address {:#x} was specified.".format(entryframe.f_code.co_name, ea))

        if not cls.__within__(ea):
            l, r = cls.__bounds__()
            raise StandardError("{:s} : Specified address {:#x} not within bounds of database ({:#x}<>{:#x}).".format(entryframe.f_code.co_name, ea, l, r))
        return ea
    @classmethod
    def __within2__(cls, start, end):
        # Ensures that both ``start`` and ``end`` are within the database
        entryframe = cls.pframe()

        if not isinstance(start, six.integer_types) or not isinstance(end, six.integer_types):
            raise TypeError("{:s} : Specified addresses are not of the correct type. : ({!r}, {!r}) -> ({!r}, {!r})".format(entryframe.f_code.co_name, start, end, start.__class__, end.__class__))

        # FIXME: off-by-one here, as end can be the size of the db.
        if any(not cls.__within__(ea) for ea in (start, end-1)):
            l, r = cls.__bounds__()
            raise StandardError("{:s} : Address range ({:#x}<>{:#x}) not within bounds of database ({:#x}<>{:#x}.)".format(entryframe.f_code.co_name, start, end, l, r))
        return start, end
    @classmethod
    def within(cls, *args):
        if len(args) > 1:
            return cls.__within2__(*args)
        return cls.__within1__(*args)

class node(object):
    """
    Various methods that extract information from the undocumented structures
    that IDA stores within a Netnode for a given address.
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
        if by&0xf0:
            # FIXME: If this doesn't match, then this is a type that forwards to the real function type.
            raise TypeError(by)
        res.append( (by&idaapi.CM_MASK) )
        res.append( (by&idaapi.CM_M_MASK) )

        # calling convention
        by = onext(iterable)
        cc, count = by&idaapi.CM_CC_MASK, by&0x0f
        if cc == idaapi.CM_CC_SPOILED:
            if count != 15:
                raise NotImplementedError((idaapi.CM_CC_SPOILED, count, repr(sup)))
            funcattr = onext(iterable)
            by = onext(iterable)
            res.append( (by&idaapi.CM_CC_MASK) )
        else:
            res.append(cc)

        return tuple(res)

        # XXX: implement a parser for type_t in order to figure out idaapi.BT_COMPLEX types
        # return type_t
        data = next(iterable)
        base, flags, mods = six.byte2int(data)&idaapi.TYPE_BASE_MASK, six.byte2int(data)&idaapi.TYPE_FLAGS_MASK, six.byte2int(data)&idaapi.TYPE_MODIF_MASK
        if base == idaapi.BT_PTR:
            data+= next(iterable)
        elif base == idaapi.BT_COMPLEX and flags == 0x30:
            by = next(iterable)
            skip, data = six.byte2int(by), data + by
            while skip > 1:
                data+= next(iterable)
                skip -= 1
        elif base in {idaapi.BT_ARRAY, idaapi.BT_FUNC, idaapi.BT_COMPLEX, idaapi.BT_BITFIELD}:
            raise NotImplementedError(base, flags, mods)
        res.append(data)

        # number of arguments
        by = onext(iterable)
        res.append(by)

        # Everything else in iterable is an array of type_t as found in "Type flags" in the SDK docs.
        ''.join(iterable)

        # now we can return it
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
        ror = lambda n, shift, bits: (n>>shift) | ((n&2**shift-1) << (bits-shift))

        # 32-bit
        # 0001 c0006e92 -- ULARGE_INTEGER
        # 0002 c0006e92 c0006e98 -- ULARGE_INTEGER.quadpart
        # 0002 c0006e92 c0006e97 -- ULARGE_INTEGER.u.lowpart
        # 0002 c0006e92 c0006e96 -- ULARGE_INTEGER.s0.lowpart
        # (x ^ 0x3f000000)

        def id32(sup):
            count, res = le(sup[:2]), sup[2:]
            chunks = zip(*((iter(res),)*4))
            if len(chunks) != count:
                raise ValueError("{:s}.op_id('{:s}') -> id32 : Number of chunks does not match count : {:d} : {!r}".format('.'.join(('internal', __name__)), sup.encode('hex'), count, map(''.join, chunks)))
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
            count = le((next(iterable), next(iterable), next(iterable)))
            chunks = zip(*((iterable,)*5))
            #count = le(chunks.pop(0))
            if len(chunks) != count:
                raise ValueError("{:s}.op_id('{:s}') -> id64 : Number of chunks does not match count : {:d} : {!r}".format('.'.join(('internal', __name__)), sup.encode('hex'), count, map(''.join, chunks)))
            res = map(le, chunks)
            res = map(functools.partial(operator.xor, 0xc0000000ff), res)
            return tuple(ror(n, 8, 64) for n in res)

        return id64(sup) if bit64Q else id32(sup)

    @staticmethod
    def alt_opinverted(ea, opnum):
        '''Return whether the operand ``opnum`` at the address ``ea`` has its sign inverted or not.'''
        OP_REPR, INVERT_BIT = 8, 0x100000
        return internal.netnode.alt.get(ea, OP_REPR) & (INVERT_BIT << opnum) != 0

def tuplename(*names):
    res = ("{:x}".format(abs(n)) if isinstance(n, six.integer_types) else n for n in names)
    return '_'.join(res)

# copied mostly from the collections.namedtuple template
class namedtypedtuple(tuple):
    '''A subclass of tuple with named fields.'''
    _fields = ()
    _types = ()

    def __new__(cls, *args):
        res = args[:]
        for n, t, x in zip(cls._fields, cls._types, args):
            if not isinstance(x, t): raise TypeError("Unexpected type for field '{:s}' : {!r} != {!r}".format(n, t, type(x)))
        return tuple.__new__(cls, res)

    @classmethod
    def _make(cls, iterable, new=tuple.__new__, len=len):
        result = new(cls, iterable)
        if len(result) != len(cls._fields):
            raise TypeError("Expected {:d} arguments, got {:d}.".format(len(cls._fields), len(result)))
        for n, t, x in zip(cls._fields, cls._types, result):
            if not isinstance(x, t): raise TypeError("Unexpected type for field '{:s}' : {!r} != {!r}".format(n, t, type(x)))
        return result

    @classmethod
    def _type(cls, name):
        res = (t for n, t in zip(cls._fields, cls._types) if n == name)
        try: return next(res)
        except StopIteration:
            raise ValueError("Got unexpected field name: {:s}".format(name))

    def __getattribute__(self, name):
        try:
            # honor the ._fields first
            res = object.__getattribute__(self, '_fields')
            res = operator.itemgetter(res.index(name))
        except (IndexError, ValueError):
            res = lambda s: object.__getattribute__(s, name)
        return res(self)

    def __repr__(self):
        cls = self.__class__
        res = ("{:s}={!r}".format(name, value) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    def _replace(self, **kwds):
        result = self._make(map(kwds.pop, self._fields, self))
        if kwds:
            raise ValueError("Got unexpected field names: {!r}".format(six.viewkeys(kwds)))
        return result
    def _asdict(self): return collections.OrderedDict(zip(self._fields, self))
    def __getnewargs__(self): return tuple(self)
    def __getstate__(self): return

class symbol_t(object):
    """
    A type that is used to describe a value that is symbolic in nature.

    Used primarily as a type-checking mechanism.
    """

    @property
    def symbols(self):
        '''Must be implemented by each sub-class: Return a generator that returns each symbol described by ``self``.'''
        raise NotImplementedError

class register_t(symbol_t):
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

class regmatch(object):
    def __new__(cls, *regs, **modifiers):
        if not regs:
            args = ', '.join(map("{:s}".format, regs))
            mods = ', '.join(map(internal.utils.unbox("{:s}={!r}".format), six.iteritems(modifiers)))
            raise AssertionError("{:s}({:s}{:s}) : Specified registers are empty.".format('.'.join((__name__, cls.__name__)), args, (', '+mods) if mods else ''))
        use, iterops = cls.use(regs), cls.modifier(**modifiers)
        def match(ea):
            return any(map(functools.partial(use, ea), iterops(ea)))
        return match

    @classmethod
    def use(cls, regs):
        _instruction = sys.modules.get('instruction', __import__('instruction'))

        # convert any regs that are strings into their correct object type
        regs = { _instruction.architecture.by_name(r) if isinstance(r, basestring) else r for r in regs }

        # returns an iterable of bools that returns whether r is a subset of any of the registers in ``regs``.
        match = lambda r, regs=regs: any(itertools.imap(r.relatedQ, regs))

        # returns true if the operand at the specified address is related to one of the registers in ``regs``.
        def uses_register(ea, opnum):
            val = _instruction.op_value(ea, opnum)
            if isinstance(val, symbol_t):
                return any(map(match, val.symbols))
            return False

        return uses_register

    @classmethod
    def modifier(cls, **modifiers):
        _instruction = sys.modules.get('instruction', __import__('instruction'))

        # by default, grab all operand indexes
        iterops = internal.utils.fcompose(_instruction.ops_count, six.moves.range, sorted)

        # if ``read`` is specified, then only grab operand indexes that are read from
        if modifiers.get('read', False):
            iterops = _instruction.ops_read

        # if ``write`` is specified that only grab operand indexes that are written to
        if modifiers.get('write', False):
            iterops = _instruction.ops_write
        return iterops

if idaapi.BADADDR == 0xffffffff:
    sval_t = ctypes.c_long
elif idaapi.BADADDR == 0xffffffffffffffff:
    sval_t = ctypes.c_longlong
else:
    sval_t = ctypes.c_int
    logging.fatal("{:s} : Unable to determine size of BADADDR in order to determine boundaries of sval_t. Setting default size to {:d}-bits. : {:#x}".format(__name__, ctypes.sizeof(sval_t), idaapi.BADADDR))

#Ref_Types = {
#    0 : 'Data_Unknown', 1 : 'Data_Offset',
#    2 : 'Data_Write', 3 : 'Data_Read', 4 : 'Data_Text',
#    5  : 'Data_Informational',
#    16 : 'Code_Far_Call', 17 : 'Code_Near_Call',
#    18 : 'Code_Far_Jump', 19 : 'Code_Near_Jump',
#    20 : 'Code_User', 21 : 'Ordinary_Flow'
#}
class ref_t(set):
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
    __mapper__[31] = '*'        # code 31 used internally by idascripts

    def __and__(self, type):
        return type in self

    def __str__(self):
        return str().join(sorted(self))
    def __repr__(self):
        return "ref_t({:s})".format(str().join(sorted(self)))

    def __init__(self, type, iterable):
        self.F = type
        self.update(iterable)

    @classmethod
    def of(cls, xrtype):
        res = cls.__mapper__.get(xrtype, '')
        return cls(xrtype, res)
    of_type = of

    @classmethod
    def of_state(cls, state):
        if state == '*':
            return cls(31, '*')     # code 31 used internally by idascripts
        res = set(state)
        for F, t in six.iteritems(cls.__mapper__):
            if set(t) == res:
                return cls(F, str().join(sorted(res)))
            continue
        raise LookupError("{:s}.of_state('{:s}') : Unable to find xrtype that matches requested state.".format('.'.join((__name__, cls.__name__)), str().join(sorted(res))))

class AddressOpnumReftype(namedtypedtuple):
    '''A named tuple containing (address, operand-number, reference-type).'''
    _fields = ('address', 'opnum', 'reftype')
    _types = (long, (types.NoneType, int), ref_t)
OREF = AddressOpnumReftype

# XXX: is .startea always guaranteed to point to an instruction that modifies
#      the switch's register? if so, then we can use this to calculate the
#      .range/.cases more accurately instead of them being based on .elbase.
class switch_t(object):
    """
    This is a wrapper around the `idaapi.switch_info_ex_t` class.
    """
    def __init__(self, switch_info_ex):
        self.object = switch_info_ex
    @property
    def ea(self):
        '''Return the address of the beginning of the switch.'''
        return self.object.startea
    @property
    def branch_ea(self):
        '''Return the address of the branch table.'''
        return self.object.jumps
    @property
    def table_ea(self):
        '''Return the address of the case/index table.'''
        return self.object.lowcase
    @property
    def default(self):
        '''Return the code that handles the default case.'''
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
        '''Return the contents of the case/index table.'''
        import database
        if self.indirectQ():
            ea, count = self.object.lowcase, self.object.ncases
            return database.get.array(ea, length=count)
        return database.get.array(self.object.jumps, length=0)
    @property
    def register(self):
        '''Return the register that the switch is based on.'''
        import instruction
        ri, rt = self.object.regnum, self.object.regdtyp
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
        '''Return whether the switch performs a transformation (subtract) on the index.'''
        return self.object.is_subtract()
    def case(self, case):
        '''Return the handler for a particular case.'''
        # return the ea of the specified case number
        # FIXME: check that this works with a different .ind_lowcase
        if case < self.base or case >= self.count + self.base:
            cls = self.__class__
            raise ValueError("{:s}.case({:#x}) : Specified case was out of bounds. : ({:#x}<>{:#x})".format(cls.__name__, case, self.base, self.base+self.count - 1))
        idx = case - self.base
        if self.indirectQ():
            idx = self.index[idx]
        return self.branch[idx]
    def handler(self, ea):
        '''Return the cases that are handled by the address ``ea`` as a `tuple`.'''
        return tuple(case for case in self.range if self.case(case) == ea)
    @property
    def cases(self):
        '''Return all of the non-default cases in the switch.'''
        import instruction
        f = lambda ea, dflt=self.default: (ea == dflt) or (instruction.is_jmp(ea) and instruction.op_value(ea, 0) == dflt)
        return tuple(idx for idx in six.moves.range(self.base, self.base+self.count) if not f(self.case(idx)))
    @property
    def range(self):
        '''Return all the possible cases for the switch.'''
        return tuple(six.moves.range(self.base, self.base+self.count))
    def __repr__(self):
        cls = self.__class__
        if self.indirectQ():
            return "<type '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} index[{:d}]:*{:#x} register:{:s}".format(cls.__name__, self.count, self.ea, self.default, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return "<type '{:s}{{{:d}}}' at {:#x}> default:*{:#x} branch[{:d}]:*{:#x} register:{:s}".format(cls.__name__, self.count, self.ea, self.default, self.object.ncases, self.object.jumps, self.register)

def xiterate(ea, start, next):
    '''Simple utility function for iterating through idaapi's xrefs.'''
    getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_flags
    ea = ea if getflags(ea) & idaapi.FF_DATA else idaapi.prev_head(ea, 0)

    addr = start(ea)
    while addr != idaapi.BADADDR:
        yield addr
        addr = next(ea, addr)
    return

def addressOfRuntimeOrStatic(func):
    '''Returns `(F, address)` if a statically linked address, or `(T, address)` if a runtime-linked address'''
    import function
    try:
        fn = function.by(func)

    # otherwise, maybe it's an rtld symbol
    except LookupError, e:
        import database
        exc_info = sys.exc_info()

        # if func is not an address, then there ain't shit we can do
        if not isinstance(func, six.integer_types): six.reraise(*exc_info)

        # make sure that we're actually data
        if not database.is_data(func): six.reraise(*exc_info)

        # ensure that we're an import, otherwise throw original exception
        try: database.imports.at(func)
        except LookupError: six.reraise(*exc_info)

        # yep, we're an import
        return True, func

    # nope, we're just a function
    return False, fn.startEA

## internal enumerations that idapython missed
class fc_block_type_t:
    fcb_normal = 0  # normal block
    fcb_indjump = 1 # block ends with indirect jump
    fcb_ret = 2     # return block
    fcb_cndret = 3  # conditional return block
    fcb_noret = 4   # noreturn block
    fcb_enoret = 5  # external noreturn block (does not belong to the function)
    fcb_extern = 6  # external normal block
    fcb_error = 7   # block passes execution past the function end

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
    """
    Base class to represent how IDA maps the registers and types returned from an operand to a register that's uniquely identifiable by the user.

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
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
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
            dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int)
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

        The register size is based on the architecture of the instance of IDA that is running.
        """
        res = idaapi.ph.regnames[index]
        return self.by_name(res)

    def by_indextype(self, index, dtyp):
        """Lookup a register according to its ``index`` and ``dtyp``.

        Some examples of dtypes: idaapi.dt_byte, idaapi.dt_word, idaapi.dt_dword, idaapi.dt_qword
        """
        res = idaapi.ph.regnames[index]
        name = self.__cache__[res, dtyp]
        return getattr(self.__register__, name)

    def by_name(self, name):
        '''Lookup a register according to its ``name``.'''
        if any(name.startswith(prefix) for prefix in ('%', '$')):        # at&t, mips
            return getattr(self.__register__, name[1:].lower())
        if name.lower() in self.__register__:
            return getattr(self.__register__, name.lower())
        return getattr(self.__register__, name)

    def by_indexsize(self, index, size):
        '''Lookup a register according to its ``index`` and ``size``.'''
        dtype_by_size = internal.utils.fcompose(idaapi.get_dtyp_by_size, six.byte2int) if idaapi.__version__ < 7.0 else idaapi.get_dtyp_by_size
        dtyp = dtype_by_size(size)
        return self.by_indextype(index, dtyp)
    def promote(self, register, size=None):
        '''Promote the specified ``register`` to its next larger ``size``.'''
        parent = internal.utils.fcompose(operator.attrgetter('__parent__'), internal.utils.box, functools.partial(filter, None), iter, next)
        try:
            if size is None:
                return parent(register)
            return register if register.size == size else self.promote(parent(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise LookupError("{:s}.promote({:s}{:s}) : Unable to find register to promote to.".format('.'.join((__name__,cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))
    def demote(self, register, size=None):
        '''Demote the specified ``register`` to its next smaller ``size``.'''
        childitems = internal.utils.fcompose(operator.attrgetter('__children__'), operator.methodcaller('iteritems'))
        firstchild = internal.utils.fcompose(childitems, functools.partial(sorted, key=operator.itemgetter(0)), iter, next, operator.itemgetter(1))
        try:
            if size is None:
                return firstchild(register)
            return register if register.size == size else self.demote(firstchild(register), size=size)
        except StopIteration: pass
        cls = self.__class__
        raise LookupError("{:s}.demote({:s}{:s}) : Unable to find register to demote to.".format('.'.join((__name__,cls.__name__)), register, '' if size is None else ", size={:d}".format(size)))
