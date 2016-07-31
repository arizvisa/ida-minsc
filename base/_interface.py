import sys
import six, logging
import operator,functools,itertools
import collections,heapq,types

import database,structure
import internal

import idaapi

class typemap:
    """Convert bidirectionally from a pythonic type into an IDA type"""

    FF_MASKSIZE = 0xf0000000    # Mask that select's the flag's size
    FF_MASK = 0xfff00000        # Mask that select's the flag's repr
    # FIXME: In some cases FF_nOFF (where n is 0 or 1) does not actually
    #        get auto-treated as an pointer by ida. Instead, it appears to
    #        only get marked as an "offset" and rendered as an integer.

    integermap = {
        1:(idaapi.byteflag(), -1),  2:(idaapi.wordflag(), -1),  3:(idaapi.tribyteflag(), -1),
        4:(idaapi.dwrdflag(), -1),  8:(idaapi.qwrdflag(), -1), 10:(idaapi.tbytflag(), -1),
        16:(idaapi.owrdflag(), -1),
    }
    if hasattr(idaapi, 'ywrdflag'): integermap[32] = getattr(idaapi, 'ywrdflag')(),-1

    decimalmap = {
         4:(idaapi.floatflag(), -1),     8:(idaapi.doubleflag(), -1),
        10:(idaapi.packrealflag(), -1), 12:(idaapi.packrealflag(), -1),
    }

    stringmap = {
        chr:(idaapi.asciflag(), 0),
        str:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
        unicode:(idaapi.asciflag(), idaapi.ASCSTR_UNICODE),
    }
    
    ptrmap = { sz : (idaapi.offflag()|flg, tid) for sz,(flg,tid) in integermap.iteritems() }
    nonemap = { None :(idaapi.alignflag(),-1) }

    typemap = {
        int:integermap,long:integermap,float:decimalmap,
        str:stringmap,unicode:stringmap,chr:stringmap,
        type:ptrmap,None:nonemap,
    }

    # inverted lookup table
    inverted = {}
    for s,(f,_) in integermap.items():
        inverted[f & FF_MASKSIZE] = (int,s)
    for s,(f,_) in decimalmap.items():
        inverted[f & FF_MASKSIZE] = (float,s)
    for s,(f,_) in stringmap.items():
        inverted[f & FF_MASKSIZE] = (str,s)
    for s,(f,_) in ptrmap.items():
        inverted[f & FF_MASK] = (type,s)
    del f
    inverted[idaapi.FF_STRU] = (int,1)  # FIXME: hack for dealing with
                                        #   structures that have the flag set
                                        #   but aren't actually structures..

    # defaults
    @classmethod
    def __database_inited__(cls, is_new_database, idc_script):
        # FIXME: figure out how to fix this recursive module dependency
        typemap.integermap[None] = typemap.integermap[(hasattr(database,'config') and database.config.bits() or 32)/8]
        typemap.decimalmap[None] = typemap.decimalmap[(hasattr(database,'config') and database.config.bits() or 32)/8]
        typemap.ptrmap[None] = typemap.ptrmap[(hasattr(database,'config') and database.config.bits() or 32)/8]
        typemap.stringmap[None] = typemap.stringmap[str]

    @classmethod
    def dissolve(cls, flag, typeid, size):
        dt = flag & cls.FF_MASKSIZE
        sf = -1 if idaapi.is_signed_data(flag) else +1
        if dt == idaapi.FF_STRU and isinstance(typeid,(int,long)):
            # FIXME: figure out how to fix this recursive module dependency
            t = structure.instance(typeid) 
            sz = t.size
            return t if sz == size else [t,size // sz]
        if dt not in cls.inverted:
            logging.warn('typemap.disolve({!r}, {!r}, {!r}) : Unable to identify a pythonic type'.format(dt, typeid, size))

        t,sz = cls.inverted[dt]
        # if the type and size are the same, then it's a string or pointer type
        if not isinstance(sz,(int,long)):
            count = size // idaapi.get_data_type_size(dt, idaapi.opinfo_t())
            return [t,count] if count > 1 else t
        # if the size matches, then we assume it's a single element
        elif sz == size:
            return t,sz
        # otherwise it's an array
        return [(t,sz*sf),size // sz]

    @classmethod
    def resolve(cls, pythonType):
        """Return ida's (flag,typeid,size) given the type (type,size) or (type/instance)
        (int,4)     -- a dword
        [(int,4),8] -- an array of 8 dwords
        (str,10)    -- an ascii string of 10 characters
        (int,2)     -- a word
        [chr,4]     -- an array of 4 characters
        """
        sz,count = None,1
        # FIXME: figure out how to fix this recursive module dependency

        # figure out what format pythonType is in
        if isinstance(pythonType, ().__class__):
            (t,sz),count = pythonType,1
            table = cls.typemap[t]
            flag,typeid = table[sz if t in (int,long,float,type) else t]
            
        elif isinstance(pythonType, [].__class__):
            # an array, which requires us to recurse...
            res,count = pythonType
            flag,typeid,sz = cls.resolve(res)

        elif isinstance(pythonType, structure.structure_t):
            # it's a structure, pass it through.
            flag,typeid,sz = idaapi.struflag(),pythonType.id,pythonType.size

        else:
            # default size that we can lookup in the typemap table
            table = cls.typemap[pythonType]
            flag,typeid = table[None]

            opinfo = idaapi.opinfo_t()
            opinfo.tid = typeid
            return flag,typeid,idaapi.get_data_type_size(flag, opinfo)

        return flag|(idaapi.signed_data_flag() if sz < 0 else 0),typeid,sz*count

class priorityhook(object):
    '''Helper class for hooking different parts of IDA.'''
    result = type('result', (object,), {})
    CONTINUE = type('continue', (result,), {})()
    STOP = type('stop', (result,), {})()

    def __init__(self, hooktype, **exclude):
        exclusions = set(exclude.get('exclude', ()))
        self.__type__ = hooktype
        self.cache = collections.defaultdict(list)
        self.object = self.cycle(self.__type__())
    
    def cycle(self, object=None):
        # uhook previous object
        ok = object.unhook()
        if not ok:
            logging.debug('{:s}.priorityhook.cycle : Error trying to unhook object. : {!r}'.format(__name__, object))

        namespace = { name : self.new(name) for name in self.cache.viewkeys() }
        res = type(object.__class__.__name__, (self.__type__,), namespace)
        object = res()
        
        ok = object.hook()
        if not ok:
            logging.debug('{:s}.priorityhook.cycle : Unable to hook with object.: {!r}'.format(__name__, object))
        return object

    def add(self, name, function, priority=10):
        if name not in self.cache:
            res = self.new(name)
            setattr(self.object, name, res)

        self.discard(name, function)

        res = self.cache[name]
        heapq.heappush(self.cache[name], (priority, function))
        return True

    def get(self, name):
        res = self.cache[name]
        return tuple(f for _,f in res)

    def discard(self, name, function):
        if not hasattr(self.object, name):
            raise AttributeError('{:s}.priorityhook.add : Unable to add a method to hooker for unknown method. : {!r}'.format(__name__, name))
        if name not in self.cache: return False

        res, found = [], 0
        for i,(p,f) in enumerate(self.cache[name][:]):
            if f != function:
                res.append((p,f))
                continue
            found += 1

        if res: self.cache[name][:] = res
        else: self.cache.pop(name, [])

        return True if found else False

    def new(self, name):
        if not hasattr(self.object, name):
            raise AttributeError('{:s}.priorityhook.new : Unable to create a hook for unknown method. : {!r}'.format(__name__, name))

        def method(hookinstance, *args):
            if name in self.cache:
                hookq = self.cache[name][:]

                for _,func in heapq.nsmallest(len(hookq), hookq):
                    res = func(*args)
                    if not isinstance(res, self.result) or res == self.CONTINUE:
                        continue
                    elif res == self.STOP:
                        break
                    raise TypeError('{:s}.priorityhook.callback : Unable to determine result type : {!r}'.format(__name__, res))

            supermethod = getattr(super(hookinstance.__class__, hookinstance), name)
            return supermethod(*args)
        return types.MethodType(method, self.object, self.object.__class__)

import sys
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
    def __head1__(cls, ea):
        # Ensures that ``ea`` is pointing to a valid address
        entryframe = cls.pframe()
        res = idaapi.get_item_head(ea)
        if res != ea:
            logging.warn("{:s} : Address {:x} not aligned to the beginning of an item. Fixing it to {:x}.".format(entryframe.f_code.co_name, ea, res))
            ea = res
        return ea
    @classmethod
    def __head2__(cls, start, end):
        entryframe = cls.pframe()
        res_start, res_end = idaapi.get_item_head(start), idaapi.get_item_head(end)
        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logging.warn("{:s} : Starting address of {:x} not aligned to the beginning of an item. Fixing it to {:x}.".format(entryframe.f_code.co_name, start, res_start))
            start = res_start
        if res_end != end:
            logging.warn("{:s} : Ending address of {:x} not aligned to the beginning of an item. Fixing it to {:x}.".format(entryframe.f_code.co_name, end, res_end))
            end = res_end
        return start, end
    @classmethod
    def head(cls, *args):
        if len(args) > 1:
            return cls.__head2__(*args)
        return cls.__head1__(*args)

    @classmethod
    def __inside1__(cls, ea):
        # Ensures that ``ea`` is within the database and pointing at a valid address
        res = cls.within(ea)
        return cls.head(res)
    @classmethod
    def __inside2__(cls, start, end):
        start, end = cls.within(start, end)
        return cls.head(start, end)
    @classmethod
    def inside(cls, *args):
        if len(args) > 1:
            return cls.__inside2__(*args)
        return cls.__inside1__(*args)

    @classmethod
    def __within1__(cls, ea):
        # Ensures that ``ea`` is within the database
        entryframe = cls.pframe()
        if not cls.__within__(ea):
            l, r = cls.__bounds__()
            raise StandardError("{:s} : Address {:x} not within bounds of database ({:x} - {:x}.)".format(entryframe.f_code.co_name, ea, l, r))
        return ea
    @classmethod
    def __within2__(cls, start, end):
        entryframe = cls.pframe()
        # FIXME: off-by-one here, as end can be the size of the db.
        if any(not cls.__within__(ea) for ea in (start,end-1)):
            l, r = cls.__bounds__()
            raise StandardError("{:s} : Address range ({:x} - {:x}) not within bounds of database ({:x} - {:x}.)".format(entryframe.f_code.co_name, start, end, l, r))
        return start, end
    @classmethod
    def within(cls, *args):
        if len(args) > 1:
            return cls.__within2__(*args)
        return cls.__within1__(*args)

class matcher(object):
    def __init__(self):
        self.__predicate__ = {}
    def __attrib__(self, *attribute):
        identity = lambda n: n
        if not attribute:
            return identity
        res = [(operator.attrgetter(a) if isinstance(a,basestring) else a) for a in attribute]
        return lambda o: tuple(x(o) for x in res) if len(res) > 1 else res[0](o)
    def attribute(self, type, *attribute):
        compose = lambda *f: reduce(lambda f1,f2: lambda *a: f1(f2(*a)), reversed(f))
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: compose(attr, functools.partial(functools.partial(operator.eq, v)))
    def mapping(self, type, function, *attribute):
        compose = lambda *f: reduce(lambda f1,f2: lambda *a: f1(f2(*a)), reversed(f))
        attr = self.__attrib__(*attribute)
        mapper = compose(attr, function)
        self.__predicate__[type] = lambda v: compose(mapper, functools.partial(operator.eq, v))
    def boolean(self, type, function, *attribute):
        compose = lambda *f: reduce(lambda f1,f2: lambda *a: f1(f2(*a)), reversed(f))
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: compose(attr, functools.partial(function, v))
    def predicate(self, type, *attribute):
        compose = lambda *f: reduce(lambda f1,f2: lambda *a: f1(f2(*a)), reversed(f))
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = functools.partial(compose, attr)
    def match(self, type, value, iterable):
        matcher = self.__predicate__[type](value)
        return itertools.ifilter(matcher, iterable)

class hook(object):
    @staticmethod
    def noapi(*args):
        fr = sys._getframe().f_back
        if fr is None:
            logging.fatal("internal.{:s}.noapi : Unexpected empty frame from caller. Continuing.. : {!r} : {!r}".format('.'.join((__name__,'hook')), sys._getframe(), sys._getframe().f_code))
            return hook.CONTINUE

        return priorityhook.CONTINUE if fr.f_back is None else priorityhook.STOP

    @staticmethod
    def rename(ea, newname):
        fl = idaapi.getFlags(ea)        
        labelQ, customQ = (fl & n == n for n in (idaapi.FF_LABL,idaapi.FF_NAME))
        #r, fn = database.xref.up(ea), idaapi.get_func(ea)
        fn = idaapi.get_func(ea)

        # figure out whether a global or function name is being changed, otherwise it's the function's contents
        ctx = internal.comment.globals if not fn or (fn.startEA == ea) else internal.comment.contents

        # if a name is being removed
        if not newname:
            # if it's a custom name
            if (not labelQ and customQ):
                ctx.dec(ea, '__name__')
            return

        # if it's currently a label or is unnamed
        if (labelQ and not customQ) or all(not n for n in (labelQ,customQ)):
            ctx.inc(ea, '__name__')
        return

    @staticmethod
    def extra_cmt_changed(ea, line_idx, cmt):
        oldcmt = internal.netnode.sup.get(ea, line_idx)
        ctx = internal.comment.contents if idaapi.get_func(ea) else internal.comment.globals

        MAX_ITEM_LINES = (idaapi.E_NEXT-idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV-idaapi.E_NEXT
        prefix = (idaapi.E_PREV, idaapi.E_PREV+MAX_ITEM_LINES, '__extra_prefix__')
        suffix = (idaapi.E_NEXT, idaapi.E_NEXT+MAX_ITEM_LINES, '__extra_suffix__')

        for l,r,key in (prefix,suffix):
            if l <= line_idx < r:
                if oldcmt is None and cmt: ctx.inc(ea, key)
                elif oldcmt and cmt is None: ctx.dec(ea, key)
            continue
        return
