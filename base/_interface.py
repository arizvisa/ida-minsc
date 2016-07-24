import operator,collections,heapq,types
import database,structure
import idaapi
import six, logging

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
        self.object = type(hooktype.__name__, (hooktype,), {})()
        self.cache = collections.defaultdict(list)
        # FIXME: create a mutex too
        for name in dir(self.object):
            if any(f(name) for f in (operator.methodcaller('startswith','_'), lambda n: not callable(getattr(self.object,n)), lambda n: n in ('hook','unhook'), lambda n: n in exclusions)):
                continue
            self.new(name)
        self.object.hook()
    
    def cycle(self):
        # FIXME: wrap this in a mutex
        ok = self.object.unhook()
        if not ok:
            logging.warn('{:s}.priorityhook.cycle : Error trying to unhook object.'.format(__name__))
        return self.object.hook()

    def add(self, name, function, priority=10):
        if not hasattr(self.object, name):
            raise AttributeError('{:s}.priorityhook.add : Unable to add a method to hooker for unknown method. : {!r}'.format(__name__, name))
        self.discard(name, function)

        # FIXME: wrap this in a mutex
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

        # FIXME: wrap this in a mutex
        if res:
            self.cache[name][:] = res
        else:
            self.cache.pop(name, [])

        return True if found else False

    def new(self, name):
        if not hasattr(self.object, name):
            raise AttributeError('{:s}.priorityhook.new : Unable to create a hook for unknown method. : {!r}'.format(__name__, name))
        def method(hook, *args):
            if name in self.cache:
                # FIXME: wrap this in a mutex
                hookq = self.cache[name][:]

                for _,func in heapq.nsmallest(len(hookq), hookq):
                    res = func(*args)
                    if not isinstance(res, self.result) or res == self.CONTINUE:
                        continue
                    elif res == self.STOP:
                        break
                    raise TypeError('{:s}.priorityhook.callback : Unable to determine result type : {!r}'.format(__name__, res))

            supermethod = getattr(super(hook.__class__, hook), name)
            return supermethod(*args)

        new_method = types.MethodType(method, self.object, self.object.__class__)
        setattr(self.object, name, new_method)
        return True

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
