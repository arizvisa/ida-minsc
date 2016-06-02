import logging,sys
import itertools,operator,functools
import six,types,heapq

import idaapi

class multicase(object):
    F_VARARG = 0x04
    F_VARKWD = 0x08
    F_VARGEN = 0x20

    cache_name = '__multicase_cache__'

    def __new__(cls, other=None, **types):
        def result(wrapped):
            # extract the FunctionType and it's arg types
            cons, func = cls.reconstructor(wrapped), cls.ex_function(wrapped)
            args, defaults, (star, starstar) = cls.ex_args(func)

            # determine the previous instance of the func
            fr_locals = sys._getframe().f_back.f_locals
            prev = fr_locals.get(func.func_name, lambda:fake) if other is None else other
            prevfunc = cls.ex_function(prev)

            # if the previous func isn't a wrapper, then create one.
            if not hasattr(prevfunc, cls.cache_name):
                cache = []
                res = cls.new_wrapper(func, cache=cache)
                setattr(res, cls.cache_name, cache)
                setattr(res, '__doc__', '')
            else:
                res, cache = prevfunc, getattr(prevfunc, cls.cache_name)

            # calculate the priority by trying to match the most first
            argtuple = args, defaults, (star, starstar)
            priority = len(args) - len(types) + sum(0.3 for _ in filter(None, (star, starstar)))

            # check to see if we're already in the cache
            current = tuple(types.get(_,None) for _ in args),(star,starstar)
            for i, (p, (_, t, a)) in enumerate(cache): 
                if p != priority: continue
                # check if it matches the entry
                if current == (tuple(t.get(_,None) for _ in a[0]), a[2]):
                    # yuuup, update it.
                    cache[i] = (priority, (func, types, argtuple))
                    res.__doc__ = cls.document(func.__name__, [n for _, n in cache])
                    return cons(res)
                continue

            # everything is ok...so add it
            heapq.heappush(cache, (priority, (func, types, argtuple)))

            # now we can update the docs
            res.__doc__ = cls.document(func.__name__, [n for _, n in cache])

            # now to restore the wrapper to it's former glory
            return cons(res)
        return result

    @classmethod
    def document(cls, name, cache):
        res = []
        for func, types, argtuple in cache:
            doc = (func.__doc__ or '').split('\n')
            if len(doc) > 1:
                res.append('{:s} ->'.format(cls.prototype(func, types)))
                res.extend('{: >{padding:d}s}'.format(n, padding=len(name)+len(n)+1) for n in map(operator.methodcaller('strip'), doc))
            elif len(doc) == 1:
                res.append(cls.prototype(func, types) + (' -> {:s}'.format(doc[0]) if len(doc[0]) else ''))
            continue
        return '\n'.join(res)

    @classmethod
    def prototype(cls, func, types={}):
        args, defaults, (star, starstar) = cls.ex_args(func)
        argsiter = (('{:s}={:s}'.format(n, '{:s}'.format('|'.join(t.__name__ for t in types[n])) if hasattr(types[n], '__iter__') else types[n].__name__) if types.has_key(n) else n) for n in args)
        res = (argsiter, ('*{:s}'.format(star),) if star else (), ('**{:s}'.format(starstar),) if starstar else ())
        return '{:s}({:s})'.format(func.func_name, ', '.join(itertools.chain(*res)))

    @classmethod
    def match(cls, (args, kwds), heap):
        # FIXME: yep, done in O(n) time.
        for f, types, (af, defaults, (argname, kwdname)) in heap:
            # populate our arguments
            ac, kc = (n for n in args), dict(kwds)
            a = tuple(kc.pop(n, defaults.pop(n)) if ac.gi_frame is None else ac.next() for n in af)
            try:
                a += tuple(kc.pop(n, defaults.pop(n)) if ac.gi_frame is None else ac.next() for n in af[len(a):])
            except KeyError:
                continue

            # check that our args matches all of our types
            if any(not isinstance(v, types[k]) for k, v in zip(af, a) if k in types):
                continue

            # now do wildcards
            wA, wK = list(ac), dict(kc)
            if (not argname and len(wA)) or (not kwdname and wK):
                continue

            # we should have a match
#            print (argname,kwdname),(wA,wK),a
            return f, (a, wA, wK)

        error_arguments = ('{:s}'.format(n.__class__.__name__) for n in args)
        error_keywords = ('{:s}={:s}'.format(n, kwds[n].__class__.__name__) for n in kwds)
        raise LookupError('@multicase.call({:s}, {{{:s}}}) : does not match any defined prototypes : {:s}'.format(', '.join(error_arguments), ', '.join(error_keywords), ', '.join(cls.prototype(f,t) for f,t,_ in heap)))

    @classmethod
    def new_wrapper(cls, func, cache):
        # build the wrapper...
        def fn(*arguments, **keywords):
            heap = [res for _,res in heapq.nsmallest(len(cache), cache)]
            f, (a, w, k) = cls.match((arguments[:],keywords), heap)
            return f(*arguments, **keywords)
            #return f(*(arguments + tuple(w)), **keywords)

        # ...and assign the cache to it.
        res = functools.update_wrapper(fn, func)
        setattr(res, cls.cache_name, cache)
        return res

    @classmethod
    def ex_function(cls, object):
        if isinstance(object, types.FunctionType):
            return object
        elif isinstance(object, types.MethodType):
            return object.im_func
        elif isinstance(object, types.CodeType):
            res, = (n for n in gc.get_referrers(c) if n.func_name == c.co_name and isinstance(n, types.FunctionType))
            return res
        elif isinstance(object, (staticmethod,classmethod)):
            return object.__func__
        raise TypeError, object

    @classmethod
    def reconstructor(cls, n):
        if isinstance(n, types.FunctionType):
            return lambda f: f
        if isinstance(n, types.MethodType):
            return lambda f: types.MethodType(f, n.im_self, n.im_class)
        if isinstance(n, (staticmethod,classmethod)):
            return lambda f: type(n)(f)
        if isinstance(n, types.InstanceType):
            return lambda f: types.InstanceType(type(n), dict(f.__dict__))
        if isinstance(n, (types.TypeType,types.ClassType)):
            return lambda f: type(n)(n.__name__, n.__bases__, dict(f.__dict__))
        raise NotImplementedError, type(func)

    @classmethod
    def ex_args(cls, f):
        c = f.func_code
        varnames_iter = iter(c.co_varnames)
        args = tuple(itertools.islice(varnames_iter, c.co_argcount))
        res = { a : v for v,a in zip(reversed(f.func_defaults or []), reversed(args)) }
        try: starargs = varnames_iter.next() if c.co_flags & cls.F_VARARG else ""
        except StopIteration: starargs = ""
        try: kwdargs = varnames_iter.next() if c.co_flags & cls.F_VARKWD else ""
        except StopIteration: kwdargs = ""
        return args, res, (starargs, kwdargs)

    @classmethod
    def generatorQ(cls, func):
        func = cls.ex_function(func)
        return bool(func.func_code.co_flags & F_VARGEN)

# FIXME: allow for a function to loop capturing exceptions until timeout
def timeout(ts):
    def result(wrapped):
        pass
    return result

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
    def initialize(cls):
        # FIXME: call this function on load

        # FIXME: figure out how to fix this recursive module dependency
        database = cls.__dict__.setdefault('database', __import__('database'))
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
            structure = cls.__dict__.setdefault('structure', __import__('structure'))
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
        structure = cls.__dict__.setdefault('structure', __import__('structure'))

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

if __name__ == '__main__':
    fn = lambda: 0
    del(fn)

    @multicase()
    def fn():
        '''contains no arguments'''
        return 0

    @multicase(name=basestring)
    def fn(name):
        '''contains `name` which is a string'''
        return 1

    @multicase()
    def fn(something):
        '''contains an unknown field `something`'''
        return 2

    @multicase(blah1=six.integer_types)
    def fn(blah1, blah2):
        """This has the following format:
        blah1 -- is an int
        blah2 -- is unknown"""
        return 3

    @multicase(blah=str, blah2=int)
    def fn(blah,blah2,*args):
        return 4

    @multicase(blah=str, blah2=int)
    def fn(blah,blah2,**kwds):
        return 5

    print fn()
