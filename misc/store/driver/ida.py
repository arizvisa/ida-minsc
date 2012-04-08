import base,logging

import idaapi,idc,comment

class Deploy(base.Deploy):
    def __init__(self):
        raise NotImplementedError("Please use IDA for this. Thanks")
        # XXX: i guess i could start ida up and build a database...

def isNotEmpty(dict):

    # discard keys that are implied
    k = set(dict.keys())
    [k.discard(x) for x in ('__address__','__context__')]

    return len(k) > 0

class Driver(base.Driver):
    class search:
        # hacks to make ida work with the query module

        @classmethod
        def _not(cls, query):
            try:
                query.conjunction
                return True
            except AttributeError:
                pass

            try:
                query.clause.__iter__
                for x in query.clause:
                    if cls._not(x):
                        return True
                    continue
            except AttributeError:
                pass
            return False

        @classmethod
        def address(cls, query):
            try:
                return query.address
            except AttributeError:
                pass

            result = set()
            try:
                for x in query.clause:
                    result.update(cls.address(x))
            except AttributeError:
                pass
            return result

        @classmethod
        def attribute(cls, query):
            try:
                return query.names
            except AttributeError:
                pass

            result = set()
            try:
                for x in query.clause:
                    result.update(cls.attribute(x))
            except AttributeError:
                pass
            return result

        @classmethod
        def context(cls, query):
            try:
                return query.context
            except AttributeError:
                pass

            result = set()
            try:
                for x in query.clause:
                    result.update(cls.context(x))
            except AttributeError:
                pass
            return result

        @classmethod
        def between(cls,query):
            try:
                return set([(query.left,query.right)])
            except AttributeError:
                pass

            result = set()
            try:
                for x in query.clause:
                    result.update(cls.between(x))
            except AttributeError:
                pass
            return result

        @classmethod
        def checkinterval(cls, address, interval):
            if len(interval) > 0:
                left,right = interval.pop()
                if address >= left and address < right:
                    return True
                return cls.checkinterval(address, interval)
            return False

    @classmethod
    def tag_fetch(cls, session):
        return set()
    @classmethod
    def tag_add(cls, session, *names):
        return
    @classmethod
    def tag_discard(cls, session, *names):
        return
    @classmethod
    def con_edge(cls, session, (ctx_source,con_source),(ctx_target,con_target)):
        if ctx_source is None:
            sourcestring = '%x'% con_source
        else:
            sourcestring = '%x:%x'% (ctx_source,con_source)

        if ctx_target is None:
            deststring = '%x'% con_target
        else:
            deststring = '%x:%x'% (ctx_target,con_target)
        logging.debug("Refusing to add xref from %s to %s"%(sourcestring,deststring))

    @classmethod
    def con_unedge(cls, session, (ctx_source,con_source),(ctx_target,con_target)):
        if ctx_source is None:
            sourcestring = '%x'% con_source
        else:
            sourcestring = '%x:%x'% (ctx_source,con_source)

        if ctx_target is None:
            deststring = '%x'% con_target
        else:
            deststring = '%x:%x'% (ctx_target,con_target)
        logging.debug("Refusing to remove xref from %s to %s"%(sourcestring,deststring))

    #######
    @classmethod
    def ctx_update(cls, session, ea, dictionary):
        i = 0
        for i,(k,v) in enumerate(dictionary.iteritems()):
            session.ida.fn_write(ea,k,v)
        return i
    @classmethod
    def con_update(cls, session, ctx, ea, dictionary):
        i = 0
        for i,(k,v) in enumerate(dictionary.iteritems()):
            session.ida.db_write(ea,k,v)
        return i

    #######
    @classmethod
    def ctx_remove(cls, session, query):
        names = cls.search.attribute(query)
        if names:
            for ea in cls.ctx_select(session, query):
                [session.ida.fn_write(ea, k, None) for k in names]
            return

        i = 0
        for i,ea in enumerate(cls.ctx_select(session, query)):
            session.ida.fn_empty(ea)
        return i

    @classmethod
    def con_remove(cls, session, query):
        names = cls.search.attribute(query)
        if names:
            for ea in cls.con_select(session, query):
                [session.ida.db_write(ea, k, None) for k in names]
            return

        i = 0
        for i,ea in enumerate(cls.con_select(session, query)):
            session.ida.db_empty(ea)
        return i

    #######
    @classmethod
    def ctx_select_fast(cls, session, query):
        result = {}
        address = cls.__list_functions()

        # reduce it a bit
        intervals = cls.search.between(query)
        if intervals:
            address = [ x for x in address if cls.search.checkinterval(x, set(intervals)) ]

        list = cls.search.address(query)
        if list:
            address = [ x for x in address if x in list ]

        # only specific attributes
        names = cls.search.attribute(query)
        gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]

        for x in address:
            x = idc.GetFunctionAttr(x, idc.FUNCATTR_START)
            v = session.ida.fn_read(x)
            if query.has(v):
                result[x] = gather(v)
            continue
        return result

    @classmethod
    def ctx_select(cls, session, query):
        if not cls.search._not(query):
            return cls.ctx_select_fast(session, query)

        names = cls.search.attribute(query)
        gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]

        result = {}
        for x in cls.__list_functions():
            x = idc.GetFunctionAttr(x, idc.FUNCATTR_START)
            v = session.ida.fn_read(x)
            if query.has(v) and isNotEmpty(v):
                result[x] = gather(v)
            continue
        return result

    @classmethod
    def con_select_fast(cls, session, context, query):
        names = cls.search.attribute(query)
        gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]
        result = {}

        interval = cls.search.between(query)
        if interval:
            for ctx in context:
                for left,right in interval:
                    for ea in cls.__iterate(left,right):
                        v = session.ida.db_read(ea)
                        if query.has(v) and isNotEmpty(v):
                            result[ea] = gather(v)
                        pass
                    continue
                continue
            return result

        for ctx in context:
            for start,end in cls.__chunks(ctx):
                for ea in cls.__iterate(start, end):
                    v = session.ida.db_read(ea)
                    if query.has(v) and isNotEmpty(v):
                        result[ea] = gather(v)
                    pass
                continue
            continue
        return result

    @classmethod
    def con_select_fastest(cls, session, context, address, query):
        names = cls.search.attribute(query)
        gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]

        result = {}
        for ctx in context:
            interval = list(cls.__chunks(ctx))

            for ea in address:
                if cls.search.checkinterval(ea, set(interval)):
                    v = session.ida.db_read(ea)
                    if query.has(v) and isNotEmpty(v):
                        result[ea] = gather(v)
                    pass
                continue
            continue
        return result

    @classmethod
    def con_select(cls, session, query):
        context = cls.search.context(query)
        address = cls.search.address(query)

        if None in context and len(address) == 0:
            raise StandardError('driver.ida: refusing to search globally due to specified query.context(None)')

        noncontext = [x for x in context if x is not None]
        if cls.search._not(query) and len(noncontext) == 0:
            raise StandardError('driver.ida: refusing to search all functions and their entire content space for your inverted query. please use query.context or query.address and no query.not')
        elif context and address and len(noncontext) > 0:
            logging.debug('fastest %s %s',repr(address), repr(noncontext))
            return cls.con_select_fastest(session,context,address,query)
        elif context and len(noncontext) > 0:
            logging.debug('fast %s',repr(noncontext))
            return cls.con_select_fast(session,context,query)
        elif address:
            logging.debug('address %s', address)
            names = cls.search.attribute(query)
            gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]
            result = {}
            for ea in address:
                v = session.ida.db_read(ea)
                if query.has(v) and isNotEmpty(v):
                    result[ea] = gather(v)
                continue
            return result

        # check for intervals
        interval = cls.search.between(query)
        if interval:
            logging.debug('interval %s', repr(interval))
            names = cls.search.attribute(query)
            gather = (lambda x: x, lambda x: dict((k,v) for k,v in x.iteritems() if k in names))[len(names) > 0]
            result = {}
            for left,right in interval:
                for ea in cls.__iterate(left,right):
                    v = session.ida.db_read(ea)
                    if query.has(v) and isNotEmpty(v):
                        result[ea] = gather(v)
                    continue
                continue
            return result

        raise StandardError('driver.ida: refusing to search all functions and their entire content space for your query. please use query.context or query.address')

    @classmethod
    def __list_functions(cls):
        start,end = idaapi.cvar.inf.minEA,idaapi.cvar.inf.maxEA
        func = idaapi.get_func(start)
        if not func:
            func = idaapi.get_next_func(start)
        while func and func.startEA < end:
            startea = func.startEA
            yield startea
            func = idaapi.get_next_func(startea)
        return

    @classmethod
    def __iterate(cls, start, end):
        '''Iterate through instruction/data boundaries within the specified range'''
        while start < end:
            yield start
            start = idc.NextHead(start, idc.MaxEA())
        return

    @classmethod
    def __chunks(cls, ea):
        '''enumerates all chunks in a function '''
        res = idc.FirstFuncFchunk(ea)
        while res != idc.BADADDR:
            (start, end) = idc.GetFchunkAttr(res, idc.FUNCATTR_START), idc.GetFchunkAttr(res, idc.FUNCATTR_END)
            yield start,end
            res = idc.NextFuncFchunk(ea, res)
        return

class Session(base.Session):
    driver = Driver
    class ida:
        ### abstractions for ida
        @classmethod
        def __color_write(cls, ea, rgb, what=1):
            if rgb is None:
                return idc.SetColor(ea, what, 0xffffffff)

            a = rgb & 0xff000000
            rgb &= 0x00ffffff

            bgr = 0
            for i in xrange(3):
                bgr,rgb = ((bgr*0x100) + (rgb&0xff), rgb/0x100)
            return idc.SetColor(ea, what, bgr)

        @classmethod
        def __color_read(cls, ea, what=1):
            bgr = idc.GetColor(ea, what)
            if bgr == 0xffffffff:
                return None

            a = bgr&0xff000000
            bgr &= 0x00ffffff

            rgb = 0
            for i in xrange(3):
                rgb,bgr = ((rgb*0x100) + (bgr&0xff), bgr/0x100)
            return rgb

        @classmethod
        def color(cls, ea, *args, **kwds):
            '''color(address, rgb?) -> fetches or stores a color to the specified address'''
            if len(args) == 0:
                return cls.__color_read(ea, *args, **kwds)
            return cls.__color_write(ea, *args, **kwds)

        @classmethod
        def db_read(cls, address, key=None, repeatable=0):
            result = comment.toDict( idc.GetCommentEx(address, repeatable) )

            name = idc.NameEx(address, address)
            if name:
                result['__name__'] = name

            # defaults
            if '__color__' not in result:
                c = cls.color(address)
                if c is not None:
                    result['__color__'] = c
            if '__address__' not in result:
                result['__address__'] = address

            if '__context__' not in result:
                result['__context__'] = idc.GetFunctionAttr(address, idc.FUNCATTR_START)
            if '__sp__' not in result:
                result['__sp__'] = idc.GetSpd(address)

            if key is not None:
                return result[key]
            return result

        @classmethod
        def db_write(cls, address, key, value, repeatable=0):
            result = cls.db_read(address, repeatable=repeatable)
            result[key] = value

            if '__color__' in result:
                value = result['__color__']
                cls.color(address, value)
                del(result['__color__'])

            if '__address__' in result:
                del(result['__address__'])

            # del all hidden things
            result = dict((k,v) for k,v in result.iteritems() if not k.startswith('__'))

            res = comment.toString(result).encode('ascii')
            if repeatable:
                return idc.MakeRptCmt(address, res)
            return idc.MakeComm(address, res)

        @classmethod
        def db_tag(cls, address, *args, **kwds):
            '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''

            if idc.GetFunctionAttr(address, idc.FUNCATTR_FLAGS) != idc.BADADDR:
                if 'repeatable' not in kwds:
                    kwds['repeatable'] = False
            else:
                # not in a function, could be a global, so it's now repeatable
                if 'repeatable' not in kwds:
                    kwds['repeatable'] = True
                pass

            if len(args) < 2:
                return cls.db_read(int(address), *args, **kwds)

            key,value = args
            return cls.db_write(int(address), key, value, **kwds)

        @classmethod
        def fn_read(cls, address, key=None, repeatable=1):
            address = idc.GetFunctionAttr(address, idc.FUNCATTR_START)
            if address == idc.BADADDR:
                raise ValueError("Address %x not in function"% address)

            result = comment.toDict(idc.GetFunctionCmt(int(address), repeatable))
            if '__name__' not in result:
                result['__name__'] = idc.GetFunctionName(address)

            if '__address__' not in result:
                result['__address__'] = address

            if key is not None:
                return result[key]
            return result

        @classmethod
        def fn_write(cls, address, key, value, repeatable=1):
            result = cls.fn_read(address, repeatable=repeatable)
            result[key] = value
            if '__address__' in result:
                del(result['__address__'])
            result = dict((k,v) for k,v in result.iteritems() if not k.startswith('__'))
            return idc.SetFunctionCmt(int(address), comment.toString(result).encode('ascii'), repeatable)

        @classmethod
        def fn_tag(cls, address, *args, **kwds):
            '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
            if len(args) < 2:
                return cls.fn_read(address, *args, **kwds)
            key,value = args
            return cls.fn_write(address, key, value, **kwds)

        @classmethod
        def fn_empty(cls, address, repeatable=1):
            idc.SetFunctionCmt(int(address), '', repeatable)
            pass

        @classmethod
        def db_empty(cls, address, repeatable=0):
            if repeatable:
                cls.color(address, None)
                return idc.MakeRptCmt(int(address), '')
            cls.color(address, None)
            return idc.MakeComm(int(address), '')

    def commit(self):
        pass
    def rollback(self):
        pass
