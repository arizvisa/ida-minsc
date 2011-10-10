import base,logging

import idaapi,idc,comment

class Deploy(base.Deploy):
    def __init__(self):
        raise NotImplementedError("Please use IDA for this. Thanks")
        # XXX: i guess i could start ida up and build a database...

class Driver(base.Driver):
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

    @classmethod
    def ctx_update(cls, session, ea, dictionary):
        for k,v in dictionary.iteritems():
            session.ida.fn_write(ea,k,v)
        return
    @classmethod
    def con_update(cls, session, ctx, ea, dictionary):
        for k,v in dictionary.iteritems():
            session.ida.db_write(ea,k,v)
        return
    @classmethod
    def ctx_remove(cls, session, query, names):
        for ea in ctx_select(sesion, query):
            [session.ida.fn_write(ea, k, None) for k in names]
        return
    @classmethod
    def con_remove(cls, session, query, names):
        for ea in con_select(session, query):
            [session.ida.db_write(ea, k, None) for k in names]
        return

    @classmethod
    def ctx_select(cls, session, query):
        result = {}
        for x in list(cls.__list_functions()):
            x = idc.GetFunctionAttr(x, idc.FUNCATTR_START)
            v = session.ida.fn_read(x)
            if query.has(v):
                result[x] = v
            continue
        return result

    # search query for something that can lead to an address
    @classmethod
    def search_address(cls, query):
        try:
            return set(query.address)
        except AttributeError:
            pass

        # XXX: pretty bad, man...
        result = set()
        try:
            for x in query.clause:
                result.update(cls.search_address(x))
        except AttributeError:
            pass
        return result

    @classmethod
    def con_select(cls, session, query):
        list = cls.search_address(query)
        if len(list) > 0:
            result = {}
            for ea in list:
                result.update(cls.__select_function(session, ea, query))
            return result

        raise NotImplementedError("not really tested..")
        return cls.__select_global(session, query)

    @classmethod
    def __select_global(cls, session, q):
        addresses = cls.search_address(q)
        # FIXME: add explicit support for query.between too
        assert len(addresses) > 0

        result = {}
        for x in addresses:
            ea, = x.address

            d = session.ida.db_read(ea)
            # only add record if it's not empty
            if len(d)>1 and q.has(d):
                result[ea] = d
            continue
        return result

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

    @classmethod
    def __select_function(cls, session, ea, q):
        result = {}
        for start,end in cls.__chunks(ea):
            for x in cls.__iterate(start, end):
                d = session.ida.db_read(x)
                # only add record if it's not empty (__address__ always exists)
                if len(d)>1 and q.has(d):
                    result[x] = d
                continue
            continue
        return result

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

            c = cls.color(address)
            if c is not None:
                result['__color__'] = c

            if '__address__' not in result:
                result['__address__'] = address
            if '__context__' not in result:
                result['__context__'] = idc.GetFunctionAttr(address, idc.FUNCATTR_START)

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
            return idc.SetFunctionCmt(int(address), comment.toString(result).encode('ascii'), repeatable)

        @classmethod
        def fn_tag(cls, address, *args, **kwds):
            '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
            if len(args) < 2:
                return cls.fn_read(address, *args, **kwds)
            key,value = args
            return cls.fn_write(address, key, value, **kwds)

    def commit(self):
        pass
    def rollback(self):
        pass
