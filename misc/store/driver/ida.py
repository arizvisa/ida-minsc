import base
import logging,query

class Deploy(base.Deploy):
    def __init__(self):
        raise NotImplementedError("Please use IDA for this. Thanks")
        # XXX: i guess i could start ida up and build a database...

try:
    import idaapi,idc,comment

    class Session(base.Session):
        def __init__(self):
            return
        def commit(self):
            return
        def rollback(self):
            return

    class Store(base.Store):
        __session = Session()

        def __init__(self, session=None):
            super(Store,self).__init__()

        def address(self, ea):
            return Context(self,ea)

        def __list_functions(self):
            start,end = idaapi.cvar.inf.minEA,idaapi.cvar.inf.maxEA
            func = idaapi.get_func(start)
            if not func:
                func = idaapi.get_next_func(start)
            while func and func.startEA < end:
                startea = func.startEA
                yield startea
                func = idaapi.get_next_func(startea)
            return

        def select(self, *q):
            q = (query.all(), query._and(*q))[bool(q)]
            result = {}
            for x in list(self.__list_functions()):
                x = idc.GetFunctionAttr(x, idc.FUNCATTR_START)
                v = self.ida.fn_read(x)
                if q.has(v):
                    result[x] = v
                continue
            return result

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

                res = comment.toString(result)
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
                return idc.SetFunctionCmt(int(address), comment.toString(result), repeatable)

            @classmethod
            def fn_tag(cls, address, *args, **kwds):
                '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
                if len(args) < 2:
                    return cls.fn_read(address, *args, **kwds)
                key,value = args
                return cls.fn_write(address, key, value, **kwds)

    class Context(base.Context):
        def __init__(self, store, address):
            super(Context,self).__init__()
            self.__id = address
            self.__store = store

        def reset(self):
            super(Context,self).clear()
            super(Context,self).update(self.store.ida.fn_read(self.id))

        def address(self, ea):
            return Content(self, ea)

        def __repr__(self):
            self.reset()
            return super(Context,self).__repr__()
            
        def __getitem__(self, key):
            return self.store.ida.fn_read(self.id, key)
        def __setitem__(self, key, value):
            return self.store.ida.fn_write(self.id, key, value)
        def __delitem__(self, key):
            return self.store.ida.fn_write(self.id, key, None)
        def keys(self):
            return self.store.ida.fn_read(self.id).keys()

        def select(self, *q):
            q = (query.all(), query._and(*q))[bool(q)]
            if self.id is None:
                return self.__select_global(q)
            return self.__select_function(q)

        def __select_global(self, q):
            addresses = [x for x in q if type(x) is query.address]
            # FIXME: add explicit support for query.between too
            assert len(addresses) > 0

            result = {}
            for x in addresses:
                ea, = x.address

                d = self.store.ida.db_read(ea)
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

        def __select_function(self, q):
            result = {}
            for start,end in self.__chunks(self.id):
                for x in self.__iterate(start, end):
                    d = self.store.ida.db_read(x)
                    # only add record if it's not empty (__address__ always exists)
                    if len(d)>1 and q.has(d):
                        result[x] = d
                    continue
                continue
            return result

    class Content(base.Content):
        def __init__(self, context, address):
            super(Content,self).__init__()
            self.__context = context
            self.__id = address

        def reset(self):
            super(Content,self).clear()
            super(Content,self).update(self.store.ida.db_read(self.id))

        def __repr__(self):
            self.reset()
            return super(Content,self).__repr__()

        def __getitem__(self, key):
            return self.store.ida.db_read(self.id, key)
        def __setitem__(self, key, value):
            return self.store.ida.db_write(self.id, key, value)
        def __delitem__(self, key):
            return self.store.ida.db_write(self.id, key, None)
        def keys(self):
            return self.store.ida.db_read(self.id).keys()

        def edge(self, (destination,address)):
            if self.context.id is None:
                sourcestring = '%x'% self.id
            else:
                sourcestring = '%x:%x'% (self.context.id, self.id)

            if destination is None:
                deststring = '%x'% address
            else:
                deststring = '%x:%x'% (destination,address)

            logging.warning("Refusing to add xref from %s to %s"%(sourcestring,deststring))
            return False 

except ImportError:
    logging.warning('unable to import idc module. skipping loading of ida driver')
