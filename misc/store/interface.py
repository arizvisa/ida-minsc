import logging,query
import cPickle as pickle
#import fu

## base user-interface (not really designed)
class __base__(object):
    def __init__(self):
        raise NotImplementedError
        self.context = self.contexttable(self)
        self.content = self.contenttable(self)

    # FIXME: the following interface definitions are not correct,
    #           look at the implementations below this for the correct ones
    class table(object):
        def __init__(self, interface):
            self.interface = interface
        def __getattr__(self, key):
            return getattr(self.interface, key)
        def set(self, address, **attributes):
            raise NotImplementedError
        def unset(self, address, key=None):
            raise NotImplementedError
        def select(self, query=query.all()):
            raise NotImplementedError

    # for simulating transactional
    def commit(self):
        return
    def rollback(self):
        return

    class contexttable(table): pass
    class contenttable(table): pass

## ida accessing interface
try:
    import database
    import idaapi,idc
    class ida(__base__):
        import function
        def __init__(self):
            pass

        @classmethod
        def commit(self):
            return
        @classmethod
        def rollback(self):
            return

        class context(__base__.contexttable):
            @classmethod
            def set(cls, address, **attributes):
                for k,v in attributes.iteritems():
                    database.ida.fn_tag(address, k, v)
                return
            @classmethod
            def unset(cls, address, key=None):
                if key is None:
                    for k,v in database.ida.fn_tag(address).iteritems():
                        database.ida.fn_tag(address, k, None)
                    return
                return database.ida.fn_tag(address, key, None)

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
            def select(cls, *q):
                if q:
                    q = query._and(*q)
                else:
                    q = query.all()
                result = {}
                for x in list(cls.__list_functions()):
                    x = ida.function.top(x)
                    v = database.ida.fn_tag(x)
                    if q.has(v):
                        result[x] = v
                    continue
                return result

            @classmethod
            def get(cls, ea):
                return database.ida.fn_tag(ea)

        class content(__base__.contenttable):
            @classmethod
            def set(cls, context_ea, ea, **attributes):
                if context_ea is not None and not ida.function.contains(context_ea, ea):
                    logging.warning('function %x does not contain %x'%(context_ea,ea))
                for k,v in attributes.iteritems():
                    database.ida.db_tag(ea, k, v)
                return

            @classmethod
            def __rm_all(cls, context_ea, key=None):
                for start,end in cls.__chunks(context_ea):
                    for x in cls.__iterate(start,end):
                        if key is not None:
                            database.ida.db_tag(x, key, None)
                            continue

                        for k in database.ida.db_tag(x).iterkeys():
                            database.ida.db_tag(x, k, None)
                        continue
                    continue
                return

            @classmethod
            def __rm_single(cls, context_ea, address, key=None):
                assert ida.function.contains(context_ea, address)
                if key:
                    return database.ida.db_tag(address, key, None)
                    
                for k in database.ida.db_tag(address).iterkeys():
                    database.ida.db_tag(address, k, None)
                return

            @classmethod
            def unset(cls, context_ea, address=None, key=None):
                if address is None:
                    return cls.__rm_all(context_ea, key)
                return cls.__rm_single(context_ea, address, key)

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
            def select(cls, ea, *q):
                if q:
                    q = query._and(*q)
                else:
                    q = query.all()

                # FIXME: if ea is None, then search the entire database?
                assert ea is not None

                result = {}
                for start,end in cls.__chunks(ea):
                    for x in cls.__iterate(start, end):
                        d = database.ida.db_tag(x)
                        # only add record if it's not empty
                        if len(d)>1 and q.has(d):
                            result[x] = d
                        continue
                    continue
                return result

except ImportError:
    pass

## sqlite user-based interface
class sql(__base__):
    __id = 0
    id = property(fget=lambda s: s.__id)
    tags = property(fget=lambda s: s.tag.list())

    def __init__(self, database, session=None):
        self.database = database

        if session:
            r = self.database.execute('select id from session where name=?', (session,)).fetchone()
            if r is None:
                raise KeyError("Session '%s' not found"% session)
            self.__id = r[0]
        else:
            logging.warning('defaulting to maintenance account (session id 0)')
            self.__id = 0

        self.tag = self.__tag(self)
        self.content = self.__content(self)
        self.context = self.__context(self)

    def commit(self):
        return self.database.commit()
    def rollback(self):
        return self.database.rollback()

    ### global tag management
    class __tag(__base__.table):
        def list(self):
            return set(x[0] for x in self.database.execute('select name from tag').fetchall())

        def add(self, name):
            c = self.database.execute('insert into tag (session,name) values (?,?)', (self.id,name,))
            return c.lastrowid

        def __drop_context(self, id):
            c = self.database.execute('delete from context where session=?', (id,))
            return c.rowcount

        def __drop_content(self, id):
            c = self.database.execute('delete from content where session=?', (id,))
            return c.rowcount

        def drop(self, name, recurse=True):
            r = self.database.execute('select id from tag where name=? and session=?', (name,self.id,)).fetchone()
            if r is None:
                raise KeyError("Tag '%s' for session %d not found"% (name, self.id))
            id = r[0]

            rowcount = 0
            if recurse:
                rowcount += self.__droptag_context(id)
                rowcount += self.__droptag_content(id)
            c = self.database.execute('delete from tag where id=?', (id,))
            return rowcount + c.rowcount

    ### for adding/removing tags to functions
    class __context(__base__.contexttable):
        def set(self, *args, **attr):
            address, = args
            [ self.tag.add(k) for k in set(attr.iterkeys()).difference(self.tags)]      # XXX: this can be racy...
            result = [(self.id,address,v,k) for k,v in attr.iteritems()]
            q = 'replace into context (session,address,tag,value) select ?,?,id,? from tag where tag.name=?'
            return self.database.executemany(q, result).rowcount == len(attr)
            
        def unset(self, address, key=None):
            if key:
                return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=? and tag.name=?', self.id, address, key).rowcount
            return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=?', self.id, address).rowcount

        def select(self, *q):
            if q:
                q = query._and(*q)
            else:
                q = query.all()
            result={}
            for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from context dataset left join tag on tag.id = dataset.tag left join content on content.context=dataset.address where %s'% q.sqlq(), q.sqld()):
                if address not in result:
                    result[address] = {}
                if type(v) is unicode:      # XXX: HACK: assume that if we get a unicode, it's marshalled. otherwise it's a string
                    try:
                        v = pickle.loads(v.encode('ascii'))
                    except pickle.UnpicklingError:
                        #logging.info('Treating marshalled data (%s) as a string'% repr(v))
                        v = v
                result[address][k] = v
            return result

        def get(self, ea):
            return self.select(query.address(ea))[ea]

    ### adding/removing tags to an address space        # XXX: i don't believe this to work correctly
    class __content(__base__.contenttable):
        def set(self, *args, **attr):
            if len(args) == 2:
                context_ea,ea = args
            else:
                context_ea,(ea,) = None, args

            [ self.tag.add(k) for k in set(attr.iterkeys()).difference(self.tags)]      # XXX: this can be racy...

            result = ((context_ea,self.id,ea,v,k) for k,v in attr.iteritems())
            q = 'replace into content (context,session,address,tag,value) select ?,?,?,tag.id,? from tag where tag.name=?'
            return self.database.executemany(q, result).rowcount == len(attr)

        def unset(self, address, key):
            if key:
                return self.database.execute('delete from content where session=? and address=? and tag=?', self.id, address, key).rowcount
            return self.database.execute('delete from content where session=? and address=?', self.id, address).rowcount

        def __rm_single(context_ea, ea, key=None):
            if key is None:
                return self.database.execute('delete from content where content.session=? and content.context=? and content.address=?', (self.id, context_ea, address)).rowcount
            return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.context=? and content.address=? and tag.name=?', (self.id, context_ea, address, key)).rowcount

        def __rm_all(context_ea, key=None):
            if key is None:
                return self.database.execute('delete from content where content.session=? and content.context=?', (self.id, context_ea)).rowcount
            return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.address=? and tag.name=?', (self.id, context_ea ,key)).rowcount

        def unset(self, context_ea, address=None, key=None):
            if address is None:
                return self.__rm_all(context_ea, key)
            return self.__rm_single(context_ea, address, key)

        def select(self, ea, *q):
            if q:
                q = query._and(*q)
            else:
                q = query.all()
            result={}
            for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from content dataset left join tag on tag.id = dataset.tag left join context on context.address=dataset.context where dataset.context=? and %s'% q.sqlq(), (ea,)+q.sqld()):
                if address not in result:
                    result[address] = {}
                if type(v) is unicode:      # XXX: HACK: assume that if we get a unicode, it's marshalled. otherwise it's a string
                    try:
                        v = pickle.loads(v.encode('ascii'))
                    except pickle.UnpicklingError:
                        #logging.info('Treating marshalled data (%s) as a string'% repr(v))
                        v = v
                result[address][k] = v
            return result
