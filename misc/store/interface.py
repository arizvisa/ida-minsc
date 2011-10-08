import logging,query
import cPickle as pickle

## for marshalling/unmarshalling data from the `value` field
try:
    import fu
    __dumps = fu.dumps
    __loads = fu.loads
    logging.error('unable to use fu module. falling back to pickle')
    raise ImportError
    # FIXME: there's some problem with writing null bytes into a BLOB field
    #           I think it's related to the escaping that happens during my sql
    #           insertion. i should build a testcase

except ImportError:
    __dumps = pickle.dumps
    __loads = pickle.loads

def dumps(x):
    if type(x) in (int,long):
        return x
    return __dumps(x)
def loads(x):
    return __loads(x)

## base user-interface (not really designed)
class __base__(object):
    def __init__(self):
        raise NotImplementedError
        self.context = self.contexttable(self)
        self.content = self.contenttable(self)

    # FIXME: the following interface definitions are not correct,
    #           look at the implementations below this for the correct ones
    class table(object):
        database = property(fget=lambda s: s.interface.database)
        def __init__(self, interface):
            self.interface = interface

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
    import data
    import idaapi,idc
    class ida(__base__):
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
                    data.ida.fn_tag(address, k, v)
                return
            @classmethod
            def unset(cls, address, key=None):
                if key is None:
                    for k,v in data.ida.fn_tag(address).iteritems():
                        data.ida.fn_tag(address, k, None)
                    return
                return data.ida.fn_tag(address, key, None)

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
#                    x = ida.function.top(x)    # XXX
                    x = idc.GetFunctionAttr(x, idc.FUNCATTR_START)
                    v = data.ida.fn_tag(x)
                    if q.has(v):
                        result[x] = v
                    continue
                return result

            @classmethod
            def get(cls, ea):
                return data.ida.fn_tag(ea)

            @classmethod
            def edge(cls, source, target):
                '''add an edge from (context address, content address) to (context address, content address)'''
                source = ((None,source), source)[type(source) is tuple]
                target = ((None,target), target)[type(target) is tuple]
                # XXX: should we add an xref anyways?

        class content(__base__.contenttable):
            @classmethod
            def set(cls, context_ea, ea, **attributes):
#                if context_ea is not None and not ida.function.contains(context_ea, ea):   # XXX
#                    logging.warning('function %x does not contain %x'%(context_ea,ea))
                for k,v in attributes.iteritems():
                    data.ida.db_tag(ea, k, v)
                return

            @classmethod
            def __rm_all(cls, context_ea, key=None):
                for start,end in cls.__chunks(context_ea):
                    for x in cls.__iterate(start,end):
                        if key is not None:
                            data.ida.db_tag(x, key, None)
                            continue

                        for k in data.ida.db_tag(x).iterkeys():
                            data.ida.db_tag(x, k, None)
                        continue
                    continue
                return

            @classmethod
            def __rm_single(cls, context_ea, address, key=None):
#                assert ida.function.contains(context_ea, address)  # XXX
                if key:
                    return data.ida.db_tag(address, key, None)
                    
                for k in data.ida.db_tag(address).iterkeys():
                    data.ida.db_tag(address, k, None)
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
                if ea is None:
                    return cls.__select_global(ea, *q)
                return cls.__select_function(ea, *q)

            @classmethod
            def __select_global(cls, ea, *q):
                assert ea is None

                addresses = [x for x in q if type(x) is query.address]
                # FIXME: add query.between too
                assert len(addresses) > 0
                q = (query.all(), query._and(*q))[bool(q)]

                result = {}
                for x in addresses:
                    ea, = x.address

                    d = data.ida.db_tag(ea)
                    # only add record if it's not empty
                    if len(d)>1 or q.has(d):
                        result[ea] = d
                    continue
                return result

            @classmethod
            def __select_function(cls, ea, *q):
                # XXX: if ea is None, then this will search the query for the hardcoded address
                #      instead of actually searching ida's entire addressspace
                q = (query.all(), query._and(*q))[bool(q)]
                result = {}
                for start,end in cls.__chunks(ea):
                    for x in cls.__iterate(start, end):
                        d = data.ida.db_tag(x)
                        # only add record if it's not empty
                        if len(d)>1 or q.has(d):
                            result[x] = d
                        continue
                    continue
                return result

except ImportError:
    logging.warning("Unable to load store.interface.ida module")
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
            c = self.database.execute('replace into tag (session,name) values (?,?)', (self.interface.id,name,))
            return c.lastrowid

        def __drop_context(self, id):
            c = self.database.execute('delete from context where session=?', (id,))
            return c.rowcount

        def __drop_content(self, id):
            c = self.database.execute('delete from content where session=?', (id,))
            return c.rowcount

        def drop(self, name, recurse=True):
            r = self.database.execute('select id from tag where name=? and session=?', (name,self.interface.id,)).fetchone()
            if r is None:
                raise KeyError("Tag '%s' for session %d not found"% (name, self.interface.id))
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
            [ self.interface.tag.add(k) for k in set(attr.iterkeys()).difference(self.interface.tag.list())]            # XXX: this can be racy...
            result = [(self.interface.id,address,dumps(v),k) for k,v in attr.iteritems()]    # XXX: HACK: conditionally keep integers in database for querying
            q = 'replace into context (session,address,tag,value) select ?,?,id,? from tag where tag.name=?'
            return self.database.executemany(q, result).rowcount == len(attr)
            
        def unset(self, address, key=None):
            if key:
                return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=? and tag.name=?', self.interface.id, address, key).rowcount
            return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=?', self.interface.id, address).rowcount

        def select(self, *q):
            if q:
                q = query._and(*q)
            else:
                q = query.all()
            result={}
            for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from context dataset left join tag on tag.id = dataset.tag left join content on content.context=dataset.address where %s'% q.sqlq(), q.sqld()):
                if address not in result:
                    result[address] = {}
                if type(v) is unicode:
                    v = loads(v.encode('ascii'))
                result[address][k.encode('ascii')] = v
            return result

        def get(self, ea):
            return self.select(query.address(ea))[ea]

        def edge(self, source, target):
            '''add an edge from (context address, content address) to (context address, content address)'''
            source = ((None,source), source)[type(source) is tuple]
            target = ((None,target), target)[type(target) is tuple]

            q = 'replace into edge (session,source,target,start,end) values (?,?,?,?,?)'
            return self.database.execute(q, (self.interface.id,source[1],target[1],source[0],target[0])).rowcount == 1

        def unedge(self, source, target):
            raise NotImplementedError

    ### adding/removing tags to an address space        # XXX: i don't believe this to work correctly
    class __content(__base__.contenttable):
        def set(self, *args, **attr):
            if len(args) == 2:
                context_ea,ea = args
            else:
                context_ea,(ea,) = None, args

            [ self.interface.tag.add(k) for k in set(attr.iterkeys()).difference(self.interface.tag.list())]      # XXX: this can be racy...
            result = ((context_ea,self.interface.id,ea,dumps(v),k) for k,v in attr.iteritems())  # XXX: HACK: conditionally keep integers in database for querying
            q = 'replace into content (context,session,address,tag,value) select ?,?,?,tag.id,? from tag where tag.name=?'
            return self.database.executemany(q, result).rowcount == len(attr)

        def __rm_single(self, context_ea, ea, key=None):
            if key is None:
                return self.database.execute('delete from content where content.session=? and content.context=? and content.address=?', (self.interface.id, context_ea, address)).rowcount
            return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.context=? and content.address=? and tag.name=?', (self.interface.id, context_ea, ea, key)).rowcount

        def __rm_all(self, context_ea, key=None):
            if key is None:
                return self.database.execute('delete from content where content.session=? and content.context=?', (self.interface.id, context_ea)).rowcount
            return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.address=? and tag.name=?', (self.interface.id, context_ea ,key)).rowcount

        def unset(self, context_ea, address=None, key=None):
            if address is None:
                return self.__rm_all(context_ea, key)
            return self.__rm_single(context_ea, address, key)

        def select(self, ea, *q):
            if q:
                q = query._and(*q)
            else:
                q = query.all()
            result = {}
            for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from content dataset left join tag on tag.id = dataset.tag left join context on context.address=dataset.context where dataset.context=? and %s'% q.sqlq(), (ea,)+q.sqld()):
                if address not in result:
                    result[address] = {}
                if type(v) is unicode:      # XXX: HACK: assume that if we get a unicode, it's marshalled. otherwise it's a string
                    v = loads(v.encode('ascii'))
                result[address][k.encode('ascii')] = v
            return result
