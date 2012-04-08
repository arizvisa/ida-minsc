import driver,trigger,query
session = driver.sqlite.Session

class Store(set):
    session = property(fget=lambda x:x.__session)
    driver = property(fget=lambda x:x.__session.driver)

    def commit(self):
        return self.session.commit()
    def rollback(self):
        return self.session.rollback()

    def __init__(self, session):
        self.__session = session
        self.reset()

    def reset(self):
        super(Store,self).clear()
        [ super(Store,self).add(x) for x in self.driver.tag_fetch(self.session) ]

    c = property(fget=lambda x:x.address)
    def address(self, ea):
        return Context(self, ea)    # XXX: hopefully the cost of constructing these isn't too expensive

    def add(self, *names):
        result = self.driver.tag_add(self.session, *names)
        super(Store,self).update(set(names))
        return result

    def remove(self, *names):
        result = self.driver.tag_discard(self.session, *names)
        for x in names:
            super(Store,self).discard(x)
        return result

    def select(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        return self.driver.ctx_select(self.session, q)

    def select_content(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        return self.driver.con_select(self.session, q)

    def __repr__(self):
        self.reset()
        return '%s %s'%(type(self), super(Store,self).__repr__())

class CachedDict(dict):
    '''Contains a caching dictionary that syncs with some data source'''
    # stuff to use
    def keys(self): 
        return list(self.iterkeys())
    def values(self):
        return list(self.itervalues())
    def items(self):
        return list(self.iteritems())
    def __iter__(self):
        return self.iterkeys()
    def __repr__(self):
        return '%s address:0x%x %s'%(type(self), self.id, super(CachedDict,self).__repr__())

    l = property(fget=lambda x: x.sync())
    def sync(self):
        return dict(self.items())

    # like a dictionary
    def __getitem__(self, key):
        if super(CachedDict,self).__contains__(key):
            return super(CachedDict,self).__getitem__(key)

        result = self.get(key)[key]
        super(CachedDict,self).__setitem__(key, result)
        return result

    def __setitem__(self, key, value):
        super(CachedDict,self).__setitem__(key, value)
        return self.set( **{key:value} )
    def __delitem__(self, key):
        if key in self:
            super(CachedDict,self).__delitem__(key)
        return self.unset(key)

    def iteritems(self):
        for k,v in self.get().iteritems():
            super(CachedDict,self).__setitem__(k,v)
            yield k,v
        return

    # stuff to implement
    def iterkeys(self):
        raise NotImplementedError
    def set(self, **attrs):
        raise NotImplementedError
    def unset(self, *names):
        raise NotImplementedError
    def get(self, *names):
        raise NotImplementedError

    # for caching an already created object
    a = property(fget=lambda x:x.address)
    __address = dict
    def address(self, ea):
        raise NotImplementedError

    def __init__(self):
        self.__address = {}
        return super(CachedDict,self).__init__()

class Context(CachedDict):
    id = property(fget=lambda x:x.__id)
    store = property(fget=lambda x:x.__store)

    def __init__(self, store, address):
        self.__id = address
        self.__store = store
        return super(Context,self).__init__()

    a = property(fget=lambda x:x.address)
    def address(self, ea):
        return Content(self, ea)

    def iterkeys(self):
        result = self.store.driver.ctx_select(self.store.session, query.address(self.id))
        try:
            return result[self.id].iterkeys()
        except KeyError:
            pass
        return iter(())

    def set(self, **attrs):
        # XXX
        [self.store.add(k) for k in set(attrs.iterkeys()).difference(self.store)]            # XXX: this is racy if we use a real database
        return self.store.driver.ctx_update(self.store.session, self.id, attrs)
    def get(self, *names):
        if names:
            result = self.store.driver.ctx_select(self.store.session, query._and(query.address(self.id),query.attribute(*names)))
        else: 
            result = self.store.driver.ctx_select(self.store.session, query.address(self.id))
        return result[self.id]
    def unset(self, *names):
        if names:
            result = self.store.driver.ctx_remove(self.store.session, query._and(query.address(self.id),query.attribute(*names)))
        else:
            result = self.store.driver.ctx_remove(self.store.session, query._and(query.address(self.id)))
        return result

    def select(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        return self.store.driver.con_select(self.store.session, query._and(query.context(self.id), q))

class Content(CachedDict):
    id = property(fget=lambda x:x.__id)
    context = property(fget=lambda x:x.__context)
    store = property(fget=lambda x:x.__context.store)

    def __init__(self, context, address):
        self.__context = context
        self.__id = address
        return super(Content,self).__init__()

    def edge(self, (destination,address)):
        return self.store.driver.con_edge(self.store.session, (self.context.id,self.id), (destination,address))

    def unedge(self, reference):
        if reference:
            destination,address = reference
            return self.store.driver.con_unedge(self.store.session, (self.context.id,self.id), (destination,address))

        q = 'drop from edge where start=? and source=?'
        raise NotImplementedError
        return self.store.driver.con_unedge(self.store.session, (self.context.id,self.id), (destination,address))

    def iterkeys(self):
        return self.store.driver.con_select(self.store.session, query._and(query.context(self.context.id),query.address(self.id)))[self.id].iterkeys()
    def set(self, **attrs):
        # XXX: this is racy if we use a real database
        [self.store.add(k) for k in set(attrs.iterkeys()).difference(self.store)]
        return self.store.driver.con_update(self.store.session, self.context.id, self.id, attrs)
    def get(self, *names):
        if names:
            result = self.store.driver.con_select(self.store.session, query._and(query.context(self.context.id),query.address(self.id),query.attribute(*names)))
        else:
            result = self.store.driver.con_select(self.store.session, query._and(query.context(self.context.id),query.address(self.id)))
        return result[self.id]
    def unset(self, *names):
        if names:
            result = self.store.driver.con_remove(self.store.session, query._and(query.context(self.context.id),query.address(self.id), query.attribute(*names)))
        else: 
            result = self.store.driver.con_remove(self.store.session, query._and(query.context(self.context.id),query.address(self.id)))
        return result

### friendly interfaces
import os,logging
import sqlite3
def open(path, id=None):
    if os.path.exists(path):
        db = sqlite3.connect(path)
        session = driver.sqlite.Session(db, id)
        logging.info('succcessfully opened up database %s as %s'% (path, id))
        return Store(session)

    db = sqlite3.connect(path)
    driver.sqlite.Deploy(db).create()
    db.commit()
    logging.info('succcessfully created database %s'% path)

    driver.sqlite.Deploy(db).session(id)
    session = driver.sqlite.Session(db, id)
    logging.info('succcessfully created new session for %s'% id)

    return Store(session)

if 'ida' in driver.list:
    ida = Store(driver.ida.Session())

    import idc
    __open = open
    def open(path=None, id=None):
        if path is None:
            path = idc.GetIdbPath().replace('\\','/')
            path = path[: path.rfind('/')] 
            path = '%s/%s.db'%(path,idc.GetInputFile())
        return __open(path, id)
