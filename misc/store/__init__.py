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

class Context(dict):
    id = property(fget=lambda x:x.__id)
    store = property(fget=lambda x:x.__store)

    def __init__(self, store, address):
        super(Context,self).__init__()
        self.__id = address
        self.__store = store

    def reset(self):
        super(Context,self).clear()
        result = self.store.select(query.address(self.id))
        if len(result) > 0:
            super(Context,self).update(result[self.id])
        return self

    a = property(fget=lambda x:x.address)
    def address(self, ea):
        return Content(self, ea)

    # friendly stuff
    def __repr__(self):
        self.reset()
        return super(Context,self).__repr__()
    def __getitem__(self, key):
        result = self.store.select(query.address(self.id),query.attribute(key))
        try:
            return result[self.id][key]
        except KeyError:
            pass
        raise KeyError((hex(self.id),key))
    def __setitem__(self, key, value):
        return self.set(**{key:value})
    def __delitem__(self, key):
        return self.unset(key)
    def keys(self):
        return self.store.select(query.address(self.id))[self.id].keys()

    def set(self, **attrs):
        [self.store.add(k) for k in set(attrs.iterkeys()).difference(self.store)]            # XXX: this is racy if we use a real database
        return self.store.driver.ctx_update(self.store.session, self.id, attrs)
    def unset(self, *names):
        return self.store.driver.ctx_remove(self.store.session, query._and(query.address(self.id), query.attribute(*names)))

    def select(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        return self.store.driver.con_select(self.store.session, query._and(query.context(self.id), q))

class Content(dict):
    id = property(fget=lambda x:x.__id)
    context = property(fget=lambda x:x.__context)
    store = property(fget=lambda x:x.__context.store)

    def __init__(self, context, address):
        super(Content,self).__init__()
        self.__context = context
        self.__id = address

    def reset(self):
        super(Content,self).clear()
        result = self.context.select(query.address(self.id))[self.id]
        super(Content,self).update(result)
        return self

    def __repr__(self):
        self.reset()
        return super(Content,self).__repr__()

    def edge(self, (destination,address)):
        return self.store.driver.con_edge(self.store.session, (self.context.id,self.id), (destination,address))

    def unedge(self, reference):
        if reference:
            destination,address = reference
            return self.store.driver.con_unedge(self.store.session, (self.context.id,self.id), (destination,address))

        q = 'drop from edge where start=? and source=?'
        raise NotImplementedError
        return self.store.driver.con_unedge(self.store.session, (self.context.id,self.id), (destination,address))

    def __getitem__(self, key):
        result = self.context.select(query.attribute(key), query.address(self.id))
        try:
            return result[self.id][key]
        except KeyError:
            pass
        raise KeyError((hex(self.context.id),hex(self.id),key))
    def __setitem__(self, key, value):
        return self.set(**{key:value})
    def keys(self):
        return self.context.select(query.address(self.id))[self.id].keys()
    def __delitem__(self, key):
        return self.unset(key)

    def set(self, **attrs):
        [self.store.add(k) for k in set(attrs.iterkeys()).difference(self.store)]            # XXX: this is racy if we use a real database
        return self.store.driver.con_update(self.store.session, self.context.id, self.id, attrs)
    def unset(self, *names):
        return self.store.driver.con_remove(self.store.session, query._and(query.context(self.context.id),query.address(self.id), query.attribute(*names)))

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
