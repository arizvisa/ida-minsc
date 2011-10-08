import base
import logging,query

##### construction
# this schema is tied directly into the query module's .sqlq commands
class Deploy(base.Deploy):
    schema = '''
    -- session info
    create table if not exists session (`id` integer primary key, `name` text unique);
    replace into session (id, name) values (0, NULL);

    -- tag info
    create table if not exists tag (
        `id` integer primary key, `session` integer not null, `name` text not null unique,  
        foreign key(session) references session(id)     
    );

    -- context of a function  (address, session-id, tag, value)
    create table if not exists context (
        `address` integer not null, `session` integer not null, `tag` integer not null, `value` blob not null,
        `timestamp` timestamp default current_timestamp,
        foreign key(tag) references tag(id), foreign key(session) references session(id)    
    );
    create unique index if not exists `context-address` on context (address,session,tag);
    create index if not exists `context-timestamp` on context (timestamp);

    -- contents of a function  (context-address, real-address, session-id, tag, value)
    create table if not exists content (
        `id` integer primary key, `context` integer, `address` integer not null, `session` integer not null, `tag` integer not null, `value` blob not null,
        `timestamp` timestamp default current_timestamp,
        foreign key(tag) references tag(id), foreign key(session) references session(id)
    );
    create unique index if not exists `content-address` on content (context,address,session,tag);
    create index if not exists `content-timestamp` on content (timestamp);

    -- table for describing hierarchy
    create table if not exists edge (
        `id` integer primary key, `session` integer not null,
        `source` integer not null, `target` integer not null,
        `start` integer, `end` integer,
        foreign key(start) references context(address), foreign key(end) references context(address),
        foreign key(source) references content(address), foreign key(target) references content(address)
    );
    create index if not exists `edge-context` on edge (start, end);
    create unique index if not exists `edge-content` on edge (source, target);
    '''
    def __init__(self, database):
        self.database = database

    def create(self):
        self.database.executescript(self.schema)
        return self.database.commit()

    def __dropsession_context(self, id):
        c = self.database.execute('delete from context where session=?', id)
        return c.rowcount

    def __dropsession_content(self, id):
        c = self.database.execute('delete from content where session=?', id)
        return c.rowcount

    def drop(self, name, recurse=True):
        c = self.database.execute('select id from session where name=?', name)
        r = c.fetchone()
        if r is None:
            raise KeyError("User '%s' not found"% name)
        id = r[0]

        rowcount = 0
        if recurse:
            rowcount += self.__dropsession_context(id)
            rowcount += self.__dropsession_content(id)
        c = self.database.execute('delete from session where id=?', (id,))
        return rowcount + c.rowcount

    def session(self, name, **kwds):
        c = self.database.execute('insert into session (name) values (?)', (name,))
        return c.lastrowid

##### sql session
class Session(base.Session):
    id = 0
    def __init__(self, database, name=None):
        self.database = database
        if name:
            r = self.database.execute('select id from session where name=?', (name,)).fetchone()
            if r is None:
                raise KeyError("Session '%s' not found"% name)
            self.id = r[0]
            return
        logging.warning('defaulting to maintenance account (session id 0)')
        self.id = 0

    def commit(self):
        return self.database.commit()
    def rollback(self):
        return self.database.rollback()

###### interface
class Store(base.Store):
    database = property(fget=lambda x:x.__session.database)

    def __init__(self, session):
        self.__session = session
        self.reset()

    def reset(self):
        super(Store,self).clear()
        [ super(Store,self).add(x[0].encode('ascii')) for x in self.database.execute('select name from tag').fetchall() ]

    def address(self, ea):
        return Context(self, ea)    # XXX: hopefully the cost of constructing these isn't too expensive0

    def add(self, name):
        return self.database.execute('replace into tag (session,name) values (?,?)', (self.session.id,name,)).lastrowid

    def remove(self, name):
        r = self.database.execute('select id from tag where name=? and session=?', (name,self.session.id,)).fetchone()
        if r is None:
            raise KeyError("Tag '%s' for session %d not found"% (name, self.session.id))
        id = r[0]

        rowcount = 0
        if recurse:
            rowcount += self.database.execute('delete from context where session=?', (id,)).rowcount
            rowcount += self.database.execute('delete from content where session=?', (id,)).rowcount
        rowcount += self.database.execute('delete from tag where id=?', (id,)).rowcount
        return rowcount

    def select(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        result={}
        for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from context dataset left join tag on tag.id = dataset.tag left join content on content.context=dataset.address where %s'% q.sqlq(), q.sqld()):
            if address not in result:
                result[address] = {}
            result[address][k.encode('ascii')] = base.loads(v)
        return result

###### per-context settings
class Context(base.Context):
    database = property(fget=lambda x:x.__store.database)

    def __init__(self, store, address):
        super(Context,self).__init__()
        self.__id = address
        self.__store = store

    def reset(self):
        super(Context,self).clear()
        [ super(Context,self).__setitem__(x[0].encode('ascii'),base.loads(x[1])) for x in self.database.execute('select tag.name,dataset.value from context dataset left join tag on tag.id=dataset.tag').fetchall() ]

    def address(self, ea):
        return Content(self, ea)

    def __repr__(self):
        self.reset()
        return super(Context,self).__repr__()

### friendly
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

### low-level
    def set(self,**attr):
        [self.store.add(k) for k in set(attr.iterkeys()).difference(self.store)]            # XXX: this can be racy...
        result = [(self.store.id,self.id,base.dumps(v),k) for k,v in attr.iteritems()]
        q = 'replace into context (session,address,tag,value) select ?,?,id,? from tag where tag.name=?'
        return self.database.executemany(q, result).rowcount == len(attr)

    def unset(self, key=None):
        if key:
            return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=? and tag.name=?', self.store.id, self.id, key).rowcount
        return self.database.execute('delete from context left join tag on tag.id=context.tag where context.session=? and context.address=?', self.store.id, address).rowcount

    def select(self, *q):
        if q:
            q = query._and(*q)
        else:
            q = query.all()
        result = {}
        for address,k,v in self.database.execute('select dataset.address,tag.name,dataset.value from content dataset left join tag on tag.id = dataset.tag left join context on context.address=dataset.context where dataset.context=? and %s'% q.sqlq(), (self.id,)+q.sqld()):
            if address not in result:
                result[address] = {}
            result[address][k.encode('ascii')] = base.loads(v)
        return result

###### per context/content setting
class Content(base.Content):
    database = property(fget=lambda x:x.__context.store.database)

    def __init__(self, context, address):
        super(Content,self).__init__()
        self.__context = context
        self.__id = address

    def reset(self):
        super(Content,self).clear()
        [ super(Content,self).__setitem__(x[0].encode('ascii'),base.loads(x[1])) for x in self.database.execute('select tag.name,dataset.value from content dataset left join tag on tag.id=dataset.tag').fetchall() ]

    def __repr__(self):
        self.reset()
        return super(Content,self).__repr__()

    def edge(self, (destination,address)):
        q = 'replace into edge (session,start,source,end,target) values (?,?,?,?,?)'
        return self.database.execute(q, (self.store.session.id, self.context.id,self.id, destination,address)).rowcount == 1

    def unedge(self, reference):
        if reference:
            destination,address = reference
            q = 'drop from edge where start=? and source=? and end=? and target=?'
            return self.database.execute(q, (self.context.id,self.id, destination,address))

        q = 'drop from edge where start=? and source=?'
        return self.database.execute(q, (self.context.id,self.id))

### friendly
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

### lowlevel
    def set(self, **attr):
        [ self.store.add(k) for k in set(attr.iterkeys()).difference(self.store)]      # XXX: this can be racy...
        result = ((self.context.id,self.store.id,self.id,base.dumps(v),k) for k,v in attr.iteritems())  # XXX: HACK: conditionally keep integers in database for querying
        q = 'replace into content (context,session,address,tag,value) select ?,?,?,tag.id,? from tag where tag.name=?'
        return self.database.executemany(q, result).rowcount == len(attr)

    def __rm_single(self, key=None):
        if key is None:
            return self.database.execute('delete from content where content.session=? and content.context=? and content.address=?', (self.store.id, self.context.id, self.id)).rowcount
        return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.context=? and content.address=? and tag.name=?', (self.store.id, self.context.id, self.id, key)).rowcount

    def __rm_all(self, key=None):
        if key is None:
            return self.database.execute('delete from content where content.session=? and content.context=?', (self.store.id, self.context.id)).rowcount
        return self.database.execute('delete from content left join tag on content.tag=tag.id where content.session=? and content.address=? and tag.name=?', (self.store.id, self.context.id ,key)).rowcount

    def unset(self, address=None, key=None):
        if address is None:
            return self.__rm_all(self.context.id, key)
        return self.__rm_single(self.context.id, address, key)
