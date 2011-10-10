import base,logging

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
        `id` integer primary key,
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
class Driver(base.Driver):
    @classmethod
    def tag_fetch(cls, session):
        return [ x[0] for x in session.database.execute('select name from tag').fetchall() ]
    @classmethod
    def tag_add(cls, session, *names):
        tags = ((session.id,t) for t in names)
        return session.database.executemany('insert into tag (session,name) values (?,?)', tags).lastrowid
    @classmethod
    def tag_discard(cls, session, *names):
        names = tuple(*names)
        result = session.database.execute('select id,name from tag where session=? and name in (%s)'%( ('?,'*len(names))[:-1] ), (session.id,)+names).fetchall()
        if len(result) == 0:
            raise KeyError("tags '%s' for session %d not found"% (repr(names), session.id))

        ids,tags = zip(*result)
        ids,tags,names = (set(ids),set(tags),set(names))
        for x in names.difference(tags):
            logging.debug("store.driver: tag '%s' not found for session %d"% (x, session.id))
        
        rowcount = 0
        for x in ids:
            rowcount += session.database.execute('delete from context where session=? and tag=?', (session.id,x)).rowcount
            rowcount += session.database.execute('delete from content where session=? and tag=?', (session.id,x)).rowcount
            rowcount += session.database.execute('delete from tag where session=? and id=?', (session.id,x)).rowcount
        return rowcount

    ### context stuff
    @classmethod
    def ctx_select(cls, session, query):
        result={}
        for address,k,v in session.database.execute('select dataset.address,tag.name,dataset.value from context dataset inner join tag on tag.id=dataset.tag where %s'% query.sqlq(), query.sqld()):
            if address not in result:
                result[address] = {}
            result[address][k] = base.loads(v)   # XXX
        return result

    # write
    @classmethod
    def ctx_update(cls, session, ea, dictionary):
        result = ((session.id,ea,base.dumps(v),k) for k,v in dictionary.iteritems())  # XXX
        q = 'replace into context (session,address,tag,value) select ?,?,id,? from tag where tag.name=?'
        return session.database.executemany(q, result).rowcount == len(dictionary)

    @classmethod
    def ctx_remove(cls, session, query):
        # don't forget query.address
        return session.database.execute('delete from context where exists (select 0 from context dataset inner join tag on tag.id=dataset.tag where context.id=dataset.id and dataset.session=? and %s)'%query.sqlq(), (session.id,)+query.sqld()).rowcount

    ### content stuff
    @classmethod
    def con_edge(cls, session, (ctx_source,con_source),(ctx_target,con_target)):
        q = 'replace into edge (session,start,source,end,target) values (?,?,?,?,?)'
        return session.database.execute(q, (session.id, ctx_source,con_source, ctx_target,con_target)).rowcount == 1

    @classmethod
    def con_unedge(cls, session, (ctx_source,con_source),(ctx_target,con_target)):
        q = 'drop from edge where start=? and source=? and end=? and target=?'
        return session.database.execute(q, (ctx_source,con_source,ctx_target,con_target))

    @classmethod
    def con_select(cls, session, query):
        result = {}
        for address,k,v in session.database.execute('select dataset.address,tag.name,dataset.value from content dataset inner join tag on tag.id = dataset.tag inner join context on context.address=dataset.context where %s'% query.sqlq(), query.sqld()):
#        for address,k,v in session.database.execute('select dataset.address,tag.name,dataset.value from content dataset left join tag on tag.id = dataset.tag inner join context on context.address=dataset.context where %s'% query.sqlq(), query.sqld()):
            if address not in result:
                result[address] = {}
            result[address][k] = base.loads(v)
        return result

    # write
    @classmethod
    def con_update(cls, session, ctx, ea, dictionary):
        result = ((session.id,ctx,ea,base.dumps(v),k) for k,v in dictionary.iteritems())  # XXX
        q = 'replace into content (session,context,address,tag,value) select ?,?,?,tag.id,? from tag where tag.name=?'
        return session.database.executemany(q, result).rowcount == len(dictionary)
    @classmethod
    def con_remove(cls, session, query):
        # don't forget query.context
        return session.database.execute('delete from content where exists (select 0 from content dataset inner join tag on tag.id=dataset.tag where content.id=dataset.id and dataset.session=? and %s)'%query.sqlq(), (session.id,)+query.sqld()).rowcount

class Session(base.Session):
    id = 0
    driver = Driver

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

