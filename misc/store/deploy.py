class __base__(object):
    def create_schema(self):
        raise NotImplementedError
    def create_session(self, id):
        raise NotImplementedError
    def drop_session(self, id):
        raise NotImplementedError

# XXX: instead of doing this in sql, should i be doing this in
#       libmemcached, or better yet..redis-py?

class sql(__base__):
    # this schema is tied directly into the query module's .sqlq commands
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
    def commit(self):
        return self.database.commit()
    def rollback(self):
        return self.database.rollback()

    def create_schema(self):
        self.database.executescript(self.schema)
        self.database.commit()
        return

    def __dropsession_context(self, id):
        c = self.database.execute('delete from context where session=?', id)
        return c.rowcount

    def __dropsession_content(self, id):
        c = self.database.execute('delete from content where session=?', id)
        return c.rowcount

    def drop_session(self, name, recurse=True):
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

    def create_session(self, name, **kwds):
        c = self.database.execute('insert into session (name) values (?)', (name,))
        return c.lastrowid

