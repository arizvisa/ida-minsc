class __base__(object):
    def create_schema(self):
        raise NotImplementedError
    def create_session(self, id):
        raise NotImplementedError
    def drop_session(self, id):
        raise NotImplementedError

# XXX: instead of doing this in sql, should i be doing this in
#       libmemcached, or better yet..redis-py?

class admin(__base__):
    # this schema is tied directly into the query module's .sqlq commands
    schema = '''
    -- session info
    create table session (`id` integer primary key, `name` text unique);
    insert into session (id, name) values (0, NULL);

    -- tag info
    create table tag (        
        `id` integer primary key, `session` integer not null, `name` text not null unique,  
        foreign key(session) references session(id)     
    );

    insert into tag (id,session,name) values (0, 0, 'up');
    insert into tag (id,session,name) values (1, 0, 'down');

    -- context of a function  (address, session-id, tag, value)
    create table context (        
        `address` integer not null, `session` integer not null, `tag` integer not null, `value` blob not null,
        foreign key(tag) references tag(id), foreign key(session) references session(id)    
    );
    create unique index `context-address` on context (address,session,tag);    -- XXX: double-check and make sure i'm remembering how multi-column indexes optimize the queries

    -- contents of a function  (context-address, real-address, session-id, tag, value)
    create table content (
        `id` integer primary key, `context` integer, `address` integer not null, `session` integer not null, `tag` integer not null, `value` blob not null,
        foreign key(tag) references tag(id), foreign key(session) references session(id)
    );
    create unique index `content-address` on content (context,address,session,tag);

    -- views for debugging
    create view `view-context` as select context.address as address,tag.name as key,context.value as value from context left join tag on tag.id = context.tag;
    create view `view-content` as select context.address as context,content.address as address,tag.name as key,content.value as value from content left join tag on tag.id = content.tag left join context on content.context=context.address;

    -- table for describing context hierarchy
    create table `context-edge` (
        `id` integer, `direction` integer not null, `node` integer not null,
        foreign key(node) references context(address)
    );
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

