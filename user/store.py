import idaapi,idc,database
from pg8000 import DBAPI

### XXX: redesign this shiz
# will need to populate idadb using results queried on idadb load
#   will want an index for the username, and the address
# will need to store tags to database on idadb close.. (not sure how to this hook yet)
# will need to insert/update tag on a comment change

### tag schema:
# timestamp with time zone not null default now()
# username text not null default current_user()
# address integer not null
# name text not null
# value text not null
# "address-name-key" primary key, btree (address, name, username)


### this object aims to be persistent
class Connection(object):
    dbh = None
    module = None
    cursor = None

    @classmethod
    def open(cls, module, **kwds):
        assert cls.dbh is None
        assert cls.module is None
        assert cls.cursor is None

        database = 'tag-store'  # XXX

        cls.dbh = DBAPI.connect(database=database, **kwds)
        cls.module = module

        # should the schema for an ida database look like:
        #     module-tags; enum-tags; struct-tags;
        #     globals, types -> {aliases, aggregates}

        cls.cursor = cls.dbh.cursor()
        return cls

    @classmethod
    def close(cls):
        cls.dbh.commit()
        cls.dbh.close()
        cls.dbh = cls.module = cls.cursor = None

    @classmethod
    def module_add(cls, address, name, value):
        cls.cursor.execute('insert into test."module-tags"(address, "name", value, "instruction-length") values (%s, %s, %s, %s)', (address, name, value, idc.ItemSize(address)))

    @classmethod
    def module_store(cls, address):
        d = database.tag(address)
        for k,v in d.items():
            cls.module_add( address, k, v )
        return

    @classmethod
    def module_fetch(cls, address):
        cls.cursor.execute('select "name",value from test."module-tags" where address = %s', (address))
        result = []
        while True:
            n = cls.cursor.fetchone()
            if n is None:
                break
            res.append(n)
        return res

    @classmethod
    def module_load(cls, address):
        d = cls.module_fetch(address)
        for k,v in d.items():
            database.tag(address, k, v)
        return

    @classmethod
    def __getattr__(cls, name):
        return getattr(cls.cursor, name)

# XXX: these hooks seem to get called right before the comment is stored...
class Hooks(idaapi.IDB_Hooks):
    def cmt_changed(self, *args):
        address,repeatable = args
        Connection.module_store(address)
        return 1

    def enum_cmt_changd(self, *args):
#        print 'enum',args
#        Connection.enum_store(address)
        return 1

    def struc_cmt_changed(self, *args):
        id, = args
#        print 'struc',args
        return 1

if __name__ == '__main__':
    import store
    store.Connection.open('test', host='172.22.22.125', user='user', password='gr0ver')
    z = store.Hooks()
    z.hook()
