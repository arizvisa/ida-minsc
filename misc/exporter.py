'''
Example database exporter
[arizvisa@tippingpoint.com]
'''

# XXX: this is intended to fucking work because python's mysql modules
#      are fucking retarded compared to perl's
class databaseServer(object):
    def __init__(self, outputFile):
        self.file = file(outputFile, 'wt')

    def close(self):
        self.file.close()

    def quote(self, value, char='"'):
        # XXX: this doesn't actually quote anything, but it should...
        if type(value) is str:
            string = value.replace(char, '\\%c'% char)
            return '%c%s%c'% (char, string, char)
        return int(value)

    def tick(self, string):
        assert type(string) is str
        return self.quote(string, char='`')

    def writeLine(self, string):
        self.file.write( string + "\n" )

    def command(self, formatString, formatArgs):
        arguments = [ self.quote(x) for x in formatArgs ]
        self.writeLine( formatString% arguments )
            
    def createDatabase(self, name, **kwds):
        self.writeLine("create database %s;"% self.tick(name))

    def createTable(self, tablename, **fields):
        res = ['%s %s'% (self.tick(name), type) for name,type in fields.items()]
        res = ','.join(res)
        self.writeLine("create table %s (%s);"% (self.tick(tablename), res))

    def insertRecord(self, name, **fields):
        # XXX: this pulls the field names
        res = [(k, self.quote(v)) for k,v in fields.items()]
        fieldnames = ','.join([k for k,v in res])
        values = ','.join([str(v) for k,v in res])
        self.writeLine("insert into %s (%s) values (%s);"% (self.tick(name), fieldnames, values))

def createSchema(db, tablename):
    ## heh
    db.createTable(tablename, address='integer', tag='text', value='text')

def insertTags(db, tableName, address, dict):
    for k,v in dict.items():
        db.insertRecord(tableName, address=address, tag=k, value=v)

def dumpIDB(path, tablename):
    db = databaseServer(path)
    createSchema(db, tablename)

    import idautils, idc
    import function,database
    base = database.baseaddress()

    # regular comments
    print "Exporting regular comments..."
    for x in idautils.Heads( idc.MinEA(), idc.MaxEA() ):
        d = database.tag(x)    
        if d:
            insertTags(db, tablename, x - base, d)

        d = database.tag(x, repeatable=1)    
        if d:
            insertTags(db, tablename, x - base, d)

    # function comments
    print "Exporting function comments..."
    for x in database.functions():
        d = function.tag(x)    
        if d:
            d = dict([('function-%s'%k, v) for k,v in d.items()])
            insertTags(db, tablename, x - base, d)

        d = function.tag(x, repeatable=1)
        if d:
            d = dict([('function-%s'%k, v) for k,v in d.items()])
            insertTags(db, tablename, x - base, d)

    print "Done!"
    db.close()
