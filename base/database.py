import logging
import idc,idautils,idaapi as ida
import instruction,function,segment,declaration
import array

def isCode(ea):
    '''True if ea marked as code'''
    return idc.isCode( idc.GetFlags(ea) )

def isData(ea):
    '''True if ea marked as data'''
    return idc.isData( idc.GetFlags(ea) )

def isUnknown(ea):
    '''True if ea marked unknown'''
    return idc.isUnknown( idc.GetFlags(ea) )

def isHead(ea):
    return idc.isHead( idc.GetFlags(ea) )

def isTail(ea):
    return idc.isTail( idc.GetFlags(ea) )

def functions():
    '''Returns a list of all the functions in the current database (using idautils)'''
    min,max = idc.MinEA(), idc.MaxEA()
    return list(idautils.Functions(min, max))

def segments():
    '''Returns a list of all segments in the current database'''
    return [s.startEA for s in segment.list()]

if False:
    def getblock(start, end):
        '''Return a string of bytes'''
        result = [ idc.Byte(ea) for ea in xrange(start, end) ]
        return ''.join(__builtins__['map'](chr, result))

def getblock(start, end):
    if start > end:
        start,end=end,start
    length = end-start

    if not contains(start):
        raise ValueError('Address %x is not in database'%start)
    return ida.get_many_bytes(start, length)

def prev(ea):
    '''return the previous address (instruction or data)'''
    return idc.PrevHead(ea, idc.MinEA())

def next(ea):
    '''return the next address (instruction or data)'''
    return idc.NextHead(ea, idc.MaxEA())

def walk(ea, next, match):
    if match(ea):
        return ea

    while True:
        ea = next(ea)
        if match(ea):
            return ea
        continue
    assert False is True

def prevdata(ea):
    '''return previous address containing data referencing it'''
    return walk(ea, prev, dxup)

def nextdata(ea):
    '''return next address containing data referencing it'''
    return walk(ea, next, dxup)

def prevcode(ea):
    '''return previous address containing code referencing it'''
    return walk(ea, prev, cxup)

def nextcode(ea):
    '''return next address containing code referencing it'''
    return walk(ea, next, cxup)

def prevref(ea):
    '''return previous address containing any kind of reference to it'''
    return walk(ea, prev, up)

def nextref(ea):
    '''return next address containing any kind of reference to it'''
    return walk(ea, next, up)

def guessrange(ea):
    '''Try really hard to get boundaries of the block at specified address'''
    start,end = function.getRange(ea)
    if function.contains(start, ea) and not (ea >= start and ea < end):
        return (idc.GetFchunkAttr(ea, idc.FUNCATTR_START), idc.GetFchunkAttr(ea, idc.FUNCATTR_END))
    return start,end

def decode(ea):
    return instruction.decode(ea)

# FIXME: there's issues when trying to get xrefs from a structure or array,
#        if it's not the first address of the item, then it will return no
#        xrefs for that particular address. it might be possible to fix this
#        in this module.

#   -- it seems like ida makes structures and stuff into an instruction_t or
#       something
def iterate_refs(address, start, next):
    ea = address
    address = start(ea)
    while address != ida.BADADDR:
        yield address
        address = next(ea, address)
    return

def drefs(ea, descend=False):
    if descend:
        start,next = ida.get_first_dref_from, ida.get_next_dref_from
    else:
        start,next = ida.get_first_dref_to, ida.get_next_dref_to

    for addr in iterate_refs(ea, start, next):
        yield addr
    return

def crefs(ea, descend=False):
    if descend:
        start,next = ida.get_first_cref_from, ida.get_next_cref_from
    else:
        start,next = ida.get_first_cref_to, ida.get_next_cref_to

    for addr in iterate_refs(ea, start, next):
        yield addr
    return

def dxdown(ea):
    return list(drefs(ea, True))

def dxup(ea):
    return list(drefs(ea, False))

def cxdown(ea):
    result = set(crefs(ea, True))
    result.discard(next(ea))
    return list(result)

def cxup(ea):
    result = set(crefs(ea, False))
    result.discard(prev(ea))
    return list(result)

def up(ea):
    '''All locations that reference specified address'''
    return cxup(ea) + dxup(ea)

def down(ea):
    '''All locations that are referenced by the specified address'''
    return cxdown(ea) + dxdown(ea)

demangle = declaration.demangle

def marks():
    '''returns all the known marked positions in an .idb'''
    index = 1
    while True:
        ea = idc.GetMarkedPos(index)
        if ea == 0xffffffff:
            break
        comment = idc.GetMarkComment(index)
        yield ea, comment
        index += 1
    return

def mark(ea, message):
    # TODO: give a warning if we're replacing a mark at the given ea
    nextmark = len(list(marks())) + 1
    idc.MarkPosition(ea, 0, 0, 0, nextmark, message)

def iterate(start, end):
    '''Iterate through instruction/data boundaries within the specified range'''
    while start < end:
        yield start
        start = next(start)
    return

def go(ea):
    '''slightly less typing for idc.Jump'''
    if not contains(ea):
        left,right=range()
        raise ValueError("Unable to goto address %x. (valid range is %x - %x)"% (ea,left,right))
    idc.Jump(ea)
    return ea

def h():
    '''slightly less typing for idc.ScreenEA()'''
    return idc.ScreenEA()

here = h    # alias

def filename():
    '''return the filename that the database was built from'''
    return idc.GetInputFile()

def path():
    '''return the full path to the database'''
    filepath = idc.GetIdbPath().replace('\\','/')
    return filepath[: filepath.rfind('/')] 

def baseaddress():
    '''returns the baseaddress of the module'''
    return ida.get_imagebase()
base=baseaddress

def getoffset(ea):
    '''returns the offset of ea from the baseaddress'''
    return ea - baseaddress()

def search(name):
    return idc.LocByName(name)

def searchname(name):
    raise DeprecationWarning('database.searchname has been deprecated in favor of database.search')
    return search(name)

def name(ea, string=None):
    '''Returns the name at the specified address. (local than global)'''
    if string is not None:
        SN_NOCHECK = 0x00
        SN_NOLIST = 0x80
        SN_LOCAL = 0x200
        SN_PUBLIC = 0x02

        n = name(ea)
        
        flags = SN_NOCHECK
        try:
            function.top(ea)
            flags |= SN_LOCAL
        except ValueError:
            flags |= 0

        idc.MakeNameEx(ea, string, flags)
        tag(ea, '__name__', string)
        return n

    try:
        return tag(ea, '__name__')
    except KeyError:
        pass
    return None

def blocks(start, end):
    '''Returns each block between the specified range of instructions'''
    block = start
    for ea in iterate(start, end):
        nextea = next(ea)

        if idc.GetMnem(ea).startswith('call'):      # FIXME: heh. ;)
            continue

        if idc.GetMnem(ea).startswith('ret'):       #   whee
            yield block,nextea
            block = ea

        elif cxdown(ea):
            yield block,nextea
            block = nextea

        elif cxup(ea) and block != ea:
            yield block,ea
            block = ea
        continue
    return

def map(l, *args, **kwds):
    '''Execute provided callback on all functions in database. Synonymous to map(l,db.functions())'''
    all = functions()
    result = []
    for i,x in enumerate(all):
        print '%x: processing # %d of %d'%( x, i+1, len(all) )
        result.append( l(x, *args, **kwds) )
    return result

def range():
    '''Return the total address range of the database'''
    left,right = 0xffffffff,0x00000000
    for x in segments():
        l,r = segment.range(x)
        if l < left:
            left = l
        if r > right:
            right = r
        continue
    return baseaddress(), right

def contains(ea):
    l,r = range()
    return (ea >= l) and (ea < r)

def erase(ea):
    for x in tag(ea):
        tag(ea, x, None)
    color(ea, None)

def color_write(ea, bgr, what=1):
    if bgr is None:
        bgr = 0xffffffff
    return idc.SetColor(ea, what, bgr)

def color_read(ea, what=1):
    return idc.GetColor(ea, what)

def color(ea, *args, **kwds):
    '''color(address, rgb?) -> fetches or stores a color to the specified address'''
    if len(args) == 0:
        return color_read(ea, *args, **kwds)
    return color_write(ea, *args, **kwds)

def add_entry(name, ea, ordinal=None):
    '''addentry(name, ea, index?) -> adds an entry point to the database'''
    if ordinal == None:
        ordinal = ida.get_entry_qty()
    return ida.add_entry(ordinal, ea, name, 0)

class config(object):
    info = ida.get_inf_structure()
    @classmethod
    def version(cls):
        return cls.info.version

    @classmethod
    def bits(cls):
        '''return number of bits'''
        if cls.info.is_64bit():
            return 64
        elif cls.info.is_32bit():
            return 32
        raise ValueError('Unknown bit size')

    @classmethod
    def processor(cls):
        '''return processor name'''
        return cls.info.procName

    @classmethod
    def graphview(cls):
        '''currently using graph view'''
        return cls.info.graph_view != 0

    @classmethod
    def main(cls):
        return cls.info.main

    @classmethod
    def entry(cls):
        return cls.info.beginEA
        #return cls.info.startIP

    @classmethod
    def margin(cls):
        return cls.info.margin

    @classmethod
    def bounds(cls):
        return cls.info.minEA,cls.info.maxEA

# FIXME: this only works on x86 where args are pushed via stack
def makecall(ea):
    result = cxdown(ea)
    if len(result) != 1:
        raise ValueError('Invalid code reference: %s'% repr(result))
    fn, = result

    if not function.contains(ea, ea):
        return None

    result = []
    for offset,name,size in function.getArguments(fn):
        left,_ = function.stackwindow(ea, offset+config.bits()/8)
        # FIXME: if left is not an assignment or a push, find last assignment
        result.append((name,left))

    result = ['%s=%s'%(name,instruction.op_repr(ea,0)) for name,ea in result]
    return '%s(%s)'%(declaration.demangle(function.getName(fn)), ','.join(result))

try:
    import store.query as query
    import store

    datastore = store.ida
    def tag(address, *args, **kwds):
        '''tag(address, key?, value?) -> fetches/stores a tag from specified address'''
        try:
            context = function.top(address)

        except ValueError:
            context = None

        if len(args) == 0 and len(kwds) == 0:
    #        result = __datastore.content.select(context, query.address(address))
            result = datastore.address(context).select(query.address(address))
            try:
                result = result[address]
            except:
                result = {}
            return result

        elif len(args) == 1:
            key, = args
    #        result = __datastore.content.select(context, query.address(address), query.attribute(key))
            result = datastore.address(context).select(query.address(address), query.attribute(key))
            try:
                result = result[address][key]
            except:
                raise KeyError( (hex(address),key) )
                result = None
            return result

        if len(args) > 0:
            key,value = args
            kwds.update({key:value})
        return datastore.address(context).address(address).set(**kwds)
    #    return __datastore.content.set(context, address, **kwds)

    def __select(q):
        for x in functions():
            x = function.top(x)
            if q.has(function.tag(x)):
                yield x
            continue
        return

    def select(*q, **where):
        if where:
            print "database.select's kwd arguments have been deprecated in favor of query"
        result = list(q)
        for k,v in where.iteritems():
            if v is None:
                result.append( query.hasattr(k) )
                continue
            result.append( query.hasvalue(k,v) )
        return __select( query._and(*result) )

except ImportError:
    import comment

    def tag_read(address, key=None, repeatable=0):
        res = idc.GetCommentEx(address, repeatable)
        dict = comment.toDict(res)
        name = idc.Name(address)
        if name:
            dict['name'] = name
        if key:
            return dict[key]
        return dict

    def tag_write(address, key, value, repeatable=0):
        dict = tag_read(address, repeatable=repeatable)
        dict[key] = value
        res = comment.toString(dict)
        if repeatable:
            return idc.MakeRptCmt(address, res)
        return idc.MakeComm(address, res)

    def tag(address, *args, **kwds):
        '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''
        try:
            # in a function
            function.top(address)
            if 'repeatable' not in kwds:
                kwds['repeatable'] = False

        except ValueError:
            # not in a function, could be a global, so it's now repeatable
            if 'repeatable' not in kwds:
                kwds['repeatable'] = True
            pass

        if len(args) < 2:
            return tag_read(int(address), *args, **kwds)
        key,value = args
        return tag_write(int(address), key, value, **kwds)

    def select(tags=None):
        if tags is None:
            result = {}
            for ea in functions():
                res = function.tag(ea)
                if res:
                    result[ea] = res
                continue
            return result

        tags = set((tags,)) if type(tags) is str else set(tags)

        result = {}
        for ea in functions():
            res = dict((k,v) for k,v in function.tag(ea).iteritems() if k in tags)
            if res:
                result[ea] = res
            continue
        return result

def getImportModules():
    return [ida.get_import_module_name(i) for i in xrange(ida.get_import_module_qty())]
def getImports(modulename):
    idx = [x.lower() for x in getImportModules()].index(modulename.lower())
    result = []
    def fn(ea,name,ordinal):
        result.append((ea,(name,ordinal)))
        return True
    ida.enum_import_names(idx,fn)
    return result
def imports():
    """Iterator containing (address,(module,name,ordinal)) of imports in database"""
    for idx,module in ((i,ida.get_import_module_name(i)) for i in xrange(ida.get_import_module_qty())):
        result = []
        def fn(ea,name,ordinal):
            result.append( (ea,(name,ordinal)) )
            return True
        ida.enum_import_names(idx,fn)
        for ea,(name,ordinal) in result:
            yield ea,(module,name,ordinal)
        continue
    return

### register information.
class register(object):
    @classmethod
    def names(cls):
        return ida.ph_get_regnames()
    @classmethod
    def segments(cls):
        names = cls.names()
        return [names[i] for i in xrange(ida.ph_get_regFirstSreg(),ida.ph_get_regLastSreg()+1)]
    @classmethod
    def codesegment(cls):
        return cls.names()[ida.ph_get_regCodeSreg()]
    @classmethod
    def datasegment(cls):
        return cls.names()[ida.ph_get_regDataSreg()]
    @classmethod
    def segmentsize(cls):
        return ida.ph_get_segreg_size()

