import idc,idautils,idaapi as ida
import instruction,function,segment,store.query as query
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
    return list(idautils.Segments())

if False:
    def getblock(start, end):
        '''Return a string of bytes'''
        result = [ idc.Byte(ea) for ea in xrange(start, end) ]
        return ''.join(__builtins__['map'](chr, result))

def getblock(start, end):
    if start > end:
        start,end=end,start
    length = end-start

    if not globals()['contains'](start):
        raise ValueError('Address %x is not in database'%start)

    tostr = lambda integer,string,length: (lambda:string, lambda:tostr(integer/0x100, string + chr(integer&0xff), length-1))[length > 0]()

    result = array.array('c')
    ea = start
    if length > 7:
        for i in xrange(length/8):
            result.fromstring(tostr(idc.Qword(ea), '', 8))
            ea += 8

    for x in xrange(ea,end):
        result.fromstring( chr(idc.Byte(x)) )
    return result.tostring()

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

def demangle(string):
    return idc.Demangle(string, idc.GetLongPrm(idc.INF_LONG_DN))

def log(string, *argv):
    '''idc.Message(formatstring, ...)'''
    return idc.Message('>' + string% argv + '\n')

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
    return idc.GetInputFile()

def path():
    filepath = idc.GetIdbPath().replace('\\','/')
    return filepath[: filepath.rfind('/')] 

def baseaddress():
    return ida.get_imagebase()
base=baseaddress

def getoffset(ea):
    return ea - baseaddress()

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

def search(name):
    return idc.LocByName(name)

def searchname(name):
    print 'database.searchname has been deprecated in favor of database.search'
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
        l,r = segment.getRange(x)
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

def color(ea, *args):
    '''color(address, rgb?) -> fetches or stores a color to the specified address'''
    if len(args) > 0:
        c, = args
        return tag(ea, '__color__', c)
    return tag(ea, '__color__')
