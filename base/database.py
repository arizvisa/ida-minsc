import idc,idautils,idaapi as ida
import comment,instruction,function,segment

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
    min = idc.NextFunction(min)
    if min == -1:
        raise StopIteration("No functions found")
    return list(idautils.Functions(min, max))

def segments():
    '''Returns a list of all segments in the current database'''
    return list(idautils.Segments())

def getblock(start, end):
    '''Return a string of bytes'''
    result = [ idc.Byte(ea) for ea in xrange(start, end) ]
    return ''.join(__builtins__['map'](chr, result))

def tag_read(address, key=None, repeatable=0):
    res = idc.GetCommentEx(address, repeatable)
    dict = comment.toDict(res)

    name = idc.NameEx(address, address)
    if name:
        dict['name'] = name

    c = color(address)
    if c is not None:
        dict['__color__'] = c

    if key is not None:
        return dict[key]
    return dict

def tag_write(address, key, value, repeatable=0):
    dict = tag_read(address, repeatable=repeatable)
    dict[key] = value

    if '__color__' in dict:
        value = dict['__color__']
        color(address, value)
        del(dict['__color__'])

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

def color_write(ea, rgb, what=1):
    if rgb is None:
        return idc.SetColor(ea, what, 0xffffffff)

    a = rgb & 0xff000000
    rgb &= 0x00ffffff

    bgr = 0
    for i in xrange(3):
        bgr,rgb = ((bgr*0x100) + (rgb&0xff), rgb/0x100)
    return idc.SetColor(ea, what, bgr)

def color_read(ea, what=1):
    bgr = idc.GetColor(ea, what)
    if bgr == 0xffffffff:
        return None

    a = bgr&0xff000000
    bgr &= 0x00ffffff

    rgb = 0
    for i in xrange(3):
        rgb,bgr = ((rgb*0x100) + (bgr&0xff), bgr/0x100)
    return rgb

def color(ea, *args, **kwds):
    '''color(address, rgb?) -> fetches or stores a color to the specified address'''
    if len(args) == 0:
        return color_read(ea, *args, **kwds)
    return color_write(ea, *args, **kwds)

def iterate(start, end):
    '''Iterate through instruction/data boundaries within the specified range'''
    while start < end:
        yield start
        start = next(start)
    return

def go(ea):
    '''slightly less typing for idc.Jump'''
    return idc.Jump(ea)

def h():
    '''slightly less typing for idc.ScreenEA()'''
    return idc.ScreenEA()

here = h    # alias

def filename():
    return idc.GetInputFile()

def baseaddress():
    return ida.get_imagebase()
base=baseaddress

def getoffset(ea):
    return ea - baseaddress()

def query(**where):
    '''query all functions in database'''
    for x in functions():
        x = function.top(x)
        if comment.has_and(function.tag(x), **where):
            yield x
        continue
    return

def select(**where):
    return set(query(**where))

def dump(*names,**where):
    '''return a formatted table containing the specified query'''
    def row(ea):
        fmt = '%x: '%ea + ' | '.join( ('%s',)*len(names) )
        d = function.tag(ea)
        return fmt% tuple(( d.get(x, None) for x in names ))
    return '--------> ' + ' | '.join(names) + '\n' + '\n'.join( (row(x) for x in query(**where)) )

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
        return n

    try:
        return tag(ea, 'name')
    except KeyError:
        pass
    return None

def blocks(start, end):
    '''Returns each block between the specified range of instructions'''
    block = start
    for ea in iterate(start, end):
        if idc.GetMnem(ea).startswith('call'):      # FIXME: heh. ;)
            continue

        if idc.GetMnem(ea).startswith('ret'):       #   whee
            yield block,next(ea)
            block = ea

        elif cxdown(ea):
            yield block,next(ea)
            block = next(ea)

        elif cxup(ea):
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
