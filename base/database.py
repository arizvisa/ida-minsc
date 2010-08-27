import idc,idautils
import comment,instruction

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

def getBlock(start, end):
    '''Return a string of bytes'''
    result = [ idc.Byte(ea) for ea in xrange(start, end) ]
    return ''.join(map(chr, result))

def tag_read(address, key=None, repeatable=0):
    res = idc.GetCommentEx(address, repeatable)
    dict = comment.toDict(res)
    name = idc.Name(address)
    if name:
        dict['name'] = name

    c = color(address)
    if c is not None:
        dict['__color__'] = c

    if key:
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

import function
def guessRange(ea):
    '''Try really hard to get boundaries of the block at specified address'''
    start,end = function.getRange(ea)
    if function.contains(start, ea) and not (ea >= start and ea < end):
        return (idc.GetFchunkAttr(ea, idc.FUNCATTR_START), idc.GetFchunkAttr(ea, idc.FUNCATTR_END))
    return start,end

def decode(ea):
    return instruction.decode(ea)

import idaapi as ida
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
    return list(crefs(ea, True))

def cxup(ea):
    return list(crefs(ea, False))

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
    for i in range(3):
        bgr,rgb = ((bgr*0x100) + (rgb&0xff), rgb/0x100)
    return idc.SetColor(ea, what, bgr)

def color_read(ea, what=1):
    bgr = idc.GetColor(ea, what)
    if bgr == 0xffffffff:
        return None

    a = bgr&0xff000000
    bgr &= 0x00ffffff

    rgb = 0
    for i in range(3):
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

def filename():
    return idc.GetInputFile()

import idaapi
def baseaddress():
    return idaapi.get_imagebase()

def getOffset(ea):
    return ea - baseaddress()

import function
def select(tag):
    '''Select all functions in database that contain the specified tag'''
    result = []
    for ea in functions():
        try:
            function.tag(ea, tag)
            result.append(ea)
        except KeyError:
            pass
        continue
    return result

def query(tag, value):
    '''Select all functions in a database that contain the specified tag,value'''
    return [ ea for ea in select(tag) if function.tag(ea, tag) == value ]
