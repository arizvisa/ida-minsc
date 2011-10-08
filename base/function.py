import idc, comment, database, structure, idautils, query
'''
function-context

generic tools for working in the context of a function.
'''
#EXPORT = ['getComment', 'setComment', 'chunks', 'getName', 'setName', 'getRange', 'make', 'tag', 'contains', 'getBranches']

def getComment(ea, repeatable=1):
    return idc.GetFunctionCmt(int(ea), repeatable)
def setComment(ea, string, repeatable=1):
    return idc.SetFunctionCmt(int(ea), string, repeatable)

def getName(ea):
    '''fetches the function name, returns None on no function'''
    res = idc.GetFunctionName(ea)
    if res:
        return res
    return None

def setName(ea, name):
    '''sets the function name, returns True or False based on success'''
    res = idc.MakeNameEx(ea, name, 2)
    return [False, True][int(res)]

def name(ea, *args):
    '''sets/gets the function name'''
    if args:
        name, = args
        return setName(ea, name)
    return getName(ea)

def chunks(ea):
    '''enumerates all chunks in a function '''
    res = idc.FirstFuncFchunk(ea)
    while res != idc.BADADDR:
        (start, end) = idc.GetFchunkAttr(res, idc.FUNCATTR_START), idc.GetFchunkAttr(res, idc.FUNCATTR_END)
        yield start,end
        res = idc.NextFuncFchunk(ea, res)
    return

def getRange(ea):
    '''tuple containing function start and end'''
    start, end = (idc.GetFunctionAttr(ea, idc.FUNCATTR_START), idc.GetFunctionAttr(ea, idc.FUNCATTR_END))
    if (start == 0xffffffff) and (end == 0xffffffff):
        raise ValueError, 'address %x is not contained in a function'% ea
    return start, end

def make(start, end=idc.BADADDR):
    '''pseudo-safely makes the address at start a function'''
    if database.isCode(start):
        return idc.MakeFunction(start, end)
    raise ValueError, 'address %x does not contain code'% start

def contains(function, address):
    '''Checks if address is contained in function and any of it's chunks'''
    (start,end) = getRange(function)
    if address >= start and address < end:
        return True

    for start,end in chunks(function):
        if address >= start and address < end:
            return True
        continue

    return False

def top(ea):
    '''Jump to the top of the specified function'''
    min,max = getRange(ea)
    return min

def marks(function):
    result = []
    function = top(function)
    for ea,comment in database.marks():
        try:
            if top(ea) == function:
                result.append( (ea,comment) )
        except ValueError:
            pass
        continue
    return result

def __select(function, q):
    for start,end in chunks(function):
        for ea in database.iterate(start, end):
            d = database.tag(ea)        # FIXME: bmn noticed .select yielding empty records
            if d and q.has(d):
                yield ea
            continue
        continue
    return

def select(function, *q, **where):
    if where:
        print "function.select's kwd arguments have been deprecated in favor of query"

    result = list(q)
    for k,v in where.iteritems():
        if v is None:
            result.append( query.hasattr(k) )
            continue
        result.append( query.hasvalue(k,v) )
    return __select(top(function), query._and(*result) )

# function frame attributes
def getFrameId(function):
    '''Returns the structure id of the frame'''
    return idc.GetFunctionAttr(function, idc.FUNCATTR_FRAME)

def getAvarSize(function):
    '''Return the number of bytes occupying argument space'''
    max = structure.size(getFrameId(function))
    total = getLvarSize(function) + getRvarSize(function)
    return max - total

def getLvarSize(function):
    '''Return the number of bytes occupying local variable space'''
    return idc.GetFunctionAttr(function, idc.FUNCATTR_FRSIZE)

def getRvarSize(function):
    '''Return the number of bytes occupying any saved registers'''
    return idc.GetFunctionAttr(function, idc.FUNCATTR_FRREGS) + 4   # +4 for the pc because ida doesn't count it

def getSpDelta(ea):
    '''Gets the stack delta at the specified address'''
    return idc.GetSpd(ea)

def iterate(function):
    '''Iterate through all the instructions in each chunk of the specified function'''
    for start,end in chunks(function):
        for ea in database.iterate(start, end):
            yield ea
        continue
    return

def searchinstruction(function, match=lambda insn: True):
    for ea in iterate(function):
        if match( database.decode(ea) ):
            yield ea
        continue
    return

def blocks(function):
    '''Returns each block in the specified function'''
    for start,end in chunks(function):
        for r in database.blocks(start, end):
            yield r
        continue
    return

import store
datastore = store.ida
def tag(address, *args, **kwds):
    '''tag(address, key?, value?) -> fetches/stores a tag from a function's comment'''
#    '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
    if len(args) == 0:
        return datastore.address(address)
#        return __datastore.context.get(address)

    elif len(args) == 1:
        key, = args
#        result = __datastore.context.select(query.address(address), query.attribute(key)).values()
        result = datastore.select(query.address(address), query.attribute(key)).values()
        try:
            result = result[0][key]
        except:
            raise KeyError(hex(address),key)
        return result

    key,value = args
    kwds.update({key:value})
    return datastore.address(address).set(**kwds)
#    return datastore.context.set(address, **kwds)
