import idc, comment, database, structure, idautils
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

def tag_read(address, key=None, repeatable=1):
    res = getComment(address, repeatable)
    dict = comment.toDict(res)
    if 'name' not in dict:
        dict['name'] = getName(address)

    if key is not None:
        return dict[key]
    return dict

def tag_write(address, key, value, repeatable=1):
    dict = tag_read(address, repeatable=repeatable)
    dict[key] = value
    res = comment.toString(dict)
    return setComment(address, res, repeatable)

def tag(address, *args, **kwds):
    '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
    if len(args) < 2:
        return tag_read(address, *args, **kwds)
    key,value = args
    return tag_write(address, key, value, **kwds)

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

def query(function, **where):
    '''query all tags associated with a function'''
    for start,end in chunks(function):
        for ea in database.iterate(start, end):
            d = database.tag(ea)        # FIXME: bmn noticed .select yielding empty records
            if d and comment.has_and(d, **where):
                yield ea
            continue
        continue
    return

def select(function, **where):
    return set(query(function, **where))

def dump(function, *names, **where):
    '''return a formatted table containing the specified query'''
    def row(ea):
        fmt = '%x: '%ea + ' | '.join( ('%s',)*len(names) )
        d = database.tag(ea)
        return fmt% tuple(( d.get(x, None) for x in names ))
    return '--------> ' + ' | '.join(names) + '\n' + '\n'.join( (row(x) for x in query(function, **where)) )

def __getchunk_tags(start, end):
    result = {}
    for ea in database.iterate(start, end):
        try:
            res = database.tag(ea)
            if res:
                result[ea-start] = res
        except KeyError:
            pass
        continue
    return result

def __fetch_chunks(function):
    result = []
    for start,end in chunks(function):
        result.append(__getchunk_tags(start, end))
    return result

def fetch(function):
    '''Fetch all tags associated with a function. Will return a list of each chunk. Each element will be keyed by offset.'''
    return { 'head':tag_read(function), 'chunk':__fetch_chunks(function) }

def __store_chunks(function, list, prefix=''):
    '''Store all tags in list to specified function. /list/ is the same format as returned by .fetch()'''
    count  = 0
    for (start,end),records in zip(chunks(function), list):
        for offset in records.keys():
            data = records[offset]
            ea = start+offset
            for k,v in data.items():
                database.tag(ea, prefix+k, v)
            count += 1
        continue
    return count

def store(function, dict, prefix=''):
    '''Fetch all tags associated with a function. Will return a list of each chunk. Each element will be keyed by offset.'''
    head = dict['head']
    for k,v in head.items():
        tag_write(function, prefix+k, v)
    return __store_chunks(function, dict['chunk'], prefix)

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
    return idc.GetFunctionAttr(function, idc.FUNCATTR_FRREGS) + 4   # +4 for the pc

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
