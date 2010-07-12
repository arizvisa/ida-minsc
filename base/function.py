import idc, comment, database
'''
function-context

generic tools for working in the context of a function.
'''
EXPORT = ['getComment', 'setComment', 'chunks', 'getName', 'setName', 'getRange', 'make', 'tag', 'contains', 'getBranches']

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
        yield res
        res = idc.NextFuncFchunk(ea, res)

def getRange(ea):
    '''tuple containing function start and end'''
    start, end = (idc.GetFunctionAttr(ea, idc.FUNCATTR_START), idc.GetFunctionAttr(ea, idc.FUNCATTR_END))
    if (start is None) or (end is None):
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
    if key:
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

    for x in chunks(function):
        (start, end) = idc.GetFchunkAttr(x, idc.FUNCATTR_START), idc.GetFchunkAttr(x, idc.FUNCATTR_END)

        if address >= start and address < end:
            return True
        continue

    return False

def top(ea=None):
    '''Jump to the top of the specified function'''
    if ea is None:
        ea = idc.ScreenEA()
    min,max = getRange(ea)
    return min

def fetchtag(function, tag):
    '''Fetch all instances of the specified tag located within function'''
    result = []
    for x in chunks(function):
        (start, end) = idc.GetFchunkAttr(x, idc.FUNCATTR_START), idc.GetFchunkAttr(x, idc.FUNCATTR_END)
        result.extend( __fetchtag_chunk(start, end, tag) )
    return result

def __fetchtag_chunk(start, end, tag):
    result = []
    for ea in database.iterate(start, end):
        try:
            database.tag(ea, tag)
            result.append(ea)
        except KeyError:
            pass
        continue
    return result

def marks(function=None):
    if function is None:
        function = idc.ScreenEA()
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

def gettags(function):
    result = []
    for x in chunks(function):
        (start, end) = idc.GetFchunkAttr(x, idc.FUNCATTR_START), idc.GetFchunkAttr(x, idc.FUNCATTR_END)
        result.append(__getchunk_tags(start, end))
    return result

def puttags(function, list):
    count  = 0
    for ea,records in zip(chunks(function), list):
        (start, end) = idc.GetFchunkAttr(ea, idc.FUNCATTR_START), idc.GetFchunkAttr(ea, idc.FUNCATTR_END)
    
        for offset in records.keys():
            data = records[offset]
            ea = start+offset
            for k,v in data.items():
                db.tag(ea, k, v)

            count += 1
        continue
    return count
