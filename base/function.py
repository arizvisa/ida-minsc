import logging
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

def contains(fn, address):
    '''Checks if address is contained in function and any of it's chunks'''
    (start,end) = getRange(fn)
    if address >= start and address < end:
        return True

    for start,end in chunks(fn):
        if address >= start and address < end:
            return True
        continue

    return False

def top(ea):
    '''Jump to the top of the specified function'''
    min,max = getRange(ea)
    return min

def marks(fn):
    result = []
    fn = top(fn)
    for ea,comment in database.marks():
        try:
            if top(ea) == fn:
                result.append( (ea,comment) )
        except ValueError:
            pass
        continue
    return result

# function frame attributes
def getFrameId(fn):
    '''Returns the structure id of the frame'''
    return idc.GetFunctionAttr(fn, idc.FUNCATTR_FRAME)

def getAvarSize(fn):
    '''Return the number of bytes occupying argument space'''
    max = structure.size(getFrameId(fn))
    total = getLvarSize(fn) + getRvarSize(fn)
    return max - total

def getLvarSize(fn):
    '''Return the number of bytes occupying local variable space'''
    return idc.GetFunctionAttr(fn, idc.FUNCATTR_FRSIZE)

def getRvarSize(fn):
    '''Return the number of bytes occupying any saved registers'''
    return idc.GetFunctionAttr(fn, idc.FUNCATTR_FRREGS) + 4   # +4 for the pc because ida doesn't count it

def getSpDelta(ea):
    '''Gets the stack delta at the specified address'''
    return idc.GetSpd(ea)

def iterate(fn):
    '''Iterate through all the instructions in each chunk of the specified function'''
    for start,end in chunks(fn):
        for ea in database.iterate(start, end):
            yield ea
        continue
    return

def searchinstruction(fn, match=lambda insn: True):
    for ea in iterate(fn):
        if match( database.decode(ea) ):
            yield ea
        continue
    return

def blocks(fn):
    '''Returns each block in the specified function'''
    for start,end in chunks(fn):
        for r in database.blocks(start, end):
            yield r
        continue
    return

try:
    import store.query as query
    import store

    def __select(fn, q):
        for start,end in chunks(fn):
            for ea in database.iterate(start, end):
                d = database.tag(ea)        # FIXME: bmn noticed .select yielding empty records
                if d and q.has(d):
                    yield ea
                continue
            continue
        return

    def select(fn, *q, **where):
        if where:
            print "function.select's kwd arguments have been deprecated in favor of query"

        result = list(q)
        for k,v in where.iteritems():
            if v is None:
                result.append( query.hasattr(k) )
                continue
            result.append( query.hasvalue(k,v) )
        return __select(top(fn), query._and(*result) )

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

except ImportError:
    import comment

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
            try:
                result = tag_read(address, *args, **kwds)
            except Exception, e:
                logging.warn('function.tag(%x): %s raised'% (address, repr(e)))
                result = None
            return result

        key,value = args
        return tag_write(address, key, value, **kwds)

    def select(fn, tags=None):
        '''Fetch all instances of the specified tag located within function'''
        if tags is None:
            result = {}
            for ea in iterate(fn):
                res = database.tag(ea)
                if res:
                    result[ea] = res
                continue
            return result

        tags = set((tags,)) if type(tags) is str else set(tags)

        result = {}
        for ea in iterate(fn):
            res = dict((k,v) for k,v in database.tag(ea).iteritems() if k in tags)
            if res:
                result[ea] = res
            continue
        return result

