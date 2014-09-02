import logging
import idc, comment, database, structure, idautils, idaapi
'''
function-context

generic tools for working in the context of a function.
'''

def getComment(ea, repeatable=1):
    fn = byAddress(ea)
    return idaapi.get_func_cmt(fn, repeatable)
def setComment(ea, string, repeatable=1):
    fn = byAddress(ea)
    return idaapi.set_func_cmt(fn, string, repeatable)

def getName(ea):
    '''fetches the function name, or the global name'''
    res = idaapi.get_func_name(ea)
    if res is None:
        res = idaapi.get_name(-1, ea)
    if res is None:
        res = idaapi.get_true_name(ea, ea)

    # if name is mangled...  and version <= 6.4
    if res and res.startswith('@'):
        return '$'+res
    return res

def setName(ea, name):
    '''sets the function name, returns True or False based on success'''
    res = idc.MakeNameEx(ea, name, 2)
    return [False, True][int(res)]

def name(ea, *args):
    '''sets/gets the function name'''
    raise DeprecationWarning
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
    func = byAddress(ea)
    if func is None:
        raise ValueError, 'address %x is not contained in a function'% ea
    return func.startEA,func.endEA

def make(start, end=idc.BADADDR):
    '''pseudo-safely makes the address at start a function'''
    # FIXME: scroll upward looking for the previous function
    if database.isCode(start):
        return idc.MakeFunction(start, end)
    raise ValueError, 'address %x does not contain code'% start

def contains(func, ea):
    '''Checks if ea is contained in function or in any of it's chunks'''
    f = byAddress(func)
    if f is None:   # or not f.contains(ea):
        return False
    for start,end in chunks(func):
        if start <= ea < end:
            return True
        continue
    return False

def top(ea):
    '''Jump to the top of the specified function'''
    func = byAddress(ea)
    if func is None:
        raise ValueError, "Address %x not in a function"% ea
    min,_ = func.startEA,func.endEA
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

import re
def search(fn, regex):
    '''Return each instruction that matches the case-insensitive regex'''
    pattern = re.compile(regex, re.I)
    for ea in iterate(fn):
        insn = re.sub(' +', ' ', database.instruction(ea))
        if pattern.search(insn) is not None:
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

import declaration
getDeclaration = declaration.function
def getArguments(ea):
    '''Returns the arguments as (offset,name,size)'''
    try:
        # grab from declaration first
        o = 0
        for arg in declaration.arguments(ea):
            sz = declaration.size(arg)
            yield o,arg,sz
            o += sz
        return

    except ValueError:
        pass

    # grab from structure
    ea = top(ea)
    fr = idaapi.get_frame(ea)
    if fr is None:  # unable to figure out arguments
        return

    base = getLvarSize(ea)+getRvarSize(ea)
    for (off,size),(name,cmt) in structure.fragment(fr.id, base, getAvarSize(ea)):
        yield off-base,name,size

def stackwindow(ea, delta, direction=-1):
    '''return the block containing all instructions within the specified stack delta'''
    assert direction != 0, 'you make no sense with your lack of direction'
    next = database.next if direction > 0 else database.prev

    sp = getSpDelta(ea)
    start = (ea,sp)
    while abs(sp - start[1]) < delta:
        sp = getSpDelta(ea)
        ea = next(ea)

    if ea < start[0]:
        return ea+idaapi.decode_insn(ea),start[0]+idaapi.decode_insn(start[0])
    return (start[0],ea)

def stackdelta(left, right):
    '''return the minimum,maximum delta of the range of instructions'''
    min,max = 0,0
    for ea in database.iterate(left,right):
        sp = getSpDelta(ea)
        min = sp if sp < min else min
        max = max if sp < max else sp
    return min,max

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
            return tag_read(address, *args, **kwds)

        key,value = args
        return tag_write(address, key, value, **kwds)

    """
    def select(fn, *tags, **boolean):
        '''Fetch all instances of the specified tag located within function'''
        if tags is None:
            for ea in iterate(fn):
                res = database.tag(ea)
                if res: yield ea, res
            return

        tags = set(tags)
        #if function.tags(fn).intersection(tags) != tags:
        #    return {}

        for ea in iterate(fn):
            res = dict((k,v) for k,v in database.tag(ea).iteritems() if k in tags)
            if res: yield ea,res
        return
    """

    # FIXME: this function can be made generic
    def select(fn, *tags, **boolean):
        '''Fetch all instances of the specified tag located within function'''
        boolean = dict((k,set(v) if type(v) is tuple else set((v,))) for k,v in boolean.viewitems())
        if tags:
            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))

        if not boolean:
            for ea in iterate(fn):
                res = database.tag(ea)
                if res: yield ea, res
            return

        for ea in iterate(fn):
            res,d = {},database.tag(ea)

            Or = boolean.get('Or', set())
            res.update((k,v) for k,v in d.iteritems() if k in Or)

            And = boolean.get('And', set())
            if And:
                if And.intersection(d.viewkeys()) == And:
                    res.update((k,v) for k,v in d.iteritems() if k in And)
                else: continue
            if res: yield ea,res
        return

def byAddress(ea):
    return idaapi.get_func(ea)

def tags(ea):
    func_ea = top(ea)    
    try:
        if func_ea is None:
            raise KeyError
        result = eval(database.tag_read(func_ea, '__tags__'))
    except KeyError:
        result = set()
    return result

class instance(object):
    # FIXME: finish this
    class chunk_t(object):
        pass

    @classmethod
    def byAddress(cls, ea):
        n = idaapi.get_fchunk_num(ea)
        f = idaapi.getn_func(n)
        return cls.getIndex(n)

def down(ea):
    """Returns all functions that are called by specified function"""
    def codeRefs(ea):
        fn = top(ea)
        resultData,resultCode = [],[]
        for l,r in chunks(fn):
            for ea in database.iterate(l,r):
                if len(database.down(ea)) == 0:
                    insn = idaapi.ua_mnem(ea)
                    if insn and insn.startswith('call'):
                        resultCode.append((ea, 0))
                    continue
                resultData.extend( (ea,x) for x in database.dxdown(ea) )
                resultCode.extend( (ea,x) for x in database.cxdown(ea) if not contains(fn,x) )
            continue
        return resultData,resultCode
    return list(set(d for x,d in codeRefs(ea)[1]))

### switch stuff
class switch_t(object):
    #x.defjump -- default case
    #x.jcases,x.jumps -- number of branches,address of branch data
    #x.ncases,x.lowcase -- number of cases,address of switch data
    #x.startea -- beginning of basicblock that is switch
    # get_jtable_element_size -- table entry size
    # need some way to get pointer size
    def __init__(self, switch_info_ex):
        self.object = switch_info_ex
    @property
    def default(self):
        # address of default case
        return self.object.defjump
    @property
    def ea(self):
        # address of beginning of switch code
        return self.object.startea
    @property
    def branch_ea(self):
        # address of branch table
        return self.object.jumps
    @property
    def table_ea(self):
        # address of case table
        return selfobject.lowcase
    @property
    def branch(self):
        # return the branch table as an array
        pass
    @property
    def table(self):
        # return the index table as an array
        pass
    def getCase(self, case):
        # return the ea of the specified case number
        raise NotImplementedError

def switches(fn):
    fn = top(fn)
    for ea in iterate(fn):
        x = idaapi.get_switch_info_ex(ea)
        if x:
            yield switch_t(x)
        continue
    return

### vtable stuff       

### flags
def hasNoFrame(fn):
    return not isThunk(fn) and (idaapi.get_func(fn).flags & idaapi.FUNC_FRAME == 0)
def hasNoReturn(fn):
    return not isThunk(fn) and (idaapi.get_func(fn).flags & idaapi.FUNC_NORET == idaapi.FUNC_NORET)
def isLibrary(fn):
    return idaapi.get_func(fn).flags & idaapi.FUNC_LIB == idaapi.FUNC_LIB
def isThunk(fn):
    return idaapi.get_func(fn).flags & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK
