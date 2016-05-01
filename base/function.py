'''
function-context

generic tools for working in the context of a function.
'''

import logging,re,itertools
import internal,database,structure,ui
import idaapi

## searching
def byAddress(ea):
    res = idaapi.get_func(ea)
    if res is None:
        raise LookupError, "function.byAddress(%x):unable to locate function"% ea
    return res
def byName(name):
    ea = idaapi.get_name_ea(-1, name)
    if ea == idaapi.BADADDR:
        raise LookupError, "function.byName(%r):unable to locate function"% name
    return idaapi.get_func(ea)
def by(n):
    if type(n) is idaapi.func_t:
        return n
    if type(n) is str:
        return byName(n)
    return byAddress(n)

def __addressOfRtOrSt(fn):
    '''Returns (F,address) if a statically linked address, or (T,address) if a runtime linked address'''
    try: fn = by(fn)

    # otherwise, maybe it's an rtld symbol
    except LookupError, e:
        if not database.isData(fn): raise

        # ensure that we're an import, otherwise throw original exception
        try: database.imports.get(fn)
        except LookupError: raise e

        # yep, we're an import
        return True,fn
    return False,fn.startEA

def address(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.address(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.startEA

def offset(key=None):
    ea = address(key)
    return database.getoffset(ea)

def guess(ea):
    '''Determine the contiguous boundaries of the code at the given address'''
    for left,right in chunks(ea):
        if left <= ea < right:
            return left,right
        continue
    raise LookupError, "Unable to determine function chunk's bounds : %x"%ea

## properties
def comment(fn, comment=None, repeatable=1):
    fn = by(fn)
    if comment is None:
        return idaapi.get_func_cmt(fn, repeatable)
    return idaapi.set_func_cmt(fn, comment, repeatable)

def name(key=None, name=None):
    '''Returns the name of the function or import identified by key.'''
    rt,ea = __addressOfRtOrSt(ui.current.address() if key is None else key)
    if rt:   
        if name is None:
            res = idaapi.get_name(-1, ea)
            return internal.declaration.extract.fullname(internal.declaration.demangle(res)) if res.startswith('?') else res
        # FIXME: shuffle the new name into the prototype and then re-mangle it
        return database.name(ea, name)

    if name is None:
        res = idaapi.get_func_name(ea)
        if not res: res = idaapi.get_name(-1, ea)
        if not res: res = idaapi.get_true_name(ea, ea)
        return internal.declaration.extract.fullname(internal.declaration.demangle(res)) if res.startswith('?') else res
        #return internal.declaration.extract.name(internal.declaration.demangle(res)) if res.startswith('?') else res
    return idaapi.set_name(ea, name, idaapi.SN_PUBLIC)

def prototype(key=None):
    '''Returns the full prototype of the function identified by fn.'''
    rt,ea = __addressOfRtOrSt(ui.current.address() if key is None else key)
    funcname = database.name(ea)
    try:
        res = internal.declaration.function(ea)
        idx = res.find('(')
        result = res[:idx] + ' ' + funcname + res[idx:]

    except ValueError:
        if not funcname.startswith('?'): raise
        result = internal.declaration.demangle(funcname)
    return result

def frame(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.frame(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)

    res = idaapi.get_frame(fn.startEA)
    if res is not None:
        return structure.instance(res.id, offset=-fn.frsize)
    #logging.fatal('%s.frame : function does not have a frame : %x %s', __name__, fn.startEA, name(fn.startEA))
    logging.info('%s.frame : function does not have a frame : %x %s', __name__, fn.startEA, name(fn.startEA))
    return structure.instance(-1)

def getRange(key=None):
    '''tuple containing function start and end'''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.getRange(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    if fn is None:
        raise ValueError, 'address %x is not contained in a function'% ea
    return fn.startEA,fn.endEA

def color_write(fn, bgr):
    fn = by(fn)
    fn.color = 0xffffffff if bgr is None else bgr
    return bool(idaapi.update_func(fn))

def color_read(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.color_read(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.color

def color(fn, *args, **kwds):
    '''color(address, rgb?) -> fetches or stores a color to the specified function.'''
    if len(args) == 0:
        return color_read(fn, *args, **kwds)
    return color_write(fn, *args, **kwds)

def top(key=None):
    '''Return the top of the specified function'''
    return address(key)

def bottom(key=None):
    '''Return the addresses of instructions that are used to exit the specified function'''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.bottom(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    fc = idaapi.FlowChart(f=fn, flags=idaapi.FC_PREDS)
    fc = flow(key)
    exit_types = (fc_block_type_t.fcb_ret,fc_block_type_t.fcb_cndret,fc_block_type_t.fcb_noret,fc_block_type_t.fcb_enoret,fc_block_type_t.fcb_error)
    return tuple(database.address.prev(n.endEA) for n in fc if n.type in exit_types)

def marks(key=None):
    funcea = top(key)
    result = []
    for ea,comment in database.marks():
        try:
            if top(ea) == funcea:
                result.append( (ea,comment) )
        except Exception:
            pass
        continue
    return result

## functions
def add(start, end=idaapi.BADADDR):
    '''Creates a function at the specified /start/'''
    return idaapi.add_func(start, end)
make = add
def remove(fn):
    if type(fn) is idaapi.func_t:
        return idaapi.del_func(fn.startEA)
    return remove(by(fn))

def addChunk(fn, start, end):
    if type(fn) is idaapi.func_t:
        return idaapi.append_func_tail(fn, start, end)
    return addChunk(by(fn), start, end)
def removeChunk(fn, ea):
    if type(fn) is idaapi.func_t:
        return idaapi.remove_func_tail(fn, ea)
    return removeChunk(by(fn), ea)
def assignChunk(fn, chunkea):
    if type(fn) is idaapi.func_t:
        idaapi.set_tail_owner(fn, chunkea)
    return assignChunk(by(fn), chunkea)

def within(ea):
    '''Returns True if address is associated with a function of some kind'''
    return idaapi.get_func(ea) is not None

## operations
def contains(fn, ea):
    '''Checks if ea is contained in function or in any of it's chunks'''
    try: fn = by(fn)
    except LookupError:
        return False

    for start,end in chunks(fn):
        if start <= ea < end:
            return True
        continue
    return False

def arguments(key=None):
    '''Returns the arguments as (offset,name,size)'''
    try:
        if key is None:
            fn = ui.current.function()
            if fn is None: raise LookupError, "function.arguments(%r):Not currently positioned within a function"% key
        else:
            fn = by(key)

    except Exception:
        target = ui.current.address() if key is None else key
        database.imports.get(target)

        # grab from declaration
        o = 0
        for arg in internal.declaration.arguments(target):
            sz = internal.declaration.size(arg)
            yield o,arg,sz
            o += sz
        return

    # grab from structure
    fr = idaapi.get_frame(fn)
    if fr is None:  # unable to figure out arguments
        raise LookupError, "function.arguments(%r):Unable to determine function frame"%key
    if database.config.bits() != 32:
        raise RuntimeError, "function.arguments(%r):Unable to determine arguments for %x due to %d-bit calling convention."%(key, fn.startEA, database.config.bits()) 

    base = getLvarSize(fn)+getRvarSize(fn)
    for (off,size),(name,cmt) in structure.fragment(fr.id, base, getAvarSize(fn)):
        yield off-base,name,size
    return

def chunks(key=None):
    '''enumerates all chunks in a function '''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.chunks(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    fci = idaapi.func_tail_iterator_t(fn, fn.startEA)
    if not fci.main():
        raise ValueError, "function.chunks(%r):Unable to create a func_tail_iterator_t"% key

    while True:
        ch = fci.chunk()
        yield ch.startEA, ch.endEA
        if not fci.next(): break
    return

def blocks(key=None):
    '''Returns each block in the specified function'''
    for start,end in chunks(key):
        for r in database.blocks(start, end):
            yield r
        continue
    return

# function frame attributes
def getFrameId(key=None):
    '''Returns the structure id of the frame'''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.getFrameId(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.frame

def getAvarSize(key=None):
    '''Return the number of bytes occupying argument space'''
    max = structure.size(getFrameId(key))
    total = getLvarSize(key) + getRvarSize(key)
    return max - total

def getLvarSize(key=None):
    '''Return the number of bytes occupying local variable space'''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.getLvarSize(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.frsize

def getRvarSize(key=None):
    '''Return the number of bytes occupying any saved registers'''
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.getRvarSize(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.frregs + 4   # +4 for the pc because ida doesn't count it

def getSpDelta(ea):
    '''Gets the stack delta at the specified address'''
    func = byAddress(ea)
    return idaapi.get_spd(func, ea)

## instruction iteration/searching
def iterate(key=None):
    '''Iterate through all the instructions in each chunk of the specified function'''
    for start,end in chunks(key):
        for ea in itertools.ifilter(database.type.isCode, database.iterate(start, end)):
            yield ea
        continue
    return

def searchinstruction(key=None, match=lambda insn: True):
    for ea in iterate(key):
        if match( database.decode(ea) ):
            yield ea
        continue
    return

def search(key, regex):
    '''Return each instruction that matches the case-insensitive regex'''
    pattern = re.compile(regex, re.I)
    for ea in iterate(key):
        insn = re.sub(' +', ' ', database.instruction(ea))
        if pattern.search(insn) is not None:
            yield ea
        continue
    return

# FIXME: come up with a better name
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
stackWindow = stackwindow

## tagging
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
        if len(args) == 0:
            return datastore.address(address)

        elif len(args) == 1:
            key, = args
            result = datastore.select(query.address(address), query.attribute(key)).values()
            try:
                result = result[0][key]
            except:
                raise KeyError(hex(address),key)
            return result

        key,value = args
        kwds.update({key:value})
        return datastore.address(address).set(**kwds)

except ImportError:
    def tag_read(address, key=None, repeatable=1):
        res = comment(byAddress(address), repeatable=repeatable)
        dict = internal.comment.toDict(res)
        if 'name' not in dict:
            dict['name'] = name(byAddress(address))
        return dict if key is None else dict[key]

    def tag_write(address, key, value, repeatable=1):
        dict = tag_read(address, repeatable=repeatable)
        dict[key] = value
        res = internal.comment.toString(dict)
        return comment(byAddress(address), res, repeatable=repeatable)

    def tag(address, *args, **kwds):
        '''tag(address, key?, value?) -> fetches/stores a tag from a function's comment'''
        if len(args) < 2:
            return tag_read(address, *args, **kwds)

        key,value = args
        return tag_write(address, key, value, **kwds)

    def select(fn, *tags, **boolean):
        '''Fetch a list of addresses within the function that contain the specified tags'''
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

def tags(key=None):
    funcea = top(key)    
    try:
        if funcea is None:
            raise KeyError
        result = eval(database.tag_read(funcea, '__tags__'))
    except KeyError:
        result = set()
    return result

if False:
    class instance(object):
        # FIXME: finish this
        class chunk_t(object):
            pass

        @classmethod
        def byAddress(cls, ea):
            n = idaapi.get_fchunk_num(ea)
            f = idaapi.getn_func(n)
            return cls.getIndex(n)

## referencing
def down(key=None):
    """Returns all functions that are called by specified function"""
    def codeRefs(func):
        resultData,resultCode = [],[]
        for ea in iterate(func):
            if len(database.down(ea)) == 0:
                insn = idaapi.ua_mnem(ea)
                if insn and insn.startswith('call'):
                    resultCode.append((ea, 0))
                continue
            resultData.extend( (ea,x) for x in database.dxdown(ea) )
            resultCode.extend( (ea,x) for x in database.cxdown(ea) if func.startEA == x or not contains(func,x) )
        return resultData,resultCode
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.down(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return list(set(d for x,d in codeRefs(fn)[1]))

def up(key=None):
    ea = address(key)
    return database.up(ea)

## switch stuff
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

def switches(key=None):
    for ea in iterate(key):
        res = idaapi.get_switch_info_ex(ea)
        if res: yield switch_t(res)
    return

## flags
def hasNoFrame(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.hasNoFrame(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return not isThunk(fn) and (fn.flags & idaapi.FUNC_FRAME == 0)
def hasNoReturn(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.hasNoReturn(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return not isThunk(fn) and (fn.flags & idaapi.FUNC_NORET == idaapi.FUNC_NORET)
def isLibrary(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.isLibrary(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.flags & idaapi.FUNC_LIB == idaapi.FUNC_LIB
def isThunk(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.isThunk(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    return fn.flags & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK

def register(fn, *regs, **options):
    write = options.get('write', 0)
    for l,r in chunks(fn):
        ea = database.address.nextreg(l, *regs, write=write)
        while ea < r:
            yield ea
            ea = database.address.nextreg(database.address.next(ea), *regs, write=write)
        continue
    return

## internal enumerations that idapython missed
class fc_block_type_t:
    fcb_normal = 0  # normal block
    fcb_indjump = 1 # block ends with indirect jump
    fcb_ret = 2     # return block
    fcb_cndret = 3  # conditional return block
    fcb_noret = 4   # noreturn block
    fcb_enoret = 5  # external noreturn block (does not belong to the function)
    fcb_extern = 6  # external normal block
    fcb_error = 7   # block passes execution past the function end

def flow(key=None):
    if key is None:
        fn = ui.current.function()
        if fn is None: raise LookupError, "function.bottom(%r):Not currently positioned within a function"% key
    else:
        fn = by(key)
    fc = idaapi.FlowChart(f=fn, flags=idaapi.FC_PREDS)
    return fc
