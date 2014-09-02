import logging,os
import idc,idautils,idaapi
import instruction as _instruction,function,segment,declaration
import array,itertools

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
    return idaapi.get_many_bytes(start, length)

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
    return _instruction.decode(ea)

def instruction(ea):
    insn = idaapi.generate_disasm_line(ea)
    unformatted = idaapi.tag_remove(insn)
    nocomment = unformatted[:unformatted.rfind(';')]
    return reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')

def disasm(ea, count=1):
    res = []
    while count > 0:
        insn = idaapi.generate_disasm_line(ea)
        unformatted = idaapi.tag_remove(insn)
        nocomment = unformatted[:unformatted.rfind(';')] if ';' in unformatted else unformatted
        res.append( '{:x}: {:s}'.format(ea, reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')) )
        ea = next(ea)
        count -= 1
    return '\n'.join(res)

# FIXME: there's issues when trying to get xrefs from a structure or array,
#        if it's not the first address of the item, then it will return no
#        xrefs for that particular address. it might be possible to fix this
#        in this module.

#   -- it seems like ida makes structures and stuff into an instruction_t or
#       something
def iterate_refs(address, start, next):
    ea = address
    address = start(ea)
    while address != idaapi.BADADDR:
        yield address
        address = next(ea, address)
    return

def drefs(ea, descend=False):
    if descend:
        start,next = idaapi.get_first_dref_from, idaapi.get_next_dref_from
    else:
        start,next = idaapi.get_first_dref_to, idaapi.get_next_dref_to

    for addr in iterate_refs(ea, start, next):
        yield addr
    return

def crefs(ea, descend=False):
    if descend:
        start,next = idaapi.get_first_cref_from, idaapi.get_next_cref_from
    else:
        start,next = idaapi.get_first_cref_to, idaapi.get_next_cref_to

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

def module():
    return filename().split('\\')[-1].rsplit('.',2)[0]

def filename():
    '''return the filename that the database was built from'''
    return idaapi.get_root_filename()

def idb():
    return idaapi.cvar.database_idb

def path():
    '''return the full path to the database'''
    filepath = idb().replace(os.sep,'/')
    return filepath[: filepath.rfind('/')] 

def baseaddress():
    '''returns the baseaddress of the module'''
    return idaapi.get_imagebase()
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
        tag(ea, 'name', string)
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
        ordinal = idaapi.get_entry_qty()
    return idaapi.add_entry(ordinal, ea, name, 0)

class config(object):
    info = idaapi.get_inf_structure()
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
    if not function.contains(ea, ea):
        return None

    # scan down until we find a call that references something
    chunk, = ((l,r) for l,r in function.chunks(ea) if l <= ea <= r)
    result = []
    while (len(result) < 1) and ea < chunk[1]:
        # FIXME: it's probably not good to just scan for a call
        if not instruction(ea).startswith('call '):
            ea = next(ea)
            continue
        result = cxdown(ea)

    if len(result) != 1:
        raise ValueError('Invalid code reference: %x %s'% (ea,repr(result)))
    fn, = result

    result = []
    for offset,name,size in function.getArguments(fn):
        left,_ = function.stackwindow(ea, offset+config.bits()/8)
        # FIXME: if left is not an assignment or a push, find last assignment
        result.append((name,left))

    result = ['%s=%s'%(name,_instruction.op_repr(ea,0)) for name,ea in result]
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
        res = idaapi.get_cmt(address, int(bool(repeatable)))
        dict = comment.toDict(res)
        name = idaapi.get_name(-1,address)
        dict.setdefault('name', name)
        if key is None:
            return dict
        return dict[key]

    def tag_write(address, key, value, repeatable=0):
        dict = tag_read(address, repeatable=repeatable)
        dict[key] = value
        res = comment.toString(dict)
        return idaapi.set_cmt(address, res, int(bool(repeatable)))

    def tag(ea, *args, **kwds):
        '''tag(ea, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''
        # if not in a function, it could be a global, so make the tag repeatable
        #   otherwise, use a non-repeatable comment
        ea = int(ea)
        func = function.byAddress(ea)
        kwds.setdefault('repeatable', True if func is None else False)

        if len(args) < 2:
            return tag_read(ea, *args, **kwds)

        key,value = args
        result = tag_write(ea, key, value, **kwds)

        # add tag-name to function's cache
        if func is not None and value is not None and key is not '__tags__':
            top = func.startEA
            tags = function.tags(ea)
            tags.add(key)
            tag_write(top, '__tags__', tags)

        return result

    """
    def select(*tags):
        '''yield function_ea,tagdict for each function that contains the specified tags'''

        everything = functions()
        if tags == ():
            for i,ea in enumerate(everything):
                res = function.tag(ea)
                if res: yield ea,res
            return

        tags = set(tags)
        for i,ea in enumerate(everything):
            res = dict((k,v) for k,v in function.tag(ea).iteritems() if k in tags)
            if res: yield ea,res
        return
    """

    # FIXME: this function can be made generic
    def select(*tags, **boolean):
        '''Fetch all instances of the specified tag located within function'''
        boolean = dict((k,set(v) if type(v) is tuple else set((v,))) for k,v in boolean.viewitems())
        if tags:
            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))

        if not boolean:
            for ea in functions():
                res = database.tag(ea)
                if res: yield ea, res
            return

        for ea in functions():
            res,d = {},function.tag(ea)

            Or = boolean.get('Or', set())
            res.update((k,v) for k,v in d.iteritems() if k in Or)

            And = boolean.get('And', set())
            if And:
                if And.intersection(d.viewkeys()) == And:
                    res.update((k,v) for k,v in d.iteritems() if k in And)
                else: continue
            if res: yield ea,res
        return

    """
    def selectcontents(*tags):
        '''yield each function that contains the requested tags in it's contents'''
        everything,tags = functions(),set(tags)
        for i,ea in enumerate(everything):
            t = function.tags(ea)
            #if tags.intersection(t) == tags:
            if tags.intersection(t):
                yield ea
            continue
        return
    """

    # FIXME: this function can be made generic
    def selectcontents(*tags, **boolean):
        '''Fetch all instances of the specified tag located within function'''
        boolean = dict((k,set(v) if type(v) is tuple else set((v,))) for k,v in boolean.viewitems())
        if tags:
            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))

        if not boolean:
            for ea in functions():
                res = function.tags(ea)
                if res: yield ea, res
            return

        for ea in functions():
            res,d = set(),function.tags(ea)

            Or = boolean.get('Or', set())
            res.update(Or.intersection(d))

            And = boolean.get('And', set())
            if And:
                if And.intersection(d) == And:
                    res.update(And)
                else: continue
            if res: yield ea,res
        return

def getImportModules():
    return [idaapi.get_import_module_name(i) for i in xrange(idaapi.get_import_module_qty())]
def getImports(modulename):
    idx = [x.lower() for x in getImportModules()].index(modulename.lower())
    result = []
    def fn(ea,name,ordinal):
        result.append((ea,(name,ordinal)))
        return True
    idaapi.enum_import_names(idx,fn)
    return result
def imports():
    """Iterator containing (address,(module,name,ordinal)) of imports in database"""
    for idx,module in ((i,idaapi.get_import_module_name(i)) for i in xrange(idaapi.get_import_module_qty())):
        result = []
        def fn(ea,name,ordinal):
            result.append( (ea,(name,ordinal)) )
            return True
        idaapi.enum_import_names(idx,fn)
        for ea,(name,ordinal) in result:
            yield ea,(module,name,ordinal)
        continue
    return

### register information.
class register(object):
    @classmethod
    def names(cls):
        return idaapi.ph_get_regnames()
    @classmethod
    def segments(cls):
        names = cls.names()
        return [names[i] for i in xrange(idaapi.ph_get_regFirstSreg(),idaapi.ph_get_regLastSreg()+1)]
    @classmethod
    def codesegment(cls):
        return cls.names()[idaapi.ph_get_regCodeSreg()]
    @classmethod
    def datasegment(cls):
        return cls.names()[idaapi.ph_get_regDataSreg()]
    @classmethod
    def segmentsize(cls):
        return idaapi.ph_get_segreg_size()

def getType(ea):
    module,F = idaapi,(idaapi.getFlags(ea)&idaapi.DT_TYPE)
    res, = itertools.islice((v for n,v in itertools.imap(lambda n:(n,getattr(module,n)),dir(module)) if n.startswith('FF_') and (F == v&0xffffffff)), 1)
    return res

def getSize(ea):
    return idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))

def getArrayLength(ea):
    sz,ele = idaapi.get_item_size(ea),getSize(ea)
    return sz // ele

def getStructId(ea):
    assert getType(ea) == idaapi.FF_STRU
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
    assert res, 'idaapi.get_opinfo returned %x at %x'% (res,ea)
    return ti.tid

