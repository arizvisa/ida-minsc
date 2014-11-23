'''
database-context

generic tools for working in the context of the database
'''

import logging,os
import idc,idautils,idaapi
import instruction as _instruction,function,segment,base._declaration as _declaration
import array,itertools

## properties
def h():
    '''slightly less typing for idc.ScreenEA()'''
    return idaapi.get_screen_ea()

here = h    # alias

def filename():
    '''return the filename that the database was built from'''
    return idaapi.get_root_filename()
def idb():
    '''Return the full path to the ida database'''
    return idaapi.cvar.database_idb.replace(os.sep, '/')
def module():
    '''return the module name as per the windows loader'''
    return os.path.splitext(os.path.split(filename())[1])[0]
def path():
    '''return the full path to the directory containing the database'''
    return os.path.split(idb())[0]

def baseaddress():
    '''returns the baseaddress of the database'''
    return idaapi.get_imagebase()
base=baseaddress

def range():
    '''Return the total address range of the database'''
    return config.bounds()

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

def functions():
    '''Returns a list of all the functions in the current database (using idautils)'''
    min,max = range()
    return list(idautils.Functions(min, max))

def segments():
    '''Returns a list of all segments in the current database'''
    return [segment.byName(s).startEA for s in segment.list()]

## information about a given address
def isCode(ea):
    '''True if ea marked as code'''
    return idaapi.getFlags(address)&idaapi.MS_CLS == idaapi.FF_CODE
def isData(ea):
    '''True if ea marked as data'''
    return idaapi.getFlags(address)&idaapi.MS_CLS == idaapi.FF_DATA
def isUnknown(ea):
    '''True if ea marked unknown'''
    return idaapi.getFlags(address)&idaapi.MS_CLS == idaapi.FF_UNK
def isHead(ea):
    return idaapi.getFlags(address)&idaapi.FF_DATA != 0
def isTail(ea):
    return idaapi.getFlags(address)&idaapi.MS_CLS == idaapi.FF_TAIL

def getType(ea):
    module,F = idaapi,(idaapi.getFlags(ea)&idaapi.DT_TYPE)
    res, = itertools.islice((v for n,v in itertools.imap(lambda n:(n,getattr(module,n)),dir(module)) if n.startswith('FF_') and (F == v&0xffffffff)), 1)
    return res
def getSize(ea):
    return idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))
def getArrayLength(ea):
    sz,ele = idaapi.get_item_size(ea),getSize(ea)
    return sz // ele
def getStructureId(ea):
    assert getType(ea) == idaapi.FF_STRU
    ti = idaapi.opinfo_t()
    res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
    assert res, 'idaapi.get_opinfo returned %x at %x'% (res,ea)
    return ti.tid

def prev(ea):
    '''return the previous address (instruction or data)'''
    return address.prev(ea)
def next(ea):
    '''return the next address (instruction or data)'''
    return address.next(ea)

def prevdata(ea):
    '''return previous address containing data referencing it'''
    return address.prevdata(ea)
def nextdata(ea):
    '''return next address containing data referencing it'''
    return address.nextdata(ea)
def prevcode(ea):
    '''return previous address containing code referencing it'''
    return address.prevcode(ea)
def nextcode(ea):
    '''return next address containing code referencing it'''
    return address.nextcode(ea)
def prevref(ea):
    '''return previous address containing any kind of reference to it'''
    return address.prevref(ea)
def nextref(ea):
    '''return next address containing any kind of reference to it'''
    return address.nextref(ea)

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

def drefs(ea, descend=False):
    return xref.data(ea, descend)
def crefs(ea, descend=False):
    return xref.code(ea, descend)

def dxdown(ea):
    return xref.data_down(ea)
def dxup(ea):
    return xref.data_up(ea)

def cxdown(ea):
    return xref.code_down(ea)
def cxup(ea):
    return xref.code_up(ea)

def up(ea):
    '''All locations that reference specified address'''
    return xref.up(ea)
def down(ea):
    '''All locations that are referenced by the specified address'''
    return xref.down(ea)

## functions
demangle = _declaration.demangle

def getblock(start, end):
    if start > end:
        start,end=end,start
    length = end-start

    if not contains(start):
        raise ValueError('Address %x is not in database'%start)
    return idaapi.get_many_bytes(start, length)
getBlock = getblock

def read(ea, size):
    return idaapi.get_many_bytes(ea, size)
def write(ea, data, original=False):
    return idaapi.patch_many_bytes(ea, data) if original else idaapi.put_many_bytes(ea, data)
def marks():
    '''returns all the known marked positions in an .idb'''
    index = 1
    while True:
        ea = idc.GetMarkedPos(index)
        if ea == idaapi.BADADDR:
            break
        comment = idc.GetMarkComment(index)
        yield ea, comment
        index += 1
    return

def mark(ea, message):
    # FIXME: give a warning if we're replacing a mark at the given ea
    res = set((n for n,_ in marks()))
    if ea in res:
        idx,comm = (comm for i,(n,comm) in enumerate(marks()) if n == ea)
        logging.warn("Replacing mark %d at %x : %r", idx, ea, comm)
    idc.MarkPosition(ea, 0, 0, 0, len(res)+1, message)

def iterate(start, end):
    '''Iterate through instruction/data boundaries within the specified range'''
    while start < end:
        yield start
        start = next(start)
    return

## searching by stuff
def byBytes(ea, string, reverse=False):
    flags = idaapi.SEARCH_UP if reverse else idaapi.SEARCH_DOWN
    return idaapi.find_binary(ea, -1, ' '.join(str(ord(c)) for c in string), 10, idaapi.SEARCH_CASE | flags)

def byRegex(ea, string, radix=16, reverse=False, sensitive=False):
    flags = idaapi.SEARCH_UP if reverse else idaapi.SEARCH_DOWN
    flags |= idaapi.SEARCH_CASE if sensitive else 0
    return idaapi.find_binary(ea, -1, string, radix, flags)

def iterate_search(start, string, type=byBytes):
    ea = type(start, string)
    while ea != idaapi.BADADDR:
        yield ea
        ea = type(ea+1, string)
    return

def go(ea):
    '''slightly less typing for idc.Jump'''
    if not contains(ea):
        left,right=range()
        logging.warn("Jumping to an invalid location %x. (valid range is %x - %x)",ea,left,right)
    idaapi.jumpto(ea)
    return ea

def getoffset(ea):
    '''returns the offset of ea from the baseaddress'''
    return ea - baseaddress()
getOffset = getoffset

def byName(name):
    return idaapi.get_name_ea(-1, name)
search = byName

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

        res = idaapi.set_name(ea, string, flags)
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

        if idaapi.ua_mnem(ea).startswith('call'):      # FIXME: heh. ;)
            continue

        if idaapi.ua_mnem(ea).startswith('ret'):       #   whee
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

def contains(ea):
    l,r = config.bounds()
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

def addEntry(name, ea, ordinal=None):
    '''addEntry(name, ea, index?) -> adds an entry point to the database'''
    return idaapi.add_entry(idaapi.get_entry_qty() if ordinal is None else ordinal, ea, name, 0)

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
    return '%s(%s)'%(_declaration.demangle(function.name(function.byAddress(fn))), ','.join(result))

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
            result = datastore.address(context).select(query.address(address))
            try:
                result = result[address]
            except:
                result = {}
            return result

        elif len(args) == 1:
            key, = args
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
    import base._comment as _comment

    def tag_read(address, key=None, repeatable=0):
        res = idaapi.get_cmt(address, int(bool(repeatable)))
        dict = _comment.toDict(res)
        name = idaapi.get_name(-1,address)
        dict.setdefault('name', name)
        if key is None:
            return dict
        return dict[key]

    def tag_write(address, key, value, repeatable=0):
        dict = tag_read(address, repeatable=repeatable)
        dict[key] = value
        res = _comment.toString(dict)
        return idaapi.set_cmt(address, res, int(bool(repeatable)))

    def tag(ea, *args, **kwds):
        '''tag(ea, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''
        # if not in a function, it could be a global, so make the tag repeatable
        #   otherwise, use a non-repeatable comment
        ea = int(ea)
        try:
            func = function.byAddress(ea)
        except Exception:
            func = None
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

    def select(*tags, **boolean):
        '''Fetch all the functions containing the specified tags within it's declaration'''
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

    def selectcontents(*tags, **boolean):
        '''Fetch all the functions containing the specified tags within it's contents'''
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

if False:
    def select_equal(ea, **matches):
        for ea,res in select(ea, And=matches.keys()):
            if all(k in res and matches[k] == res[k] for k in matches.items()):
                yield ea,res
            continue
        return
            
    def selectcontents_equal(ea, **matches):
        for ea,res in selectcontents(ea, And=matches.keys()):
            if all(k in res and matches[k] == res[k] for k in matches.items()):
                yield ea,res
            continue
        return

## imports
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

### register information
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

class address(object):
    @staticmethod
    def walk(ea, next, match):
        while match(ea):
            ea = next(ea)
        return ea

    @staticmethod
    def prev(ea):
        return idaapi.prev_head(ea, 0)
    @staticmethod
    def next(ea):
        return idaapi.next_head(ea, idaapi.BADADDR)

    @staticmethod
    def prevdata(ea):
        return address.walk(ea, address.prev, xref.du)
    @staticmethod
    def nextdata(ea):
        return address.walk(ea, address.next, xref.du)

    @staticmethod
    def prevcode(ea):
        return address.walk(ea, address.prev, xref.cu)
    @staticmethod
    def nextcode(ea):
        return address.walk(ea, address.next, xref.cu)

    @staticmethod
    def prevref(ea):
        return address.walk(ea, address.prev, xref.u)
    @staticmethod
    def nextref(ea):
        return address.walk(ea, address.next, xref.u)

class xref(object):
    @staticmethod
    def iterate(address, start, next):
        ea = address if (idaapi.getFlags(address)&idaapi.FF_DATA) else idaapi.prev_head(address,0)
        address = start(ea)
        while address != idaapi.BADADDR:
            yield address
            address = next(ea, address)
        return

    @staticmethod
    def code(ea, descend=False):
        if descend:
            start,next = idaapi.get_first_cref_from, idaapi.get_next_cref_from
        else:
            start,next = idaapi.get_first_cref_to, idaapi.get_next_cref_to
        for addr in xref.iterate(ea, start, next):
            yield addr
        return
    c=code

    @staticmethod
    def data(ea, descend=False):
        if descend:
            start,next = idaapi.get_first_dref_from, idaapi.get_next_dref_from
        else:
            start,next = idaapi.get_first_dref_to, idaapi.get_next_dref_to
        for addr in xref.iterate(ea, start, next):
            yield addr
        return
    d=data

    @staticmethod
    def data_down(ea):
        return list(xref.data(ea, True))
    @staticmethod
    def data_up(ea):
        return list(xref.data(ea, False))
    dd,du=data_down,data_up
    @staticmethod
    def code_down(ea):
        result = set(xref.code(ea, True))
        result.discard(address.next(ea))
        return list(result)
    @staticmethod
    def code_up(ea):
        result = set(xref.code(ea, False))
        result.discard(address.prev(ea))
        return list(result)
    cd,cu=code_down,code_up

    @staticmethod
    def up(ea):
        return list(set(xref.data_up(ea) + xref.code_up(ea)))
    @staticmethod
    def down(ea):
        return list(set(xref.data_down(ea) + xref.code_down(ea)))
    u,d=up,down

    @staticmethod
    def add_code(ea, target, isCall=False):
        if abs(target-ea) > 2**(config.bits()/2):
            flowtype = idaapi.fl_CF if isCall else idaapi.fl_JF
        else:
            flowtype = idaapi.fl_CN if isCall else idaapi.fl_JN
        idaapi.add_cref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.code_down(ea)
    @staticmethod
    def add_data(ea, target, write=False):
        flowtype = idaapi.dr_W if write else idaapi.dr_R
        idaapi.add_dref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.data_down(ea)
    @staticmethod
    def del_code(ea, target=None):
        if target is None:
            [ idaapi.del_cref(ea, target, 0) for target in xref.code_down(ea) ]
            return False if len(xref.code_down(ea)) > 0 else True
        idaapi.del_cref(ea, target, 0)
        return target not in xref.code_down(ea)
    @staticmethod
    def del_data(ea, target=None):
        if target is None:
            [ idaapi.del_dref(ea, target) for target in xref.data_down(ea) ]
            return False if len(xref.data_down(ea)) > 0 else True
        idaapi.del_dref(ea, target)
        return target not in xref.data_down(ea)
    @staticmethod
    def clear(ea):
        return all((res is True) for res in (xref.del_code(ea),xref.del_data(ea)))

