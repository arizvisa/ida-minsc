'''
database-context

generic tools for working in the context of the database
'''

import logging,os
import idc,idautils,idaapi
import instruction as _instruction,function,segment,structure,internal
import array,itertools,ctypes

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
    def compiler(cls):
        return cls.info.cc
    @classmethod
    def version(cls):
        return cls.info.version

    @classmethod
    def type(cls, typestr):
        lookup = {
            'char':'size_b',
            'short':'size_s',
            'int':'size_i',
            'long':'size_l',
            'longlong':'size_ll',
        }
        return getattr(cls.compiler, lookup.get(typestr.lower(),typestr) )

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

def prev(ea, count=1):
    '''return the previous address (instruction or data)'''
    return address.prev(ea, count=count)
def next(ea, count=1):
    '''return the next address (instruction or data)'''
    return address.next(ea, count=count)

def prevdata(ea, count=1):
    '''return previous address containing data referencing it'''
    return address.prevdata(ea, count=count)
def nextdata(ea, count=1):
    '''return next address containing data referencing it'''
    return address.nextdata(ea, count=count)
def prevcode(ea, count=1):
    '''return previous address containing code referencing it'''
    return address.prevcode(ea, count=count)
def nextcode(ea, count=1):
    '''return next address containing code referencing it'''
    return address.nextcode(ea, count=count)
def prevref(ea, count=1):
    '''return previous address containing any kind of reference to it'''
    return address.prevref(ea, count=count)
def nextref(ea, count=1):
    '''return next address containing any kind of reference to it'''
    return address.nextref(ea, count=count)
def prevreg(ea, *regs, **write):
    """return previous address containing an instruction that uses one of the requested registers ``regs`

    If the keyword ``write`` is True, then only return the address if it's writing to the register.
    """
    return address.prevreg(ea, *regs, **write)
def nextreg(ea, *regs, **write):
    """return next address containing an instruction that uses one of the requested registers ``regs`

    If the keyword ``write`` is True, then only return the address if it's writing to the register.
    """
    return address.nextreg(ea, *regs, **write)

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
        for idx,(n,comm) in enumerate(marks()):
            if n == ea:
                logging.warn("Replacing mark %d at %x : %r", idx, ea, comm)
            continue
    idc.MarkPosition(ea, 0, 0, 0, len(res)+1, message)

def iterate(start, end):
    '''Iterate through instruction/data boundaries within the specified range'''
    while start < end:
        yield start
        start = next(start)
    return

## searching by stuff
class search(object):
    @staticmethod
    def byBytes(ea, string, reverse=False):
        flags = idaapi.SEARCH_UP if reverse else idaapi.SEARCH_DOWN
        return idaapi.find_binary(ea, -1, ' '.join(str(ord(c)) for c in string), 10, idaapi.SEARCH_CASE | flags)

    @staticmethod
    def byRegex(ea, string, radix=16, reverse=False, sensitive=False):
        flags = idaapi.SEARCH_UP if reverse else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if sensitive else 0
        return idaapi.find_binary(ea, -1, string, radix, flags)

    @staticmethod
    def byName(ea, name):
        return idaapi.get_name_ea(ea is None and -1 or ea, name)

    @staticmethod
    def iterate(start, string, type=byBytes):
        ea = type(start, string)
        while ea != idaapi.BADADDR:
            yield ea
            ea = type(ea+1, string)
        return

    def __new__(cls, string):
        return cls.byName(here(), string)

def go(ea):
    '''slightly less typing for idc.Jump'''
    if not contains(ea):
        left,right=range()
        logging.warn("Jumping to an invalid location %x. (valid range is %x - %x)",ea,left,right)
    idaapi.jumpto(ea)
    return ea

def offset(ea):
    '''returns the offset of ea from the baseaddress'''
    return ea - baseaddress()
getoffset = offset
getOffset = getoffset
o = offset

def goof(ea):
    '''goes to the specified offset'''
    idaapi.jumpto(baseaddress()+ea)
    return ea
gotooffset = goof

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
        except (ValueError,Exception):
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

def comment(ea, comment=None, repeatable=0):
    if comment is None:
        return idaapi.get_cmt(ea, int(bool(repeatable)))
    return idaapi.set_cmt(ea, comment, int(bool(repeatable)))

def addEntry(name, ea, ordinal=None):
    '''addEntry(name, ea, index?) -> adds an entry point to the database'''
    return idaapi.add_entry(idaapi.get_entry_qty() if ordinal is None else ordinal, ea, name, 0)

try:
    ## tag data storage using a lisp-like syntax
    import store.query as query
    import store

    datastore = store.ida
    def tag(ea, *args, **kwds):
        '''tag(ea, key?, value?) -> fetches/stores a tag from specified address'''
        try:
            context = function.top(ea)

        except ValueError:
            context = None

        if len(args) == 0 and len(kwds) == 0:
            result = datastore.address(context).select(query.address(ea))
            try:
                result = result[address]
            except:
                result = {}
            return result

        elif len(args) == 1:
            key, = args
            result = datastore.address(context).select(query.address(ea), query.attribute(key))
            try:
                result = result[address][key]
            except:
                raise KeyError( (hex(ea),key) )
                result = None
            return result

        if len(args) > 0:
            key,value = args
            kwds.update({key:value})
        return datastore.address(context).address(ea).set(**kwds)

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
    ## tag data storage hack using magically syntaxed comments
    def tag_read(ea, key=None, repeatable=0):
        res = idaapi.get_cmt(ea, int(bool(repeatable)))
        dict = internal.comment.toDict(res)
        name = idaapi.get_name(-1,ea)
        if name is not None: dict.setdefault('name', name)
        if key is None:
            return dict
        return dict[key]

    def tag_write(ea, key, value, repeatable=0):
        dict = tag_read(ea, repeatable=repeatable)
        dict[key] = value
        res = internal.comment.toString(dict)
        return idaapi.set_cmt(ea, res, int(bool(repeatable)))

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
        boolean = dict((k,set(v) if v.__class__ is tuple else set((v,))) for k,v in boolean.viewitems())
        if tags:
            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))

        if not boolean:
            for ea in functions():
                res = tag(ea)
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
        boolean = dict((k,set(v) if v.__class__ is tuple else set((v,))) for k,v in boolean.viewitems())
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
class imports(object):
    def __new__(cls):
        return cls.iterate()

    # searching
    @classmethod
    def get(cls,ea):
        for addr,(module,name,ordinal) in cls.iterate():
            if addr == ea:
                return (module,name,ordinal)
            continue
        raise LookupError, 'Unable to determine import at address %x'% ea

    @classmethod
    def module(cls,ea):
        for addr,(module,_,_) in cls.iterate():
            if addr == ea:
                return module
            continue
        raise LookupError, 'Unable to determine import module name at address %x'% ea

    # specific parts of the import
    @classmethod
    def fullname(cls,ea):
        module,name,ordinal = cls.get(ea)
        return '{:s}!{:s}'.format(module, name or 'Ordinal%d'%ordinal)
    @classmethod
    def name(cls,ea):
        _,name,ordinal = cls.get(ea)
        return name or 'Ordinal%d'%ordinal
    @classmethod
    def ordinal(cls,ea):
        _,_,ordinal = cls.get(ea)
        return ordinal

    # iteration
    @staticmethod
    def modules():
        return [idaapi.get_import_module_name(i) for i in xrange(idaapi.get_import_module_qty())]

    @staticmethod
    def list(modulename):
        idx = [x.lower() for x in imports.modules()].index(modulename.lower())
        result = []
        def fn(ea,name,ordinal):
            result.append((ea,(name,ordinal)))
            return True
        idaapi.enum_import_names(idx,fn)
        return result

    @staticmethod
    def iterate():
        """Iterator containing (ea,(module,name,ordinal)) of imports in database"""
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

getImportModules = imports.modules
getImports = imports.list

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

### navigating the database according to the address reference type
class address(object):
    @staticmethod
    def walk(ea, next, match):
        while match(ea):
            ea = next(ea)
        return ea

    @staticmethod
    def prev(ea, count=1):
        res = idaapi.prev_head(ea,0)
        return address.prev(res, count-1) if count > 1 else res
    @staticmethod
    def next(ea, count=1):
        res = idaapi.next_head(ea, idaapi.BADADDR)
        return address.next(res, count-1) if count > 1 else res

    @staticmethod
    def prevdata(ea, count=1):
        res = address.walk(ea, address.prev, lambda n: len(xref.du(n)) == 0)
        return address.prevdata(res-1, count-1) if count > 1 else res
    @staticmethod
    def nextdata(ea, count=1):
        res = address.walk(ea, address.next, lambda n: len(xref.du(n)) == 0)
        return address.nextdata(res+1, count-1) if count > 1 else res

    @staticmethod
    def prevcode(ea, count=1):
        res = address.walk(ea, address.prev, lambda n: len(xref.cu(n)) == 0)
        return address.prevcode(res-1, count-1) if count > 1 else res
    @staticmethod
    def nextcode(ea, count=1):
        res = address.walk(ea, address.next, lambda n: len(xref.cu(n)) == 0)
        return address.nextcode(res+1, count-1) if count > 1 else res

    @staticmethod
    def prevref(ea, count=1):
        res = address.walk(ea, address.prev, lambda n: len(xref.u(n)) == 0)
        return address.prevref(res-1, count-1) if count > 1 else res
    @staticmethod
    def nextref(ea, count=1):
        res = address.walk(ea, address.next, lambda n: len(xref.u(n)) == 0)
        return address.nextref(res+1, count-1) if count > 1 else res

    @staticmethod
    def prevreg(ea, *regs, **kwds):
        count = kwds.get('count',1)
        write = kwds.get('write',False)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg_t.byName(r).related,itertools.imap(_instruction.reg_t.byName,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and ('w' in st if write else True):
                    return True
                if t == 'opt_phrase' and not write:
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        res = address.walk(ea, address.prev, lambda ea: not uses_register(ea, regs))
        return address.prevreg(res-1, *regs, count=count-1) if count > 1 else res
    @staticmethod
    def nextreg(ea, *regs, **kwds):
        count = kwds.get('count',1)
        write = kwds.get('write',False)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg_t.byName(r).related,itertools.imap(_instruction.reg_t.byName,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and ('w' in st if write else True):
                    return True
                if t == 'opt_phrase' and not write:
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        res = address.walk(ea, address.next, lambda ea: not uses_register(ea, regs))
        return address.nextreg(res+1, *regs, count=count-1) if count > 1 else res

    @staticmethod
    def prevstack(ea, delta):
        fn,sp = function.top(ea),function.getSpDelta(ea)
        return address.walk(ea, address.prev, lambda n: abs(function.getSpDelta(n) - sp) < delta)
    @staticmethod
    def nextstack(ea, delta):
        fn,sp = function.top(ea),function.getSpDelta(ea)
        return address.walk(ea, address.next, lambda n: abs(function.getSpDelta(n) - sp) < delta)

a = addr = address

class type(object):
    def __new__(cls, ea):
        module,F = idaapi,(idaapi.getFlags(ea)&idaapi.DT_TYPE)
        res, = itertools.islice((v for n,v in itertools.imap(lambda n:(n,getattr(module,n)),dir(module)) if n.startswith('FF_') and (F == v&0xffffffff)), 1)
        return res
    @staticmethod
    def isCode(ea):
        '''True if ea marked as code'''
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_CODE
    @staticmethod
    def isData(ea):
        '''True if ea marked as data'''
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_DATA
    @staticmethod
    def isUnknown(ea):
        '''True if ea marked unknown'''
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_UNK
    @staticmethod
    def isHead(ea):
        return idaapi.getFlags(ea)&idaapi.FF_DATA != 0
    @staticmethod
    def isTail(ea):
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_TAIL
    @staticmethod
    def isAlign(ea):
        return idaapi.isAlign(idaapi.getFlags(ea))

    class array(object):
        def __new__(cls, ea):
            """Return the values of the array at address ``ea``"""
            numerics = {
                idaapi.FF_BYTE : 'B',
                idaapi.FF_WORD : 'H',
                idaapi.FF_DWRD : 'L',
                idaapi.FF_QWRD : 'Q',
                idaapi.FF_FLOAT : 'f',
                idaapi.FF_DOUBLE : 'd',
            }
            strings = {
                1 : 'c',
                2 : 'u',
            }
            fl = idaapi.getFlags(ea)
            elesize = idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))
            if fl & idaapi.FF_ASCI == idaapi.FF_ASCI:
                t = strings[elesize]
            elif fl & idaapi.FF_STRU == idaapi.FF_STRU:
                t = type.structure.id(ea)
                raise TypeError, 'array : Unable to handle an array of structure type %x'% t
            else:
                ch = numerics[fl & idaapi.DT_TYPE]
                t = ch.lower() if idaapi.is_signed_data(fl) else ch
            res = array.array(t, read(ea, cls.size(ea)))
            if len(res) != cls.length(ea):
                logging.warn('array : Unexpected length : (%d != %d)', len(res), cls.length(ea))
            return res
            
        @staticmethod
        def element(ea):
            """Return the size of an element in the array at address ``ea``"""
            return idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))
        @staticmethod
        def length(ea):
            """Return the number of elements in the array at address ``ea``"""
            sz,ele = idaapi.get_item_size(ea),idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))
            return sz // ele
        @staticmethod
        def size(ea):
            """Return the size of the array at address ``ea``"""
            return idaapi.get_item_size(ea)

    class structure(object):
        def __new__(cls, ea):
            """Return the structure at address ``ea``"""
            return cls.get(ea)

        @staticmethod
        def id(ea):
            """Return the identifier of the structure at address ``ea``"""
            assert type(ea) == idaapi.FF_STRU, 'Specified IDA Type is not an FF_STRU(%x) : %x'% (idaapi.FF_STRU, type(ea))
            ti = idaapi.opinfo_t()
            res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
            assert res, 'idaapi.get_opinfo returned %x at %x'% (res,ea)
            return ti.tid

        @staticmethod
        def get(ea):
            st = structure.instance(type.structure.id(ea), offset=ea)
            typelookup = {
                (int,-1) : ctypes.c_int8, (int,1) : ctypes.c_uint8,
                (int,-2) : ctypes.c_int16, (int,2) : ctypes.c_uint16,
                (int,-4) : ctypes.c_int32, (int,4) : ctypes.c_uint32,
                (int,-8) : ctypes.c_int64, (int,8) : ctypes.c_uint64,
                (float,4) : ctypes.c_float, (float,8) : ctypes.c_double,
            }

            res = {}
            for m in st.members:
                val = read(m.offset, m.size)
                try:
                    ct = typelookup[m.type]
                except KeyError:
                    ty,sz = m.type
                    if isinstance(ty, list):
                        t = typelookup[tuple(ty)]
                        ct = t*sz
                    elif isinstance(ty, (chr,str)):
                        ct = ctypes.c_char*sz
                    else:
                        ct = None
                finally:
                    res[m.name] = val if any(_ is None for _ in (ct,val)) else ctypes.cast(ctypes.pointer(ctypes.c_buffer(val)),ctypes.POINTER(ct)).contents
            return res

        @staticmethod
        def apply(ea, st):
            """Apply the structure ``st`` to the address at ``ea``"""
            ti = idaapi.opinfo_t()
            res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
            ti.tid = st.id
            return idaapi.set_opinfo(ea, 0, idaapi.getFlags(ea) | idaapi.struflag(), ti)
            
t = type

## information about a given address
isCode = type.isCode
isData = type.isData
isUnknown = type.isUnknown
isHead = type.isHead
isTail = type.isTail
isAlign = type.isAlign
getType = type

# arrays
getSize = type.array.element
getArrayLength = type.array.length

# structures
getStructureId = type.structure.id

class xref(object):
    @staticmethod
    def iterate(ea, start, next):
        ea = ea if (idaapi.getFlags(ea)&idaapi.FF_DATA) else idaapi.prev_head(ea,0)

        addr = start(ea)
        while addr != idaapi.BADADDR:
            yield addr
            addr = next(ea, addr)
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
        '''All locations that reference specified address'''
        return list(set(xref.data_up(ea) + xref.code_up(ea)))
    @staticmethod
    def down(ea):
        '''All locations that are referenced by the specified address'''
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
x = xref

drefs = xref.data
crefs = xref.code

dxdown = xref.data_down
dxup = xref.data_up

cxdown = xref.code_down
cxup = xref.code_up

up = xref.up
down = xref.down

## functions
#demangle = internal.declaration.demangle

