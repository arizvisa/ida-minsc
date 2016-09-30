'''
database-context

generic tools for working in the context of the database
'''

import __builtin__,logging,os
import functools,itertools,operator
import math,types,array
import six,fnmatch,re,ctypes

import function,segment,structure,ui,internal
import instruction as _instruction
from internal import utils,interface

import idaapi

## properties
def h():
    '''Return the current address.'''
    return ui.current.address()
here = utils.alias(h)

def filename():
    '''Returns the filename that the database was built from.'''
    return idaapi.get_root_filename()
def idb():
    '''Return the full path to the ida database.'''
    return idaapi.cvar.database_idb.replace(os.sep, '/')
def module():
    '''Return the module name as per the windows loader.'''
    return os.path.splitext(os.path.split(filename())[1])[0]
def path():
    '''Return the full path to the directory containing the database.'''
    return os.path.split(idb())[0]

def baseaddress():
    '''Returns the baseaddress of the database.'''
    return idaapi.get_imagebase()
base = utils.alias(baseaddress)

def range():
    '''Return the total address range of the database.'''
    return config.bounds()

@utils.multicase()
def within():
    '''Should always return True.'''
    return within(ui.current.address())
@utils.multicase(ea=six.integer_types)
def within(ea):
    '''Returns True if address ``ea`` is within the bounds of the database.'''
    l, r = config.bounds()
    return l <= ea < r
contains = utils.alias(within)

def top():
    return config.bounds()[0]
def bottom():
    return config.bounds()[1]

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
        '''Return number of bits of the database.'''
        if cls.info.is_64bit():
            return 64
        elif cls.info.is_32bit():
            return 32
        raise ValueError("{:s}.{:s}.bits : Unknown bit size.".format(__name__, cls.__name__))

    @classmethod
    def processor(cls):
        '''Return processor name used by the database.'''
        return cls.info.procName

    @classmethod
    def graphview(cls):
        '''Returns True if the user is currently using graph view.'''
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
    '''Returns a list of all the functions in the current database (ripped from idautils).'''
    left,right = range()

    # find first function chunk
    ch = idaapi.get_fchunk(left) or idaapi.get_next_fchunk(left)
    while ch and ch.startEA < right and (ch.flags & idaapi.FUNC_TAIL) != 0:
        ch = idaapi.get_next_fchunk(ch.startEA)

    # iterate through the rest of the functions in the database
    result = []
    while ch and ch.startEA < right:
        result.append(ch.startEA)
        ch = idaapi.get_next_func(ch.startEA)
    return result

def segments():
    '''Returns a list of all segments in the current database.'''
    return [segment.by_name(s).startEA for s in segment.list()]

@utils.multicase()
def decode():
    '''Decode the instruction at the current address.'''
    return decode(ui.current.address())
@utils.multicase(ea=six.integer_types)
def decode(ea):
    '''Decode the instruction at the address ``ea``.'''
    return _instruction.decode(interface.address.inside(ea))

@utils.multicase()
def instruction():
    '''Return the instruction at the current address.'''
    return instruction(ui.current.address())
@utils.multicase(ea=six.integer_types)
def instruction(ea):
    '''Return the instruction at the specified address ``ea``.'''
    insn = idaapi.generate_disasm_line(interface.address.inside(ea))
    unformatted = idaapi.tag_remove(insn)
    nocomment = unformatted[:unformatted.rfind(';')]
    return reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')

@utils.multicase()
def disasm(**options):
    '''Disassemble the instructions at the current address.'''
    return disasm(ui.current.address(), **options)
@utils.multicase(ea=six.integer_types)
def disasm(ea, **options):
    """Disassemble the instructions at the address ``ea``.
    If the integer ``count`` is specified, then return ``count`` number of instructions.
    If the bool ``comments`` is True, then return the comments for each instruction as well.
    """
    ea = interface.address.inside(ea)

    res,count = [], options.get('count',1)
    while count > 0:
        insn = idaapi.generate_disasm_line(ea)
        unformatted = idaapi.tag_remove(insn)
        nocomment = unformatted[:unformatted.rfind(';')] if ';' in unformatted and options.get('comments',False) else unformatted
        res.append('{:x}: {:s}'.format(ea, reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')) )
        ea = next(ea)
        count -= 1
    return '\n'.join(res)

def block(start, end):
    '''Return the block of bytes from address ``start`` to ``end``.'''
    if start > end:
        start,end=end,start
    start, end = interface.address.within(start, end)
    length = end-start
    return read(start, length)
getBlock = getblock = get_block = read_block = utils.alias(block)

@utils.multicase(size=six.integer_types)
def read(size):
    '''Return ``size`` number of bytes from the current address.'''
    return read(ui.current.address(), size)
@utils.multicase(ea=six.integer_types, size=six.integer_types)
def read(ea, size):
    '''Return ``size`` number of bytes from address ``ea``.'''
    start, end = interface.address.within(ea, ea+size)
    return idaapi.get_many_bytes(ea, end-start)

@utils.multicase(data=bytes)
def write(data, **original):
    '''Modify the database at the current address with the bytes ``data``.'''
    return write(ui.current.address(), data, **original)
@utils.multicase(ea=six.integer_types, data=bytes)
def write(ea, data, **original):
    """Modify the database at address ``ea`` with the bytes ``data``
    If the bool ``original`` is specified, then modify what IDA considers the original bytes.
    """
    ea, _ = interface.address.within(ea, ea + len(data))
    return idaapi.patch_many_bytes(ea, data) if original.get('original', False) else idaapi.put_many_bytes(ea, data)

def iterate(start, end, step=None):
    '''Iterate through all the instruction and data boundaries from address ``start`` to ``end``.'''
    step = step or (address.prev if start > end else address.next)
    start, end = __builtin__.map(interface.address.head, (start, end))
    op = operator.gt if start > end else operator.lt
    while start != idaapi.BADADDR and op(start,end):
        yield start
        start = step(start)
    yield end

class names(object):
    __matcher__ = utils.matcher()
    __matcher__.mapping('address', idaapi.get_nlist_ea)
    __matcher__.mapping('ea', idaapi.get_nlist_ea)
    __matcher__.boolean('name', operator.eq, idaapi.get_nlist_name)
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_nlist_name)
    __matcher__.boolean('regex', re.search, idaapi.get_nlist_name)
    __matcher__.predicate('predicate', idaapi.get_nlist_ea)
    __matcher__.predicate('pred', idaapi.get_nlist_ea)
    __matcher__.attribute('index')

    def __new__(cls):
        for index in xrange(idaapi.get_nlist_size()):
            res = zip((idaapi.get_nlist_ea,idaapi.get_nlist_name), (index,)*2)
            yield tuple(f(n) for f,n in res)
        return

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        return cls.list(like=string)

    @utils.multicase()
    @classmethod
    def list(cls, **type):
        if not type: type = {'predicate':lambda n: True}
        result = __builtin__.range(idaapi.get_nlist_size())
        for k,v in type.iteritems():
            res = __builtin__.list(cls.__matcher__.match(k, v, result))
            maxindex = max(res)
            maxaddr = max(__builtin__.map(idaapi.get_nlist_ea, res) or [idaapi.BADADDR])
            cindex = math.ceil(math.log(maxindex)/math.log(10))
            caddr = math.floor(math.log(maxaddr)/math.log(16))

            for index in res:
                print '[{:>{:d}d}] {:0{:d}x} {:s}'.format(index, int(cindex), idaapi.get_nlist_ea(index), int(caddr), idaapi.get_nlist_name(index))
            continue
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        iterable = xrange(idaapi.get_nlist_size())

        searchstring = ', '.join('{:s}={!r}'.format(k,v) for k,v in type.iteritems())
        if len(type) != 1:
            raise LookupError('{:s}.{:s}.search({:s}) : More than one search type specified.', __name__, cls.__name__, searchstring)
        k, v = __builtin__.next(type.iteritems())
        res = __builtin__.map(None, cls.__matcher__.match(k, v, iterable))
        if len(res) > 1:
            __builtin__.map(logging.info, (('[{:d}] {:s}'.format(idaapi.get_struc_idx(x.id), st.name)) for i,st in enumerate(res)))
            logging.warn('{:s}.{:s}.search({:s}) : Found {:d} matching results, returning the first one.'.format(__name__, cls.__name__, len(res)))
        res = __builtin__.next(iter(res), None)
        if res is None:
            raise LookupError('{:s}.{:s}.search({:s}) : Found 0 matching results.', __name__, cls.__name__, searchstring)
        return idaapi.get_nlist_ea(res), idaapi.get_nlist_name(res)

## searching by stuff
# FIXME: bounds-check all these addresses
class search(object):
    @utils.multicase(string=bytes)
    @staticmethod
    def by_bytes(string, **direction):
        '''Search through the database at the current address for the bytes specified by ``string``.'''
        return search.by_bytes(ui.current.address(), string, **direction)
    @utils.multicase(ea=six.integer_types, string=bytes, reverse=bool)
    @staticmethod
    def by_bytes(ea, string, **direction):
        """Search through the database at address ``ea`` for the bytes specified by ``string``.
        If ``reverse`` is specified as a bool, then search backwards from the given address.
        """
        flags = idaapi.SEARCH_UP if direction.get('reverse', False) else idaapi.SEARCH_DOWN
        return idaapi.find_binary(ea, -1, ' '.join(str(ord(c)) for c in string), 10, idaapi.SEARCH_CASE | flags)
    byBytes = by_bytes

    @utils.multicase(string=basestring)
    @staticmethod
    def by_regex(string, **options):
        '''Search through the database at the current address for the regex matched by ``string``.'''
        return search.by_regex(ui.current.address(), string, **options)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @staticmethod
    def by_regex(ea, string, **options):
        """Search the database at address ``ea`` for the regex matched by ``string``.
        If ``reverse`` is specified as a bool, then search backwards from the given address.
        If ``sensitive`` is specified as bool, then perform a case-sensitive search.
        """
        flags = idaapi.SEARCH_UP if options.get('reverse',False) else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive',False) else 0
        return idaapi.find_binary(ea, -1, string, options.get('radix',16), flags)
    byRegex = by_regex

    @utils.multicase(name=basestring)
    @staticmethod
    def by_name(name):
        '''Search through the database at the current address for the symbol ``name``.'''
        return idaapi.get_name_ea(-1, name)
    @utils.multicase(ea=six.integer_types, name=basestring)
    @staticmethod
    def by_name(ea, name):
        '''Search through the database at address ``ea`` for the symbol ``name``.'''
        return idaapi.get_name_ea(ea, name)
    byName = utils.alias(by_name, 'search')

    @utils.multicase(string=basestring)
    @staticmethod
    def iterate(string):
        '''Iterate through all results that match the bytes ``string`` starting at the current address.'''
        return search.iterate(ui.current.address(), string, search.by_bytes)
    @utils.multicase(start=six.integer_types, string=basestring)
    @staticmethod
    def iterate(start, string):
        '''Iterate through all results that match the bytes ``string`` starting at address ``start``.'''
        return search.iterate(start, string, search.by_bytes)
    @utils.multicase(start=six.integer_types, string=basestring)
    @staticmethod
    def iterate(start, string, type):
        '''Iterate through all searches matched by the function ``type`` and ``string`` starting at address ``start``.'''
        ea = type(start, string)
        while ea != idaapi.BADADDR:
            yield ea
            ea = type(ea+1, string)
        return

    def __new__(cls, string):
        return cls.by_name(here(), string)

byName = by_name = utils.alias(search.by_name, 'search')

def go(ea):
    '''Jump to the specified address at ``ea``.'''
    if isinstance(ea, basestring):
        ea = search.by_name(None, ea)
    idaapi.jumpto(interface.address.inside(ea))
    return ea

# returns the offset of ea from the baseaddress
@utils.multicase()
def offset():
    '''Return the current address converted to an offset from the base-address of the database.'''
    return offset(ui.current.address())
@utils.multicase(ea=six.integer_types)
def offset(ea):
    '''Return the address ``ea`` converted to an offset from the base-address of the database.'''
    return interface.address.inside(ea) - baseaddress()

getoffset = getOffset = o = utils.alias(offset)

def translate(offset):
    '''Translate the specified ``offset`` to an address in the database.'''
    return baseaddress()+offset
coof = convert_offset = convertOffset = utils.alias(translate)

def goof(offset):
    '''Jump to the specified ``offset`` within the database.'''
    res = ui.current.address()-baseaddress()
    ea = coof(offset)
    idaapi.jumpto(interface.address.inside(ea))
    return res
gotooffset = goto_offset = utils.alias(goof)

@utils.multicase()
def get_name():
    '''Return the name defined at the current address.'''
    return get_name(ui.current.address())
@utils.multicase(ea=six.integer_types)
def get_name(ea):
    '''Return the name defined at the address ``ea``.'''
    ea = interface.address.inside(ea)

    # if get_true_name is going to return the function's name instead of a real one
    # then consider the address itself as being unnamed.
    fn = idaapi.get_func(ea)
    if fn and fn.startEA == ea:
        return None

    # now return the name at the specified address
    aname = idaapi.get_true_name(ea) or idaapi.get_true_name(ea, ea)

    # ..or not
    return aname or None

@utils.multicase(none=types.NoneType)
def set_name(none, **listed):
    '''Remove the name at the current address.'''
    return set_name(ui.current.address(), '', **listed)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def set_name(ea, none, **listed):
    '''Remove the name defined at the address ``ea``.'''
    return set_name(ea, '', **listed)
@utils.multicase(string=basestring)
def set_name(string, **listed):
    '''Rename the current address to ``string``.'''
    return set_name(ui.current.address(), string, **listed)
@utils.multicase(ea=six.integer_types, string=basestring)
def set_name(ea, string, **listed):
    """Rename the address specified by ``ea`` to ``string``.
    If ``listed`` is True, then specify that the name is added to the Names list.
    """

    ea = interface.address.inside(ea)
    if idaapi.SN_NOCHECK != 0:
        raise AssertionError( '{:s}.name : idaapi.SN_NOCHECK != 0'.format(__name__))
    SN_NOLIST = idaapi.SN_NOLIST
    SN_LOCAL = idaapi.SN_LOCAL
    SN_NON_PUBLIC = idaapi.SN_NON_PUBLIC

    # FIXME: what's this for?
    if idaapi.has_any_name(idaapi.getFlags(ea)):
        pass

    flags = idaapi.SN_NON_AUTO
    flags |= 0 if idaapi.is_in_nlist(ea) else idaapi.SN_NOLIST
    flags |= idaapi.SN_WEAK if idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK
    flags |= idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC

    # If the bool ``listed`` is True, then ensure that this name is added to the name list.
    flags = (flags & ~idaapi.SN_NOLIST) if listed.get('listed', False) else (flags | idaapi.SN_NOLIST)

    try:
        function.top(ea)
        flags |= idaapi.SN_LOCAL
    except Exception:
        flags &= ~idaapi.SN_LOCAL

    try:
        # check if we're a label of some kind
        f = idaapi.getFlags(ea)
        if idaapi.has_dummy_name(f) or idaapi.has_user_name(f):
            # that is referenced by an array with a correctly sized pointer inside it
            (r,sidata), = ((r,type.array(r)) for r in xref.data_up(ea))
            if config.bits() == sidata.itemsize*8 and ea in sidata:
                # which we check to see if it's a switch_info_t
                si, = (idaapi.get_switch_info_ex(r) for r in xref.data_up(r))
                if si is not None:
                    # because it's name has it's local flag cleared
                    flags ^= idaapi.SN_LOCAL
    except: pass

    res = idaapi.validate_name2(buffer(string)[:])
    if string and string != res:
        logging.warn('{:s}.set_name : Stripping invalid chars from name {!r} at {:x}. : {!r}'.format(__name__, string, ea, res))
        string = res

    res,ok = get_name(ea),idaapi.set_name(ea, string or "", flags)

    if not ok:
        raise AssertionError('{:s}.set_name : Unable to call idaapi.set_name(0x{:x}, {!r}, 0x{:x})'.format(__name__, ea, string, flags))
    return res

@utils.multicase()
def name():
    '''Returns the name at the current address.'''
    return get_name(ui.current.address())
@utils.multicase(ea=six.integer_types)
def name(ea):
    '''Returns the name at the address ``ea``.'''
    return get_name(ea) or None
@utils.multicase(string=basestring)
def name(string, *suffix):
    '''Renames the current address to ``string``.'''
    return name(ui.current.address(), string, *suffix)
@utils.multicase(none=types.NoneType)
def name(none):
    '''Removes the name at the current address.'''
    return set_name(ui.current.address(), None)
@utils.multicase(ea=six.integer_types, string=basestring)
def name(ea, string, *suffix):
    '''Renames the address ``ea`` to ``string``.'''
    res = (string,) + suffix
    return set_name(ea, interface.tuplename(*res))
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def name(ea, none):
    '''Removes the name at address ``ea``.'''
    return set_name(ea, None)

def blocks(start, end):
    '''Returns each block between the addresses ``start`` and ``end``.'''
    block, _ = start, end = interface.address.head(start), address.tail(end)+1
    for ea in iterate(start, end):
        nextea = next(ea)

        if _instruction.is_call(ea):
            continue

        if _instruction.is_return(ea):
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

# FIXME: The idaapi.is_basic_block_end api has got to be faster than doing it
#        with ida's xrefs in python..
if False:
    def blocks(start, end):
        '''Returns each block between the specified range of instructions.'''
        start, end = interface.address.head(start), address.tail(end)+1
        block = start
        for ea in iterate(start, end):
            nextea = next(ea)
            idaapi.decode_insn(ea)
            # XXX: for some reason idaapi.is_basic_block_end(...)
            #      occasionally includes some stray 'call' instructions.
            if idaapi.is_basic_block_end(ea):
                yield block,nextea
                block = nextea
            continue
        return

def map(l, *args, **kwds):
    """Execute provided callback on all functions in database. Synonymous to map(l,db.functions()).
    ``l`` is defined as a function(address, *args, **kwds).
    Any other arguments are passed to ``l`` unmodified.
    """
    i,x = 0,here()
    current = x
    all = functions()
    result = []
    try:
        for i,x in enumerate(all):
            go(x)
            print("{:x}: processing # {:d} of {:d} : {:s}".format(x, i+1, len(all), name(x)))
            result.append( l(x, *args, **kwds) )
    except KeyboardInterrupt:
        print("{:x}: terminated at # {:d} of {:d} : {:s}".format(x, i+1, len(all), name(x)))
    go(current)
    return result

@utils.multicase()
def erase():
    '''Remove all the defined tags at the current address.'''
    return erase(ui.current.address())
@utils.multicase(ea=six.integer_types)
def erase(ea):
    '''Remove all the defined tags at address ``ea``.'''
    ea = interface.address.inside(ea)
    for k in tag(ea): tag(ea, k, None)
    color(ea, None)

@utils.multicase()
def get_color():
    '''Return the rgb color at the current address.'''
    return get_color(ui.current.address())
@utils.multicase(ea=six.integer_types)
def get_color(ea):
    '''Return the rgb color at the address ``ea``.'''
    res = idaapi.get_item_color(interface.address.inside(ea))
    b,r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == 0xffffffff else (r<<16)|(res&0x00ff00)|b
@utils.multicase(none=types.NoneType)
def set_color(none):
    '''Remove the color at the current address.'''
    return set_color(ui.current.address(), None)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def set_color(ea, none):
    '''Remove the color at address ``ea``.'''
    return idaapi.set_item_color(interface.address.inside(ea), 0xffffffff)
@utils.multicase(ea=six.integer_types, rgb=int)
def set_color(ea, rgb):
    '''Set the color at address ``ea`` to ``rgb``.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    return idaapi.set_item_color(interface.address.inside(ea), (b<<16)|(rgb&0x00ff00)|r)

@utils.multicase()
def color():
    '''Return the rgb color at the current address.'''
    return get_color(ui.current.address())
@utils.multicase(none=types.NoneType)
def color(none):
    '''Remove the color from the current address.'''
    return set_color(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def color(ea):
    '''Return the color at the address ``ea``.'''
    return get_color(ea)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def color(ea, none):
    '''Remove the color at the address ``ea``.'''
    return set_color(ea, None)
@utils.multicase(ea=six.integer_types, rgb=int)
def color(ea, rgb):
    '''Set the color at address ``ea`` to ``rgb``.'''
    return set_color(ea, rgb)

@utils.multicase()
def get_comment(**repeatable):
    '''Return the comment at the current address.'''
    return get_comment(ui.current.address(), **repeatable)
@utils.multicase(ea=six.integer_types)
def get_comment(ea, **repeatable):
    """Return the comment at the address ``ea``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    return idaapi.get_cmt(interface.address.inside(ea), repeatable.get('repeatable', False))
@utils.multicase(comment=basestring)
def set_comment(comment, **repeatable):
    '''Set the comment at the current address to the string ``comment``.'''
    return set_comment(ui.current.address(), comment, **repeatable)
@utils.multicase(ea=six.integer_types, comment=basestring)
def set_comment(ea, comment, **repeatable):
    """Set the comment at address ``ea`` to ``comment``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    return idaapi.set_cmt(interface.address.inside(ea), comment, repeatable.get('repeatable', False))

@utils.multicase()
def comment(**repeatable):
    '''Return the comment at the current address.'''
    return get_comment(ui.current.address(), **repeatable)
@utils.multicase(ea=six.integer_types)
def comment(ea, **repeatable):
    """Return the comment at the address ``ea``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    return get_comment(ea, **repeatable)
@utils.multicase(comment=basestring)
def comment(comment, **repeatable):
    '''Set the comment at the current address to ``comment``.'''
    return set_comment(ui.current.address(), comment, **repeatable)
@utils.multicase(ea=six.integer_types, comment=basestring)
def comment(ea, comment, **repeatable):
    """Set the comment at address ``ea`` to ``comment``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    return set_comment(ea, comment, **repeatable)

class entry(object):
    # FIXME: document this class

    __matcher__ = utils.matcher()
    __matcher__.mapping('address', utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.mapping('ea', utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('greater', operator.le, utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry)), __matcher__.boolean('gt', operator.lt, utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('less', operator.ge, utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry)), __matcher__.boolean('lt', operator.gt, utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('name', operator.eq, utils.compose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.compose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.boolean('regex', re.search, utils.compose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.predicate('predicate', idaapi.get_entry_ordinal)
    __matcher__.predicate('pred', idaapi.get_entry_ordinal)
    __matcher__.boolean('index', operator.eq)

    @classmethod
    def iterate(cls):
        for idx in xrange(idaapi.get_entry_qty()):
            yield idx
        return

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        '''List all the entry points that match the glob ``string`` against the name.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all the entry points within the database.

        Search type can be identified by providing a named argument.
        like = glob match against name
        ea, address = exact address match
        name = exact name match
        regex = regular-expression against name
        index = particular index
        greater, less = greater-or-equal against address, less-or-equal against address
        pred = function predicate
        """
        to_address = utils.compose(idaapi.get_entry_ordinal, idaapi.get_entry)
        to_numlen = utils.compose('{:x}'.format, len)

        if not type: type = {'predicate':lambda n: True}
        result = __builtin__.list(cls.iterate())
        for k,v in type.iteritems():
            res = __builtin__.list(cls.__matcher__.match(k, v, result))
            maxindex = max(res+[1])
            maxaddr = max(__builtin__.map(to_address, res) or [idaapi.BADADDR])
            maxordinal = max(__builtin__.map(idaapi.get_entry_ordinal, res) or [1])
            cindex = math.ceil(math.log(maxindex)/math.log(10))
            caddr = math.floor(math.log(maxaddr)/math.log(16))
            cordinal = math.floor(math.log(maxordinal)/math.log(16))

            for index in res:
                print '[{:{:d}d}] {:>{:d}x} : ({:{:d}x}) {:s}'.format(index, int(cindex), to_address(index), int(caddr), idaapi.get_entry_ordinal(index), int(cindex), idaapi.get_entry_name(idaapi.get_entry_ordinal(index)))
            continue
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        '''Search through all the entry-points matching the glob ``string`` against the name.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        """Search through all the entry-points within the database and return the first result.

        Search type can be identified by providing a named argument.
        like = glob match against name
        ea, address = exact address match
        name = exact name match
        regex = regular-expression against name
        index = particular index
        greater, less = greater-or-equal against address, less-or-equal against address
        pred = function predicate
        """

        searchstring = ', '.join('{:s}={!r}'.format(k,v) for k,v in type.iteritems())
        if len(type) != 1:
            raise LookupError('{:s}.search({:s}) : Invalid number of search types specified.', '.'.join((__name__,cls.__name__)), searchstring)

        k,v = __builtin__.next(type.iteritems())
        res = __builtin__.map(None,cls.__matcher__.match(k, v, cls.iterate()))
        if len(res) > 1:
            __builtin__.map(logging.info, (('[{:d}] {:x} : ({:x}) {:s}'.format(idx, idaapi.get_entry(idaapi.get_entry_ordinal(idx)), idaapi.get_entry_ordinal(idx), idaapi.get_entry_name(idaapi.get_entry_ordinal(idx)))) for idx in res))
            logging.warn('{:s}.search({:s}) : Found {:d} matching results, returning the first one.'.format('.'.join((__name__,cls.__name__)), searchstring, len(res)))

        res = __builtin__.next(iter(res), None)
        if res is None:
            raise LookupError('{:s}.search({:s}) : Found 0 matching results.'.format('.'.join((__name__,cls.__name__)), searchstring))
        return res

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Makes an entry-point at the current address.'''
        ea,entryname,ordinal = ui.current.address(), name(ui.current.address()), idaapi.get_entry_qty()
        if entryname is None:
            raise ValueError('{:s}.new : Unable to determine name at address 0x{:x}'.format( '.'.join((__name__,cls.__name__)), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def new(cls, ea):
        '''Makes an entry-point at the specified address ``ea``.'''
        entryname,ordinal = name(ea), idaapi.get_entry_qty()
        if entryname is None:
            raise ValueError('{:s}.new : Unable to determine name at address 0x{:x}'.format( '.'.join((__name__,cls.__name__)), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(name=basestring)
    @classmethod
    def new(cls, name):
        '''Adds an entry point to the database named ``name`` using the next available index as the ordinal.'''
        return cls.new(ui.current.address(), name, idaapi.get_entry_qty())
    @utils.multicase(ea=six.integer_types, name=basestring)
    @classmethod
    def new(cls, ea, name):
        '''Makes the specified address ``ea`` an entry-point named according to ``name``.'''
        ordinal = idaapi.get_entry_qty()
        return cls.new(ea, name, ordinal)
    @utils.multicase(name=basestring, ordinal=six.integer_types)
    @classmethod
    def new(cls, name, ordinal):
        '''Adds an entry point to the database named ``name`` with ``ordinal`` as it's index.'''
        return cls.new(ui.current.address(), name, ordinal)
    @utils.multicase(ea=six.integer_types, name=basestring, ordinal=six.integer_types)
    @classmethod
    def new(cls, ea, name, ordinal):
        '''Adds an entry point at ``ea`` with the specified ``name`` and ``ordinal``.'''
        return idaapi.add_entry(ordinal, interface.address.inside(ea), name, 0)

def tags():
    '''Returns all the tag names used globally.'''
    return internal.comment.globals.name()

@utils.multicase()
def tag_read():
    '''Returns all the tags at the current address.'''
    return tag_read(ui.current.address())
@utils.multicase(key=basestring)
def tag_read(key):
    '''Returns the tag identified by ``key`` at the current addres.'''
    return tag_read(ui.current.address(), key)
@utils.multicase(ea=six.integer_types)
def tag_read(ea):
    '''Returns all the tags defined at address ``ea``.'''
    ea = interface.address.inside(ea)

    # if not within a function, then use a repeatable comment
    # otherwise, use a non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # fetch the tags at the given address
    res = comment(ea, repeatable=repeatable)
    d1 = internal.comment.decode(res)
    res = comment(ea, repeatable=not repeatable)
    d2 = internal.comment.decode(res)
    if d1.viewkeys() & d2.viewkeys():
        logging.warn('{:s}.tag_read : Contents of both repeatable and non-repeatable comments conflict with one another. Giving the {:s} comment priority.'.format(__name__, 'repeatable' if repeatable else 'non-repeatable', d1 if repeatable else d2))
    res = {}
    __builtin__.map(res.update, (d1,d2))

    # modify the decoded dictionary with implicit tags
    aname = get_name(ea)
    if aname and (idaapi.getFlags(ea) & idaapi.FF_NAME): res.setdefault('__name__', aname)
    eprefix = extra.get_prefix(ea)
    if eprefix is not None: res.setdefault('__extra_prefix__', eprefix)
    esuffix = extra.get_suffix(ea)
    if esuffix is not None: res.setdefault('__extra_suffix__', esuffix)
    col = get_color(ea)
    if col is not None: res.setdefault('__color__', col)

    # now return what the user cares about
    return res
@utils.multicase(ea=six.integer_types, key=basestring)
def tag_read(ea, key):
    '''Returns the tag identified by ``key`` from address ``ea``.'''
    res = tag_read(ea)
    return res[key]

@utils.multicase(key=basestring)
def tag_write(key, value):
    '''Set the tag ``key`` to ``value`` at the current address.'''
    return tag_write(ui.current.address(), key, value)
@utils.multicase(key=basestring, none=types.NoneType)
def tag_write(key, none):
    '''Removes the tag specified by ``key`` from the current address ``ea``.'''
    return tag_write(ui.current.address(), key, value)
@utils.multicase(ea=six.integer_types, key=basestring)
def tag_write(ea, key, value):
    '''Set the tag ``key`` to ``value`` at the address ``ea``.'''
    if value is None:
        raise AssertionError('{:s}.tag_write : Tried to set tag {!r} to an invalid value.'.format(__name__, key))

    # if the user wants to change the '__name__' tag, then
    # change the name fo' real.
    if key == '__name__':
        return set_name(ea, value, listed=True)
    if key == '__extra_prefix__':
        return extra.set_prefix(ea, value)
    if key == '__extra_suffix__':
        return extra.set_suffix(ea, value)
    if key == '__color__':
        return set_color(ea, value)

    # if not within a function, then use a repeatable comment
    # otherwise, use a non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # grab the current value
    ea = interface.address.inside(ea)
    state = internal.comment.decode(comment(ea, repeatable=repeatable))

    # update the tag's reference
    if key not in state:
        if func:
            internal.comment.contents.inc(ea, key)
        else:
            internal.comment.globals.inc(ea, key)

    # now we can actually update the tag
    res,state[key] = state.get(key,None),value
    comment(ea, internal.comment.encode(state), repeatable=repeatable)
    return res
@utils.multicase(ea=six.integer_types, key=basestring, none=types.NoneType)
def tag_write(ea, key, none):
    '''Removes the tag specified by ``key`` from the address ``ea``.'''
    ea = interface.address.inside(ea)

    # if the '__name__' is being cleared, then really remove it.
    if key == '__name__':
        return set_name(ea, None, listed=True)
    if key == '__extra_prefix__':
        return extra.del_prefix(ea)
    if key == '__extra_suffix__':
        return extra.del_suffix(ea)

    # if not within a function, then fetch the repeatable comment
    # otherwise update the non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # fetch the dict, remove the key, then write it back.
    state = internal.comment.decode(comment(ea, repeatable=repeatable))
    res = state.pop(key)
    comment(ea, internal.comment.encode(state), repeatable=repeatable)

    # delete it's reference
    if func:
        internal.comment.contents.dec(ea, key)
    else:
        internal.comment.globals.dec(ea, key)

    return res

#FIXME: define tag_erase

@utils.multicase()
def tag():
    '''Return all the tags defined at the current address.'''
    return tag_read(ui.current.address())
@utils.multicase(ea=six.integer_types)
def tag(ea):
    '''Return all the tags defined at address ``ea``.'''
    return tag_read(ea)
@utils.multicase(key=basestring)
def tag(key):
    '''Return the tag identified by ``key`` at the current address.'''
    return tag_read(ui.current.address(), key)
@utils.multicase(key=basestring)
def tag(key, value):
    '''Set the tag identified by ``key`` to ``value`` at the current address.'''
    return tag_write(ui.current.address(), key, value)
@utils.multicase(ea=six.integer_types, key=basestring)
def tag(ea, key):
    '''Return the tag at address ``ea`` identified by ``key``.'''
    return tag_read(ea, key)
@utils.multicase(ea=six.integer_types, key=basestring)
def tag(ea, key, value):
    '''Set the tag identified by ``key`` to ``value`` at address ``ea``.'''
    return tag_write(ea, key, value)
@utils.multicase(key=basestring, none=types.NoneType)
def tag(key, none):
    '''Remove the tag identified by ``key`` at the current address.'''
    return tag_write(ui.current.address(), key, None)
@utils.multicase(ea=six.integer_types, key=basestring, none=types.NoneType)
def tag(ea, key, none):
    '''Removes the tag identified by ``key`` at the address ``ea``.'''
    return tag_write(ea, key, None)

# FIXME: consolidate the boolean querying logic into the utils module
# FIXME: document this properly
# FIXME: add support for searching global tags using the addressing cache
@utils.multicase(tag=basestring)
def select(tag, *tags, **boolean):
    tags = (tag,) + tags
    boolean['And'] = tuple(set(boolean.get('And',set())).union(tags))
    return select(**boolean)
@utils.multicase()
def select(**boolean):
    '''Fetch all the functions containing the specified tags within it's declaration'''
    boolean = dict((k,set(v if isinstance(v, (__builtin__.tuple,__builtin__.set,__builtin__.list)) else (v,))) for k,v in boolean.viewitems())

    if not boolean:
        for ea in internal.comment.globals.address():
            res = function.tag(ea) if function.within(ea) else tag(ea)
            if res: yield ea, res
        return

    for ea in internal.comment.globals.address():
        res,d = {},function.tag(ea) if function.within(ea) else tag(ea)

        Or = boolean.get('Or', set())
        res.update((k,v) for k,v in d.iteritems() if k in Or)

        And = boolean.get('And', set())
        if And:
            if And.intersection(d.viewkeys()) == And:
                res.update((k,v) for k,v in d.iteritems() if k in And)
            else: continue
        if res: yield ea,res
    return

# FIXME: consolidate the boolean querying logic into the utils module
# FIXME: document this properly
@utils.multicase(tag=basestring)
def selectcontents(tag, *tags, **boolean):
    tags = (tag,) + tags
    boolean['Or'] = tuple(set(boolean.get('Or',set())).union(tags))
    return selectcontents(**boolean)
@utils.multicase()
def selectcontents(**boolean):
    '''Fetch all the functions containing the specified tags within it's contents'''
    boolean = dict((k,set(v if isinstance(v, (__builtin__.tuple,__builtin__.set,__builtin__.list)) else (v,))) for k,v in boolean.viewitems())

    if not boolean:
        for ea,_ in internal.comment.contents.iterate():
            res = internal.comment.contents.name(ea)
            if res: yield ea, res
        return

    for ea, res in internal.comment.contents.iterate():
        # check to see that the dict's keys match
        res,d = set(res),internal.comment.contents._read(None, ea)
        if set(d.viewkeys()) != res:
            logging.warn("{:s}.selectcontents : Contents cache is out of sync. Using contents blob instead of supval. : {:x}".format(__name__, ea))

        # now start aggregating the keys that the user is looking for
        res, d = set(), internal.comment.contents.name(ea)

        Or = boolean.get('Or', set())
        res.update(Or.intersection(d))

        And = boolean.get('And', set())
        if And:
            if And.intersection(d) == And:
                res.update(And)
            else: continue
        if res: yield ea,res
    return
selectcontent = utils.alias(selectcontents)

## imports
class imports(object):
    def __new__(cls):
        return cls.iterate()

    # searching
    @utils.multicase()
    @classmethod
    def get(cls):
        '''Returns the import at the current address.'''
        return cls.get(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get(cls, ea):
        '''Return the import at the address ``ea``.'''
        ea = interface.address.inside(ea)
        for addr,(module,name,ordinal) in cls.iterate():
            if addr == ea:
                return (module,name,ordinal)
            continue
        raise LookupError("{:s}.imports.get : Unable to determine import at address 0x{:x}".format(__name__, ea))

    @utils.multicase()
    @classmethod
    def module(cls):
        '''Return the import module at the current address.'''
        return cls.module(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def module(cls, ea):
        '''Return the import module at the specified address ``ea``.'''
        ea = interface.address.inside(ea)
        for addr,(module,_,_) in cls.iterate():
            if addr == ea:
                return module
            continue
        raise LookupError("{:s}.imports.module : Unable to determine import module name at address 0x{:x}".format(__name__, ea))

    # specific parts of the import
    @utils.multicase()
    @classmethod
    def fullname(cls):
        '''Return the full name of the import at the current address.'''
        return cls.fullname(ui.current.address())
    @utils.multicase()
    @classmethod
    def fullname(cls, ea):
        '''Return the full name of the import at address ``ea``.'''
        module,name,ordinal = cls.get(ea)
        return '{:s}!{:s}'.format(module, name or 'Ordinal{:d}'.format(ordinal))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the import at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase()
    @classmethod
    def name(cls, ea):
        '''Return the name of the import at address ``ea``.'''
        _,name,ordinal = cls.get(ea)
        return name or 'Ordinal{:d}'.format(ordinal)

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the import at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase()
    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal of the import at the address ``ea``.'''
        _,_,ordinal = cls.get(ea)
        return ordinal

    # iteration
    @staticmethod
    def modules():
        '''Return all the import modules defined in the database.'''
        return [idaapi.get_import_module_name(i) for i in xrange(idaapi.get_import_module_qty())]

    @staticmethod
    def list(modulename):
        '''List all the imports specified in the module ``modulename``.'''
        idx = [x.lower() for x in imports.modules()].index(modulename.lower())
        result = []
        def fn(ea,name,ordinal):
            result.append((ea,(name,ordinal)))
            return True
        idaapi.enum_import_names(idx,fn)
        return result

    @staticmethod
    def iterate():
        """Iterate through all of the imports in the database.
        Yields (ea,(module,name,ordinal)) for each iteration.
        """
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

    # FIXME: include a import matching class so that somebody can search imports
    #        by module or wildcard or name or address..etc.

getImportModules = utils.alias(imports.modules, 'imports')
getImports = utils.alias(imports.list, 'imports')

### register information
class register(object):
    @classmethod
    def names(cls):
        '''Return all the register names in the database.'''
        return idaapi.ph_get_regnames()
    @classmethod
    def segments(cls):
        '''Return all the segment registers in the database.'''
        names = cls.names()
        return [names[i] for i in xrange(idaapi.ph_get_regFirstSreg(),idaapi.ph_get_regLastSreg()+1)]
    @classmethod
    def codesegment(cls):
        '''Return all the code segment registers in the database.'''
        return cls.names()[idaapi.ph_get_regCodeSreg()]
    @classmethod
    def datasegment(cls):
        '''Return all the data segment registers in the database.'''
        return cls.names()[idaapi.ph_get_regDataSreg()]
    @classmethod
    def segmentsize(cls):
        '''Return the segment register size for the database.'''
        return idaapi.ph_get_segreg_size()

### navigating the database according to the address reference type
class address(object):
    @staticmethod
    def walk(ea, next, match):
        '''Used internally. Please see .iterate() instead.'''
        ea = interface.address.inside(ea)
        while ea not in (None,idaapi.BADADDR) and match(ea):
            ea = next(ea)
        return ea

    @utils.multicase()
    def iterate(cls):
        '''Return an iterator that walks forward through the database from the current address.'''
        return cls.iterate(ui.current.address(), cls.next)
    @utils.multicase(ea=six.integer_types)
    def iterate(cls, ea):
        '''Return an iterator that walks forward through the database start at address ``ea``.'''
        return cls.iterate(ea, cls.next)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def iterate(cls, ea, next):
        ea = interface.address.inside(ea)
        while ea not in (None,idaapi.BADADDR):
            yield ea
            ea = next(ea)
        return

    @utils.multicase()
    @classmethod
    def head(cls):
        '''Return the current address.'''
        return cls.head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def head(cls, ea):
        '''Return the address of the byte at the beginning of the address ``ea``.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_head(ea)

    @utils.multicase()
    @classmethod
    def tail(cls):
        '''Return the last byte at the end of the current address.'''
        return cls.tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def tail(cls, ea):
        '''Return the address of the last byte at the end of the address ``ea``.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_end(ea)-1

    @utils.multicase()
    @classmethod
    def size(cls):
        '''Returns the size of the item at the current address.'''
        return size(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def size(cls, ea):
        '''Returns the size of the item at the address ``ea``.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_size(ea)

    @utils.multicase()
    @classmethod
    def prev(cls):
        '''Return the previously defined address from the current one.'''
        return cls.prev(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prev(cls, ea):
        '''Return the previously defined address from the address ``ea``.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prev(cls, ea, count):
        res = idaapi.prev_head(interface.address.within(ea),0)
        return cls.prev(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def next(cls):
        '''Return the next defined address from the current one.'''
        return cls.next(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def next(cls, ea):
        '''Return the next defined address from the address ``ea``.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def next(cls, ea, count):
        res = idaapi.next_head(interface.address.within(ea), idaapi.BADADDR)
        return cls.next(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevdata(cls):
        '''Returns the previous address that has data referencing it.'''
        return cls.prevdata(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevdata(cls, ea):
        '''Returns the previous address from ``ea`` that has data referencing it.'''
        return cls.prevdata(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevdata(cls, ea, count):
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: len(xref.du(n)) == 0)
        return cls.prevdata(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nextdata(cls):
        '''Returns the next address that has data referencing it.'''
        return cls.nextdata(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextdata(cls, ea):
        '''Returns the next address from ``ea`` that has data referencing it.'''
        return cls.nextdata(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextdata(cls, ea, count):
        res = cls.walk(ea, cls.next, lambda n: len(xref.du(n)) == 0)
        return cls.nextdata(cls.next(res), count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevcode(cls):
        '''Returns the previous address that has code referencing it.'''
        return cls.prevcode(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcode(cls, ea):
        '''Returns the previous address from ``ea`` that has code referencing it.'''
        return cls.prevcode(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcode(cls, ea, count):
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: len(xref.cu(n)) == 0)
        return cls.prevcode(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nextcode(cls):
        '''Returns the next address that has code referencing it.'''
        return cls.nextcode(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcode(cls, ea):
        '''Returns the next address from ``ea`` that has code referencing it.'''
        return cls.nextcode(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcode(cls, ea, count):
        res = cls.walk(ea, cls.next, lambda n: len(xref.cu(n)) == 0)
        return cls.nextcode(cls.next(res), count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevref(cls):
        '''Returns the previous address that has anything referencing it.'''
        return cls.prevref(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevref(cls, ea):
        '''Returns the previous address from ``ea`` that has anything referencing it.'''
        return cls.prevref(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevref(cls, ea, count):
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: len(xref.u(n)) == 0)
        return cls.prevref(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nextref(cls):
        '''Returns the next address that has anything referencing it.'''
        return cls.nextref(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextref(cls, ea):
        '''Returns the next address from ``ea`` that has anything referencing it.'''
        return cls.nextref(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextref(cls, ea, count):
        res = cls.walk(ea, cls.next, lambda n: len(xref.u(n)) == 0)
        return cls.nextref(cls.next(res), count-1) if count > 1 else res

    @utils.multicase(ea=six.integer_types, reg=basestring)
    @classmethod
    def prevreg(cls, ea, reg, *regs, **modifiers):
        """Return the previous address from ``ea`` containing an instruction that uses one of the specified registers ``regs``.
        If the modifier ``write`` is True, then only return the address if it's writing to the register.
        """
        regs = (reg,) + regs
        count = modifiers.get('count',1)
        write = (not modifiers.get('read',None)) if 'read' in modifiers else modifiers.get('write',None)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg.by_name(r).related,itertools.imap(_instruction.reg.by_name,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and (('w' in st) if write else ('r' in st) if (write is not None and not write) else True):
                    return True
                if t == 'opt_phrase' and (('w' in st) if write else ('r' in st) if (write is not None and not write) else True):
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        prevea = cls.prev(ea)
        if prevea is None:
            logging.fatal("{:s}.{:s}.prevreg : Unable to start walking from previous address. : {:x}".format(__name__, cls.__name__, ea))
            return ea
        res = cls.walk(ea, cls.prev, lambda ea: not uses_register(ea, regs))
        modifiers['count'] = count - 1
        return cls.prevreg( cls.prev(res), *regs, **modifiers) if count > 1 else res
    @utils.multicase(reg=basestring)
    @classmethod
    def prevreg(cls, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.prevreg(ui.current.address(), reg, *regs, **modifiers)

    @utils.multicase(ea=six.integer_types, reg=basestring)
    @classmethod
    def nextreg(cls, ea, reg, *regs, **modifiers):
        """Return next address containing an instruction that uses one of the specified registers ``regs``.
        If the modifier ``write`` is True, then only return the address if it's writing to the register.
        """
        regs = (reg,) + regs
        count = modifiers.get('count',1)
        write = (not modifiers.get('read',None)) if 'read' in modifiers else modifiers.get('write',None)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg.by_name(r).related,itertools.imap(_instruction.reg.by_name,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and (('w' in st) if write else ('r' in st) if (write is not None and not write) else True):
                    return True
                if t == 'opt_phrase' and (('w' in st) if write else ('r' in st) if (write is not None and not write) else True):
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        nextea = cls.next(ea)
        if nextea is None:
            logging.fatal("{:s}.{:s}.next : Unable to start walking from next address. : {:x}".format(__name__, cls.__name__, res))
            return ea
        res = cls.walk(ea, cls.next, lambda ea: not uses_register(ea, regs))
        modifiers['count'] = count - 1
        return cls.nextreg(cls.next(res), *regs, **modifiers) if count > 1 else res
    @utils.multicase(reg=basestring)
    @classmethod
    def nextreg(cls, reg, *regs, **modifiers):
        '''Return the next address containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.nextreg(ui.current.address(), reg, *regs, **modifiers)

    @utils.multicase()
    @classmethod
    def prevstack(cls, delta):
        '''Return the previous instruction that is past the sp delta ``delta``.'''
        return cls.prevstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevstack(cls, ea, delta):
        '''Return the previous instruction from ``ea`` that is past the sp delta ``delta``.'''
        fn,sp = function.top(ea),function.get_spdelta(ea)
        return cls.walk(ea, cls.prev, lambda n: abs(function.get_spdelta(n) - sp) < delta)

    @utils.multicase()
    @classmethod
    def nextstack(cls, delta):
        '''Return the next instruction that is past the sp delta ``delta``.'''
        return cls.nextstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextstack(cls, ea, delta):
        '''Return the next instruction from ``ea`` that is past the sp delta ``delta``.'''
        fn,sp = function.top(ea),function.get_spdelta(ea)
        return cls.walk(ea, cls.next, lambda n: abs(function.get_spdelta(n) - sp) < delta)

    @utils.multicase()
    @classmethod
    def prevcall(cls):
        '''Return the previous call instruction.'''
        return cls.prevcall(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcall(cls, ea):
        '''Return the previous call instruction from the address ``ea``.'''
        return cls.prevcall(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcall(cls, ea, count):
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: not _instruction.is_call(n))
        return cls.prevcall(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nextcall(cls):
        '''Return the next call instruction.'''
        return cls.nextcall(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcall(cls, ea):
        '''Return the next call instruction from the address ``ea``.'''
        return cls.nextcall(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcall(cls, ea, count):
        res = cls.walk(ea, cls.next, lambda n: not _instruction.is_call(n))
        return cls.nextcall(cls.next(res), count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevbranch(cls):
        '''Return the previous branch instruction.'''
        return cls.prevbranch(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevbranch(cls, ea):
        '''Return the previous branch instruction from the address ``ea``.'''
        return cls.prevbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevbranch(cls, ea, count):
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: _instruction.is_call(n) and not _instruction.is_branch(n))
        return cls.prevbranch(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nextbranch(cls):
        '''Return the next branch instruction.'''
        return cls.nextbranch(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    def nextbranch(cls, ea):
        '''Return the next branch instruction from the address ``ea``.'''
        return cls.nextbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextbranch(cls, ea, count):
        res = cls.walk(ea, cls.next, lambda n: _instruction.is_call(n) and not _instruction.is_branch(n))
        return cls.nextbranch(cls.next(res), count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevtag(cls, **tagname):
        '''Return the previous address that contains a tag.'''
        return cls.prevtag(ui.current.address(), 1, **tagname)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevtag(cls, ea, **tagname):
        """Returns the previous address from ``ea`` that contains a tag.
        If the str ``tag`` is specified, then only return the address if the specified tag is defined.
        """
        return cls.prevtag(ea, 1, **tagname)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevtag(cls, ea, count, **tagname):
        tagname = tagname.get('tagname', None)
        res = cls.walk(cls.prev(ea), cls.prev, lambda n: not (type.has_comment(n) if tagname is None else tagname in tag(n)))
        return cls.prevbranch(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def nexttag(cls, **tagname):
        '''Return the next address that contains a tag.'''
        return cls.nexttag(ui.current.address(), 1, **tagname)
    @utils.multicase(ea=six.integer_types)
    def nexttag(cls, ea, **tagname):
        """Returns the next address from ``ea`` that contains a tag.
        If the str ``tag`` is specified, then only return the address if the specified tag is defined.
        """
        return cls.nexttag(ea, 1, **tagname)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nexttag(cls, ea, count, **tagname):
        tagname = tagname.get('tagname', None)
        res = cls.walk(ea, cls.next, lambda n: not (type.has_comment(n) if tagname is None else tagname in tag(n)))
        return cls.nextbranch(cls.next(res), count-1) if count > 1 else res

a = addr = address

prev,next = utils.alias(address.prev, 'address'), utils.alias(address.next, 'address')
prevdata,nextdata = utils.alias(address.prevdata, 'address'), utils.alias(address.nextdata, 'address')
prevcode,nextcode = utils.alias(address.prevcode, 'address'), utils.alias(address.nextcode, 'address')
prevref,nextref = utils.alias(address.prevref, 'address'), utils.alias(address.nextref, 'address')
prevreg,nextreg = utils.alias(address.prevreg, 'address'), utils.alias(address.nextreg, 'address')
head,tail = utils.alias(address.head, 'address'), utils.alias(address.tail, 'address')
size = utils.alias(address.size, 'address')

class flow(address):
    @staticmethod
    def walk(ea, next, match):
        '''Used internally. Please see .iterate() instead.'''
        ea = interface.address.inside(ea)
        res = set()
        while ea not in (None,idaapi.BADADDR) and is_code(ea) and ea not in res and match(ea):
            res.add(ea)
            ea = next(ea)
        return ea

    @utils.multicase()
    @classmethod
    def prev(cls):
        '''Return the previous address that would have to be executed to get to the current address.'''
        return cls.prev(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prev(cls, ea):
        '''Return the previous address that would have to be executed to get to the address ``ea``.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prev(cls, ea, count):
        ea = interface.address.within(ea)
        isStop = lambda ea: _instruction.feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
        refs = xref.up(ea)
        if len(refs) > 1 and isStop(address.prev(ea)):
            logging.fatal("{:s}.flow.prev : 0x{:x} : Unable to determine previous address due to multiple previous references being available : {:s}".format(__name__, ea, ', '.join(__builtin__.map(hex,refs))))
            return None
        res = refs[0] if isStop(address.prev(ea)) else address.prev(ea)
        return cls.prev(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def next(cls):
        '''Emulate the current instruction and return the next address that would be executed.'''
        return cls.next(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def next(cls, ea):
        '''Emulate the instruction at ``ea`` and return the next address that would be executed.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def next(cls, ea, count):
        ea = interface.address.within(ea)
        isStop = lambda ea: _instruction.feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
        refs = xref.down(ea)
        if len(refs) > 1:
            logging.fatal("{:s}.flow.next : 0x{:x} : Unable to determine next address due to multiple xrefs being available : {:s}".format(__name__, ea, ', '.join(__builtin__.map(hex,refs))))
            return None
        if isStop(ea) and not _instruction.is_jmp(ea):
#            logging.fatal("{:s}.flow.next : 0x{:x} : Unable to move to next address. Flow has stopped.".format(__name__, ea))
            return None
        res = refs[0] if _instruction.is_jmp(ea) else address.next(ea)
        return cls.next(res, count-1) if count > 1 else res
f = flow

class type(object):
    @utils.multicase()
    def __new__(cls):
        '''Return the type at the address specified at the current address.'''
        ea = ui.current.address()
        module,F = idaapi,(idaapi.getFlags(ea)&idaapi.DT_TYPE)
        res, = itertools.islice((v for n,v in itertools.imap(lambda n:(n,getattr(module,n)),dir(module)) if n.startswith('FF_') and (F == v&0xffffffff)), 1)
        return res
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea):
        '''Return the type at the address specified by ``ea``.'''
        module,F = idaapi,(idaapi.getFlags(interface.address.within(ea))&idaapi.DT_TYPE)
        res, = itertools.islice((v for n,v in itertools.imap(lambda n:(n,getattr(module,n)),dir(module)) if n.startswith('FF_') and (F == v&0xffffffff)), 1)
        return res

    @utils.multicase()
    @staticmethod
    def is_code():
        '''Return True if the current address is marked as code.'''
        return type.is_code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_code(ea):
        '''Return True if the address specified by ``ea`` is marked as code.'''
        return idaapi.getFlags(interface.address.within(ea))&idaapi.MS_CLS == idaapi.FF_CODE

    @utils.multicase()
    @staticmethod
    def is_data():
        '''Return True if the current address is marked as data.'''
        return type.is_data(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_data(ea):
        '''Return True if the address specified by ``ea`` is marked as data.'''
        return idaapi.getFlags(interface.address.within(ea))&idaapi.MS_CLS == idaapi.FF_DATA

    # True if ea marked unknown
    @utils.multicase()
    @staticmethod
    def is_unknown():
        '''Return True if the current address is undefined.'''
        return type.is_unknown(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_unknown(ea):
        '''Return True if the address specified by ``ea`` is undefined.'''
        return idaapi.getFlags(interface.address.within(ea))&idaapi.MS_CLS == idaapi.FF_UNK

    @utils.multicase()
    @staticmethod
    def is_head():
        return type.is_head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_head(ea):
        '''Return True if the address ``ea`` is aligned to a definition in the database.'''
        return idaapi.getFlags(interface.address.within(ea))&idaapi.FF_DATA != 0

    @utils.multicase()
    @staticmethod
    def is_tail():
        return type.is_tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_tail(ea):
        '''Return True if the address ``ea`` is not-aligned to a definition in the database.'''
        return idaapi.getFlags(interface.address.within(ea))&idaapi.MS_CLS == idaapi.FF_TAIL

    @utils.multicase()
    @staticmethod
    def is_align():
        '''Return True if the current address is defined as an alignment.'''
        return type.is_align(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_align(ea):
        '''Return True if the address at ``ea`` is defined as an alignment.'''
        return idaapi.isAlign(idaapi.getFlags(interface.address.within(ea)))

    @utils.multicase()
    @staticmethod
    def has_comment():
        '''Return True if the current address is commented.'''
        return type.has_comment(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_comment(ea):
        '''Return True if the address at ``ea`` is commented.'''
        return bool(idaapi.getFlags(interface.address.within(ea)) & idaapi.FF_COMM == idaapi.FF_COMM)

    @utils.multicase()
    @staticmethod
    def has_reference():
        '''Return True if the current address has a reference.'''
        return type.has_reference(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_reference(ea):
        '''Return True if the address at ``ea`` has a reference.'''
        return bool(idaapi.getFlags(interface.address.within(ea)) & idaapi.FF_REF == idaapi.FF_REF)

    @utils.multicase()
    @staticmethod
    def has_name():
        '''Return True if the current address has a name.'''
        return type.has_name(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_name(ea):
        '''Return True if the address at ``ea`` has a name.'''
        return idaapi.has_any_name(idaapi.getFlags(interface.address.within(ea)))

    @utils.multicase()
    @staticmethod
    def has_customname():
        '''Return True if the current address has a custom-name.'''
        return type.has_customname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_customname(ea):
        '''Return True if the address at ``ea`` has a custom-name.'''
        return bool(idaapi.getFlags(interface.address.within(ea)) & idaapi.FF_NAME == idaapi.FF_NAME)

    @utils.multicase()
    @staticmethod
    def has_dummyname():
        '''Return True if the current address has a dummy-name.'''
        return type.has_dummyname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_dummyname(ea):
        '''Return True if the address at ``ea`` has a dummy-name.'''
        return bool(idaapi.getFlags(interface.address.within(ea)) & idaapi.FF_LABL == idaapi.FF_LABL)

    @utils.multicase()
    @staticmethod
    def has_autoname():
        '''Return True if the current address is automatically named.'''
        return type.has_autoname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_autoname(ea):
        '''Return True if the address ``ea`` is automatically named.'''
        return idaapi.has_auto_name(idaapi.getFlags(interface.address.within(ea)))

    @utils.multicase()
    @staticmethod
    def has_publicname():
        '''Return True if the current address has a public name.'''
        return type.has_publicname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_publicname(ea):
        '''Return True if the address at ``ea`` has a public name.'''
        return idaapi.is_public_name(interface.address.within(ea))

    @utils.multicase()
    @staticmethod
    def has_weakname():
        '''Return True if the current address has a weakly-typed name.'''
        return type.has_weakname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_weakname(ea):
        '''Return True if the address at ``ea`` has a weakly-typed name.'''
        return idaapi.is_weak_name(interface.address.within(ea))

    @utils.multicase()
    @staticmethod
    def has_listedname():
        '''Return True if the current address has a name that is listed.'''
        return type.has_listedname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_listedname(ea):
        '''Return True if the address at ``ea`` has a name that is listed.'''
        return idaapi.is_in_nlist(interface.address.within(ea))

    @utils.multicase()
    @staticmethod
    def is_label():
        '''Return True if the current address has a label.'''
        return type.is_label(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_label(ea):
        '''Return True if the address at ``ea`` has a label.'''
        return type.has_dummyname(ea) or type.has_customname(ea)

    class array(object):
        @utils.multicase()
        def __new__(cls):
            '''Return the values of the array at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the values of the array at address ``ea``.'''
            ea = interface.address.within(ea)
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
                raise TypeError("{:s}.type.array : Unable to handle an array of structure type 0x{:x}".format(__name_, t))
            else:
                ch = numerics[fl & idaapi.DT_TYPE]
                t = ch.lower() if idaapi.is_signed_data(fl) else ch
            res = array.array(t, read(ea, cls.size(ea)))
            if len(res) != cls.length(ea):
                logging.warn('{:s}.type.array : Unexpected length : ({:d} != {:d})'.format(__name__, len(res), cls.length(ea)))
            return res

        @utils.multicase()
        @staticmethod
        def element():
            '''Return the size of an element in the array at the current address.'''
            return type.array.element(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @staticmethod
        def element(ea):
            '''Return the size of an element in the array at address ``ea``.'''
            ea = interface.address.within(ea)
            return idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))

        @utils.multicase()
        @staticmethod
        def length():
            '''Return the number of elements of the array at the current address.'''
            return type.array.length(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @staticmethod
        def length(ea):
            '''Return the number of elements in the array at address ``ea``.'''
            ea = interface.address.within(ea)
            sz,ele = idaapi.get_item_size(ea),idaapi.get_full_data_elsize(ea, idaapi.getFlags(ea))
            return sz // ele

        @utils.multicase()
        @staticmethod
        def size():
            '''Return the total size of the array at the current address.'''
            return type.array.size(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @staticmethod
        def size(ea):
            '''Return the total size of the array at address ``ea``.'''
            ea = interface.address.within(ea)
            return idaapi.get_item_size(ea)

    class structure(object):
        @utils.multicase()
        def __new__(cls):
            '''Return the structure at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the structure at address ``ea``.'''
            return cls.get(ea)

        @utils.multicase()
        @staticmethod
        def id():
            '''Return the identifier of the structure at the current address.'''
            return type.structure.id(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @staticmethod
        def id(ea):
            '''Return the identifier of the structure at address ``ea``.'''
            ea = interface.address.within(ea)
            if type(ea) != idaapi.FF_STRU:
                raise AssertionError('{:s}.type.structure.id : Specified IDA Type is not an FF_STRU(0x{:x}) : 0x{:x}'.format(__name__, idaapi.FF_STRU, type(ea)))
            ti = idaapi.opinfo_t()
            res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
            if not res:
                raise AssertionError('{:s}.type.structure.id : idaapi.get_opinfo returned 0x{:x} at 0x{:x}'.format(__name__, res, ea))
            return ti.tid

        @utils.multicase()
        @staticmethod
        def get():
            '''Return the structure_t at the current address.'''
            return type.structure.get(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @staticmethod
        def get(ea):
            '''Return the structure_t at address ``ea``.'''
            ea = interface.address.within(ea)
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
                    if isinstance(ty, __builtin__.list):
                        t = typelookup[tuple(ty)]
                        ct = t*sz
                    elif isinstance(ty, (chr,str)):
                        ct = ctypes.c_char*sz
                    else:
                        ct = None
                finally:
                    res[m.name] = val if any(_ is None for _ in (ct,val)) else ctypes.cast(ctypes.pointer(ctypes.c_buffer(val)),ctypes.POINTER(ct)).contents
            return res

        @utils.multicase(id=six.integer_types)
        @staticmethod
        def apply(id):
            '''Apply the structure identified by ``id`` to the current address.'''
            return type.structure.apply(ui.current.address(), structure.instance(id))
        @utils.multicase(st=structure.structure_t)
        @staticmethod
        def apply(st):
            '''Apply the structure ``st`` to the current address.'''
            return type.structure.apply(ui.current.address(), st)
        @utils.multicase(ea=six.integer_types, id=six.integer_types)
        @staticmethod
        def apply(ea, id):
            '''Apply the structure identified by ``id`` to the address at ``ea``.'''
            return type.structure.apply(ea, structure.instance(id))
        @utils.multicase(ea=six.integer_types, st=structure.structure_t)
        @staticmethod
        def apply(ea, st):
            '''Apply the structure ``st`` to the address at ``ea``.'''
            ea = interface.address.inside(ea)
            ti = idaapi.opinfo_t()
            res = idaapi.get_opinfo(ea, 0, idaapi.getFlags(ea), ti)
            ti.tid = st.id
            return idaapi.set_opinfo(ea, 0, idaapi.getFlags(ea) | idaapi.struflag(), ti)

    class switch(object):
        @classmethod
        def __getlabel(cls, ea):
            try:
                f = idaapi.getFlags(ea)
                if idaapi.has_dummy_name(f) or idaapi.has_user_name(f):
                    r, = xref.data_up(ea)
                    return cls.__getarray(r)
            except TypeError: pass
            raise TypeError("{:s}.type.switch : Unable to instantiate a switch_info_ex_t at target label : 0x{:x}".format(__name__, ea))

        @classmethod
        def __getarray(cls, ea):
            try:
                c, = xref.data_up(ea)
                sidata,each = type.array(ea),set(xref.code_down(c))

                # check to see if first element is the correct dataref
                lastea, = xref.data_down(c)
                if ea != lastea: raise TypeError
                # then copy the first element since it's been decoded already
                each.add(sidata[0])

                # ensure that each element matches
                if config.bits() == sidata.itemsize*8 and all(x in each for x in sidata):
                    r, = xref.data_up(ea)
                    return cls.__getinsn(r)

            except (IndexError,TypeError,KeyError,ValueError): pass
            raise TypeError("{:s}.type.switch : Unable to instantiate a switch_info_ex_t at switch array : 0x{:x}".format(__name__, ea))

        @classmethod
        def __getinsn(cls, ea):
            res = idaapi.get_switch_info_ex(ea)
            if res is None:
                raise TypeError("{:s}.type.switch : Unable to instantiate a switch_info_ex_t at branch instruction : 0x{:x}".format(__name__, ea))
            return res

        @utils.multicase()
        def __new__(cls):
            '''Return the switch at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the switch at the address ``ea``.'''
            ea = interface.address.within(ea)
            try: return cls.__getinsn(ea)
            except TypeError: pass
            try: return cls.__getarray(ea)
            except TypeError: pass
            try: return cls.__getlabel(ea)
            except TypeError: pass
            raise TypeError("{:s}.type.switch : Unable to instantiate a switch_info_ex_t : 0x{:x}".format(__name__, ea))
t = type

## information about a given address
is_code = utils.alias(type.is_code, 'type')
is_data = utils.alias(type.is_data, 'type')
is_unknown = utils.alias(type.is_unknown, 'type')
is_head = utils.alias(type.is_head, 'type')
is_tail = utils.alias(type.is_tail, 'type')
is_align = utils.alias(type.is_align, 'type')
getType = get_type = utils.alias(type.__new__, 'type')

# arrays
getSize = get_size = utils.alias(type.array.element, 'type.array')
getArrayLength = get_arraylength = utils.alias(type.array.length, 'type.array')

# structures
getStructureId = get_strucid = get_structureid = utils.alias(type.structure.id, 'type.structure')

class xref(object):
    @staticmethod
    def iterate(ea, start, next):
        ea = interface.address.inside(ea)
        ea = ea if (idaapi.getFlags(ea)&idaapi.FF_DATA) else idaapi.prev_head(ea,0)

        addr = start(ea)
        while addr != idaapi.BADADDR:
            yield addr
            addr = next(ea, addr)
        return

    @utils.multicase()
    @staticmethod
    def code():
        '''Return all the code xrefs that refer to the current address.'''
        return xref.code(ui.current.address(), False)
    @utils.multicase(descend=bool)
    def code(descend):
        return xref.code(ui.current.address(), descend)
    @utils.multicase(ea=six.integer_types)
    def code(ea):
        '''Return all the code xrefs that refer to the address ``ea``.'''
        return xref.code(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def code(ea, descend):
        """Return all the code xrefs that refer to the address ``ea``.
        If the bool ``descend`` is defined, then return only code refs that are referred by the specified address.
        """
        if descend:
            start,next = idaapi.get_first_cref_from, idaapi.get_next_cref_from
        else:
            start,next = idaapi.get_first_cref_to, idaapi.get_next_cref_to
        for addr in xref.iterate(ea, start, next):
            yield addr
        return
    c = utils.alias(code, 'xref')

    @utils.multicase()
    @staticmethod
    def data():
        '''Return all the data xrefs that refer to the current address.'''
        return xref.data(ui.current.address(), False)
    @utils.multicase(descend=bool)
    @staticmethod
    def data(descend):
        return xref.data(ui.current.address(), descend)
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data(ea):
        '''Return all the data xrefs that refer to the address ``ea``.'''
        return xref.data(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def data(ea, descend):
        """Return all the data xrefs that refer to the address ``ea``.
        If the bool ``descend`` is defined, then return only the data refs that are referred by the specified address.
        """
        if descend:
            start,next = idaapi.get_first_dref_from, idaapi.get_next_dref_from
        else:
            start,next = idaapi.get_first_dref_to, idaapi.get_next_dref_to
        for addr in xref.iterate(ea, start, next):
            yield addr
        return
    d = utils.alias(data, 'xref')

    @utils.multicase()
    @staticmethod
    def data_down():
        '''Return all the data xrefs that are referenced by the current address.'''
        return xref.data_down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_down(ea):
        '''Return all the data xrefs that are referenced by the address ``ea``.'''
        return sorted(xref.data(ea, True))
    dd = utils.alias(data_down, 'xref')

    @utils.multicase()
    @staticmethod
    def data_up():
        '''Return all the data xrefs that refer to the current address.'''
        return xref.data_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_up(ea):
        '''Return all the data xrefs that refer to the address ``ea``.'''
        return sorted(xref.data(ea, False))
    du = utils.alias(data_up, 'xref')

    @utils.multicase()
    @staticmethod
    def code_down():
        '''Return all the code xrefs that are referenced by the current address.'''
        return xref.code_down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code_down(ea):
        '''Return all the code xrefs that are referenced by the address ``ea``.'''
        result = set(xref.code(ea, True))
        result.discard(address.next(ea))
        return sorted(result)
    cd = utils.alias(code_down, 'xref')

    @utils.multicase()
    @staticmethod
    def code_up():
        '''Return all the code xrefs that are referenced by the current address.'''
        return xref.code_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code_up(ea):
        '''Return all the code xrefs that refer to the address ``ea``.'''
        result = set(xref.code(ea, False))
        result.discard(address.prev(ea))
        return sorted(result)
    cu = utils.alias(code_up, 'xref')

    @utils.multicase()
    @staticmethod
    def up():
        '''Return all the references that refer to the current address.'''
        return xref.up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def up(ea):
        '''Return all the references that refer to the address ``ea``.'''
        return sorted(set(xref.data_up(ea) + xref.code_up(ea)))
    u = utils.alias(up, 'xref')

    # All locations that are referenced by the specified address
    @utils.multicase()
    @staticmethod
    def down():
        '''Return all the references that are referred by the current address.'''
        return xref.down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def down(ea):
        '''Return all the references that are referred by the address ``ea``.'''
        return sorted(set(xref.data_down(ea) + xref.code_down(ea)))
    d = utils.alias(down, 'xref')

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_code(target, **reftype):
        '''Add a code reference from the current address to ``target``.'''
        return xref.add_code(ui.current.address(), target, **reftype)
    @utils.multicase(six=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_code(ea, target, **reftype):
        """Add a code reference from address ``ea`` to ``target``.
        If the reftype ``call`` is True, then specify this ref as a function call.
        """
        ea, target = interface.address.inside(ea, target)
        isCall = reftype.get('call', reftype.get('is_call', reftype.get('isCall', False)))
        if abs(target-ea) > 2**(config.bits()/2):
            flowtype = idaapi.fl_CF if isCall else idaapi.fl_JF
        else:
            flowtype = idaapi.fl_CN if isCall else idaapi.fl_JN
        idaapi.add_cref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.code_down(ea)

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_data(target, **reftype):
        '''Add a data reference from the current address to ``target``.'''
        return xref.add_data(ui.current.address(), target, **reftype)
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_data(ea, target, **reftype):
        """Add a data reference from the address ``ea`` to ``target``.
        If the reftype ``write`` is True, then specify that this ref is writing to the target.
        """
        ea, target = interface.address.inside(ea, target)
        isWrite = reftype.get('write', False)
        flowtype = idaapi.dr_W if isWrite else idaapi.dr_R
        idaapi.add_dref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.data_down(ea)

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_code(ea):
        '''Delete _all_ the code references at ``ea``.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_cref(ea, target, 0) for target in xref.code_down(ea) ]
        return False if len(xref.code_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_code(ea, target):
        '''Delete any code references at ``ea`` that point to address ``target``.'''
        ea = interface.address.inside(ea)
        idaapi.del_cref(ea, target, 0)
        return target not in xref.code_down(ea)

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_data(ea):
        '''Delete _all_ the data references at ``ea``.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_dref(ea, target) for target in xref.data_down(ea) ]
        return False if len(xref.data_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_data(ea, target=None):
        '''Delete any data references at ``ea`` that point to address ``target``.'''
        ea = interface.address.inside(ea)
        idaapi.del_dref(ea, target)
        return target not in xref.data_down(ea)
    @staticmethod
    def clear(ea):
        ea = interface.address.inside(ea)
        return all((res is True) for res in (xref.del_code(ea),xref.del_data(ea)))
x = xref

drefs,crefs = utils.alias(xref.data, 'xref'), utils.alias(xref.code, 'xref')
dxdown,dxup = utils.alias(xref.data_down, 'xref'), utils.alias(xref.data_up, 'xref')
cxdown,cxup = utils.alias(xref.code_down, 'xref'), utils.alias(xref.code_up, 'xref')
up,down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')

# create/erase a mark at the specified address in the .idb
class marks(object):
    MAX_SLOT_COUNT = 0x400
    table = {}

    def __new__(cls):
        '''Yields each of the marked positions within the database.'''
        res = __builtin__.list(cls.iterate()) # make a copy in-case someone is actively it
        for ea,comment in cls.iterate():
            yield ea, comment
        return

    @utils.multicase(description=basestring)
    @classmethod
    def new(cls, description):
        '''Create a mark at the current address with the given ``description``.'''
        return cls.new(ui.current.address(), description)
    @utils.multicase(ea=six.integer_types, description=basestring)
    @classmethod
    def new(cls, ea, description):
        '''Create a mark at the address ``ea`` with the given ``description``.'''
        ea = interface.address.inside(ea)
        try:
            idx = cls.get_slotindex(ea)
            ea,comm = cls.by_index(idx)
            logging.warn("{:s}.new : Replacing mark {:d} at 0x{:x} : {!r} -> {!r}".format('.'.join((__name__,cls.__name__)), idx, ea, comm, description))
        except KeyError:
            idx = cls.length()
            logging.info("{:s}.new : Creating mark {:d} at 0x{:x} : {!r}".format('.'.join((__name__,cls.__name__)), idx, ea, description))

        res = cls.location(ea=ea, x=0, y=0, lnnum=0)
        title,descr = description,description
        res.mark(idx, title, descr)
        return idx

    @utils.multicase()
    @classmethod
    def remove(cls):
        '''Remove the mark at the current address.'''
        return cls.remove(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def remove(cls, ea):
        '''Remove the mark at the specified address ``ea``.'''
        ea = interface.address.inside(ea)
        idx = cls.get_slotindex(ea)
        descr = cls.location().markdesc(idx)

        res = cls.location(ea=idaapi.BADADDR)
        res.mark(idx, "", "")

        logging.warn("{:s}.remove : Removed mark {:d} at 0x{:x} : {!r}".format('.'.join((__name__,cls.__name__)), idx, ea, descr))
        return idx

    @classmethod
    def iterate(cls):
        '''Iterate through all the marks in the database.'''
        count = 0
        try:
            for count,idx in enumerate(xrange(cls.MAX_SLOT_COUNT)):
                yield cls.by_index(idx)
        except KeyError:
            pass
        return

    @classmethod
    def length(cls):
        '''Return the number of marks in the database.'''
        return len(__builtin__.list(cls.iterate()))

    @classmethod
    def location(cls, **attrs):
        '''Return a location_t object with the specified attributes.'''
        res = idaapi.curloc()
        __builtin__.list(itertools.starmap(functools.partial(setattr, res), attrs.items()))
        return res

    @classmethod
    def by_index(cls, index):
        '''Return the mark at the specified ``index`` in the mark list.'''
        if 0 <= index < cls.MAX_SLOT_COUNT:
            return (cls.get_slotaddress(index), cls.location().markdesc(index))
        raise KeyError("{:s}.by_index : Mark slot index is out of bounds : 0x{:x}".format('.'.join((__name__,cls.__name__)), ('{:d} < 0'.format(index)) if index < 0 else ('{:d} >= MAX_SLOT_COUNT'.format(index))))
    byIndex = utils.alias(by_index, 'marks')

    @utils.multicase()
    @classmethod
    def by_address(cls):
        '''Return the mark at the current address.'''
        return cls.by_address(ui.current.address())
    @utils.multicase()
    @classmethod
    def by_address(cls, ea):
        '''Return the mark at the given address ``ea``.'''
        return cls.by_index(cls.get_slotindex(ea))
    byAddress = utils.alias(by_address, 'marks')

    @utils.multicase()
    @classmethod
    def find_slotaddress(cls): return cls.find_slotaddress(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def find_slotaddress(cls, ea):
        # FIXME: figure out how to fail if this address isn't found
        res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
        res, iterable = itertools.tee(itertools.imap(cls.get_slotaddress, res))
        try:
            count = len(__builtin__.list(itertools.takewhile(lambda n: n != ea, res)))
        except IndexError:
            raise KeyError(ea)
        __builtin__.list(itertools.islice(iterable, count))
        if iterable.next() != ea:
            raise KeyError(ea)
        return count
    findSlotAddress = utils.alias(find_slotaddress, 'marks')

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_slotindex(cls):
        '''Get the index of the mark at the current address.'''
        return cls.get_slotindex(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_slotindex(cls, ea):
        '''Get the index of the mark at address ``ea``.'''
        # FIXME: figure out how to fail if this address isn't found
        return cls.table.get(ea, cls.find_slotaddress(ea))
    getSlotIndex = utils.alias(get_slotindex, 'marks')

    @classmethod
    def get_slotaddress(cls, slotidx):
        '''Get the address of the mark at index ``slotidx``.'''
        loc = cls.location()
        intp = idaapi.int_pointer()
        intp.assign(slotidx)
        res = loc.markedpos(intp)
        if res == idaapi.BADADDR:
            raise KeyError(slotidx)
        ea = address.head(res)
        cls.table[ea] = slotidx
        return ea

@utils.multicase()
def mark():
    '''Return the mark at the current address.'''
    return marks.by_address(ui.current.address())
@utils.multicase(none=types.NoneType)
def mark(none):
    '''Remove the mark at the current address.'''
    return mark(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def mark(ea):
    '''Return the mark at the specified address ``ea``.'''
    return marks.by_address(ea)
@utils.multicase(description=basestring)
def mark(description):
    '''Create a mark at the current address with the specified ``description``.'''
    return mark(ui.current.address(), description)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def mark(ea, none):
    '''Erase the mark at address ``ea``.'''
    try: tag(ea, 'mark', None)
    except KeyError: pass
    color(ea, None)
    return marks.remove(ea)
@utils.multicase(ea=six.integer_types, description=basestring)
def mark(ea, description):
    '''Create a mark at address ``ea`` with the given ``description``.'''
    return marks.new(ea, description)

class extra(object):
    '''Allow one to manipulate the extra comments that suffix or prefix a given address'''

    MAX_ITEM_LINES = 5000   # defined in cfg/ida.cfg according to python/idc.py
    MAX_ITEM_LINES = (idaapi.E_NEXT-idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV-idaapi.E_NEXT

    @classmethod
    def __hide(cls, ea):
        if idaapi.hasExtra(ea) or True: # FIXME: idaapi.hasExtra doesn't seem to work
            return idaapi.noExtra(ea)
        return False

    @classmethod
    def __show(cls, ea):
        if idaapi.hasExtra(ea) or True: # FIXME: idaapi.hasExtra doesn't seem to work
            return idaapi.doExtra(ea)
        return False

    @classmethod
    def has_extra(cls, ea, base):
        sup = internal.netnode.sup
        return sup.get(ea, base) is not None

    @classmethod
    def count(cls, ea, base):
        sup = internal.netnode.sup
        for i in xrange(0, cls.MAX_ITEM_LINES):
            row = sup.get(ea, base+i)
            if row is None: break
        return i or None

    @classmethod
    def __get(cls, ea, base):
        sup = internal.netnode.sup
        count = cls.count(ea, base)
        if count is None: return None
        res = (sup.get(ea, base+i) for i in xrange(count))
        return '\n'.join(row[:-1] if row.endswith('\x00') else row for row in res)
    @classmethod
    def __set(cls, ea, string, base):
        sup = internal.netnode.sup
        [ sup.set(ea, base+i, row+'\x00') for i,row in enumerate(string.split('\n')) ]
        return True
    @classmethod
    def __del(cls, ea, base):
        sup = internal.netnode.sup
        count = cls.count(ea, base)
        if count is None: return False
        [ sup.remove(ea, base+i) for i in xrange(count) ]
        return True

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_prefix(cls, ea):
        '''Return the prefixed comment at address ``ea``.'''
        return cls.__get(ea, idaapi.E_PREV)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_suffix(cls, ea):
        '''Return the suffixed comment at address ``ea``.'''
        return cls.__get(ea, idaapi.E_NEXT)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def del_prefix(cls, ea):
        '''Delete the prefixed comment at address ``ea``.'''
        res = cls.__get(ea, idaapi.E_PREV)
        cls.__hide(ea)
        cls.__del(ea, idaapi.E_PREV)
        cls.__show(ea)
        return res
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def del_suffix(cls, ea):
        '''Delete the suffixed comment at address ``ea``.'''
        res = cls.__get(ea, idaapi.E_NEXT)
        cls.__hide(ea)
        cls.__del(ea, idaapi.E_NEXT)
        cls.__show(ea)
        return res

    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def set_prefix(cls, ea, string):
        '''Set the prefixed comment at address ``ea`` to the specified ``string``.'''
        cls.__hide(ea)
        res, ok = cls.del_prefix(ea), cls.__set(ea, string, idaapi.E_PREV)
        ok = cls.__set(ea, string, idaapi.E_PREV)
        cls.__show(ea)
        return res
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def set_suffix(cls, ea, string):
        '''Set the suffixed comment at address ``ea`` to the specified ``string``.'''
        cls.__hide(ea)
        res, ok = cls.del_suffix(ea), cls.__set(ea, string, idaapi.E_NEXT)
        cls.__show(ea)
        return res

    @utils.multicase()
    @classmethod
    def get_prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.get_prefix(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.get_suffix(ui.current.address())
    @utils.multicase()
    @classmethod
    def del_prefix(cls):
        '''Delete the prefixed comment at the current address.'''
        return cls.del_prefix(ui.current.address())
    @utils.multicase()
    @classmethod
    def del_suffix(cls):
        '''Delete the suffixed comment at the current address.'''
        return cls.del_suffix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def set_prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified ``string``.'''
        return cls.set_prefix(ui.current.address(), string)
    @utils.multicase(string=basestring)
    @classmethod
    def set_suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified ``string``.'''
        return cls.set_suffix(ui.current.address(), string)

    @utils.multicase()
    @classmethod
    def prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.get_prefix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified ``string``.'''
        return cls.set_prefix(ui.current.address(), string)
    @utils.multicase(none=types.NoneType)
    @classmethod
    def prefix(cls, none):
        '''Delete the prefixed comment at the current address.'''
        return cls.del_prefix(ui.current.address())

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prefix(cls, ea):
        '''Return the prefixed comment at address ``ea``.'''
        return cls.get_prefix(ea)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def prefix(cls, ea, string):
        '''Set the prefixed comment at address ``ea`` to the specified ``string``.'''
        return cls.set_prefix(ea, string)
    @utils.multicase(ea=six.integer_types, none=types.NoneType)
    @classmethod
    def prefix(cls, ea, none):
        '''Delete the prefixed comment at address ``ea``.'''
        return cls.del_prefix(ea)

    @utils.multicase()
    @classmethod
    def suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.get_suffix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified ``string``.'''
        return cls.set_suffix(ui.current.address(), string)
    @utils.multicase(none=types.NoneType)
    @classmethod
    def suffix(cls, none):
        '''Delete the suffixed comment at the current address.'''
        return cls.del_suffix(ui.current.address())

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def suffix(cls, ea):
        '''Return the suffixed comment at address ``ea``.'''
        return cls.get_suffix(ea)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def suffix(cls, ea, string):
        '''Set the suffixed comment at address ``ea`` to the specified ``string``.'''
        return cls.set_suffix(ea, string)
    @utils.multicase(ea=six.integer_types, none=types.NoneType)
    @classmethod
    def suffix(cls, ea, none):
        '''Delete the suffixed comment at address ``ea``.'''
        return cls.del_suffix(ea)

    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def insert(cls, ea, count):
        '''Insert ``count`` lines in front of the item at address ``ea``.'''
        return cls.set_prefix(ea, '\n'*(count-1)) if count > 0 else cls.del_prefix(ea)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def append(cls, ea, count):
        '''Append ``count`` lines after the item at address ``ea``.'''
        return cls.set_suffix(ea, '\n'*(count-1)) if count > 0 else cls.del_suffix(ea)

    @utils.multicase(count=six.integer_types)
    @classmethod
    def insert(cls, count):
        '''Insert ``count`` lines in front of the item at the current address.'''
        return cls.insert(ui.current.address(), count)
    @utils.multicase(count=six.integer_types)
    @classmethod
    def append(cls, count):
        '''Append ``count`` lines after the item at the current address.'''
        return cls.append(ui.current.address(), count)
