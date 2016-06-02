'''
database-context

generic tools for working in the context of the database
'''

import __builtin__,logging,os
import array,itertools,functools,ctypes
import six,types

import internal,function,segment,structure,ui
import instruction as _instruction
from internal import utils

import idaapi

## properties
def h():
    '''Return the current address.'''
    return ui.current.address()
here = h    # alias

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
base=baseaddress

def range():
    '''Return the total address range of the database.'''
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
        '''Return number of bits of the database.'''
        if cls.info.is_64bit():
            return 64
        elif cls.info.is_32bit():
            return 32
        raise ValueError("{:s}.config.bits : Unknown bit size".format(__name__))

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
    return [segment.byName(s).startEA for s in segment.list()]

@utils.multicase()
def prev():
    '''Returns the previously defined address from the current one.'''
    return prev(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def prev(ea):
    '''Returns the previous address from ``ea``.'''
    return prev(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def prev(ea, count):
    return address.prev(ea, count)

# return the next address (instruction or data)
@utils.multicase()
def next():
    '''Returns the next defined address from the current one.'''
    return next(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def next(ea):
    '''Returns the next address from ``ea``.'''
    return next(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def next(ea, count):
    return address.next(ea, count)

@utils.multicase()
def prevdata():
    '''Returns the previous address that has data referencing it.'''
    return prevdata(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def prevdata(ea):
    '''Returns the previous address from ``ea`` that has data referencing it.'''
    return prevdata(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def prevdata(ea, count): return address.prevdata(ea, count)

@utils.multicase()
def nextdata():
    '''Returns the next address that has data referencing it.'''
    return nextdata(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def nextdata(ea):
    '''Returns the next address from ``ea`` that has data referencing it.'''
    return nextdata(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def nextdata(ea, count): return address.nextdata(ea, count)

@utils.multicase()
def prevcode():
    '''Returns the previous address that has code referencing it.'''
    return prevcode(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def prevcode(ea):
    '''Returns the previous address from ``ea`` that has code referencing it.'''
    return prevcode(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def prevcode(ea, count): return address.prevcode(ea, count)

@utils.multicase()
def nextcode():
    '''Returns the next address that has code referencing it.'''
    return nextcode(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def nextcode(ea):
    '''Returns the next address from ``ea`` that has code referencing it.'''
    return nextcode(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def nextcode(ea, count): return address.nextcode(ea, count)

@utils.multicase()
def prevref():
    '''Returns the previous address that has anything referencing it.'''
    return prevref(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def prevref(ea):
    '''Returns the previous address from ``ea`` that has anything referencing it.'''
    return prevref(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def prevref(ea, count): return address.prevref(ea, count)

@utils.multicase()
def nextref():
    '''Returns the next address that has anything referencing it.'''
    return nextref(ui.current.address(), 1)
@utils.multicase(ea=six.integer_types)
def nextref(ea):
    '''Returns the next address from ``ea`` that has anything referencing it.'''
    return nextref(ea, 1)
@utils.multicase(ea=six.integer_types, count=six.integer_types)
def nextref(ea, count): return address.nextref(ea, count)

# FIXME: multicase this
def prevreg(ea, *regs, **write):
    """Return the previous address containing an instruction that uses one of the specified registers ``regs``.
    If the keyword ``write`` is True, then only return the address if it's writing to the register.
    """
    return address.prevreg(ea, *regs, **write)
def nextreg(ea, *regs, **write):
    """Return next address containing an instruction that uses one of the specified registers ``regs``.
    If the keyword ``write`` is True, then only retur  the address if it's writing to the register.
    """
    return address.nextreg(ea, *regs, **write)

@utils.multicase()
def decode():
    '''Decode the instruction at the current address.'''
    return decode(ui.current.address())
@utils.multicase(ea=six.integer_types)
def decode(ea):
    '''Decode the instruction at the address ``ea``.'''
    return _instruction.decode(ea)

@utils.multicase()
def instruction():
    '''Return the instruction at the current address.'''
    return instruction(ui.current.address())
@utils.multicase(ea=six.integer_types)
def instruction(ea):
    '''Return the instruction at the specified address ``ea``.'''
    insn = idaapi.generate_disasm_line(ea)
    unformatted = idaapi.tag_remove(insn)
    nocomment = unformatted[:unformatted.rfind(';')]
    return reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')

@utils.multicase()
def disasm(**kwds):
    '''Disassemble the instructions at the current address.'''
    return disasm(ui.current.address(), **kwds)
@utils.multicase(ea=six.integer_types)
def disasm(ea, **kwds):
    """Disassemble the instructions at the address ``ea``.
    If the integer ``count`` is specified, then return ``count`` number of instructions.
    If the bool ``comments`` is True, then return the comments for each instruction as well.
    """
    res,count = [], kwds.get('count',1)
    while count > 0:
        insn = idaapi.generate_disasm_line(ea)
        unformatted = idaapi.tag_remove(insn)
        nocomment = unformatted[:unformatted.rfind(';')] if ';' in unformatted and kwds.get('comments',False) else unformatted
        res.append( '{:x}: {:s}'.format(ea, reduce(lambda t,x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')) )
        ea = next(ea)
        count -= 1
    return '\n'.join(res)

def read_block(start, end):
    '''Return the block of bytes from address ``start`` to ``end``.'''
    if start > end:
        start,end=end,start
    length = end-start

    if not contains(start):
        raise ValueError("{:s}.read_block : Address 0x{:x} is not in database".format(__name__, start))
    return idaapi.get_many_bytes(start, length)
getBlock = getblock = get_block = read_block

@utils.multicase(size=six.integer_types)
def read(size):
    '''Return ``size`` number of bytes from the current address.'''
    return read(ui.current.address(), size)
@utils.multicase(ea=six.integer_types, size=six.integer_types)
def read(ea, size):
    '''Return ``size`` number of bytes from address ``ea``.'''
    return idaapi.get_many_bytes(ea, size)

@utils.multicase(data=bytes)
def write(data, **kwds):
    '''Modify the database at the current address with the bytes ``data``.'''
    return write(ui.current.address, data, **kwds)
@utils.multicase(ea=six.integer_types, data=bytes)
def write(ea, data, **kwds):
    """Modify the database at address ``ea`` with the bytes ``data``
    If the bool ``original`` is specified, then modify what IDA considers the original bytes.
    """
    original = kwds.get('original', False)
    return idaapi.patch_many_bytes(ea, data) if original else idaapi.put_many_bytes(ea, data)

def iterate(start, end):
    '''Iterate through all the instruction and data boundaries from address ``start`` to ``end``.'''
    while start < end:
        yield start
        start = next(start)
    return

## searching by stuff
class search(object):
    @utils.multicase(string=bytes)
    @staticmethod
    def by_bytes(string, **kwds):
        '''Search through the database at the current address for the bytes specified by ``string``.'''
        return search.by_bytes(ui.current.address(), string, **kwds)
    @utils.multicase(ea=six.integer_types, string=bytes, reverse=bool)
    @staticmethod
    def by_bytes(ea, string, **kwds):
        """Search through the database at address ``ea`` for the bytes specified by ``string``.
        If ``reverse`` is specified as a bool, then search backwards from the given address.
        """
        flags = idaapi.SEARCH_UP if kwds.get('reverse', False) else idaapi.SEARCH_DOWN
        return idaapi.find_binary(ea, -1, ' '.join(str(ord(c)) for c in string), 10, idaapi.SEARCH_CASE | flags)
    byBytes = by_bytes

    @utils.multicase(string=basestring)
    @staticmethod
    def by_regex(string, **kwds):
        '''Search through the database at the current address for the regex matched by ``string``.'''
        return search.by_regex(ui.current.address(), string, **kwds)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @staticmethod
    def by_regex(ea, string, **kwds):
        """Search the database at address ``ea`` for the regex matched by ``string``.
        If ``reverse`` is specified as a bool, then search backwards from the given address.
        If ``sensitive`` is specified as bool, then perform a case-sensitive search.
        """
        flags = idaapi.SEARCH_UP if kwds.get('reverse',False) else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if kwds.get('sensitive',False) else 0
        return idaapi.find_binary(ea, -1, string, kwds.get('radix',16), flags)
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
    byName = by_name

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
        return cls.byName(here(), string)

def go(ea):
    '''Jump to the specified address at ``ea``.'''
    if isinstance(ea, basestring):
        ea = search.byName(None, ea)
    if not contains(ea):
        left,right=range()
        logging.warn("{:s}.go : Jumping to an invalid location 0x{:x}. (valid range is 0x{:x} - 0x{:x})".format(__name__, ea, left, right))
    idaapi.jumpto(ea)
    return ea

# returns the offset of ea from the baseaddress
@utils.multicase()
def offset():
    '''Return the current address converted to an offset from the base-address of the database.'''
    return offset(ui.current.address())
@utils.multicase(ea=six.integer_types)
def offset(ea):
    '''Return the address ``ea`` converted to an offset from the base-address of the database.'''
    return ea - baseaddress()

getoffset = offset
getOffset = getoffset
o = offset

def coof(offset):
    '''Convert the specified ``offset`` to an address in the database.'''
    return baseaddress()+offset

def goof(offset):
    '''Jump to the specified ``offset`` in the database.'''
    res = ui.current.address()-baseaddress()
    idaapi.jumpto(coof(offset))
    return res
gotooffset = goof

@utils.multicase()
def get_name():
    '''Return the name defined at the current address.'''
    return get_name(ui.current.address())
@utils.multicase(ea=six.integer_types)
def get_name(ea):
    '''Return the name defined at the address ``ea``.'''
    try: return tag(ea, 'name')
    except KeyError: pass
    return None

@utils.multicase(none=types.NoneType)
def set_name(none):
    '''Remove the name at the current address.'''
    return set_name(ui.current.address(), '')
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def set_name(ea, none):
    '''Remove the name defined at the address ``ea``.'''
    return set_name(ea, '')
@utils.multicase(string=basestring)
def set_name(string):
    '''Rename the current address to ``string``.'''
    return set_name(ui.current.address(), string)
@utils.multicase(ea=six.integer_types, string=basestring)
def set_name(ea, string):
    '''Rename the address specified by ``ea`` to ``string``.'''
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

    res,ok = get_name(ea),idaapi.set_name(ea, string or "", flags)

    try: tag(ea, 'name', string or None)
    except KeyError: pass

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
    res = ('{:x}'.format(_) if isinstance(_, six.integer_types) else _ for _ in res)
    return set_name(ea, '_'.join(res))
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def name(ea, none):
    '''Removes the name at address ``ea``.'''
    return set_name(ea, None)

def blocks(start, end):
    '''Returns each block between the addresses ``start`` and ``end``.'''
    block = start
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

# FIXME: The idaapi.is_basic_block_end api has got to be faster than doing it with pythonic xrefs.
if False:   # XXX: can't trust idaapi.is_basic_block_end(...)
    def blocks(start, end):
        '''Returns each block between the specified range of instructions.'''
        block = start
        for ea in iterate(start, end):
            nextea = next(ea)
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
def contains():
    '''Should always return True.'''
    return contains(ui.current.address())
@utils.multicase(ea=six.integer_types)
def contains(ea):
    '''Returns True if address ``ea`` is within the bounds of the database.'''
    l,r = config.bounds()
    return (ea >= l) and (ea < r)

@utils.multicase()
def erase():
    '''Remove all the defined tags at the current address.'''
    return erase(ui.current.address())
@utils.multicase(ea=six.integer_types)
def erase(ea):
    '''Remove all the defined tags at address ``ea``.'''
    for k in tag(ea): tag(ea, k, None)
    color(ea, None)

@utils.multicase()
def get_color():
    '''Return the rgb color at the current address.'''
    return get_color(ui.current.address())
@utils.multicase(ea=six.integer_types)
def get_color(ea):
    '''Return the rgb color at the address ``ea``.'''
    res = idaapi.get_item_color(ea)
    b,r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == 0xffffffff else (r<<16)|(res&0x00ff00)|b
@utils.multicase(none=types.NoneType)
def set_color(none):
    '''Remove the color at the current address.'''
    return set_color(ui.current.address(), None)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def set_color(ea, none):
    '''Remove the color at address ``ea``.'''
    return idaapi.set_item_color(ea, 0xffffffff)
@utils.multicase(ea=six.integer_types, rgb=int)
def set_color(ea, rgb):
    '''Set the color at address ``ea`` to ``rgb``.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    return idaapi.set_item_color(ea, (b<<16)|(rgb&0x00ff00)|r)

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
def get_comment(**kwds):
    '''Return the comment at the current address.'''
    return get_comment(ui.current.address(), **kwds)
@utils.multicase(ea=six.integer_types)
def get_comment(ea, **kwds):
    """Return the comment at the address ``ea``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    return idaapi.get_cmt(ea, kwds.get('repeatable', False))
@utils.multicase(comment=basestring)
def set_comment(comment, **kwds):
    '''Set the comment at the current address to the string ``comment``.'''
    return set_comment(ui.current.address(), comment, **kwds)
@utils.multicase(ea=six.integer_types, comment=basestring)
def set_comment(ea, comment, **kwds):
    """Set the comment at address ``ea`` to ``comment``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    return idaapi.set_cmt(ea, comment, kwds.get('repeatable', False))

@utils.multicase()
def comment(**kwds):
    '''Return the comment at the current address.'''
    return get_comment(ui.current.address(), **kwds)
@utils.multicase(ea=six.integer_types)
def comment(ea, **kwds):
    """Return the comment at the address ``ea``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    return get_comment(ea, **kwds)
@utils.multicase(comment=basestring)
def comment(comment, **kwds):
    '''Set the comment at the current address to ``comment``.'''
    return set_comment(ui.current.address(), comment, **kwds)
@utils.multicase(ea=six.integer_types, comment=basestring)
def comment(ea, comment, **kwds):
    """Set the comment at address ``ea`` to ``comment``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    return set_comment(ea, comment, **kwds)

@utils.multicase()
def make_entry():
    '''Makes an entry-point at the current address.'''
    ea,entryname,ordinal = ui.current.address(), name(ui.current.address()), idaapi.get_entry_qty()
    if entryname is None:
        raise ValueError('{:s}.make_entry : Unable to determine name at address 0x{:x}'.format(__name__, ea))
    return make_entry(ea, entryname, ordinal)
@utils.multicase(ea=six.integer_types)
def make_entry(ea):
    '''Makes an entry-point at the specified address ``ea``.'''
    entryname,ordinal = name(ea), idaapi.get_entry_qty()
    if entryname is None:
        raise ValueError('{:s}.make_entry : Unable to determine name at address 0x{:x}'.format(__name__, ea))
    return make_entry(ea, entryname, ordinal)
@utils.multicase(name=basestring)
def make_entry(name):
    '''Adds an entry point to the database named ``name`` using the next available index as the ordinal.'''
    return make_entry(ui.current.address(), name, idaapi.get_entry_qty())
@utils.multicase(ea=six.integer_types, name=basestring)
def make_entry(ea, name):
    '''Makes the specified address ``ea`` an entry-point named according to ``name``.'''
    ordinal = idaapi.get_entry_qty()
    return make_entry(ea, name, ordinal)
@utils.multicase(name=basestring, ordinal=six.integer_types)
def make_entry(name, ordinal):
    '''Adds an entry point to the database named ``name`` with ``ordinal`` as it's index.'''
    return make_entry(ui.current.address(), name, ordinal)
@utils.multicase(ea=six.integer_types, name=basestring, ordinal=six.integer_types)
def make_entry(ea, name, ordinal):
    '''Adds an entry point at ``ea`` with the specified ``name`` and ``ordinal``.'''
    return idaapi.add_entry(ordinal, ea, name, 0)

#try:
#    ## tag data storage using a lisp-like syntax
#    import store.query as query
#    import store
#
#    datastore = store.ida
#    def tag(ea, *args, **kwds):
#        '''tag(ea, key?, value?) -> fetches/stores a tag from specified address'''
#        try:
#            context = function.top(ea)
#
#        except ValueError:
#            context = None
#
#        if len(args) == 0 and len(kwds) == 0:
#            result = datastore.address(context).select(query.address(ea))
#            try:
#                result = result[address]
#            except:
#                result = {}
#            return result
#
#        elif len(args) == 1:
#            key, = args
#            result = datastore.address(context).select(query.address(ea), query.attribute(key))
#            try:
#                result = result[address][key]
#            except:
#                raise KeyError( (hex(ea),key) )
#                result = None
#            return result
#
#        if len(args) > 0:
#            key,value = args
#            kwds.update({key:value})
#        return datastore.address(context).address(ea).set(**kwds)
#
#    def __select(q):
#        for x in functions():
#            x = function.top(x)
#            if q.has(function.tag(x)):
#                yield x
#            continue
#        return
#
#    def select(*q, **where):
#        if where:
#            print "database.select's kwd arguments have been deprecated in favor of query"
#        result = list(q)
#        for k,v in where.iteritems():
#            if v is None:
#                result.append( query.hasattr(k) )
#                continue
#            result.append( query.hasvalue(k,v) )
#        return __select( query._and(*result) )
#
#except ImportError:
#    ## tag data storage hack using magically syntaxed comments
#    def tag_read(ea, key=None, repeatable=0):
#        res = idaapi.get_cmt(ea, int(bool(repeatable)))
#        dict = internal.comment.toDict(res)
#        name = idaapi.get_true_name(ea)
#        if name: dict.setdefault('name', name)
#        return dict if key is None else dict[key]
#
#    def tag_write(ea, key, value, repeatable=0):
#        dict = tag_read(ea, repeatable=repeatable)
#        dict[key] = value
#        res = internal.comment.toString(dict)
#        return idaapi.set_cmt(ea, res, int(bool(repeatable)))
#
#    def tag(ea, *args, **kwds):
#        '''tag(ea, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''
#        # if not in a function, it could be a global, so make the tag repeatable
#        #   otherwise, use a non-repeatable comment
#        ea = int(ea)
#        try:
#            func = function.by_address(ea)
#        except Exception:
#            func = None
#        kwds.setdefault('repeatable', True if func is None else False)
#
#        if len(args) < 2:
#            return tag_read(ea, *args, **kwds)
#
#        key,value = args
#        result = tag_write(ea, key, value, **kwds)
#
#        # add tag-name to function's cache
#        if func is not None and value is not None and key is not '__tags__':
#            top = func.startEA
#            tags = function.tags(ea)
#            tags.add(key)
#            tag_write(top, '__tags__', tags)
#
#        return result
#
#    def select(*tags, **boolean):
#        '''Fetch all the functions containing the specified tags within it's declaration'''
#        boolean = dict((k,set(v) if v.__class__ is tuple else set((v,))) for k,v in boolean.viewitems())
#        if tags:
#            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))
#
#        if not boolean:
#            for ea in functions():
#                res = tag(ea)
#                if res: yield ea, res
#            return
#
#        for ea in functions():
#            res,d = {},function.tag(ea)
#
#            Or = boolean.get('Or', set())
#            res.update((k,v) for k,v in d.iteritems() if k in Or)
#
#            And = boolean.get('And', set())
#            if And:
#                if And.intersection(d.viewkeys()) == And:
#                    res.update((k,v) for k,v in d.iteritems() if k in And)
#                else: continue
#            if res: yield ea,res
#        return
#
#    def selectcontents(*tags, **boolean):
#        '''Fetch all the functions containing the specified tags within it's contents'''
#        boolean = dict((k,set(v) if v.__class__ is tuple else set((v,))) for k,v in boolean.viewitems())
#        if tags:
#            boolean.setdefault('And', set(boolean.get('And',set())).union(set(tags) if len(tags) > 1 else set(tags,)))
#
#        if not boolean:
#            for ea in functions():
#                res = function.tags(ea)
#                if res: yield ea, res
#            return
#
#        for ea in functions():
#            res,d = set(),function.tags(ea)
#
#            Or = boolean.get('Or', set())
#            res.update(Or.intersection(d))
#
#            And = boolean.get('And', set())
#            if And:
#                if And.intersection(d) == And:
#                    res.update(And)
#                else: continue
#            if res: yield ea,res
#        return
#
#if False:
#    def select_equal(ea, **matches):
#        for ea,res in select(ea, And=matches.keys()):
#            if all(k in res and matches[k] == res[k] for k in matches.items()):
#                yield ea,res
#            continue
#        return
#
#    def selectcontents_equal(ea, **matches):
#        for ea,res in selectcontents(ea, And=matches.keys()):
#            if all(k in res and matches[k] == res[k] for k in matches.items()):
#                yield ea,res
#            continue
#        return

@utils.multicase(ea=six.integer_types, key=basestring)
def tag_read(ea, key):
    '''Returns the tag identified by ``key`` from address ``ea``.'''
    res = comment(ea, repeatable=0)
    dict = internal.comment.toDict(res)
    aname = idaapi.get_true_name(ea)
    if aname: dict['name'] = aname
    return dict[key]
@utils.multicase(ea=six.integer_types)
def tag_read(ea):
    '''Returns all the tags defined at address ``ea``.'''
    res = comment(ea, repeatable=0)
    dict = internal.comment.toDict(res)
    aname = idaapi.get_true_name(ea)
    if aname: dict['name'] = aname
    return dict
@utils.multicase()
def tag_read():
    '''Returns all the tags at the current address.'''
    return tag_read(ui.current.address())
@utils.multicase(key=basestring)
def tag_read(key):
    '''Returns the tag identified by ``key`` at the current addres.'''
    return tag_read(ui.current.address(), key)

@utils.multicase(key=basestring)
def tag_write(key, value):
    '''Set the tag ``key`` to ``value`` at the current address.'''
    return tag_write(ui.current.address(), key, value, **kwds)
@utils.multicase(key=basestring, none=types.NoneType)
def tag_write(key, none):
    '''Removes the tag specified by ``key`` from the current address ``ea``.'''
    return tag_write(ui.current.address(), key, value, **kwds)
@utils.multicase(ea=six.integer_types, key=basestring)
def tag_write(ea, key, value):
    '''Set the tag ``key`` to ``value`` at the address ``ea``.'''
    if value is None:
        raise AssertionError('{:s}.tag_write : Tried to set tag {!r} to an invalid value.'.format(__name__, key))

    state = internal.comment.toDict(comment(ea, repeatable=0))
    res,state[key] = state.get(key,None),value

    try: func = function.by_address(ea)
    except: pass
    else: comment(func.startEA, internal.comment.toString({'__tags__':function.tags(func.startEA).union((key,))}), repeatable=0)

    # FIXME: keep a reference count of the tags used inside the function
    #if func is not None:
    #    funcstate = internal.comment.toDict(comment(func.startEA, repeatable=0))
    #    count = funcstate.setdefault(key, 0)
    #    if value is None:
    #        count = 0 if count > 0 else (count-1)
    #        if count == 0: del(funcstate[key])
    #    else:
    #        count += 1; funcstate[key] = count
    #    comment(func.startEA, internal.comment.toString({'__tags__':funcstate}), repeatable=0)
    comment(ea, internal.comment.toString(state), repeatable=0)
    return res
@utils.multicase(ea=six.integer_types, key=basestring, none=types.NoneType)
def tag_write(ea, key, none):
    '''Removes the tag specified by ``key`` from the address ``ea``.'''
    state = internal.comment.toDict(comment(ea, repeatable=0))
    res = state.pop(key)
    comment(ea, internal.comment.toString(state), repeatable=0)
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
# FIXME: multicase this
# FIXME: document this properly
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

# FIXME: consolidate the boolean querying logic into the utils module
# FIXME: multicase this
# FIXME: document this properly
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
selectcontent = selectcontents

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

getImportModules = imports.modules
getImports = imports.list

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
        '''Return the aligned address in the database from the address ``ea``.'''
        return idaapi.get_item_head(ea)

    @utils.multicase()
    @classmethod
    def prev(cls):
        '''Return the previously defined address from the current one in the database.'''
        return cls.prev(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prev(cls, ea):
        '''Return the previously defined address from the address ``ea``.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prev(cls, ea, count):
        res = idaapi.prev_head(ea,0)
        return cls.prev(res, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def next(cls):
        '''Return the next defined address from the current one in the database.'''
        return cls.next(ui.current.address(), 1)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def next(cls, ea):
        '''Return the next defined address from the address ``ea``.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def next(cls, ea, count):
        res = idaapi.next_head(ea, idaapi.BADADDR)
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

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevreg(cls, ea, *regs, **kwds):
        """Return the previous address from ``ea`` containing an instruction that uses one of the specified registers ``regs``.
        If the keyword ``write`` is True, then only return the address if it's writing to the register.
        """
        count = kwds.get('count',1)
        write = kwds.get('write',False)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg.byName(r).related,itertools.imap(_instruction.reg.byName,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and ('w' in st if write else True):
                    return True
                if t == 'opt_phrase' and not write:
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        res = cls.walk(cls.prev(ea), cls.prev, lambda ea: not uses_register(ea, regs))
        return cls.prevreg(res, *regs, count=count-1) if count > 1 else res
    @utils.multicase()
    @classmethod
    def prevreg(cls, *regs, **kwds):
        """Return the previous address containing an instruction that used one of the specified registers ``regs``."""
        return cls.prevreg(ui.current.address(), *regs, **kwds)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextreg(cls, ea, *regs, **kwds):
        """Return the next address from ``ea`` containing an instruction that uses one of the specified registers ``regs``.
        If the keyword ``write`` is True, then only return the address if it's writing to the register.
        """
        count = kwds.get('count',1)
        write = kwds.get('write',False)
        def uses_register(ea, regs):
            res = [(_instruction.op_type(ea,x),_instruction.op_value(ea,x),_instruction.op_state(ea,x)) for x in xrange(_instruction.ops_count(ea)) if _instruction.op_type(ea,x) in ('opt_reg','opt_phrase')]
            match = lambda r,regs: itertools.imap(_instruction.reg.byName(r).related,itertools.imap(_instruction.reg.byName,regs))
            for t,p,st in res:
                if t == 'opt_reg' and any(match(p,regs)) and ('w' in st if write else True):
                    return True
                if t == 'opt_phrase' and not write:
                    _,(base,index,_) = p
                    if (base and any(match(base,regs))) or (index and any(match(index,regs))):
                        return True
                continue
            return False
        res = cls.walk(ea, cls.next, lambda ea: not uses_register(ea, regs))
        return cls.nextreg(cls.next(res), *regs, count=count-1) if count > 1 else res
    @utils.multicase()
    @classmethod
    def nextreg(cls, *regs, **kwds):
        '''Return the next address containing an instruction that used one of the specified registers ``regs``.'''
        return cls.nextreg(ui.current.address(), *regs, **kwds)

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
        tagname = tagname.get('tag', None)
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

class flow(address):
    @staticmethod
    def walk(ea, next, match):
        '''Used internally. Please see .iterate() instead.'''
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
        isStop = lambda ea: _instruction.feature(ea) & idaapi.CF_STOP == idaapi.CF_STOP
        refs = xref.up(ea)
        if len(refs) > 1 and isStop(address.prev(ea)):
            logging.fatal("{:s}.flow.prev : 0x{:x} : Unable to determine previous address due to multiple xrefs being available : {:s}".format(__name__, ea, ', '.join(__builtin__.map(hex,refs))))
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
    # FIXME: multicase this
    def __new__(cls, ea):
        '''Return the type at the address specified by ``ea``.'''
        module,F = idaapi,(idaapi.getFlags(ea)&idaapi.DT_TYPE)
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
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_CODE

    @utils.multicase()
    @staticmethod
    def is_data():
        '''Return True if the current address is marked as data.'''
        return type.is_data(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_data(ea):
        '''Return True if the address specified by ``ea`` is marked as data.'''
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_DATA

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
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_UNK

    @utils.multicase()
    @staticmethod
    def is_head():
        return type.is_head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_head(ea):
        '''Return True if the address ``ea`` is aligned to a definition in the database.'''
        return idaapi.getFlags(ea)&idaapi.FF_DATA != 0

    @utils.multicase()
    @staticmethod
    def is_tail():
        return type.is_tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_tail(ea):
        '''Return True if the address ``ea`` is not-aligned to a definition in the database.'''
        return idaapi.getFlags(ea)&idaapi.MS_CLS == idaapi.FF_TAIL

    @utils.multicase()
    @staticmethod
    def is_align():
        '''Return True if the current address is defined as an alignment.'''
        return type.is_align(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_align(ea):
        '''Return True if the address at ``ea`` is defined as an alignment.'''
        return idaapi.isAlign(idaapi.getFlags(ea))

    @utils.multicase()
    @staticmethod
    def has_comment():
        '''Return True if the current address is commented.'''
        return type.has_comment(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_comment(ea):
        '''Return True if the address at ``ea`` is commented.'''
        return bool(idaapi.getFlags(ea) & idaapi.FF_COMM == idaapi.FF_COMM)

    @utils.multicase()
    @staticmethod
    def has_reference():
        '''Return True if the current address has a reference.'''
        return type.has_reference(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_reference(ea):
        '''Return True if the address at ``ea`` has a reference.'''
        return bool(idaapi.getFlags(ea) & idaapi.FF_REF == idaapi.FF_REF)

    @utils.multicase()
    @staticmethod
    def has_name():
        '''Return True if the current address has a name.'''
        return type.has_name(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_name(ea):
        '''Return True if the address at ``ea`` has a name.'''
        return idaapi.has_any_name(idaapi.getFlags(ea))

    @utils.multicase()
    @staticmethod
    def has_customname():
        '''Return True if the current address has a custom-name.'''
        return type.has_customname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_customname(ea):
        '''Return True if the address at ``ea`` has a custom-name.'''
        return bool(idaapi.getFlags(ea) & idaapi.FF_NAME == idaapi.FF_NAME)

    @utils.multicase()
    @staticmethod
    def has_dummyname():
        '''Return True if the current address has a dummy-name.'''
        return type.has_dummyname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_dummyname(ea):
        '''Return True if the address at ``ea`` has a dummy-name.'''
        return bool(idaapi.getFlags(ea) & idaapi.FF_LABL == idaapi.FF_LABL)

    @utils.multicase()
    @staticmethod
    def has_autoname():
        '''Return True if the current address is automatically named.'''
        return type.has_autoname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_autoname(ea):
        '''Return True if the address ``ea`` is automatically named.'''
        return idaapi.has_auto_name(idaapi.getFlags(ea))

    @utils.multicase()
    @staticmethod
    def has_publicname():
        '''Return True if the current address has a public name.'''
        return type.has_publicname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_publicname(ea):
        '''Return True if the address at ``ea`` has a public name.'''
        return idaapi.is_public_name(ea)

    @utils.multicase()
    @staticmethod
    def has_weakname():
        '''Return True if the current address has a weakly-typed name.'''
        return type.has_weakname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_weakname(ea):
        '''Return True if the address at ``ea`` has a weakly-typed name.'''
        return idaapi.is_weak_name(ea)

    @utils.multicase()
    @staticmethod
    def has_listedname():
        '''Return True if the current address has a name that is listed.'''
        return type.has_listedname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_listedname(ea):
        '''Return True if the address at ``ea`` has a name that is listed.'''
        return idaapi.is_in_nlist(ea)

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
        # FIXME: finish multicasing this
        def __new__(cls, ea):
            '''Return the values of the array at address ``ea``.'''
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
            return idaapi.get_item_size(ea)

    class structure(object):
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

        def __new__(cls, ea):
            try: return cls.__getinsn(ea)
            except TypeError: pass
            try: return cls.__getarray(ea)
            except TypeError: pass
            try: return cls.__getlabel(ea)
            except TypeError: pass
            raise TypeError("{:s}.type.switch : Unable to instantiate a switch_info_ex_t : 0x{:x}".format(__name__, ea))
t = type

## information about a given address
is_code = type.is_code
is_data = type.is_data
is_unknown = type.is_unknown
is_head = type.is_head
is_tail = type.is_tail
is_align = type.is_align
getType = get_type = type

# arrays
getSize = get_size = type.array.element
getArrayLength = get_arraylength = type.array.length

# structures
getStructureId = get_strucid = get_structureid = type.structure.id

class xref(object):
    @staticmethod
    def iterate(ea, start, next):
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
    c=code

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
    d=data

    @utils.multicase()
    @staticmethod
    def data_down():
        '''Return all the data xrefs that are referenced by the current address.'''
        return xref.data_down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_down(ea):
        '''Return all the data xrefs that are referenced by the address ``ea``.'''
        return list(xref.data(ea, True))
    dd = data_down

    @utils.multicase()
    @staticmethod
    def data_up():
        '''Return all the data xrefs that refer to the current address.'''
        return xref.data_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_up(ea):
        '''Return all the data xrefs that refer to the address ``ea``.'''
        return list(xref.data(ea, False))
    du=data_up

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
        return list(result)
    cd = code_down

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
        return list(result)
    cu=code_up

    @utils.multicase()
    @staticmethod
    def up():
        '''Return all the references that refer to the current address.'''
        return xref.up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def up(ea):
        '''Return all the references that refer to the address ``ea``.'''
        return list(set(xref.data_up(ea) + xref.code_up(ea)))
    u = up

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
        return list(set(xref.data_down(ea) + xref.code_down(ea)))
    d=down

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_code(target, **kwds):
        '''Add a code reference from the current address to ``target``.'''
        return xref.add_code(ui.current.address(), target, **kwds)
    @utils.multicase(six=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_code(ea, target, **kwds):
        """Add a code reference from address ``ea`` to ``target``.
        If the bool ``isCall`` is specified, then specify this ref as a function call.
        """
        isCall = kwds.get('isCall', False)
        if abs(target-ea) > 2**(config.bits()/2):
            flowtype = idaapi.fl_CF if isCall else idaapi.fl_JF
        else:
            flowtype = idaapi.fl_CN if isCall else idaapi.fl_JN
        idaapi.add_cref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.code_down(ea)

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_data(target, **kwds):
        '''Add a data reference from the current address to ``target``.'''
        return xref.add_data(ui.current.address(), target, **kwds)
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_data(ea, target, **kwds):
        """Add a data reference from the address ``ea`` to ``target``.
        If the bool ``write`` is specified, then specify this ref is writing to the target.
        """
        write = kwds.get('write', False)
        flowtype = idaapi.dr_W if write else idaapi.dr_R
        idaapi.add_dref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.data_down(ea)

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_code(ea):
        '''Delete _all_ the code references at ``ea``.'''
        [ idaapi.del_cref(ea, target, 0) for target in xref.code_down(ea) ]
        return False if len(xref.code_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_code(ea, target):
        '''Delete any code references at ``ea`` that point to address ``target``.'''
        idaapi.del_cref(ea, target, 0)
        return target not in xref.code_down(ea)

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_data(ea):
        '''Delete _all_ the data references at ``ea``.'''
        [ idaapi.del_dref(ea, target) for target in xref.data_down(ea) ]
        return False if len(xref.data_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_data(ea, target=None):
        '''Delete any data references at ``ea`` that point to address ``target``.'''
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

# create/erase a mark at the specified address in the .idb
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
    tag(ea, 'mark', None)
    color(ea, None)
    return marks.remove(ea)
@utils.multicase(ea=six.integer_types, description=basestring)
def mark(ea, description):
    '''Create a mark at address ``ea`` with the given ``description``.'''
    return marks.new(ea, description)

class marks(object):
    MAX_SLOT_COUNT = 0x400
    table = {}

    def __new__(cls):
        '''Yields each of the marked positions within the database.'''
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
        ea = address.head(ea)
        try:
            idx = cls.get_slotindex(ea)
            ea,comm = cls.by_index(idx)
            logging.warn("{:s}.marks.new : Replacing mark {:d} at 0x{:x} : {!r} -> {!r}".format(__name__, idx, ea, comm, description))
        except KeyError:
            idx = cls.length()
            logging.info("{:s}.marks.new : Creating mark {:d} at 0x{:x} : {!r}".format(__name__, idx, ea, description))

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
        ea = address.head(ea)
        idx = cls.get_slotindex(ea)
        descr = cls.location().markdesc(idx)

        res = cls.location(ea=idaapi.BADADDR)
        res.mark(idx, "", "")

        logging.warn("{:s}.marks.remove : Removed mark {:d} at 0x{:x} : {!r}".format(__name__, idx, ea, descr))
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
        return len(list(cls.iterate()))

    @classmethod
    def location(cls, **attrs):
        '''Return a location_t object with the specified attributes.'''
        res = idaapi.curloc()
        list(itertools.starmap(functools.partial(setattr, res), attrs.items()))
        return res

    @classmethod
    def by_index(cls, index):
        '''Return the mark at the specified ``index`` in the mark list.'''
        if 0 <= index < cls.MAX_SLOT_COUNT:
            return (cls.get_slotaddress(index), cls.location().markdesc(index))
        raise KeyError("{:s}.marks.by_index : Mark slot index is out of bounds : {:x}".format(__name__, ('{:d} < 0'.format(index)) if index < 0 else ('{:d} >= MAX_SLOT_COUNT'.format(index))))
    byIndex = by_index

    @utils.multicase()
    @classmethod
    def by_address(cls):
        '''Return the mark at the current address.'''
        return cls.by_address(ui.current.address())
    @utils.multicase()
    @classmethod
    def by_address(cls, ea):
        '''Return the mark at the given address ``ea``.'''
        res = address.head(ea)
        return cls.by_index(cls.get_slotindex(res))
    byAddress = by_address

    @utils.multicase()
    @classmethod
    def find_slotaddress(cls): return cls.find_slotaddress(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def find_slotaddress(cls, ea):
        ea = address.head(ea)
        res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
        res, iterable = itertools.tee(itertools.imap(cls.get_slotaddress, res))
        try:
            count = len(list(itertools.takewhile(lambda n: n != ea, res)))
        except IndexError:
            raise KeyError(ea)
        list(itertools.islice(iterable, count))
        if iterable.next() != ea:
            raise KeyError(ea)
        return count
    findSlotAddress = find_slotaddress

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_slotindex(cls):
        '''Get the index of the mark at the current address.'''
        return cls.get_slotindex(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_slotindex(cls, ea):
        '''Get the index of the mark at address ``ea``.'''
        ea = address.head(ea)
        return cls.table.get(ea, cls.find_slotaddress(ea))
    getSlotIndex = get_slotindex

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
