r"""
Segment module

This module provides a number of tools that can be used to enumerate
or work with segments within a database.

The base argument type for some of the utilities within this module
is the ``idaapi.segment_t``. This type is interchangeable with the
address or the segment name and so either can be used to identify a
segment.

When listing or enumerating segments there are different types that
one can use in order to filter or match them. These types are as
follows:

    `name` - Filter the segments by a name or a list of names
    `like` - Filter the segment names according to a glob
    `regex` - Filter the function names according to a regular-expression
    `iregex` - Filter the function names according to a case-insensitive regular-expression
    `index` - Filter the segments by an index or a list of indices
    `identifier` - Filter the segments by an integer identifier or a list of identifiers
    `selector` - Filter the segments by a selector or a list of selectors
    `greater` or `ge` - Filter the segments for any after the specified address (inclusive)
    `gt` - Filter the segments for any after the specified address (exclusive)
    `less` or `le` - Filter the segments for any before the specified address (inclusive)
    `lt` - Filter the segments for any before the specified address (exclusive)
    `predicate` - Filter the segments by passing their ``idaapi.segment_t`` to a callable

Some examples of using these keywords are as follows::

    > for l, r in database.segments(): ...
    > database.segments.list(regex=r'\.r?data')
    > iterable = database.segments.iterate(like='*text*')
    > result = database.segments.search(greater=0x401000)

"""

import functools, operator, itertools, logging, builtins, os, six
import math, re, fnmatch

import database, ui
import idaapi, internal
from internal import utils, interface, types, exceptions as E
logging = logging.getLogger(__name__)

# FIXME: there is definitely availability for adding more matchers. we haven't
#        implemented any of them because filtering segments is not that useful.
__matcher__ = utils.matcher()
__matcher__.combinator('iregex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of)
__matcher__.combinator('regex', utils.fcompose(re.compile, operator.attrgetter('match')), idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of)
__matcher__.attribute('index', 'index')     # XXX: dirty attribute added to segment_t
__matcher__.attribute('identifier', 'name'), __matcher__.attribute('id', 'name')
__matcher__.attribute('selector', 'sel')
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of)
__matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(utils.itermap, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of, operator.methodcaller('lower'))

if idaapi.__version__ < 7.0:
    __matcher__.boolean('greater', operator.le, 'endEA')
    __matcher__.boolean('gt', operator.lt, 'endEA')
    __matcher__.boolean('less', operator.ge, 'startEA')
    __matcher__.boolean('lt', operator.gt, 'startEA')
else:
    __matcher__.boolean('greater', operator.le, 'end_ea')
    __matcher__.boolean('gt', operator.lt, 'end_ea')
    __matcher__.boolean('less', operator.ge, 'start_ea')
    __matcher__.boolean('lt', operator.gt, 'start_ea')
__matcher__.predicate('predicate'), __matcher__.predicate('pred')

## enumerating
@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'iregex', 'regex', 'like', 'name')
def __iterate__(string, **type):
    '''Iterate through each segment whose name matches the glob specified by `string`.'''
    type['like'] = string
    return __iterate__(**type)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def __iterate__(**type):
    '''Iterate through each segment defined in the database that match the keywords specified by `type`.'''
    def newsegment(index):
        seg = idaapi.getnseg(index)
        seg.index, _ = index, ui.navigation.set(interface.range.start(seg))
        return seg
    iterable = (newsegment(index) for index in builtins.range(idaapi.get_segm_qty()))
    for key, value in (type or {'predicate': utils.fconstant(True)}).items():
        iterable = (item for item in __matcher__.match(key, value, iterable))
    for item in iterable: yield item

@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'iregex', 'regex', 'like', 'name')
def list(string, **type):
    '''List all of the segments whose name matches the glob specified by `string`.'''
    type['like'] = string
    return list(**type)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def list(**type):
    '''List all of the segments in the database that match the keyword specified by `type`.'''
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    listable = []

    # Set some reasonable defaults
    maxindex = maxaddr = maxsize = maxname = 0

    # First pass through our segments to grab lengths of displayed fields
    for seg in __iterate__(**type):
        maxindex = max(seg.index, maxindex)
        maxaddr = max(interface.range.end(seg), maxaddr)
        maxsize = max(seg.size(), maxsize)
        maxname = max(len(get_segment_name(seg)), maxname)

        listable.append(seg)

    # Collect the maximum sizes for everything from the first pass. We have
    # to use different algorithms as due to Python's issues with imprecision,
    # the resulting number of digits will vary depending on what base is
    # actually being used when calculating the logarithm.
    cindex = utils.string.digits(maxindex, 10)
    caddr, csize = (utils.string.digits(item, 10) for item in [maxaddr, maxsize])
    permissions = [(idaapi.SEGPERM_READ, 'r'), (idaapi.SEGPERM_WRITE, 'w'), (idaapi.SEGPERM_EXEC, 'x')]

    # List all the fields for each segment that we've aggregated
    for seg in listable:
        comment, _ = idaapi.get_segment_cmt(seg, 0) or idaapi.get_segment_cmt(seg, 1), ui.navigation.set(interface.range.start(seg))
        rwx = ''.join(bit if seg.perm & perm else '-' for perm, bit in permissions)
        six.print_(u"[{:{:d}d}] {:#0{:d}x}..{:#0{:d}x} : {:s} : {:>{:d}s} : {:<+#{:d}x} : sel:{:04x} flags:{:02x}{:s}".format(seg.index, math.trunc(cindex), interface.range.start(seg), 2 + math.trunc(caddr), interface.range.end(seg), 2 + math.trunc(caddr), rwx, utils.string.of(get_segment_name(seg)), maxname, seg.size(), 3 + math.trunc(csize), seg.sel, seg.flags, u"// {:s}".format(utils.string.of(comment)) if comment else ''))
    return

## searching
@utils.multicase()
def has():
    '''Returns true if the current address is within any segment.'''
    return has(ui.current.address())
@utils.multicase(ea=types.integer)
def has(ea):
    '''Returns true if the address `ea` is within any segment.'''
    return any(interface.range.within(ea, seg) for seg in __iterate__())
@utils.multicase(name=types.string)
def has(name, *suffix):
    '''Returns true if the segment with the given `name` exists.'''
    fullname = (name,) + suffix
    string = interface.tuplename(*fullname)
    return idaapi.get_segm_by_name(utils.string.to(string)) is not None
within = utils.alias(has)

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def by_name(name, *suffix):
    '''Return the segment with the given `name`.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    seg = idaapi.get_segm_by_name(utils.string.to(string))
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_name({!r}) : Unable to find the segment with the specified name.".format(__name__, res if suffix else string))
    return seg
byname = utils.alias(by_name)
def by_selector(selector):
    '''Return the segment associated with `selector`.'''
    seg = idaapi.get_segm_by_sel(selector)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_selector({:#x}) : Unable to locate the segment with the specified selector.".format(__name__, selector))
    return seg
byselector = utils.alias(by_selector)
@utils.multicase(ea=types.integer)
def by_address(ea):
    '''Return the segment that contains the specified `ea`.'''
    seg = idaapi.getseg(interface.address.within(ea))
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_address({:#x}) : Unable to locate segment containing the specified address.".format(__name__, ea))
    return seg
byaddress = utils.alias(by_address)
@utils.multicase(index=types.integer)
def by_index(index):
    '''Return the segment at the specified `index``.'''
    seg = idaapi.getnseg(index)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_index({:d}) : Unable to locate segment at the specified index.".format(__name__, index))
    return seg
byindex = utils.alias(by_index)
@utils.multicase(segment=idaapi.segment_t)
def by(segment):
    '''Return a segment by its ``idaapi.segment_t``.'''
    ea, _ = interface.range.bounds(segment)
    return by_address(ea)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name')
def by(name, *suffix):
    '''Return the segment by its `name`.'''
    return by_name(name, *suffix)
@utils.multicase(ea=types.integer)
def by(ea):
    '''Return the segment containing the address `ea`.'''
    return by_address(ea)
@utils.multicase(bounds=interface.bounds_t)
def by(bounds):
    '''Return the segment containing the specified `bounds`.'''
    ea, _ = bounds
    return by_address(ea)
@utils.multicase()
def by():
    '''Return the current segment.'''
    return ui.current.segment()
@utils.multicase()
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def by(**type):
    '''Return the segment matching the specified keywords in `type`.'''
    searchstring = utils.string.kwargs(type)
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    listable = [item for item in __iterate__(**type)]
    if len(listable) > 1:
        maxaddr = max(builtins.map(interface.range.end, listable) if listable else [1])
        caddr = utils.string.digits(maxaddr, 16)
        permissions = [(idaapi.SEGPERM_READ, 'r'), (idaapi.SEGPERM_WRITE, 'w'), (idaapi.SEGPERM_EXEC, 'x')]
        messages = ((u"[{:d}] {:0{:d}x}..{:0{:d}x} : {:s} : {:s} {:+#x} : sel:{:04x} flags:{:02x}".format(seg.index, interface.range.start(seg), math.trunc(caddr), interface.range.end(seg), math.trunc(caddr), ''.join(bit if seg.perm & perm else '-' for perm, bit in permissions), utils.string.of(get_segment_name(seg)), seg.size(), seg.sel, seg.flags)) for seg in listable)
        [ logging.info(msg) for msg in messages ]
        logging.warning(u"{:s}.by({:s}) : Found {:d} matching results. Returning the first segment at index {:d} from {:0{:d}x}<>{:0{:d}x} with the name {:s} and size {:+#x}.".format(__name__, searchstring, len(listable), listable[0].index, interface.range.start(listable[0]), math.trunc(caddr), interface.range.end(listable[0]), math.trunc(caddr), utils.string.of(get_segment_name(listable[0])), listable[0].size()))

    iterable = (item for item in listable)
    res = builtins.next(iterable, None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.by({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix', 'regex', 'iregex', 'like')
def search(name, *suffix, **type):
    '''Search through all the segments and return the first one matching the glob `name`.'''
    res = (name,) + suffix
    type['like'] = interface.tuplename(*res)
    return by(**type)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def search(**type):
    '''Search through all the segments and return the first one that matches the keyword specified by `type`.'''
    return by(**type)

## properties
@utils.multicase()
def bounds():
    '''Return the bounds of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.bounds() : Unable to locate the current segment.".format(__name__))
    return interface.range.bounds(seg)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def bounds(segment):
    '''Return the bounds of the segment specified by `segment`.'''
    seg = by(segment)
    return interface.range.bounds(seg)
range = utils.alias(bounds)

@utils.multicase()
def iterate():
    '''Iterate through all of the addresses within the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.iterate() : Unable to locate the current segment.".format(__name__))
    return iterate(seg)
@utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
def iterate(segment):
    '''Iterate through all of the addresses within the specified `segment`.'''
    seg = by(segment)
    return iterate(seg)
@utils.multicase(segment=idaapi.segment_t)
def iterate(segment):
    '''Iterate through all of the addresses within the ``idaapi.segment_t`` represented by `segment`.'''
    left, right = interface.range.unpack(segment)
    for ea in database.address.iterate(left, right):
        yield ea
    return

@utils.multicase()
def size():
    '''Return the size of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.size() : Unable to locate the current segment.".format(__name__))
    return interface.range.size(seg)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def size(segment):
    '''Return the size of the segment specified by `segment`.'''
    seg = by(segment)
    return interface.range.size(seg)

@utils.multicase()
def offset():
    '''Return the offset of the current address from the beginning of the current segment.'''
    return offset(ui.current.segment(), ui.current.address())
@utils.multicase(ea=types.integer)
def offset(ea):
    '''Return the offset of the address `ea` from the beginning of the current segment.'''
    return offset(ui.current.segment(), ea)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), ea=types.integer)
def offset(segment, ea):
    '''Return the offset of the address `ea` from the beginning of `segment`.'''
    seg = by(segment)
    return ea - interface.range.start(seg)

@utils.multicase(offset=types.integer)
def by_offset(offset):
    '''Return the specified `offset` translated to the beginning of the current segment.'''
    return by_offset(ui.current.segment(), offset)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), offset=types.integer)
def by_offset(segment, offset):
    '''Return the specified `offset` translated to the beginning of `segment`.'''
    seg = by(segment)
    return interface.range.start(seg) + offset
byoffset = utils.alias(by_offset)

@utils.multicase(offset=types.integer)
def go_offset(offset):
    '''Go to the `offset` of the current segment.'''
    return go_offset(ui.current.segment(), offset)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), offset=types.integer)
def go_offset(segment, offset):
    '''Go to the `offset` of the specified `segment`.'''
    seg = by(segment)
    return database.go(offset + interface.range.start(seg))
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@utils.multicase()
def read():
    '''Return the contents of the current segment.'''
    get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.read() : Unable to locate the current segment.".format(__name__))
    return get_bytes(interface.range.start(seg), interface.range.size(seg))
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def read(segment):
    '''Return the contents of the segment identified by `segment`.'''
    get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

    seg = by(segment)
    return get_bytes(interface.range.start(seg), interface.range.size(seg))
string = utils.alias(read)

@utils.multicase()
def repr():
    '''Return the current segment in a printable form.'''
    segment = ui.current.segment()
    if segment is None:
        raise E.SegmentNotFoundError(u"{:s}.repr() : Unable to locate the current segment.".format(__name__))
    return repr(segment)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def repr(segment):
    '''Return the specified `segment` in a printable form.'''
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    seg = by(segment)
    return "{:s} {:s} {:#x}-{:#x} ({:+#x})".format(object.__repr__(seg), get_segment_name(seg), interface.range.start(seg), interface.range.end(seg), interface.range.size(seg))

@utils.multicase()
def top():
    '''Return the top address of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.top() : Unable to locate the current segment.".format(__name__))
    return interface.range.start(seg)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def top(segment):
    '''Return the top address of the segment identified by `segment`.'''
    seg = by(segment)
    return interface.range.start(seg)

@utils.multicase()
def bottom():
    '''Return the bottom address of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.bottom() : Unable to locate the current segment.".format(__name__))
    return interface.range.end(seg)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def bottom(segment):
    '''Return the bottom address of the segment identified by `segment`.'''
    seg = by(segment)
    return interface.range.end(seg)

@utils.multicase()
def name():
    '''Return the name of the current segment.'''
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.name() : Unable to locate the current segment.".format(__name__))
    res = get_segment_name(seg)
    return utils.string.of(res)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def name(segment):
    '''Return the name of the segment identified by `segment`.'''
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    seg = by(segment)
    res = get_segment_name(seg)
    return utils.string.of(res)

@utils.multicase()
def color():
    '''Return the color of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.color() : Unable to locate the current segment.".format(__name__))
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def color(segment):
    '''Return the color of the segment identified by `segment`.'''
    seg = by(segment)
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase(none=types.none)
def color(none):
    '''Clear the color of the current segment.'''
    return color(ui.current.segment(), None)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), none=types.none)
def color(segment, none):
    '''Clear the color of the segment identified by `segment`.'''
    seg = by(segment)
    seg.color = 0xffffffff
    return bool(seg.update())
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), rgb=types.integer)
def color(segment, rgb):
    '''Sets the color of the segment identified by `segment` to `rgb`.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    seg = by(segment)
    seg.color = (b<<16)|(rgb&0x00ff00)|r
    return bool(seg.update())

@utils.multicase(ea=types.integer)
def contains(ea):
    '''Returns true if the address `ea` is contained within the current segment.'''
    return contains(ui.current.segment(), ea)
@utils.multicase(address=types.integer, ea=types.integer)
def contains(address, ea):
    '''Returns true if the address `ea` is contained within the segment belonging to the specified `address`.'''
    seg = by_address(address)
    return contains(seg, ea)
@utils.multicase(name=types.string, ea=types.integer)
def contains(name, ea):
    '''Returns true if the address `ea` is contained within the segment with the specified `name`.'''
    seg = by_name(name)
    return contains(seg, ea)
@utils.multicase(segment=idaapi.segment_t, ea=types.integer)
def contains(segment, ea):
    '''Returns true if the address `ea` is contained within the ``idaapi.segment_t`` specified by `segment`.'''
    return interface.range.within(ea, segment)

class type(object):
    """
    This namespace is used for getting and setting information about the type of
    a segment as specified in the "type" property of the segment. Some of the
    other functions within the namespace can also be used to get information
    about the abstract type of the segment.

    Some examples of using the functions in this namespace are::

        > type = segment.type(ea)
        > type = segment.type('.text')
        > old = segment.type(ea, idaapi.SEG_XTRN)
        > boolean = segment.type.loader(ea)
        > old = segment.type.loader(ea, True)
        > boolean = segment.type.header(ea)
        > old = segment.type.header(ea, True)
        > boolean = segment.type.visibility(ea)
        > old = segment.type.visibility(ea, False)
        > boolean = segment.type.hidden(ea)
        > old = segment.type.hidden(ea, False)
        > boolean = segment.type.debugger(ea)
        > old = segment.type.debugger(ea, False)

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the type of the current segment.'''
        seg = ui.current.segment()
        return cls(seg)
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea):
        '''Return the type of the segment containing the address `ea`.'''
        result = idaapi.segtype(ea)
        left, right = interface.address.bounds()
        if result == idaapi.SEG_UNDF and not (left <= ea < right):
            description, results = "{:#x}<>{:#x}".format(left, right), {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('SEG_')}
            logging.warning(u"{:s}({:#x}) : Returning {:s}({:d}) for the segment type due to the given address ({:#x}) not being within the boundaries of the database ({:s}).".format(__name__, ea, results[result], result, ea, description))
        return result
    @utils.multicase(bounds=interface.bounds_t)
    def __new__(cls, bounds):
        '''Return the type of the segment containing the specified `bounds`.'''
        ea, _ = bounds
        return cls(ea)
    @utils.multicase(name=types.string)
    @utils.string.decorate_arguments('name', 'suffix')
    def __new__(cls, name, *suffix):
        '''Return the type of the segment with the specified `name`.'''
        seg = by_name(name, *suffix)
        return cls(seg)
    @utils.multicase(segment=idaapi.segment_t)
    def __new__(cls, segment):
        '''Return the type of the ``idaapi.segment_t`` specified by `segment`.'''
        return segment.type
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t), type=types.integer)
    @utils.string.decorate_arguments('segment')
    def __new__(cls, segment, type):
        '''Set the type for the specified `segment` to `type`.'''
        seg = by(segment)
        return cls(segment, type)
    @utils.multicase(segment=idaapi.segment_t, type=types.integer)
    def __new__(cls, segment, type):
        '''Set the type for the specified `segment` to `type`.'''
        res, segment.type = segment.type, type
        if not segment.update():
            description = "{:s}".format(interface.range.bounds(segment))
            raise E.DisassemblerError(u"{:s}({:s}, {:d}) : Unable to update the segment type for the specified segment to {:d}.".format(__name__, description, code, code))
        return res

    @utils.multicase()
    @classmethod
    def loader(cls):
        '''Return whether the current segment was created by the loader.'''
        seg = ui.current.segment()
        return seg.is_loader_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def loader(cls, segment):
        '''Return whether the specified `segment` was created by the loader.'''
        seg = by(segment)
        return seg.is_loader_segm()
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def loader(cls, segment):
        '''Return whether the specified `segment` was created by the loader.'''
        return segment.is_loader_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def loader(cls, segment, boolean):
        '''Set the loader flag for the specified `segment` to `boolean`.'''
        seg = by(segment)
        return cls.loader(seg, boolean)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def loader(cls, segment, boolean):
        '''Set the loader flag for the specified `segment` to `boolean`.'''
        res, ok = segment.is_loader_segm(), segment.set_loader_segm(True if boolean else False)
        return res

    @utils.multicase()
    @classmethod
    def header(cls):
        '''Return whether the current segment belongs to a header.'''
        seg = ui.current.segment()
        return seg.is_header_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def header(cls, segment):
        '''Return whether the specified `segment` belongs to a header.'''
        seg = by(segment)
        return seg.is_header_segm()
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def header(cls, segment):
        '''Return whether the specified `segment` belongs to a header.'''
        return segment.is_header_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def header(cls, segment, boolean):
        '''Set the header flag for the specified `segment` to `boolean`.'''
        seg = by(segment)
        return cls.header(seg, boolean)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def header(cls, segment, boolean):
        '''Set the header flag for the specified `segment` to `boolean`.'''
        res, ok = segment.is_header_segm(), segment.set_header_segm(True if boolean else False)
        return res

    @utils.multicase()
    @classmethod
    def visible(cls):
        '''Return whether the current segment is visible.'''
        seg = ui.current.segment()
        return seg.is_visible_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def visible(cls, segment):
        '''Return whether the specified `segment` is visible.'''
        seg = by(segment)
        return seg.is_visible_segm()
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def visible(cls, segment):
        '''Return whether the specified `segment` is visible.'''
        return segment.is_visible_segm()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def visible(cls, segment, boolean):
        '''Set the visibility flag for the specified `segment` to `boolean`.'''
        seg = by(segment)
        return cls.visible(seg, boolean)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def visible(cls, segment, boolean):
        '''Set the visibility flag for the specified `segment` to `boolean`.'''
        res, ok = segment.is_visible_segm(), segment.set_visible_segm(True if boolean else False)
        return res
    visibility = utils.alias(visible, 'type')

    @utils.multicase()
    @classmethod
    def hidden(cls):
        '''Return whether type of the current segment is hidden.'''
        seg = ui.current.segment()
        return seg.is_hidden_segtype()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def hidden(cls, segment):
        '''Return whether type of the specified `segment` is hidden.'''
        seg = by(segment)
        return seg.is_hidden_segtype()
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def hidden(cls, segment):
        '''Return whether type of the specified `segment` is hidden.'''
        return segment.is_hidden_segtype()
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def hidden(cls, segment, boolean):
        '''Mark the type of the specified `segment` as hidden depending on the value of `boolean`.'''
        seg = by(segment)
        return cls.hidden(seg, boolean)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def hidden(cls, segment, boolean):
        '''Mark the type of the specified `segment` as hidden depending on the value of `boolean`.'''
        res, ok = segment.is_hidden_segtype(), segment.set_hidden_segtype(True if boolean else False)
        return res
    hide = utils.alias(hidden, 'type')

    @utils.multicase()
    @classmethod
    def debugger(cls):
        '''Return whether the current segment was created for the debugger.'''
        seg = ui.current.segment()
        return cls.debugger(seg)
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def debugger(cls, segment):
        '''Return whether the specified `segment` was created for the debugger.'''
        seg = by(segment)
        return cls.debugger(seg)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def debugger(cls, segment):
        '''Return whether the specified `segment` was created for the debugger.'''
        return True if segment.flags & idaapi.SFL_DEBUG else False
    @utils.multicase(segment=(types.integer, types.string, interface.bounds_t))
    @classmethod
    @utils.string.decorate_arguments('segment')
    def debugger(cls, segment, boolean):
        '''Set the debugger flag for the specified `segment` to `boolean`.'''
        seg = by(segment)
        return cls.debugger(seg, boolean)
    @utils.multicase(segment=idaapi.segment_t)
    @classmethod
    def debugger(cls, segment, boolean):
        '''Set the debugger flag for the specified `segment` to `boolean`.'''
        res, ok = segment.flags & idaapi.SFL_DEBUG, segment.set_debugger_segm(True if boolean else False)
        return True if res else False
    debug = debugging = utils.alias(debugger, 'type')

@utils.multicase()
def permissions():
    '''Return the permissions for the current `segment`.'''
    seg = ui.current.segment()
    return permissions(seg)
@utils.multicase(segment=idaapi.segment_t)
def permissions(segment):
    '''Return the permissions for the specified `segment`.'''
    res = segment.perm
    invert = {1: 'x', 2: 'w', 4: 'r'}
    x = [res & bit for bit in invert]
    iterable = builtins.map(invert.get, (res & bit for bit in invert))
    return str().join(sorted(filter(None, iterable)))
@utils.multicase(segment=idaapi.segment_t, flags=(types.string, types.unordered))
def permissions(segment, flags):
    '''Set the permissions for the specified `segment` to the given `flags`.'''
    lookup = {
        'r': idaapi.SEGPERM_READ,
        'w': idaapi.SEGPERM_WRITE,
        'x': idaapi.SEGPERM_EXEC,
        idaapi.SEGPERM_READ: idaapi.SEGPERM_READ,
        idaapi.SEGPERM_WRITE: idaapi.SEGPERM_WRITE,
        idaapi.SEGPERM_EXEC: idaapi.SEGPERM_EXEC,
    }
    new = functools.reduce(operator.or_, builtins.map(lookup.get, {flag for flag in flags}), 0)
    old = permissions(segment, new)
    return permissions(segment)
@utils.multicase(segment=idaapi.segment_t, permissions=types.integer)
def permissions(segment, permissions):
    '''Set the permissions for the specified `segment` to `permissions`.'''
    res, segment.perm = segment.perm, permissions
    if not segment.update():
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.DisassemblerError(u"{:s}.permissions({:s}, {:#x}) : Unable to update the permissions for the specified segment to {:#x}.".format(__name__, description, permissions, segment.perm))
    return res
perms = utils.alias(permissions)

@utils.multicase()
def bitness():
    '''Return the number of segment addressing bits for the current segment.'''
    seg = ui.current.segment()
    return bitness(seg)
@utils.multicase(segment=idaapi.segment_t)
def bitness(segment):
    '''Return the number of segment addressing bits for the specified `segment`.'''
    bits = segment.bitness
    lookup = {0: 16, 1: 32, 2: 64}
    if bits not in lookup:
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.DisassemblerError(u"{:s}.bitness({:s}) : Unable to determine the number of segment addressing bits for the specified segment from the integer ({:d}).".format(__name__, description, bits))
    return lookup[bits]
@utils.multicase(segment=idaapi.segment_t, bits=types.integer)
def bitness(segment, bits):
    '''Set the number of segment addressing bits for the specified `segment` to `bits` (16, 32, or 64).'''
    lookup, inverted = {0: 16, 1: 32, 2: 64}, {16: 0, 32: 1, 64: 2}
    if bits not in inverted:
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.InvalidParameterError(u"{:s}.bitness({:s}, {:d}) : Unable to set the number of segment addressing bits for the specified segment to an unsupported value ({:d}).".format(__name__, description, bits, bits))
    res = segment.bitness
    if res not in lookup:
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.InvalidTypeOrValueError(u"{:s}.bitness({:s}, {:d}) : Unable to determine the number of segment addressing bits for the specified segment from the integer ({:d}).".format(__name__, description, bits, res))
    if not idaapi.set_segm_addressing(segment, inverted[bits]):
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.DisassemblerError(u"{:s}.bitness({:s}, {:d}) : Unable to update the number of segment addressing bits for the specified segment to {:d}.".format(__name__, description, bits, bits))
    return lookup[res]
bits = utils.alias(bitness)

@utils.multicase()
def combination():
    '''Return the segment combination code for the current segment.'''
    seg = ui.current.segment()
    return combination(seg)
@utils.multicase(segment=idaapi.segment_t)
def combination(segment):
    '''Return the segment combination code for the specified `segment`.'''
    return segment.comb
@utils.multicase(segment=idaapi.segment_t, code=types.integer)
def combination(segment, code):
    '''Set the segment combination code for the specified `segment` to `code`.'''
    res, segment.comb = segment.comb, code
    if not segment.update():
        description = "{:s}".format(interface.range.bounds(segment))
        raise E.DisassemblerError(u"{:s}.combination({:s}, {:d}) : Unable to update the segment combination code for the specified segment to {:d}.".format(__name__, description, code, code))
    return res
comb = utils.alias(combination)

## functions
@utils.string.decorate_arguments('filename')
def load(filename, ea, size=None, offset=0, **kwds):
    """Load the specified `filename` to the address `ea` as a segment.

    If `size` is not specified, use the length of the file.
    The keyword `offset` represents the offset into the file to use.
    The keyword `name` can be used to name the segment.
    """
    filesize = os.stat(filename).st_size

    # shamefully ripped from idc.py
    def __load_file(filename, ea, size, offset=0):
        path = os.path.abspath(filename)

        # use IDA to open up the file contents
        # XXX: does IDA support unicode file paths?
        res = idaapi.open_linput(path, False)
        if not res:
            raise E.DisassemblerError(u"{:s}.load_file({!r}, {:#x}, {:+#x}) : Unable to create an `idaapi.loader_input_t` from path \"{:s}\".".format(__name__, filename, ea, size, path))

        # now we can write the file into the specified address as a segment
        ok = idaapi.file2base(res, offset, ea, ea+size, False)
        idaapi.close_linput(res)
        return ok

    cb = filesize - offset if size is None else size
    res = __load_file(utils.string.to(filename), ea, cb, offset)
    if not res:
        raise E.ReadOrWriteError(u"{:s}.load({!r}, {:#x}, {:+#x}, {:#x}{:s}) : Unable to load file into {:#x}{:+#x} from \"{:s}\".".format(__name__, filename, ea, cb, offset, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', ea, cb, utils.string.escape(os.path.relpath(filename), '"')))
    return new(ea, cb, kwds.get('name', os.path.split(filename)[1]))

@utils.multicase(ea=types.integer, size=types.integer, new=types.integer)
def map(ea, size, new):
    '''Map `size` bytes of data from `ea` into a new segment at the address specified by `new`.'''
    return map(ea, size, new, "map_{:x}".format(ea))
@utils.multicase(ea=types.integer, size=types.integer, new=types.integer)
@utils.string.decorate_arguments('name')
def map(ea, size, new, name):
    '''Map `size` bytes of data from `ea` into a new segment at the address specified by `new` with the given `name`.'''

    # grab the file offset and the data we want
    fpos, data = idaapi.get_fileregion_offset(ea), database.read(ea, size)
    if len(data) != size:
        raise E.ReadOrWriteError(u"{:s}.map({:#x}, {:+#x}, {:#x}{:s}) : Unable to read {:#x} bytes from {:#x}.".format(__name__, ea, size, new, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', size, ea))

    # rebase the data to the new address
    res = idaapi.mem2base(data, new, fpos)
    if not res:
        raise E.DisassemblerError(u"{:s}.map({:#x}, {:+#x}, {:#x}{:s}) : Unable to remap {:#x}:{:+#x} to {:#x}.".format(__name__, ea, size, new, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', ea, size, new))

    # now we can create the new segment
    return new(new, size, name)
    #return create(new, size, kwds.get("name", "map_{:s}".format(new>>4)))

# creation/destruction
@utils.multicase(offset=types.integer, size=types.integer, name=types.string)
@utils.string.decorate_arguments('name')
def new(offset, size, name, **kwds):
    """Create a segment at `offset` with `size` and name it according to `name`.

    The keyword `bits` can be used to specify the bit size of the segment
    The keyword `comb` can be used to specify any flags (idaapi.sc*)
    The keyword `align` can be used to specify paragraph alignment (idaapi.sa*)
    The keyword `org` specifies the origin of the segment (must be paragraph aligned due to ida)
    """
    res = utils.string.to(name)

    # find the segment according to the name specified by the user
    seg = idaapi.get_segm_by_name(res)
    if seg is not None:
        raise E.DuplicateItemError(u"{:s}.new({:#x}, {:+#x}, \"{:s}\"{:s}) : A segment with the specified name (\"{:s}\") already exists.".format(__name__, offset, size, utils.string.escape(name, '"'), u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', utils.string.escape(name, '"')))

    bits = kwds.get('bits', interface.database.bits() if idaapi.getseg(offset) is None else idaapi.getseg(offset).abits())

    ## create a selector with the requested origin
    if bits == 16:
        org = kwds.get('org',0)
        if org & 0xf > 0:
            raise E.InvalidTypeOrValueError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : The specified origin ({:#x}) is not aligned to the size of a paragraph (0x10).".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', org))

        para = offset // 16
        sel = idaapi.allocate_selector(para)
        idaapi.set_selector(sel, (para - kwds.get('org', 0) // 16) & 0xffffffff)

    ## if the user specified a selector, then use it
    elif 'sel' in kwds or 'selector' in kwds:
        sel = kwds.get('sel', kwds.get('selector', idaapi.find_free_selector()))

    ## choose the paragraph size defined by the user
    elif 'para' in kwds or 'paragraphs' in kwds:
        para = kwds.get('paragraph', kwds.get('para', 1))
        sel = idaapi.setup_selector(para)

    ## find a selector that is 1 paragraph size,
    elif idaapi.get_selector_qty():
        sel = idaapi.find_selector(1)

    # otherwise find a free one and set it.
    else:
        sel = idaapi.find_free_selector()
        idaapi.set_selector(sel, 1)

    # populate the segment_t for versions of IDA prior to 7.0
    if idaapi.__version__ < 7.0:
        seg = idaapi.segment_t()
        seg.startEA, seg.endEA = offset, offset + size

    # now for versions of IDA 7.0 and newer
    else:
        seg = idaapi.segment_t()
        seg.start_ea, seg.end_ea = offset, offset + size

    # assign the rest of the necessary attributes
    seg.sel = sel
    seg.bitness = {16:0, 32:1, 64:2}[bits]
    seg.comb = kwds.get('comb', idaapi.scPub)   # public
    seg.align = kwds.get('align', idaapi.saAbs) # absolute address

    # now we can add our segment_t to the database
    res = utils.string.to(name)
    ok = idaapi.add_segm_ex(seg, res, "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)
    if not ok:
        ok = idaapi.del_selector(sel)
        if not ok:
            logging.warning(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to delete the created selector ({:#x}) for the new segment.".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', sel))
        raise E.DisassemblerError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to add a new segment.".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else ''))
    return seg
create = utils.alias(new)

@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def remove(segment):
    '''Remove the specified `segment` and its contents from the database.'''
    return remove(segment, True)
@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t))
def remove(segment, contents):
    '''Remove the specified `segment` and its `contents` if specified as true.'''
    seg, get_segment_name = by(segment), idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    # grab the segment's selector and its bounds so we can remove it if necessary,
    # and return the segment's boundaries after we've removed it.
    name, selector, bounds = utils.string.of(get_segment_name(seg)), seg.sel, interface.range.bounds(seg)

    # verify the selector is the same as our segment, if it isn't then reassign
    # our variable to BADSEL so we avoid trying to delete it.
    owner = idaapi.get_segm_by_sel(selector)
    selector = selector if owner and interface.range.bounds(owner) == bounds else idaapi.BADSEL

    # remove the actual segment using the address in the segment_t
    if not idaapi.del_segm(interface.range.start(seg), idaapi.SEGMOD_KILL if contents else idaapi.SEGMOD_KEEP):
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to delete the given segment \"{:s}\" at {:#x}.".format(__name__, segment, utils.string.escape(name, '"'), interface.range.start(seg)))

    # now we need to check that our selector doesn't point to anything. if it
    # does, then it's not safe to remove and we just return the segment bounds.
    if selector == idaapi.BADSEL or idaapi.get_segm_by_sel(selector):
        return bounds

    # idaapi.del_selector doesn't actualy return anything, so we're pretty much done.
    ea, void = idaapi.sel2ea(selector), idaapi.del_selector(selector)
    logging.info(u"{:s}.remove({!r}) : Removed selector ({:d}) for address {:#x} that was orphaned by removal of segment \"{:s}\" ({:s}).".format(__name__, segment, selector, ea, utils.string.escape(name, '"'), bounds))
    return bounds
delete = utils.alias(remove)

@utils.multicase(segment=(idaapi.segment_t, types.integer, types.string, interface.bounds_t), filename=types.string)
@utils.string.decorate_arguments('filename')
def save(segment, filename):
    '''Export the segment identified by `segment` to the file named `filename`.'''
    return save(segment, filename, 0)
@utils.multicase(segment=(types.integer, types.string, interface.bounds_t), filename=types.string, offset=types.integer)
@utils.string.decorate_arguments('filename')
def save(segment, filename, offset):
    '''Export the segment identified by `segment` to the file named `filename` starting at the given `offset`.'''
    seg = by(segment)
    return save(seg, filename, offset)
@utils.multicase(segment=idaapi.segment_t, filename=types.string, offset=types.integer)
@utils.string.decorate_arguments('filename')
def save(segment, filename, offset):
    '''Export the segment identified by `segment` to the file named `filename` starting at the given `offset`.'''

    # shamefully ripped from idc.py
    def __save_file(filename, ea, size, offset=0):
        path = os.path.abspath(filename)

        # use IDA to open up a file to write to
        # XXX: does IDA support unicode file paths?
        of = idaapi.fopenWB(path)
        if not of:
            raise E.DisassemblerError(u"{:s}.save_file({!r}, {:#x}, {:+#x}) : Unable to open target file \"{:s}\".".format(__name__, filename, ea, size, utils.string.escape(path, '"')))

        # now we can write the segment into the file we opened
        res = idaapi.base2file(of, offset, ea, ea+size)
        idaapi.eclose(of)
        return res
    return __save_file(utils.string.to(filename), interface.range.start(segment), size(segment), offset)
export = utils.alias(save)

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)
