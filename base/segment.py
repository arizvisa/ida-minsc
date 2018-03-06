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

    `name` - Match according to the exact segment name
    `like` - Filter the segment names according to a glob
    `regex` - Filter the function names according to a regular-expression
    `index` - Match the segment by its index
    `identifier` - Match the segment by its identifier
    `selector` - Match the segment by its selector
    `greater` or `gt` - Filter the segments for any after the specified address
    `less` or `lt` - Filter the segments for any before the specified address
    `predicate` - Filter the segments by passing their ``idaapi.segment_t`` to a callable

Some examples of using these keywords are as follows::

    > for l, r in database.segments(): ...
    > database.segments.list(regex=r'\.r?data')
    > iterable = database.segments.iterate(like='*text*')
    > result = database.segments.search(greater=0x401000)

"""

import six
from six.moves import builtins

import functools, operator, itertools, types
import os, logging
import math, re, fnmatch

import database
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

## enumerating
__matcher__ = utils.matcher()
__matcher__.boolean('regex', re.search, utils.fcompose(idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of))
__matcher__.attribute('index', 'index')
__matcher__.attribute('identifier', 'name'), __matcher__.attribute('id', 'name')
__matcher__.attribute('selector', 'sel')
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of))
__matcher__.boolean('name', operator.eq, utils.fcompose(idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name, utils.string.of))
if idaapi.__version__ < 7.0:
    __matcher__.boolean('greater', operator.le, 'endEA'), __matcher__.boolean('gt', operator.lt, 'endEA')
    __matcher__.boolean('less', operator.ge, 'startEA'), __matcher__.boolean('lt', operator.gt, 'startEA')
else:
    __matcher__.boolean('greater', operator.le, 'end_ea'), __matcher__.boolean('gt', operator.lt, 'end_ea')
    __matcher__.boolean('less', operator.ge, 'start_ea'), __matcher__.boolean('lt', operator.gt, 'start_ea')
__matcher__.predicate('predicate'), __matcher__.predicate('pred')

@utils.string.decorate_arguments('regex', 'like', 'name')
def __iterate__(**type):
    '''Iterate through each segment defined in the database that match the keywords specified by `type`.'''
    def newsegment(index):
        seg = idaapi.getnseg(index)
        seg.index, _ = index, ui.navigation.set(interface.range.start(seg))
        return seg
    iterable = itertools.imap(newsegment, six.moves.range(idaapi.get_segm_qty()))
    for key, value in six.iteritems(type or builtins.dict(predicate=utils.fconstant(True))):
        iterable = builtins.list(__matcher__.match(key, value, iterable))
    for item in iterable: yield item

@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string')
@document.parameters(string='the glob to filter the segment names with')
def list(string):
    '''List all of the segments whose name matches the glob specified by `string`.'''
    return list(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to filter the segments with')
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

    # Collect the maximum sizes for everything from the first pass
    cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
    caddr = math.ceil(math.log(maxaddr or 1)/math.log(16))
    csize = math.ceil(math.log(maxsize or 1)/math.log(16))

    # List all the fields for each segment that we've aggregated
    for seg in listable:
        comment, _ = idaapi.get_segment_cmt(seg, 0) or idaapi.get_segment_cmt(seg, 1), ui.navigation.set(interface.range.start(seg))
        six.print_(u"[{:{:d}d}] {:#0{:d}x}<>{:#0{:d}x} : {:<+#{:d}x} : {:>{:d}s} : sel:{:04x} flags:{:02x}{:s}".format(seg.index, int(cindex), interface.range.start(seg), 2+int(caddr), interface.range.end(seg), 2+int(caddr), seg.size(), 3+int(csize), utils.string.of(get_segment_name(seg)), maxname, seg.sel, seg.flags, u"// {:s}".format(utils.string.of(comment)) if comment else ''))
    return

## searching
@utils.string.decorate_arguments('name')
@document.aliases('byName')
@document.parameters(name='the name of the segment to return')
def by_name(name):
    '''Return the segment with the given `name`.'''
    res = utils.string.to(name)
    seg = idaapi.get_segm_by_name(res)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_name({!r}) : Unable to locate the segment with the specified name.".format(__name__, name))
    return seg
byName = utils.alias(by_name)
@document.aliases('bySelector')
@document.parameters(selector='the selector belonging to the segment to return')
def by_selector(selector):
    '''Return the segment associated with `selector`.'''
    seg = idaapi.get_segm_by_sel(selector)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_selector({:#x}) : Unable to locate the segment with the specified selector.".format(__name__, selector))
    return seg
bySelector = utils.alias(by_selector)
@document.aliases('byAddress')
@document.parameters(ea='an address belonging to the segment to return')
def by_address(ea):
    '''Return the segment that contains the specified `ea`.'''
    seg = idaapi.getseg(interface.address.within(ea))
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_address({:#x}) : Unable to locate segment containing the specified address.".format(__name__, ea))
    return seg
byAddress = utils.alias(by_address)
@utils.multicase(segment=idaapi.segment_t)
@document.parameters(segment='an `idaapi.segment_t` to return')
def by(segment):
    '''Return a segment by its ``idaapi.segment_t``.'''
    return segment
@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(name='the name of the segment to return')
def by(name):
    '''Return the segment by its `name`.'''
    return by_name(name)
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='an address belonging to the segment to return')
def by(ea):
    '''Return the segment containing the address `ea`.'''
    return by_address(ea)
@utils.multicase()
def by():
    '''Return the current segment.'''
    return ui.current.segment()
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to match the segment with')
def by(**type):
    '''Return the segment matching the specified keywords in `type`.'''
    searchstring = utils.string.kwargs(type)
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name

    listable = builtins.list(__iterate__(**type))
    if len(listable) > 1:
        maxaddr = max(builtins.map(interface.range.end, listable) or [1])
        caddr = math.ceil(math.log(maxaddr)/math.log(16))
        builtins.map(logging.info, ((u"[{:d}] {:0{:d}x}:{:0{:d}x} {:s} {:+#x} sel:{:04x} flags:{:02x}".format(seg.index, interface.range.start(seg), int(caddr), interface.range.end(seg), int(caddr), utils.string.of(get_segment_name(seg)), seg.size(), seg.sel, seg.flags)) for seg in listable))
        logging.warn(u"{:s}.by({:s}) : Found {:d} matching results. Returning the first segment at index {:d} from {:0{:d}x}<>{:0{:d}x} with the name {:s} and size {:+#x}.".format(__name__, searchstring, len(listable), listable[0].index, interface.range.start(listable[0]), int(caddr), interface.range.end(listable[0]), int(caddr), utils.string.of(get_segment_name(listable[0])), listable[0].size()))

    res = six.next(iter(listable), None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.by({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(name='the glob to match the segment name with')
def search(name):
    '''Search through all the segments and return the first one matching the glob `name`.'''
    return by(like=name)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to filter segments with')
def search(**type):
    '''Search through all the segments and return the first one that matches the keyword specified by `type`.'''
    return by(**type)

## properties
@document.aliases('range')
@utils.multicase()
def bounds():
    '''Return the bounds of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.bounds() : Unable to locate the current segment.".format(__name__))
    return interface.range.bounds(seg)
@document.aliases('range')
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
def iterate(segment):
    '''Iterate through all of the addresses within the specified `segment`.'''
    seg = by(segment)
    return iterate(seg)
@utils.multicase(segment=idaapi.segment_t)
@document.parameters(segment='an `idaapi.segment_t` to iterate through')
def iterate(segment):
    '''Iterate through all of the addresses within the ``idaapi.segment_t`` represented by `segment`.'''
    for ea in database.address.iterate(*interface.range.unpack(segment)):
        yield ea
    return

@utils.multicase()
def size():
    '''Return the size of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.size() : Unable to locate the current segment.".format(__name__))
    return interface.range.size(seg)
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
def size(segment):
    '''Return the size of the segment specified by `segment`.'''
    seg = by(segment)
    return interface.range.size(seg)

@utils.multicase()
def offset():
    '''Return the offset of the current address from the beginning of the current segment.'''
    return offset(ui.current.segment(), ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='an address within the current segment')
def offset(ea):
    '''Return the offset of the address `ea` from the beginning of the current segment.'''
    return offset(ui.current.segment(), ea)
@utils.multicase(ea=six.integer_types)
@document.parameters(segment='an identifier used to describe a segment', ea='an address within the segment')
def offset(segment, ea):
    '''Return the offset of the address `ea` from the beginning of `segment`.'''
    seg = by(segment)
    return ea - interface.range.start(seg)

@document.aliases('goof',' gooffset', 'gotooffset')
@utils.multicase(offset=six.integer_types)
@document.parameters(offset='an offset into the current segment')
def go_offset(offset):
    '''Go to the `offset` of the current segment.'''
    return go_offset(ui.current.segment(), offset)
@document.aliases('goof',' gooffset', 'gotooffset')
@utils.multicase(offset=six.integer_types)
@document.parameters(segment='an identifier used to describe a segment', offset='an offset into the segment')
def go_offset(segment, offset):
    '''Go to the `offset` of the specified `segment`.'''
    seg = by(segment)
    return database.go(offset + interface.range.start(seg))
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@document.aliases('string')
@utils.multicase()
def read():
    '''Return the contents of the current segment.'''
    get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes

    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.read() : Unable to locate the current segment.".format(__name__))
    return get_bytes(interface.range.start(seg), interface.range.size(seg))
@document.aliases('string')
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
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
@utils.multicase()
@document.parameters(segment='an identifier used to describe a segment')
def color(segment):
    '''Return the color of the segment identified by `segment`.'''
    seg = by(segment)
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase(none=types.NoneType)
@document.parameters(none='the value `None`')
def color(none):
    '''Clear the color of the current segment.'''
    return color(ui.current.segment(), None)
@utils.multicase(none=types.NoneType)
@document.parameters(segment='an identifier used to describe a segment', none='the value `None`')
def color(segment, none):
    '''Clear the color of the segment identified by `segment`.'''
    seg = by(segment)
    seg.color = 0xffffffff
    return bool(seg.update())
@utils.multicase(rgb=six.integer_types)
@document.parameters(segment='an identifier used to describe a segment', rgb='the color as a red, green, and blue integer (``0x00RRGGBB``)')
def color(segment, rgb):
    '''Sets the color of the segment identified by `segment` to `rgb`.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    seg = by(segment)
    seg.color = (b<<16)|(rgb&0x00ff00)|r
    return bool(seg.update())

@utils.multicase()
def within():
    '''Returns true if the current address is within any segment.'''
    return within(ui.current.address())
@utils.multicase(ea=six.integer_types)
@document.parameters(ea='an address in the database')
def within(ea):
    '''Returns true if the address `ea` is within any segment.'''
    return any(interface.range.within(ea, seg) for seg in __iterate__())

@utils.multicase(ea=six.integer_types)
@document.parameters(ea='an address in the database')
def contains(ea):
    '''Returns true if the address `ea` is contained within the current segment.'''
    return contains(ui.current.segment(), ea)
@utils.multicase(segaddr=six.integer_types, ea=six.integer_types)
@document.parameters(address='an address belonging to a segment', ea='an address in the database')
def contains(address, ea):
    '''Returns true if the address `ea` is contained within the segment belonging to the specified `address`.'''
    seg = by_address(address)
    return contains(seg, ea)
@utils.multicase(name=basestring, ea=six.integer_types)
@utils.string.decorate_arguments('name')
@document.parameters(name='the name of a segment', ea='an address in the database')
def contains(name, ea):
    '''Returns true if the address `ea` is contained within the segment with the specified `name`.'''
    seg = by_name(name)
    return contains(seg, ea)
@utils.multicase(segment=idaapi.segment_t, ea=six.integer_types)
@document.parameters(segment='an `idaapi.segment_t` to check', ea='an address in the database')
def contains(segment, ea):
    '''Returns true if the address `ea` is contained within the ``idaapi.segment_t`` specified by `segment`.'''
    return interface.range.within(ea, segment)

## functions
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

@utils.string.decorate_arguments('filename')
@document.parameters(filename='a filename to read from', ea='the address to map to', size='the number of bytes to map', offset='the offset into the file to read from', kwds='if ``name`` is specified as a string, then use it as the name for the new segment')
def load(filename, ea, size=None, offset=0, **kwds):
    """Load the specified `filename` to the address `ea` as a segment.

    If `size` is not specified, use the length of the file.
    The keyword `offset` represents the offset into the file to use.
    The keyword `name` can be used to name the segment.
    """
    filesize = os.stat(filename).st_size

    cb = filesize - offset if size is None else size
    res = __load_file(utils.string.to(filename), ea, cb, offset)
    if not res:
        raise E.ReadOrWriteError(u"{:s}.load({!r}, {:#x}, {:+#x}, {:#x}{:s}) : Unable to load file into {:#x}{:+#x} from \"{:s}\".".format(__name__, filename, ea, cb, offset, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', ea, cb, utils.string.escape(os.path.relpath(filename), '"')))
    return new(ea, cb, kwds.get('name', os.path.split(filename)[1]))

@document.parameters(ea='the address of the data to map', size='the number of bytes to map', newea='the target address to map the data to', kwds='if ``name`` is specified as a string, then use it as the name for the new segment')
def map(ea, size, newea, **kwds):
    """Map `size` bytes of data from `ea` into a new segment at `newea`.

    The keyword `name` can be used to name the segment.
    """

    # grab the file offset and the data we want
    fpos, data = idaapi.get_fileregion_offset(ea), database.read(ea, size)
    if len(data) != size:
        raise E.ReadOrWriteError(u"{:s}.map({:#x}, {:+#x}, {:#x}{:s}) : Unable to read {:#x} bytes from {:#x}.".format(__name__, ea, size, newea, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', size, ea))

    # rebase the data to the new address
    res = idaapi.mem2base(data, newea, fpos)
    if not res:
        raise E.DisassemblerError(u"{:s}.map({:#x}, {:+#x}, {:#x}{:s}) : Unable to remap {:#x}:{:+#x} to {:#x}.".format(__name__, ea, size, newea, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', ea, size, newea))

    # now we can create the new segment
    return new(newea, size, kwds.get("name", "map_{:x}".format(ea)))
    #return create(newea, size, kwds.get("name", "map_{:s}".format(newea>>4)))

# creation/destruction
@utils.string.decorate_arguments('name')
@document.aliases('create')
@document.parameters(
    offset='the offset to create the segment at',
    size='the size of the segment',
    name='the name of the segment',
    kwds='If `bits` is specified, then specify the bit size of the segment. `align` can be used to specify the paragraph alignment. `org` can be used to set the origin and `comb` can be used to specify any other flags'
)
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

    # FIXME: use disassembler default bit length instead of 32
    bits = kwds.get( 'bits', 32 if idaapi.getseg(offset) is None else idaapi.getseg(offset).abits())

    ## create a selector with the requested origin
    if bits == 16:
        org = kwds.get('org',0)
        if org & 0xf > 0:
            raise E.InvalidTypeOrValueError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : The specified origin ({:#x}) is not aligned to the size of a paragraph (0x10).".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', org))

        para = offset/16
        sel = idaapi.allocate_selector(para)
        idaapi.set_selector(sel, (para-kwds.get('org',0)/16)&0xffffffff)

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
    seg.bitness = {16:0,32:1,64:2}[bits]
    seg.comb = kwds.get('comb', idaapi.scPub)       # public
    seg.align = kwds.get('align', idaapi.saRelByte)  # paragraphs

    # now we can add our segment_t to the database
    res = utils.string.to(name)
    ok = idaapi.add_segm_ex(seg, res, "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)
    if not ok:
        ok = idaapi.del_selector(sel)
        if not ok:
            logging.warn(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to delete the created selector ({:#x}) for the new segment.".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else '', sel))
        raise E.DisassemblerError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to add a new segment.".format(__name__, offset, size, name, u", {:s}".format(utils.string.kwargs(kwds)) if kwds else ''))
    return seg
create = utils.alias(new)

@document.aliases('delete')
@document.parameters(segment='an identifier used to describe a segment', contents='whether to remove the contents of the segment from the database')
def remove(segment, contents=False):
    """Remove the specified `segment`.

    If the bool `contents` is specified, then remove the contents of the segment from the database.
    """
    if not isinstance(segment, idaapi.segment_t):
        cls = idaapi.segment_t
        raise E.InvalidParameterError(u"{:s}.remove({!r}) : Expected an `idaapi.segment_t`, but received a {!s}.".format(__name__, segment, type(segment)))

    # delete the selector defined by the segment_t
    res = idaapi.del_selector(segment.sel)
    if res == 0:
        logging.warn(u"{:s}.remove({!r}) : Unable to delete the selector {:#x}.".format(__name__, segment, segment.sel))

    # remove the actual segment using the address in the segment_t
    res = idaapi.del_segm(interface.range.start(segment), idaapi.SEGMOD_KILL if contents else idaapi.SEGMOD_KEEP)
    if res == 0:
        logging.warn(u"{:s}.remove({!r}) : Unable to delete the segment {:s} with the selector {:s}.".format(__name__, segment, segment.name, segment.sel))
    return res
delete = utils.alias(remove)

@utils.string.decorate_arguments('filename')
@document.aliases('export')
@document.parameters(filename='the path to the filename to write the segment to', segment='an identifier used to specify a segment', offset='the offset into the file to start writing the segment')
def save(filename, segment, offset=0):
    """Export the segment identified by `segment` to the file named `filename`.

    If the int `offset` is specified, then begin writing into the file at the specified offset.
    """
    if isinstance(segment, idaapi.segment_t):
        return __save_file(utils.string.to(filename), interface.range.start(segment), size(segment), offset)
    return save(filename, by(segment))
export = utils.alias(save)

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)

