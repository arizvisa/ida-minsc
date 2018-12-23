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
__matcher__.boolean('regex', re.search, utils.fcompose(idaapi.get_true_segm_name, interface.string.of))
__matcher__.attribute('index', 'index')
__matcher__.attribute('identifier', 'name'), __matcher__.attribute('id', 'name')
__matcher__.attribute('selector', 'sel')
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(idaapi.get_true_segm_name, interface.string.of))
__matcher__.boolean('name', operator.eq, utils.fcompose(idaapi.get_true_segm_name, interface.string.of))
__matcher__.boolean('greater', operator.le, 'endEA'), __matcher__.boolean('gt', operator.lt, 'endEA')
__matcher__.boolean('less', operator.ge, 'startEA'), __matcher__.boolean('lt', operator.gt, 'startEA')
__matcher__.predicate('predicate'), __matcher__.predicate('pred')

def __iterate__(**type):
    '''Iterate through each segment defined in the database that match the keywords specified by `type`.'''
    if not type: type = {'predicate':lambda n: True}
    def newsegment(index):
        res = idaapi.getnseg(index)
        res.index = index
        return res
    res = builtins.map(newsegment, six.moves.range(idaapi.get_segm_qty()))
    for key, value in six.iteritems(type):
        res = builtins.list(__matcher__.match(key, value, res))
    for item in res: yield item

@utils.multicase(string=basestring)
def list(string):
    '''List all of the segments whose name matches the glob specified by `string`.'''
    return list(like=string)
@utils.multicase()
def list(**type):
    '''List all of the segments in the database that match the keyword specified by `type`.'''
    res = builtins.list(__iterate__(**type))

    maxindex = max(builtins.map(operator.attrgetter('index'), res) or [1])
    maxaddr = max(builtins.map(operator.attrgetter('endEA'), res) or [1])
    maxsize = max(builtins.map(operator.methodcaller('size'), res) or [1])
    maxname = max(builtins.map(utils.fcompose(idaapi.get_true_segm_name,len), res) or [1])
    cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
    caddr = math.ceil(math.log(maxaddr or 1)/math.log(16))
    csize = math.ceil(math.log(maxsize or 1)/math.log(16))

    for seg in res:
        comment = idaapi.get_segment_cmt(seg, 0) or idaapi.get_segment_cmt(seg, 1)
        six.print_(u"[{:{:d}d}] {:#0{:d}x}<>{:#0{:d}x} : {:<+#{:d}x} : {:>{:d}s} : sel:{:04x} flags:{:02x}{:s}".format(seg.index, int(cindex), seg.startEA, 2+int(caddr), seg.endEA, 2+int(caddr), seg.size(), 3+int(csize), interface.string.of(idaapi.get_true_segm_name(seg)), maxname, seg.sel, seg.flags, u"// {:s}".format(interface.string.of(comment)) if comment else ''))
    return

## searching
def by_name(name):
    '''Return the segment with the given `name`.'''
    res = interface.string.to(name)
    seg = idaapi.get_segm_by_name(res)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_name({!r}) : Unable to locate the segment with the specified name.".format(__name__, name))
    return seg
byName = utils.alias(by_name)
def by_selector(selector):
    '''Return the segment associated with `selector`.'''
    seg = idaapi.get_segm_by_sel(selector)
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_selector({:#x}) : Unable to locate the segment with the specified selector.".format(__name__, selector))
    return seg
bySelector = utils.alias(by_selector)
def by_address(ea):
    '''Return the segment that contains the specified `ea`.'''
    seg = idaapi.getseg(interface.address.within(ea))
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.by_address({:#x}) : Unable to locate segment containing the specified address.".format(__name__, ea))
    return seg
byAddress = utils.alias(by_address)
@utils.multicase(segment=idaapi.segment_t)
def by(segment):
    '''Return a segment by its ``idaapi.segment_t``.'''
    return segment
@utils.multicase(name=basestring)
def by(name):
    '''Return the segment by its `name`.'''
    return by_name(name)
@utils.multicase(ea=six.integer_types)
def by(ea):
    '''Return the segment containing the address `ea`.'''
    return by_address(ea)
@utils.multicase()
def by():
    '''Return the current segment.'''
    return ui.current.segment()
@utils.multicase()
def by(**type):
    '''Return the segment matching the specified keywords in `type`.'''
    searchstring = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

    res = builtins.list(__iterate__(**type))
    if len(res) > 1:
        maxaddr = max(builtins.map(operator.attrgetter('endEA'), res) or [1])
        caddr = math.ceil(math.log(maxaddr)/math.log(16))
        builtins.map(logging.info, (("[{:d}] {:0{:d}x}:{:0{:d}x} {:s} {:+#x} sel:{:04x} flags:{:02x}".format(seg.index, seg.startEA, int(caddr), seg.endEA, int(caddr), interface.string.of(idaapi.get_true_segm_name(seg)), seg.size(), seg.sel, seg.flags)) for seg in res))
        logging.warn("{:s}.by({:s}) : Found {:d} matching results. Returning the first segment at index {:d} from {:0{:d}x}<>{:0{:d}x} with the name {:s} and size {:+#x}.".format(__name__, searchstring, len(res), res[0].index, res[0].startEA, int(caddr), res[0].endEA, int(caddr), interface.string.of(idaapi.get_true_segm_name(res[0])), res[0].size()))

    res = next(iter(res), None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.by({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(name=basestring)
def search(name):
    '''Search through all the segments and return the first one matching the glob `name`.'''
    return by(like=string)
@utils.multicase()
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
    return seg.startEA, seg.endEA
@utils.multicase()
def bounds(segment):
    '''Return the bounds of the segment specified by `segment`.'''
    seg = by(segment)
    return seg.startEA, seg.endEA
range = utils.alias(bounds)

@utils.multicase()
def iterate():
    '''Iterate through all of the addresses within the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.iterate() : Unable to locate the current segment.".format(__name__))
    return iterate(seg)
@utils.multicase()
def iterate(segment):
    '''Iterate through all of the addresses within the specified `segment`.'''
    seg = by(segment)
    return iterate(seg)
@utils.multicase(segment=idaapi.segment_t)
def iterate(segment):
    '''Iterate through all of the addresses within the ``idaapi.segment_t`` represented by `segment`.'''
    for ea in database.address.iterate(segment.startEA, segment.endEA):
        yield ea
    return

@utils.multicase()
def size():
    '''Return the size of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.size() : Unable to locate the current segment.".format(__name__))
    return seg.endEA - seg.startEA
@utils.multicase()
def size(segment):
    '''Return the size of the segment specified by `segment`.'''
    seg = by(segment)
    return seg.endEA - seg.startEA

@utils.multicase()
def offset():
    '''Return the offset of the current address from the beginning of the current segment.'''
    return offset(ui.current.segment(), ui.current.address())
@utils.multicase(ea=six.integer_types)
def offset(ea):
    '''Return the offset of the address `ea` from the beginning of the current segment.'''
    return offset(ui.current.segment(), ea)
@utils.multicase(ea=six.integer_types)
def offset(segment, ea):
    '''Return the offset of the address `ea` from the beginning of `segment`.'''
    seg = by(segment)
    return ea - segment.startEA

@utils.multicase(offset=six.integer_types)
def go_offset(offset):
    '''Go to the `offset` of the current segment.'''
    return go_offset(ui.current.segment(), offset)
@utils.multicase(offset=six.integer_types)
def go_offset(segment, offset):
    '''Go to the `offset` of the specified `segment`.'''
    seg = by(segment)
    return database.go(seg.startEA + offset)
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@utils.multicase()
def read():
    '''Return the contents of the current segment.'''
    segment = ui.current.segment()
    if segment is None:
        raise E.SegmentNotFoundError(u"{:s}.read() : Unable to locate the current segment.".format(__name__))
    return idaapi.get_many_bytes(segment.startEA, segment.endEA-segment.startEA)
@utils.multicase()
def read(segment):
    '''Return the contents of the segment identified by `segment`.'''
    seg = by(segment)
    return idaapi.get_many_bytes(seg.startEA, seg.endEA-seg.startEA)
string = utils.alias(read)

@utils.multicase()
def repr():
    '''Return the current segment in a printable form.'''
    segment = ui.current.segment()
    if segment is None:
        raise E.SegmentNotFoundError(u"{:s}.repr() : Unable to locate the current segment.".format(__name__))
    return repr(segment)
@utils.multicase()
def repr(segment):
    '''Return the specified `segment` in a printable form.'''
    seg = by(segment)
    return "{:s} {:s} {:#x}-{:#x} ({:+#x})".format(object.__repr__(seg),idaapi.get_true_segm_name(seg),seg.startEA,seg.endEA,seg.endEA-seg.startEA)

@utils.multicase()
def top():
    '''Return the top address of the current segment.'''
    segment = ui.current.segment()
    if segment is None:
        raise E.SegmentNotFoundError(u"{:s}.top() : Unable to locate the current segment.".format(__name__))
    return segment.startEA
@utils.multicase()
def top(segment):
    '''Return the top address of the segment identified by `segment`.'''
    seg = by(segment)
    return seg.startEA

@utils.multicase()
def bottom():
    '''Return the bottom address of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.bottom() : Unable to locate the current segment.".format(__name__))
    return seg.endEA
@utils.multicase()
def bottom(segment):
    '''Return the bottom address of the segment identified by `segment`.'''
    seg = by(segment)
    return seg.endEA

@utils.multicase()
def name():
    '''Return the name of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.name() : Unable to locate the current segment.".format(__name__))
    res = idaapi.get_true_segm_name(seg)
    return interface.string.of(res)
@utils.multicase()
def name(segment):
    '''Return the name of the segment identified by `segment`.'''
    seg = by(segment)
    res = idaapi.get_true_segm_name(seg)
    return interface.string.of(res)

@utils.multicase()
def color():
    '''Return the color of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise E.SegmentNotFoundError(u"{:s}.color() : Unable to locate the current segment.".format(__name__))
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase()
def color(segment):
    '''Return the color of the segment identified by `segment`.'''
    seg = by(segment)
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase(none=types.NoneType)
def color(none):
    '''Clear the color of the current segment.'''
    return color(ui.current.segment(), None)
@utils.multicase(none=types.NoneType)
def color(segment, none):
    '''Clear the color of the segment identified by `segment`.'''
    seg = by(segment)
    seg.color = 0xffffffff
    return bool(seg.update())
@utils.multicase(rgb=six.integer_types)
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
def within(ea):
    '''Returns true if the address `ea` is within any segment.'''
    return any(segment.startEA <= ea < segment.endEA for segment in __iterate__())

@utils.multicase(ea=six.integer_types)
def contains(ea):
    '''Returns true if the address `ea` is contained within the current segment.'''
    return contains(ui.current.segment(), ea)
@utils.multicase(segaddr=six.integer_types, ea=six.integer_types)
def contains(address, ea):
    '''Returns true if the address `ea` is contained within the segment belonging to the specified `address`.'''
    seg = by_address(address)
    return contains(seg, ea)
@utils.multicase(name=basestring, ea=six.integer_types)
def contains(name, ea):
    '''Returns true if the address `ea` is contained within the segment with the specified `name`.'''
    seg = by_name(name)
    return contains(seg, ea)
@utils.multicase(segment=idaapi.segment_t, ea=six.integer_types)
def contains(segment, ea):
    '''Returns true if the address `ea` is contained within the ``idaapi.segment_t`` specified by `segment`.'''
    return segment.startEA <= ea < segment.endEA

## functions
# shamefully ripped from idc.py
def __load_file(filename, ea, size, offset=0):
    path = os.path.abspath(filename)

    # use IDA to open up the file contents
    # XXX: does IDA support unicode file paths?
    res = idaapi.open_linput(path, False)
    if not res:
        raise E.DisassemblerError(u"{:s}.load_file({!r}, {:#x}, {:+#x}) : Unable to create loader_input_t from path \"{:s}\".".format(__name__, filename, ea, size, path))

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
        raise E.DisassemblerError(u"{:s}.save_file({!r}, {:#x}, {:+#x}) : Unable to open target file \"{:s}\".".format(__name__, filename, ea, size, path))

    # now we can write the segment into the file we opened
    res = idaapi.base2file(of, offset, ea, ea+size)
    idaapi.eclose(of)
    return res

def load(filename, ea, size=None, offset=0, **kwds):
    """Load the specified `filename` to the address `ea` as a segment.

    If `size` is not specified, use the length of the file.
    The keyword `offset` represents the offset into the file to use.
    The keyword `name` can be used to name the segment.
    """
    filesize = os.stat(filename).st_size

    cb = filesize - offset if size is None else size
    res = __load_file(filename, ea, cb, offset)
    if not res:
        raise E.ReadOrWriteError(u"{:s}.load({!r}, {:#x}, {:+#x}, {:#x}) : Unable to load file into {:#x}:{:+#x} from \"{:s}\".".format(__name__, filename, ea, cb, offset, ea, cb, os.path.relpath(filename)))
    return new(ea, cb, kwds.get('name', os.path.split(filename)[1]))

def map(ea, size, newea, **kwds):
    """Map `size` bytes of data from `ea` into a new segment at `newea`.

    The keyword `name` can be used to name the segment.
    """

    # grab the file offset and the data we want
    fpos, data = idaapi.get_fileregion_offset(ea), database.read(ea, size)
    if len(data) != size:
        raise E.ReadOrWriteError(u"{:s}.map({:#x}, {:+#x}, {:#x}) : Unable to read {:#x} bytes from {:#x}.".format(__name__, ea, size, newea, size, ea))

    # rebase the data to the new address
    res = idaapi.mem2base(data, newea, fpos)
    if not res:
        raise E.DisassemblerError(u"{:s}.map({:#x}, {:+#x}, {:#x}) : Unable to remap {:#x}:{:+#x} to {:#x}.".format(__name__, ea, size, newea, ea, size, newea))

    # now we can create the new segment
    return new(newea, size, kwds.get("name', 'map_{:x}".format(ea)))
    #return create(newea, size, kwds.get("name', 'map_{:s}".format(newea>>4)))

# creation/destruction
def new(offset, size, name, **kwds):
    """Create a segment at `offset` with `size` and name it according to `name`.

    The keyword `bits` can be used to specify the bit size of the segment
    The keyword `comb` can be used to specify any flags (idaapi.sc*)
    The keyword `align` can be used to specify paragraph alignment (idaapi.sa*)
    The keyword `org` specifies the origin of the segment (must be paragraph aligned due to ida)
    """
    res = interface.string.to(name)

    # find the segment according to the name specified by the user
    seg = idaapi.get_segm_by_name(res)
    if seg is not None:
        raise NameError("{:s}.new({:#x}, {:+#x}, {!r}{:s}) : A segment with the specified name ({!r}) already exists.".format(__name__, offset, size, name.encode('utf8') if isinstance(name, unicode) else name, ", {:s}".format(', '.join("{:s}={!r}".format(k, v) for k, v in kwds.iteritems())) if kwds else '', name))

    # FIXME: use disassembler default bit length instead of 32
    bits = kwds.get( 'bits', 32 if idaapi.getseg(offset) is None else idaapi.getseg(offset).abits())

    ## create a selector with the requested origin
    if bits == 16:
        org = kwds.get('org',0)
        if org & 0xf > 0:
            raise E.InvalidTypeOrValueError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : The specified origin ({:#x}) is not aligned to the size of a paragraph (0x10).".format(__name__, offset, size, name, ", {:s}".format(', '.join("{:s}={!r}".format(k, v) for k, v in kwds.iteritems())) if kwds else '', org))

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

    # populate the segment_t using code ripped from the idc module
    seg = idaapi.segment_t()
    seg.startEA = offset
    seg.endEA = offset+size
    seg.sel = sel
    seg.bitness = {16:0,32:1,64:2}[bits]
    seg.comb = kwds.get('comb', idaapi.scPub)       # public
    seg.align = kwds.get('align', idaapi.saRelByte)  # paragraphs

    # now we can add our segment_t to the database
    res = interface.string.to(name)
    ok = idaapi.add_segm_ex(seg, res, "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)
    if not ok:
        ok = idaapi.del_selector(sel)
        if not ok:
            logging.warn("{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to delete the created selector ({:#x}) for the new segment.".format(__name__, offset, size, name, ", {:s}".format(', '.join("{:s}={!r}".format(k, v) for k, v in kwds.iteritems())) if kwds else '', sel))

        raise E.DisassemblerError(u"{:s}.new({:#x}, {:+#x}, {!r}{:s}) : Unable to add a new segment.".format(__name__, offset, size, name, ", {:s}".format(', '.join("{:s}={!r}".format(k, v) for k, v in kwds.iteritems())) if kwds else ''))
    return seg
create = utils.alias(new)

def remove(segment, contents=False):
    """Remove the specified `segment`.

    If the bool `contents` is specified, then remove the contents of the segment from the database.
    """
    if not isinstance(segment, idaapi.segment_t):
        cls = idaapi.segment_t
        raise E.InvalidParameterError(u"{:s}.remove({!r}) : Expected a {!s}, but received a {!s}.".format(__name__, segment, cls, type(segment)))

    # delete the selector defined by the segment_t
    res = idaapi.del_selector(segment.sel)
    if res == 0:
        logging.warn("{:s}.remove({!r}) : Unable to delete the selector {:#x}.".format(__name__, segment, segment.sel))

    # remove the actual segment using the address in the segment_t
    res = idaapi.del_segm(segment.startEA, idaapi.SEGMOD_KILL if contents else idaapi.SEGMOD_KEEP)
    if res == 0:
        logging.warn("{:s}.remove({!r}) : Unable to delete the segment {:s} with the selector {:s}.".format(__name__, segment, segment.name, segment.sel))
    return res
delete = utils.alias(remove)

def save(filename, segment, offset=0):
    """Export the segment identified by `segment` to the file named `filename`.

    If the int `offset` is specified, then begin writing into the file at the specified offset.
    """
    if isinstance(segment, idaapi.segment_t):
        return __save_file(filename, segment.startEA, size(segment), offset)
    return save(filename, by(segment))
export = utils.alias(save)

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)

