'''
segment-context

generic tools for working with segments
'''
import logging,os
import math,types
import itertools,operator,functools
import six,re,fnmatch

import database,ui
from internal import utils,interface

import __builtin__,idaapi

## enumerating
__matcher__ = utils.matcher()
__matcher__.boolean('regex', re.search, idaapi.get_true_segm_name)
__matcher__.attribute('index', 'index')
__matcher__.attribute('identifier', 'name'), __matcher__.attribute('id', 'name')
__matcher__.attribute('selector', 'sel')
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_true_segm_name)
__matcher__.boolean('name', operator.eq, idaapi.get_true_segm_name)
__matcher__.boolean('greater', operator.le, 'endEA'), __matcher__.boolean('gt', operator.lt, 'endEA')
__matcher__.boolean('less', operator.ge, 'startEA'), __matcher__.boolean('lt', operator.gt, 'startEA')
__matcher__.predicate('predicate'), __matcher__.predicate('pred')

def iterate(**type):
    '''Iterate through each segment defined in the database.'''
    if not type: type = {'predicate':lambda n: True}
    def newsegment(index):
        res = idaapi.getnseg(index)
        res.index = index
        return res
    res = __builtin__.map(newsegment, xrange(idaapi.get_segm_qty()))
    for k,v in type.iteritems():
        res = __builtin__.list(__matcher__.match(k, v, res))
    for n in res: yield n

@utils.multicase(string=basestring)
def list(string):
    return list(like=string)
@utils.multicase()
def list(**type):
    '''List all the segments defined in the database by name.'''
    res = __builtin__.list(iterate(**type))

    maxindex = max(__builtin__.map(operator.attrgetter('index'), res) or [1])
    maxaddr = max(__builtin__.map(operator.attrgetter('endEA'), res) or [1])
    maxsize = max(__builtin__.map(operator.methodcaller('size'), res) or [1])
    maxname = max(__builtin__.map(utils.compose(idaapi.get_true_segm_name,len), res) or [1])
    cindex = math.ceil(math.log(maxindex)/math.log(10))
    caddr = math.ceil(math.log(maxaddr)/math.log(16))
    csize = math.ceil(math.log(maxsize)/math.log(16))

    for seg in res:
        comment = idaapi.get_segment_cmt(seg, 0) or idaapi.get_segment_cmt(seg, 1)
        print('[{:{:d}d}] {:0{:d}x}:{:0{:d}x} {:>{:d}s} {:<+#{:d}x} sel:{:04x} flags:{:02x}{:s}'.format(seg.index, int(cindex), seg.startEA, int(caddr), seg.endEA, int(caddr), idaapi.get_true_segm_name(seg), maxname, seg.size(), int(csize), seg.sel, seg.flags, '// {:s}'.format(comment) if comment else ''))
    return

## searching
def by_name(name):
    '''Return the segment with the given ``name``.'''
    s = idaapi.get_segm_by_name(name)
    if s is None:
        raise LookupError("{:s}.by_name({!r}) : Unable to locate segment".format(__name__, name))
    return s
byName = utils.alias(by_name)
def by_selector(selector):
    '''Return the segment associated with ``selector``.'''
    s = idaapi.get_segm_by_sel(selector)
    if s is None:
        raise LookupError("{:s}.by_selector({:x}) : Unable to locate segment".format(__name__, selector))
    return s
bySelector = utils.alias(by_selector)
def by_address(ea):
    '''Return the segment that contains the specified ``ea``.'''
    s = idaapi.getseg(interface.address.within(ea))
    if s is None:
        raise LookupError("{:s}.by_address({:x}) : Unable to locate segment".format(__name__, ea))
    return s
byAddress = utils.alias(by_address)
@utils.multicase(segment=idaapi.segment_t)
def by(segment):
    '''Return a segment by it's segment_t.'''
    return segment
@utils.multicase(name=basestring)
def by(name):
    '''Return the segment by it's ``name``.'''
    return by_name(name)
@utils.multicase(ea=six.integer_types)
def by(ea):
    '''Return the segment containing the address ``ea``.'''
    return by_address(ea)
@utils.multicase()
def by():
    '''Return the segment containing the current address.'''
    return by_address(ui.current.address())

## properties
@utils.multicase()
def range():
    '''Return the range of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise LookupError("{:s}.range() : Not currently positioned within a segment".format(__name__))
    return seg.startEA, seg.endEA
@utils.multicase()
def range(segment):
    '''Return the range of the segment specified by ``seg``.'''
    seg = by(segment)
    return seg.startEA, seg.endEA

@utils.multicase()
def size():
    '''Return the size of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise LookupError("{:s}.size() : Not currently positioned within a segment".format(__name__))
    return seg.endEA - seg.startEA
@utils.multicase()
def size(segment):
    '''Return the size of the segment specified by ``segment``.'''
    seg = by(segment)
    return seg.endEA - seg.startEA

@utils.multicase()
def offset():
    '''Return the offset of the current address from the beginning of the current segment.'''
    return offset(ui.current.segment(), ui.current.address())
@utils.multicase(ea=six.integer_types)
def offset(ea):
    '''Return the offset of the address ``ea`` from the beginning of the current segment.'''
    return offset(ui.current.segment(), ea)
@utils.multicase(ea=six.integer_types)
def offset(segment, ea):
    '''Return the offset of the address ``ea`` from the beginning of ``segment``.'''
    seg = by(segment)
    return ea - segment.startEA

@utils.multicase(offset=six.integer_types)
def goof(offset):
    '''Go to the ``offset`` of the current segment.'''
    return goof(ui.current.segment(), offset)
@utils.multicase(offset=six.integer_types)
def goof(segment, offset):
    '''Go to the ``offset`` of the specified ``segment``.'''
    seg = by(segment)
    return database.go(seg.startEA + offset)

@utils.multicase()
def read():
    '''Return the contents of the current segment.'''
    segment = ui.current.segment()
    if segment is None:
        raise LookupError("{:s}.read() : Not currently positioned within a segment".format(__name__))
    return idaapi.get_many_bytes(segment.startEA, segment.endEA-segment.startEA)
@utils.multicase()
def read(segment):
    '''Return the contents of the segment identified by ``segment``.'''
    seg = by(segment)
    return idaapi.get_many_bytes(seg.startEA, seg.endEA-seg.startEA)
string = utils.alias(read)

@utils.multicase()
def repr():
    '''Return a repr() of the current segment.'''
    segment = ui.current.segment()
    if segment is None:
        raise LookupError("{:s}.repr() : Not currently positioned within a segment".format(__name__))
    return '{:s} {:s} {:x}-{:x} (+{:x})'.format(object.__repr__(segment),idaapi.get_true_segm_name(segment),segment.startEA,segment.endEA,segment.endEA-segment.startEA)
@utils.multicase()
def repr(segment):
    '''Return a repr() of the segment identified by ``segment``.'''
    '''Given a segment_t/address, return a printable representation of it'''
    seg = by(segment)
    return '{:s} {:s} {:x}-{:x} (+{:x})'.format(object.__repr__(seg),idaapi.get_true_segm_name(seg),seg.startEA,seg.endEA,seg.endEA-seg.startEA)

@utils.multicase()
def top():
    '''Return the top address of the current segment.'''
    segment = ui.current.segment()
    if segment is None:
        raise LookupError("{:s}.top() : Not currently positioned within a segment".format(__name__))
    return segment.startEA
@utils.multicase()
def top(segment):
    '''Return the top address of the segment identified by ``segment``.'''
    seg = by(segment)
    return seg.startEA

@utils.multicase()
def bottom():
    '''Return the bottom address of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise LookupError("{:s}.bottom() : Not currently positioned within a segment".format(__name__))
    return seg.endEA
@utils.multicase()
def bottom(segment):
    '''Return the bottom address of the segment identified by ``segment``.'''
    seg = by(segment)
    return seg.endEA

@utils.multicase()
def name():
    '''Return the name of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise LookupError("{:s}.name() : Not currently positioned within a segment".format(__name__))
    return idaapi.get_true_segm_name(seg)
@utils.multicase()
def name(segment):
    '''Return the name of the segment identified by ``segment``.'''
    seg = by(segment)
    return idaapi.get_true_segm_name(seg)

@utils.multicase(none=types.NoneType)
def set_color(segment, none):
    '''Clear the color of the segment identified by ``segment``.'''
    seg = by(segment)
    seg.color = 0xffffffff
    return bool(seg.update())
@utils.multicase(rgb=int)
def set_color(segment, rgb):
    '''Set the color of the segment identified by ``segment`` to ``rgb``.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    seg = by(segment)
    seg.color = (b<<16)|(rgb&0x00ff00)|r
    return bool(seg.update())
@utils.multicase(rgb=int)
def set_color(rgb):
    '''Set the color of the current segment to ``rgb``.'''
    return set_color(ui.current.segment(), rgb)
@utils.multicase(none=types.NoneType)
def set_color(none):
    '''Clear the color of the current segment.'''
    return set_color(ui.current.segment(), None)

@utils.multicase()
def get_color():
    '''Return the color of the current segment.'''
    seg = ui.current.segment()
    if seg is None:
        raise LookupError("{:s}.get_color() : Not currently positioned within a segment".format(__name__))
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b
@utils.multicase()
def get_color(segment):
    '''Return the color of the segment identified by ``segment``.'''
    seg = by(segment)
    b,r = (seg.color&0xff0000)>>16, seg.color&0x0000ff
    return None if seg.color == 0xffffffff else (r<<16)|(seg.color&0x00ff00)|b

@utils.multicase()
def color():
    '''Return the color of the current segment.'''
    return get_color(ui.current.segment())
@utils.multicase()
def color(segment):
    '''Return the color of the segment identified by ``segment``.'''
    return get_color(segment)
@utils.multicase(none=types.NoneType)
def color(none):
    '''Clear the color of the current segment.'''
    return set_color(ui.current.segment(), None)
@utils.multicase(none=types.NoneType)
def color(segment, none):
    '''Clear the color of the segment identified by ``segment``.'''
    return set_color(segment, None)
@utils.multicase(rgb=int)
def color(segment, rgb):
    '''Sets the color of the segment identified by ``segment`` to ``rgb``.'''
    return set_color(segment, rgb)

def contains():
    '''Returns True if the current address is within a segment.'''
    return contains(ui.current.segment(), ui.current.address())
@utils.multicase(ea=six.integer_types)
def contains(ea):
    '''Returns True if the address ``ea`` is contained within the current segment.'''
    return contains(ui.current.segment(), ea)
@utils.multicase(segaddr=six.integer_types, ea=six.integer_types)
def contains(segaddr, ea):
    '''Returns True if the address ``ea`` is contained within the segment owning the specified ``segaddr``.'''
    seg = by_address(segaddr)
    return contains(seg, ea)
@utils.multicase(name=basestring, ea=six.integer_types)
def contains(segname, ea):
    '''Returns True if the address ``ea`` is contained within the segment named ``segname``.'''
    seg = by_name(segname)
    return contains(seg, ea)
@utils.multicase(segment=idaapi.segment_t, ea=six.integer_types)
def contains(segment, ea):
    '''Returns True if the address ``ea`` is contained within the specified ``segment``.'''
    return segment.startEA <= ea < segment.endEA

## functions
# shamefully ripped from idc.py
def _load_file(filename, ea, size, offset=0):
    path = os.path.abspath(filename)
    li = idaapi.open_linput(path, False)
    if not li:
        raise IOError('{:s}.load_file({!r}, {:x}, {:#x}) : Unable to create loader_input_t : {:s}'.format(__name__, filename, ea, size, path))
    res = idaapi.file2base(li, offset, ea, ea+size, True)
    idaapi.close_linput(li)
    return res

def _save_file(filename, ea, size, offset=0):
    path = os.path.abspath(filename)
    of = idaapi.fopenWB(path)
    if not of:
        raise IOError('{:s}.save_file({!r}, {:x}, {:#x}) : Unable to open target file : {:s}'.format(__name__, filename, ea, size, path))
    res = idaapi.base2file(of, offset, ea, ea+size)
    idaapi.eclose(of)
    return res

def load(filename, ea, size=None, offset=0, **kwds):
    """Load the specified ``filename`` to the address ``ea`` as a segment.
    If ``size`` is not specified, use the length of the file.
    ``offset`` represents the offset into the file to use.
    ``name`` can be used to name the segment.
    """
    filesize = os.stat(filename).st_size

    if size is None:
        size = filesize - offset
    res = _load_file(filename, size, ea, offset)
    if not res:
        raise IOError("{:s}.load({!r}, {:x}, {:#x}, {:x}) : Unable to load file into {:#x}:{:+#x} : {:s}".format(__name__, filename, ea, size, offset, ea, size, os.path.relpath(filename)))
    return create(ea, size, kwds.get('name', os.path.split(filename)[1]))

def map(ea, size, newea, **kwds):
    """Map ``size`` bytes of data from ``ea`` into a new segment at ``newea``.
    ``name`` can be used to name the segment.
    """
    fpos,data = idaapi.get_fileregion_offset(ea),database.read(ea, size)
    if len(data) != size:
        raise ValueError("{:s}.map({:x}, {:#x}, {:x}) : Unable to read {:#x} bytes from {:#x}".format(__name__, ea, size, newea, size, ea))
    res = idaapi.mem2base(data, newea, fpos)
    if not res:
        raise ValueError("{:s}.map({:x}, {:#x}, {:x}) : Unable to remap {:#x}:{:+#x} to {:#x}".format(__name__, ea, size, newea, ea, size, newea))
    return create(newea, size, kwds.get('name', 'map_{:x}'.format(ea)))
    #return create(newea, size, kwds.get('name', 'map_{:s}'.format(newea>>4)))

# creation/destruction
def new(offset, size, name, **kwds):
    """Create a segment at ``offset`` with ``size`` and name it according to ``name``.
    ``bits`` can be used to specify the bit size of the segment
    ``comb`` can be used to specify any flags (idaapi.sc*)
    ``align`` can be used to specify paragraph alignment (idaapi.sa*)
    ``org`` specifies the origin of the segment (must be paragraph aligned due to ida)
    """
    s = idaapi.get_segm_by_name(name)
    if s is not None:
        logging.fatal("{:s}.new({:x}, {:x}, {!r}, {!r}) : a segment with the specified name already exists : {:s}".format(__name__, offset, size, name, kwds, name))
        return None

    bits = kwds.get( 'bits', 32 if idaapi.getseg(offset) is None else idaapi.getseg(offset).abits()) # FIXME: use disassembler default bit length instead of 32

    if bits == 16:
        ## create a selector with the requested origin
        org = kwds.get('org',0)
        if org&0xf > 0:
            logging.fatal("{:s}.new({:x}, {:x}, {!r}, {!r}) : origin (.org) is not aligned to the size of a paragraph (0x10) : {:x}".format(__name__, offset, size, name, kwds, org))
            return None

        para = offset/16
        sel = idaapi.allocate_selector(para)
        idaapi.set_selector(sel, (para-kwds.get('org',0)/16)&0xffffffff)
    else:
        ## auto-create a selector for everything else
        sel = idaapi.setup_selector(kwds['selector']) if 'selector' in kwds else idaapi.find_free_selector()

    # create segment. ripped from idc
    s = idaapi.segment_t()
    s.startEA = offset
    s.endEA = offset+size
    s.sel = sel
    s.bitness = {16:0,32:1,64:2}[bits]
    s.comb = kwds.get('comb', idaapi.scPub)       # public
    s.align = kwds.get('align', idaapi.saRelByte)  # paragraphs

    res = idaapi.add_segm_ex(s, name, "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)
    if res == 0:
        logging.warn("{:s}.new({:x}, {:x}, {!r}, {!r}) : unable to add a new segment".format(__name__, offset, size, name, kwds))
        res = idaapi.del_selector(sel)
        #assert res != 0
        return None
    return s
create = utils.alias(new)

def remove(segment, remove=False):
    """Remove the segment identified by ``segment``.
    If the bool ``remove`` is specified, then remove the content of the segment from the database.
    """
    if not isinstance(segment, idaapi.segment_t):
        raise TypeError('{:s}.remove({!r}) : segment is not of an idaapi.segment_t. : {!r}'.format(__name__, segment, type(segment)))
    res = idaapi.del_selector(segment.sel)
    if res == 0:
        logging.warn("{:s}.remove({!r}):Unable to delete selector {:x}".format(__name__, segment, segment.sel))
    res = idaapi.del_segm(segment.startEA, idaapi.SEGMOD_KILL if remove else idaapi.SEGMOD_KEEP)
    if res == 0:
        logging.warn("{:s}.remove({!r}):Unable to delete segment {:s} : {:s}".format(__name__, segment, segment.name, segment.sel))
    return res
delete = utils.alias(remove)

def save(filename, segment, offset=0):
    """Export the segment identified by ``segment`` to the file named ``filename``.

    If the int ``offset`` is specified, then begin writing into the file at the specified offset.
    """
    if isinstance(segment, idaapi.segment_t):
        return _save_file(filename, segment.startEA, size(segment), offset)
    return save(filename, by(segment))
export = utils.alias(save)

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)

