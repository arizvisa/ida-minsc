'''
segment-context

generic tools for working with segments
'''
import idc,database,idaapi
import logging,os

## enumerating
def iterate():
    '''Iterate through each segment_t defined in the database'''
    for n in xrange(idaapi.get_segm_qty()):
        yield idaapi.getnseg(n)
    return
def list():
    '''List all the segments defined in the database by name'''
    for n in iterate():
        yield idaapi.get_true_segm_name(n) or ""
    return

## searching
def byName(name):
    '''Return the segment_t with the given /name/'''
    s = idaapi.get_segm_by_name(name)
    if s is None:
        raise Exception, "segment.byName(%r):unable to locate segment"% name
    return s
def bySelector(selector):
    '''Return the segment_t associated with /selector/'''
    s = idaapi.get_segm_by_sel(selector)
    if s is None:
        raise Exception, "segment.bySelector(%x):unable to locate segment"% selector
    return s
def byAddress(ea):
    '''Return the segment_t that holds the specified /ea/'''
    s = idaapi.getseg(ea)
    if s is None:
        raise Exception, "segment.byAddress(%x):unable to locate segment"% ea
    return s
def by(n):
    if type(n) is idaapi.segment_t:
        return n
    if type(n) is str:
        return byName(n)
    return byAddress(n)

## properties
def range(segment):
    '''Given a segment_t/address, return it's (begin,end)'''
    if type(segment) is idaapi.segment_t:
        return segment.startEA,segment.endEA
    return range(by(segment))
def size(segment):
    '''Given a segment_t/address, return it's size'''
    if type(segment) is idaapi.segment_t:
        return segment.endEA - segment.startEA
    return size(by(segment))
def string(segment):
    '''Given a segment_t/address, return it's contents as a string'''
    if type(segment) is idaapi.segment_t:
        return idaapi.get_many_bytes(segment.startEA, segment.endEA-segment.startEA)
    return string(by(segment))
def repr(segment):
    '''Given a segment_t/address, return a printable representation of it'''
    if type(segment) is idaapi.segment_t:
        return '{:s} {:s} {:x}-{:x} (+{:x})'.format(object.__repr__(segment),idaapi.get_true_segm_name(segment),segment.startEA,segment.endEA,segment.endEA-segment.startEA)
    return repr(by(segment))
def top(segment):
    '''Given a segment_t/address, return it's top address'''
    if type(segment) is idaapi.segment_t:
        return segment.startEA
    return top(by(segment))
def bottom(segment):
    '''Given a segment_t/address, return it's bottom address'''
    if type(segment) is idaapi.segment_t:
        return segment.endEA
    return bottom(by(segment))
def name(segment):
    '''Given a segment_t/address, return it's name'''
    if type(segment) is idaapi.segment_t:
        return idaapi.get_true_segm_name(segment)
    return name(by(segment))

## functions
# shamefully ripped from idc.py
def _load_file(filename, ea, size, offset=0):
    path = os.path.abspath(filename)
    li = idaapi.open_linput(path, False)
    if not li:
        raise Exception, 'Unable to create loader_input_t : %s'% path
    res = idaapi.file2base(li, offset, ea, ea+size, True)
    idaapi.close_linput(li)
    return res
def _save_file(filename, ea, size, offset=0):
    path = os.path.abspath(filename)
    of = idaapi.fopenWB(path)
    if not of:
        raise Exception, 'Unable to open target file : %s'% path
    res = idaapi.base2file(of, offset, ea, ea+size)
    idaapi.eclose(of)
    return res
def load(filename, ea, size=None, offset=0, **kwds):
    '''Load the specified /filename/ to the address /ea/

    If /size/ is not specified, use the length of the file.
    /offset/ represents the offset into the file to use.
    /name/ can be used to name the segment.
    '''
    filesize = os.stat(filename).st_size

    if size is None:
        size = filesize - offset
    res = _load_file(filename, size, ea, offset)
    if not res:
        raise Exception, "Unable to load file into %x:+%x : %s"% (ea, size, os.path.relpath(filename))
    return create(ea, size, kwds.get('name', os.path.split(filename)[1]))

def map(ea, size, newea, **kwds):
    '''Map /size/ bytes of data from /ea/ into a new segment at /newea/

    /name/ can be used to name the segment.
    '''
    fpos,data = idaapi.get_fileregion_offset(ea),database.read(ea, size)
    if len(data) != size:
        raise Exception, "Unable to read %x bytes from %x"% (size, ea)
    res = idaapi.mem2base(data, newea, fpos)
    if not res:
        raise Exception, "Unable to remap %x:+%x to %x"% (ea, size, newea)
    return create(newea, size, kwds.get('name', 'map_%x'% ea))
    #return create(newea, size, kwds.get('name', 'map_%x'% newea>>4))

# creation/destruction
def create(offset, size, name, **kwds):
    '''Create a segment at /offset/ and /size/ and name it /name/

    /bits/ can be used to specify the bit size of the segment
    /comb/ can be used to specify any flags (idaapi.sc*)
    /align/ can be used to specify paragraph alignment (idaapi.sa*)
    /org/ specifies the origin of the segment (must be paragraph aligned due to ida)
    '''
    s = idaapi.get_segm_by_name(name)
    if s is not None:
        logging.fatal("segment.create(%x, %x, %r, %r) : a segment with the specified name already exists : %s", offset, size, name, kwds, name)
        return None

    bits = kwds.get( 'bits', 32 if idaapi.getseg(offset) is None else idaapi.getseg(offset).abits()) # FIXME: use disassembler default bit length instead of 32

    if bits == 16:
        ## create a selector with the requested origin
        org = kwds.get('org',0)
        if org&0xf > 0:
            logging.fatal("segment.create(%x, %x, %r, %r) : origin (.org) is not aligned to the size of a paragraph (0x10):%x", offset, size, name, kwds, org)
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
        logging.warn("segment.create(%x, %x, %r, %r) : unable to add a new segment", offset, size, name, kwds)
        res = idaapi.del_selector(sel)
        #assert res != 0
        return None
    return s

def delete(segment, remove=False):
    '''Given a segment_t, delete it along with any selectors that might point to it.'''
    assert type(segment) is idaapi.segment_t
    assert segment is not None
    res = idaapi.del_selector(segment.sel)
    if res == 0:
        logging.warn("segment.delete(%s):Unable to delete selector %x", repr(segment), segment.sel)
    res = idaapi.del_segm(segment.startEA, idaapi.SEGMOD_KILL if remove else idaapi.SEGMOD_KEEP)
    if res == 0:
        logging.warn("segment %s:Unable to delete segment %s", segment.name, segment.sel)
    return res

def save(filename, segment, offset=0):
    '''Export /segment/ into the file specified by /filename/

    /offset/ specified an offset into the file
    '''
    if type(segment) is idaapi.segment_t:
        return _save_file(filename, segment.startEA, size(segment), offset)
    return save(filename, by(segment))

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)

