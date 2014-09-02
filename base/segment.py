'''
segment-context

generic tools for working with segments
'''
import idc,database
import idaapi,logging

def top(ea):
    return byAddress(ea).startEA
def bottom(ea):
    return byAddress(ea).endEA

# enumerating
def iterate():
    for n in xrange(idaapi.get_segm_qty()):
        yield idaapi.getnseg(n)
    return

def list():
    for n in iterate():
        yield idaapi.get_true_segm_name(n) or ""
    return

# searching
def byName(name):
    s = idaapi.get_segm_by_name(name)
    if s is None:
        # these should be in a decorator...
        logging.warn("segment.byName(%s):unable to locate segment", repr(name))
    return s

def bySelector(ea):
    s = idaapi.get_segm_by_sel(ea)
    if s is None:
        logging.warn("segment.bySelector(%x):unable to locate segment", ea)
    return s

def byAddress(ea):
    s = idaapi.getseg(ea)
    if s is None:
        logging.warn("segment.byAddress(%x):unable to locate segment", ea)
    return s

# creation/destruction
def create(selector, offset, size, bits=32, name=""):
    sel = idaapi.setup_selector(selector)
    assert sel is not None
    res = idaapi.set_selector(sel, offset>>4)
    assert res != 0

    # create segment. ripped from idc
    s = idaapi.segment_t()
    s.startEA = offset
    s.endEA = offset+size
    s.sel = sel
    s.bitness = {16:0,32:1,64:2}[bits]
    s.comb = idaapi.scPub       # public
    s.align = idaapi.saRelPara  # paragraphs
    res = idaapi.add_segm_ex(s, name, "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)
    if res == 0:
        logging.warn("segment.create(%x, %x, %x, %d, %s):unable to create segment", selector, offset, size, bits, repr(name))
        res = idaapi.del_selector(sel)
        assert res != 0
        return None
    return s

def delete(segment):
    assert type(segment) is idaapi.segment_t
    assert segment is not None
    res = idaapi.del_selector(segment.sel)
    if res == 0:
        logging.warn("segment.delete(%s):Unable to delete selector %x", repr(segment), segment.sel)
    res = idaapi.del_segm(segment.startEA, idaapi.SEGMOD_KILL)
    if res == 0:
        logging.warn("segment %s:Unable to delete segment %s", name, segment.sel)
    return res

# properties
def range(segment):
    if type(segment) is idaapi.segment_t:
        return segment.startEA,segment.endEA
    return range(byAddress(segment))

#res = idaapi.add_segment_translation(ea, selector)
#res = idaapi.del_segment_translation(ea)

