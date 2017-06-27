import six
import idaapi

try:
    # XXX: fuck you ida 6.95 for breaking your api
    import _ida_netnode
except ImportError:
    import idaapi as _ida_netnode

MAXSPECSIZE = idaapi.MAXSTR
MAXNAMESIZE = idaapi.MAXNAMELEN

class utils(object):
    @classmethod
    def range(cls):
        this = _ida_netnode.new_netnode()
        ok, start = _ida_netnode.netnode_start(this), _ida_netnode.netnode_index(this)
        if not ok: raise StandardError("{:s}.range : Unable to find first node.".format('.'.join((__name__,cls.__name__))))
        ok, end = _ida_netnode.netnode_end(this), _ida_netnode.netnode_index(this)
        if not ok: raise StandardError("{:s}.range : Unable to find last node.".format('.'.join((__name__,cls.__name__))))
        return start, end

    @classmethod
    def renumerate(cls):
        start, end = cls.range()
        this = _ida_netnode.new_netnode()
        ok = _ida_netnode.netnode_end(this)
        assert ok

        yield end, _ida_netnode.new_netnode(end)
        while end != start:
            ok = _ida_netnode.netnode_prev(this)
            if not ok: break
            end = _ida_netnode.netnode_index(this)
            yield end, _ida_netnode.new_netnode(end)
        return

    @classmethod
    def fenumerate(cls):
        start, end = cls.range()
        this = _ida_netnode.new_netnode()
        ok = _ida_netnode.netnode_start(this)
        assert ok

        yield start, _ida_netnode.new_netnode(start)
        while start != end:
            ok = _ida_netnode.netnode_next(this)
            if not ok: break
            start = _ida_netnode.netnode_index(this)
            yield start, _ida_netnode.new_netnode(start)
        return

    @classmethod
    def valfiter(cls, node, first, last, next, val):
        start, end = first(node), last(node)
        if start in (None,idaapi.BADADDR): return
        yield start, val(node, start)
        while start != end:
            start = next(node, start)
            yield start, val(node, start)
        return

    @classmethod
    def valriter(cls, node, first, last, prev, val):
        start, end = first(node), last(node)
        if end in (None,idaapi.BADADDR): return
        yield end, val(node, end)
        while end != start:
            end = prev(node, end)
            yield end, val(node, end)
        return

    @classmethod
    def hfiter(cls, node, first, last, next, val):
        start, end = first(node), last(node)
        if val(node, start or '') is None: return
        yield start or '', val(node, start or '')
        while start != end:
            start = next(node, start or '')
            yield start or '', val(node, start or '')
        return

    @classmethod
    def hriter(cls, node, first, last, prev, val):
        start, end = first(node), last(node)
        if val(node, start or '') is None: return
        yield end or '', val(node, end or '')
        while end != start:
            end = prev(node, end or '')
            yield end, val(node, end or '')
        return

    @classmethod
    def falt(cls, node):
        for res in cls.valfiter(node, _ida_netnode.netnode_alt1st, _ida_netnode.netnode_altlast, _ida_netnode.netnode_altnxt, _ida_netnode.netnode_altval):
            yield res
        return
    @classmethod
    def ralt(cls, node):
        for res in cls.valriter(node, _ida_netnode.netnode_alt1st, _ida_netnode.netnode_altprev, _ida_netnode.netnode_altnxt, _ida_netnode.netnode_altval):
            yield res
        return

    @classmethod
    def fsup(cls, node):
        for res in cls.valfiter(node, _ida_netnode.netnode_sup1st, _ida_netnode.netnode_suplast, _ida_netnode.netnode_supnxt, _ida_netnode.netnode_supval):
            yield res
        return
    @classmethod
    def rsup(cls, node):
        for res in cls.valriter(node, _ida_netnode.netnode_sup1st, _ida_netnode.netnode_supprev, _ida_netnode.netnode_supnxt, _ida_netnode.netnode_supval):
            yield res
        return

    @classmethod
    def fhash(cls, node):
        for res in cls.hfiter(node, _ida_netnode.netnode_hash1st, _ida_netnode.netnode_hashlast, _ida_netnode.netnode_hashnxt, _ida_netnode.netnode_hashval):
            yield res
        return
    @classmethod
    def rhash(cls, node):
        for res in cls.hriter(node, _ida_netnode.netnode_hash1st, _ida_netnode.netnode_hashprev, _ida_netnode.netnode_hashnxt, _ida_netnode.netnode_hashval):
            yield res
        return

    @classmethod
    def fchar(cls, node):
        for res in cls.valfiter(node, _ida_netnode.netnode_char1st, _ida_netnode.netnode_charlast, _ida_netnode.netnode_charnxt, _ida_netnode.netnode_charval):
            yield res
        return
    @classmethod
    def rchar(cls, node):
        for res in cls.valriter(node, _ida_netnode.netnode_char1st, _ida_netnode.netnode_charprev, _ida_netnode.netnode_charnxt, _ida_netnode.netnode_charval):
            yield res
        return

def new(name):
    node = _ida_netnode.new_netnode(name, len(name), True)
    return _ida_netnode.netnode_index(node)

def get(name):
    if isinstance(name, six.integer_types):
        node = _ida_netnode.new_netnode(name)
        return _ida_netnode.netnode_index(node)
    node = _ida_netnode.new_netnode(name, len(name), False)
    return _ida_netnode.netnode_index(node)

def remove(nodeidx):
    node = _ida_netnode.new_netnode(nodeidx)
    return _ida_netnode.netnode_kill(node)

### node name
class name(object):
    @classmethod
    def get(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_name(node)
    @classmethod
    def set(cls, nodeidx, string):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_rename(node, string)

### node value (?)
class value(object):
    @classmethod
    def exists(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_value_exists(node)

    @classmethod
    def get(cls, nodeidx, type=None):
        node = _ida_netnode.new_netnode(nodeidx)
        if not _ida_netnode.netnode_value_exists(node):
            return None

        if type is None:
            return _ida_netnode.netnode_valobj(node)
        elif issubclass(type, basestring):
            return _ida_netnode.netnode_valstr(node)
        elif issubclass(type, six.integer_types):
            return _ida_netnode.netnode_long_value(node)
        raise TypeError(type)

    @classmethod
    def set(cls, nodeidx, value, type=None):
        node = _ida_netnode.new_netnode(nodeidx)
        if type is None:
            return _ida_netnode.netnode_set(node, value)
        elif issubclass(type, six.integer_types):
            return _ida_netnode.netnode_set_long(node, value)
        raise TypeError(type)

    @classmethod
    def remove(cls, nodeidx, value):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_delvalue(node)

    @classmethod
    def repr(cls, nodeidx):
        if not cls.exists(nodeidx):
            raise ValueError("Node {:x} has no value.".format(nodeidx))
        res, s, val = cls.get(nodeidx), cls.get(nodeidx, type=str), cls.get(nodeidx, type=int)
        return '{!r} {!r} 0x{:x}'.format(res, s, val)

### node blob
class blob(object):
    @classmethod
    def get(cls, nodeidx, tag, start=0):
        node = _ida_netnode.new_netnode(nodeidx)
        sz = _ida_netnode.netnode_blobsize(node, start, tag)
        res = _ida_netnode.netnode_getblob(node, start, tag)
        return None if res is None else res[:sz]

    @classmethod
    def set(cls, nodeidx, tag, val, start=0):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_setblob(node, val, start, tag)

    @classmethod
    def remove(cls, nodeidx, tag, start=0):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_delblob(node, start, tag)

    @classmethod
    def size(cls, nodeidx, tag, start=0):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_blobsize(node, start, tag)

    @classmethod
    def repr(cls, nodeidx, tag):
        if cls.size(nodeidx, tag) == 0:
            raise ValueError("Node {:x}({:s}) has no blob.".format(nodeidx, tag))
        res = cls.get(nodeidx, tag)
        return repr(res)

### node iteration
def riter():
    for nodeidx,_ in utils.renumerate():
        yield nodeidx
    return
def fiter():
    for nodeidx,_ in utils.fenumerate():
        yield nodeidx
    return

### node altval iteration
class alt(object):
    '''Sparse array[int] of int'''
    @classmethod
    def get(cls, nodeidx, idx):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_altval(node, idx)

    @classmethod
    def set(cls, nodeidx, idx, val):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_altset(node, idx, val)

    @classmethod
    def remove(cls, nodeidx, idx):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_altdel(node, idx)

    @classmethod
    def fiter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for idx,val in utils.falt(node):
            yield idx,val
        return

    @classmethod
    def riter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for idx,val in utils.ralt(node):
            yield idx,val
        return

    @classmethod
    def repr(cls, nodeidx):
        res = []
        for idx, val in cls.fiter(nodeidx):
            res.append('{0:x} : 0x{1:x} ({1:d})'.format(idx, val))
        if not res:
            raise ValueError("Node {:x} has no alts.".format(nodeidx))
        return '\n'.join(res)

### node sup iteration
class sup(object):
    '''Sparse array[int] of 1024b strings'''

    @classmethod
    def get(cls, nodeidx, idx, type=None):
        node = _ida_netnode.new_netnode(nodeidx)
        if type is None:
            return _ida_netnode.netnode_supval(node, idx)
        elif issubclass(type, basestring):
            return _ida_netnode.netnode_supstr(node, idx)
        raise TypeError(type)

    @classmethod
    def set(cls, nodeidx, idx, val):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_supset(node, idx, val)

    @classmethod
    def remove(cls, nodeidx, idx):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_supdel(node, idx)

    @classmethod
    def fiter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for idx,_ in utils.fsup(node):
            yield idx
        return

    @classmethod
    def riter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for idx,_ in utils.rsup(node):
            yield idx
        return

    @classmethod
    def repr(cls, nodeidx):
        res = []
        for i, idx in enumerate(cls.fiter(nodeidx)):
            val = cls.get(nodeidx, idx)
            res.append('[{:d}] {:x} : {!r}'.format(i, idx, val))
        if not res:
            raise ValueError("Node {:x} has no sups.".format(nodeidx))
        return '\n'.join(res)

### node hash iteration
class hash(object):
    '''Dictionary[char*510] of 1024b strings'''
    @classmethod
    def get(cls, nodeidx, key, type=None):
        node = _ida_netnode.new_netnode(nodeidx)
        if type is None:
            return _ida_netnode.netnode_hashval(node, key or '')
        elif issubclass(type, basestring):
            return _ida_netnode.netnode_hashstr(node, key or '')
        elif issubclass(type, buffer):
            return _ida_netnode.netnode_hashstr_buf(node, key or '')
        elif issubclass(type, six.integer_types):
            return _ida_netnode.netnode_hashval_long(node, key or '')
        raise TypeError(type)

    @classmethod
    def set(cls, nodeidx, key, val):
        node = _ida_netnode.new_netnode(nodeidx)
        # in my testing the type really doesn't matter
        if isinstance(val, basestring):
            return _ida_netnode.netnode_hashset(node, key, val)
        elif isinstance(val, buffer):
            return _ida_netnode.netnode_hashset_buf(node, key, val)
        elif isinstance(val, six.integer_types):
            return _ida_netnode.netnode_hashset_idx(node, key, val)
        raise TypeError(type)

    @classmethod
    def remove(cls, nodeidx, key):
        node = _ida_netnode.new_netnode(nodeidx)
        return _ida_netnode.netnode_hashdel(node, key)

    @classmethod
    def fiter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for key,_ in utils.fhash(node):
            yield key
        return

    @classmethod
    def riter(cls, nodeidx):
        node = _ida_netnode.new_netnode(nodeidx)
        for key,_ in utils.rhash(node):
            yield key
        return

    @classmethod
    def repr(cls, nodeidx):
        res = []
        try:
            l1 = max(len(key or '') for key in cls.fiter(nodeidx))
            l2 = max(len(repr(cls.get(nodeidx, key))) for key in cls.fiter(nodeidx))
        except ValueError:
            l1, l2 = 0, 2

        for i, key in enumerate(cls.fiter(nodeidx)):
            val = '{:<{:d}s} : str="{:s}", buffer={!r}, int=0x{:x}({:d})'.format(repr(cls.get(nodeidx, key)), l2, cls.get(nodeidx, key, str), cls.get(nodeidx, key, buffer), cls.get(nodeidx, key, int), cls.get(nodeidx, key, int))
            res.append('[{:d}] {:<{:d}s} -> {:s}'.format(i, key, l1, val))
        if not res:
            raise ValueError("Node {:x} has no hashes.".format(nodeidx))
        return '\n'.join(res)

# FIXME: implement a file-allocation-table based filesystem using the netnode wrappers defined above
class filesystem(object):
    ALLOCATION_TABLE = '$ file-allocation-table'
    SECTOR_TABLE = '$ sector-table'
    SECTOR = 1024
    def __init__(self, name):
        node = idaapi.netnode(name, 0, True)
