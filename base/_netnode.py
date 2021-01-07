"""
Netnode module (internal)

This module wraps IDA's netnode API and dumbs it down so that a user
can be mindless when reading/writing/enumerating data out of a netnode.
This is an internal module and is not expected to be used by the user.
"""

import six
import idaapi

import internal

MAXSPECSIZE = idaapi.MAXSTR
MAXNAMESIZE = idaapi.MAXNAMELEN

class netnode(object):
    """
    This namespace is an interface to IDA's netnode api. This aims to provide a
    portable way of accessing a netnode between all the different variations and
    versions of IDA.
    """
    try:
        # ida 6.95 splits up their idaapi module into smaller namespaces
        import _ida_netnode
    except ImportError:
        # _ida_netnode has got to be in at least one of these idaapi modules...
        import idaapi as _ida_netnode
        if not hasattr(idaapi, 'new_netnode'):
            import _idaapi as _ida_netnode

    new = get = root = _ida_netnode.new_netnode
    delete = _ida_netnode.delete_netnode
    start = _ida_netnode.netnode_start
    end = _ida_netnode.netnode_end
    index = _ida_netnode.netnode_index
    kill = _ida_netnode.netnode_kill
    long_value = _ida_netnode.netnode_long_value
    next = _ida_netnode.netnode_next
    prev = _ida_netnode.netnode_prev
    rename = _ida_netnode.netnode_rename
    #copyto = _ida_netnode.netnode_copyto
    #create = _ida_netnode.netnode_create
    #moveto = _ida_netnode.netnode_moveto
    set = _ida_netnode.netnode_set
    set_long = _ida_netnode.netnode_set_long
    delvalue = _ida_netnode.netnode_delvalue

    blobsize = _ida_netnode.netnode_blobsize
    getblob = _ida_netnode.netnode_getblob
    setblob = _ida_netnode.netnode_setblob
    delblob = _ida_netnode.netnode_delblob

    altdel = _ida_netnode.netnode_altdel
    altlast = _ida_netnode.netnode_altlast
    altprev = _ida_netnode.netnode_altprev
    altset = _ida_netnode.netnode_altset
    altval = _ida_netnode.netnode_altval

    charlast = _ida_netnode.netnode_charlast
    charprev = _ida_netnode.netnode_charprev
    chardel = _ida_netnode.netnode_chardel
    charset = _ida_netnode.netnode_charset
    charval = _ida_netnode.netnode_charval

    hashdel = _ida_netnode.netnode_hashdel
    hashlast = _ida_netnode.netnode_hashlast
    hashprev = _ida_netnode.netnode_hashprev
    hashset = _ida_netnode.netnode_hashset
    hashset_buf = _ida_netnode.netnode_hashset_buf
    hashset_idx = _ida_netnode.netnode_hashset_idx
    hashstr = _ida_netnode.netnode_hashstr
    hashstr_buf = _ida_netnode.netnode_hashstr_buf
    hashval = _ida_netnode.netnode_hashval
    hashval_long = _ida_netnode.netnode_hashval_long

    supdel = _ida_netnode.netnode_supdel
    suplast = _ida_netnode.netnode_suplast
    supprev = _ida_netnode.netnode_supprev
    supset = _ida_netnode.netnode_supset
    supstr = _ida_netnode.netnode_supstr
    supval = _ida_netnode.netnode_supval

    valobj = _ida_netnode.netnode_valobj
    valstr = _ida_netnode.netnode_valstr
    value_exists = _ida_netnode.netnode_value_exists

    # now to fix up the version skew as a result of IDA 7.0
    if idaapi.__version__ < 7.0:
        supfirst = _ida_netnode.netnode_sup1st
        supnext = _ida_netnode.netnode_supnxt
        hashnext = _ida_netnode.netnode_hashnxt
        hashfirst = _ida_netnode.netnode_hash1st
        charfirst = _ida_netnode.netnode_char1st
        charnext = _ida_netnode.netnode_charnxt
        name = _ida_netnode.netnode_name
        altfirst = _ida_netnode.netnode_alt1st
        altnext = _ida_netnode.netnode_altnxt

    else:   # >= 7.0
        supfirst = _ida_netnode.netnode_supfirst
        supnext = _ida_netnode.netnode_supnext
        hashnext = _ida_netnode.netnode_hashnext
        hashfirst = _ida_netnode.netnode_hashfirst
        charfirst = _ida_netnode.netnode_charfirst
        charnext = _ida_netnode.netnode_charnext
        name = _ida_netnode.netnode_get_name
        altfirst = _ida_netnode.netnode_altfirst
        altnext = _ida_netnode.netnode_altnext

class utils(object):
    """
    This namespace provides utilities for interacting with a netnode and each
    of the types that it may be composed of. Primarily, these functions allow
    one to iterate through the types contained within the netnode.
    """
    @classmethod
    def range(cls):
        '''Return the bounds of each netnode (nodeidx_t) within the database.'''
        this = netnode.root()
        ok, start = netnode.start(this), netnode.index(this)
        if not ok: raise internal.exceptions.NetNodeNotFoundError(u"{:s}.range() : Unable to find first node.".format('.'.join([__name__, cls.__name__])))
        ok, end = netnode.end(this), netnode.index(this)
        if not ok: raise internal.exceptions.NetNodeNotFoundError(u"{:s}.range() : Unable to find end node.".format('.'.join([__name__, cls.__name__])))
        return start, end

    @classmethod
    def renumerate(cls):
        '''Iterate through each netnode in the database in reverse order, and yield the (nodeidx_t, netnode*) for each item found.'''
        start, end = cls.range()
        this = netnode.root()
        ok = netnode.end(this)
        if not ok:
            raise internal.exceptions.NetNodeNotFoundError(u"{:s}.renumerate() : Unable to find the end node.".format('.'.join([__name__, cls.__name__])))

        yield end, netnode.get(end)
        while end != start:
            ok = netnode.prev(this)
            if not ok: break
            end = netnode.index(this)
            yield end, netnode.get(end)
        return

    @classmethod
    def fenumerate(cls):
        '''Iterate through each netnode in the database in order, and yield the (nodeidx_t, netnode*) for each item found.'''
        start, end = cls.range()
        this = netnode.root()
        ok = netnode.start(this)
        if not ok:
            raise internal.exceptions.NetNodeNotFoundError(u"{:s}.fenumerate() : Unable to find the start node.".format('.'.join([__name__, cls.__name__])))

        yield start, netnode.get(start)
        while start != end:
            ok = netnode.next(this)
            if not ok: break
            start = netnode.index(this)
            yield start, netnode.get(start)
        return

    @classmethod
    def valfiter(cls, node, first, last, next, val):
        '''Iterate through all of the values for a netnode in order, and yield the (item, value) for each item that was found.'''
        start, end = first(node), last(node)
        if start in {None, idaapi.BADADDR}: return
        yield start, val(node, start)
        while start != end:
            start = next(node, start)
            yield start, val(node, start)
        return

    @classmethod
    def valriter(cls, node, first, last, prev, val):
        '''Iterate through all of the values for a netnode in reverse order, and yield the (item, value) for each item that was found.'''
        start, end = first(node), last(node)
        if end in {None, idaapi.BADADDR}: return
        yield end, val(node, end)
        while end != start:
            end = prev(node, end)
            yield end, val(node, end)
        return

    @classmethod
    def hfiter(cls, node, first, last, next, val):
        '''Iterate through all of the hash values for a netnode in order, and yield the (item, value) for each item that was found.'''
        start, end = first(node), last(node)

        # if start is not defined, its the same as end, and there's no value
        # for the empty string...then there's no keys defined and we can leave.
        if start is None and start == end and val(node, start or '') is None:
            return

        # otherwise, we start at the first item and continue on till the end.
        yield start or '', val(node, start or '')
        while start != end:
            start = next(node, start or '')
            yield start or '', val(node, start or '')
        return

    @classmethod
    def hriter(cls, node, first, last, prev, val):
        '''Iterate through all of the hash values for a netnode in reverse order, and yield the (item, value) for each item that was found.'''
        start, end = first(node), last(node)

        # if end is not defined, its the same as start, and there's no value
        # for the empty string...then there's no keys defined and we can leave.
        if end is None and start == end and val(node, end or '') is None:
            return

        # otherwise, we start at the last item and continue on till the beginning.
        yield end or '', val(node, end or '')
        while end != start:
            end = prev(node, end or '')
            yield end or '', val(node, end or '')
        return

    @classmethod
    def falt(cls, node):
        '''Iterate through each "altval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.altfirst, netnode.altlast, netnode.altnext, netnode.altval):
            yield item
        return
    @classmethod
    def ralt(cls, node):
        '''Iterate through each "altval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.altfirst, netnode.altlast, netnode.altprev, netnode.altval):
            yield item
        return

    @classmethod
    def fsup(cls, node):
        '''Iterate through each "supval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.supfirst, netnode.suplast, netnode.supnext, netnode.supval):
            yield item
        return
    @classmethod
    def rsup(cls, node):
        '''Iterate through each "supval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.supfirst, netnode.suplast, netnode.supprev, netnode.supval):
            yield item
        return

    @classmethod
    def fhash(cls, node):
        '''Iterate through each "hashval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.hfiter(node, netnode.hashfirst, netnode.hashlast, netnode.hashnext, netnode.hashval):
            yield item
        return
    @classmethod
    def rhash(cls, node):
        '''Iterate through each "hashval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.hriter(node, netnode.hashfirst, netnode.hashlast, netnode.hashprev, netnode.hashval):
            yield item
        return

    @classmethod
    def fchar(cls, node):
        '''Iterate through each "charval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.charfirst, netnode.charlast, netnode.charnext, netnode.charval):
            yield item
        return
    @classmethod
    def rchar(cls, node):
        '''Iterate through each "charval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.charfirst, netnode.charlast, netnode.charprev, netnode.charval):
            yield item
        return

def new(name):
    '''Create a netnode with the given `name`, and return its identifier.'''
    res = internal.utils.string.to(name)
    node = netnode.new(res, len(res), True)
    return netnode.index(node)

def get(name):
    '''Get (or create) a netnode with the given `name`, and return its identifier.'''
    if isinstance(name, six.integer_types):
        node = netnode.get(name)
        return netnode.index(node)
    res = internal.utils.string.to(name)
    node = netnode.get(res, len(res))
    return netnode.index(node)

def remove(nodeidx):
    '''Remove the netnode with the identifier `nodeidx`.'''
    node = netnode.get(nodeidx)
    return netnode.kill(node)

### node name
class name(object):
    """
    This namespace is used to interact with the naming information for a given netnode.
    """
    @classmethod
    def get(cls, nodeidx):
        '''Return the name of the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        res = netnode.name(node)
        return internal.utils.string.of(res)
    @classmethod
    def set(cls, nodeidx, string):
        '''Set the name of the netnode identified by `nodeidx` to `string`.'''
        node = netnode.get(nodeidx)
        res = internal.utils.string.to(string)
        return netnode.rename(node, res)

### node value (?)
class value(object):
    """
    This namespace is used to interact with the value for a given netnode.
    """
    @classmethod
    def exists(cls, nodeidx):
        '''Return whether the node identified by `nodeidx` has a value associated with it.'''
        node = netnode.get(nodeidx)
        return netnode.value_exists(node)

    @classmethod
    def get(cls, nodeidx, type=None):
        '''Return the value for the netnode identified by `nodeidx` casted to the provided `type`.'''
        node = netnode.get(nodeidx)
        if not netnode.value_exists(node):
            return None

        if type in {None}:
            return netnode.valobj(node)
        elif issubclass(type, memoryview):
            res = netnode.valobj(node)
            return res and memoryview(res)
        elif issubclass(type, bytes):
            res = netnode.valstr(node)
            return res and bytes(res)
        elif issubclass(type, six.string_types):
            return netnode.valstr(node)
        elif issubclass(type, six.integer_types):
            return netnode.long_value(node)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's value.".format('.'.join([__name__, cls.__name__]), nodeidx, type, type))

    @classmethod
    def set(cls, nodeidx, value):
        '''Set the value for the netnode identified by `nodeidx` to the provided `value`.'''
        node = netnode.get(nodeidx)
        if isinstance(value, memoryview):
            return netnode.set(nodeidx, value.tobytes())
        elif isinstance(value, bytes):
            return netnode.set(node, value)
        elif isinstance(value, six.string_types):
            return netnode.set(node, value)
        elif isinstance(value, six.integer_types):
            return netnode.set_long(node, value)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:#x}, {!r}) : An unsupported type ({!r}) was specified for the netnode's value.".format('.'.join([__name__, cls.__name__]), nodeidx, value, value.__class__))

    @classmethod
    def remove(cls, nodeidx):
        '''Remove the value for the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.delvalue(node)

    @classmethod
    def repr(cls, nodeidx):
        '''Display the value for the netnode identified by `nodeidx`.'''
        if not cls.exists(nodeidx):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:#x}) : The specified node ({:x}) does not have any value.".format('.'.join([__name__, cls.__name__]), nodeidx, nodeidx))
        res, string, value = cls.get(nodeidx), cls.get(nodeidx, type=bytes), cls.get(nodeidx, type=int)
        return "{!r} {!r} {:#x}".format(res, string, value)

### node blob
class blob(object):
    """
    This namespace is used to interact with the blob assigned to a given netnode.
    """
    @classmethod
    def get(cls, nodeidx, tag, start=0):
        """Return the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then return the bytes from the specified offset.
        """
        node = netnode.get(nodeidx)
        sz = netnode.blobsize(node, start, tag)
        res = netnode.getblob(node, start, tag)
        return None if res is None else res[:sz]

    @classmethod
    def set(cls, nodeidx, tag, value, start=0):
        """Assign the data provided by `value` to the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then store the provided `value` at the given offset.
        """
        node = netnode.get(nodeidx)
        return netnode.setblob(node, value.tobytes() if isinstance(value, memoryview) else value, start, tag)

    @classmethod
    def remove(cls, nodeidx, tag, start=0):
        """Remove the data from the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then remove the data at the given offset.
        """
        node = netnode.get(nodeidx)
        return netnode.delblob(node, start, tag)

    @classmethod
    def size(cls, nodeidx, tag, start=0):
        """Return the size of the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then return the size from the given offset.
        """
        node = netnode.get(nodeidx)
        return netnode.blobsize(node, start, tag)

    @classmethod
    def repr(cls, nodeidx, tag):
        '''Display the blob stored in `tag` for the netnode identified by `nodeidx`.'''
        if cls.size(nodeidx, tag) == 0:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:#x}, {!r}) : The tag {!r} for the specified node ({:x}) does not have a blob.".format('.'.join([__name__, cls.__name__]), nodeidx, tag, tag, nodeidx))
        res = cls.get(nodeidx, tag)
        return "{!r}".format(res)

### node iteration
def riter():
    '''Iterate through each netnode in the database in reverse order.'''
    for nodeidx, _ in utils.renumerate():
        yield nodeidx
    return
def fiter():
    '''Iterate through each netnode in the database in order.'''
    for nodeidx, _ in utils.fenumerate():
        yield nodeidx
    return

### node altval : sparse array[integer] = integer
class alt(object):
    """
    This namespace is used for interacting with the sparse array stored
    within a given netnode. This sparse array is used to store integers,
    and is referred to by IDA as an "altval".
    """

    @classmethod
    def get(cls, nodeidx, index):
        '''Return the integer at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.altval(node, index)

    @classmethod
    def set(cls, nodeidx, index, value):
        '''Assign the integer `value` at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.altset(node, index, value)

    @classmethod
    def remove(cls, nodeidx, index):
        '''Remove the integer from the specified `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.altdel(node, index)

    @classmethod
    def fiter(cls, nodeidx):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = netnode.get(nodeidx)
        for index, value in utils.falt(node):
            yield index, value
        return

    @classmethod
    def riter(cls, nodeidx):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = netnode.get(nodeidx)
        for index, value in utils.ralt(node):
            yield index, value
        return

    @classmethod
    def repr(cls, nodeidx):
        '''Display the "altval" array belonging to the netnode identified by `nodeidx`.'''
        res = []
        for index, value in cls.fiter(nodeidx):
            res.append("{0:x} : {1:#x} ({1:d})".format(index, value))
        if not res:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:#x}) : The specified node ({:x}) does not have any altvals.".format('.'.join([__name__, cls.__name__]), nodeidx, nodeidx))
        return '\n'.join(res)

### node supval : sparse array[integer] = str * 1024
class sup(object):
    """
    This namespace is used for interacting with the sparse array stored
    within a given netnode. This sparse array is used to store bytes,
    and is referred to by IDA as a "supval".
    """

    MAX_SIZE = 0x400

    @classmethod
    def get(cls, nodeidx, index, type=None):
        '''Return the value at the `index` of the "supval" array belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        node = netnode.get(nodeidx)
        if type in {None}:
            return netnode.supval(node, index)
        elif issubclass(type, memoryview):
            res = netnode.supval(node, index)
            return res and memoryview(res)
        elif issubclass(type, bytes):
            return netnode.supstr(node, index)
        elif issubclass(type, six.string_types):
            return netnode.supstr(node, index)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, {:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), nodeidx, index, type, type))

    @classmethod
    def set(cls, nodeidx, index, value):
        '''Assign the provided `value` to the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.supset(node, index, value.tobytes() if isinstance(value, memoryview) else value)

    @classmethod
    def remove(cls, nodeidx, index):
        '''Remove the value at the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.supdel(node, index)

    @classmethod
    def fiter(cls, nodeidx):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = netnode.get(nodeidx)
        for index, _ in utils.fsup(node):
            yield index
        return

    @classmethod
    def riter(cls, nodeidx):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = netnode.get(nodeidx)
        for index, _ in utils.rsup(node):
            yield index
        return

    @classmethod
    def repr(cls, nodeidx):
        '''Display the "supval" array belonging to the netnode identified by `nodeidx`.'''
        res = []
        for index, item in enumerate(cls.fiter(nodeidx)):
            value = cls.get(nodeidx, item)
            res.append("[{:d}] {:x} : {!r}".format(index, item, value))
        if not res:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:#x}) : The specified node ({:x}) does not have any supvals.".format('.'.join([__name__, cls.__name__]), nodeidx, nodeidx))
        return '\n'.join(res)

### node hashval : sparse dictionary[str * 510] = str * 1024
class hash(object):
    """
    This namespace is used for interacting with the dictionary stored
    within a given netnode. This dictionary is keyed by bytes of a
    maximum length of 510, and is used to store bytes of a maximum
    length of 1024. IDA refers to this dictionary as a "hashval".
    """
    @classmethod
    def get(cls, nodeidx, key, type=None):
        '''Return the value for the provided `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        node = netnode.get(nodeidx)
        if type in {None}:
            return netnode.hashval(node, key)
        elif issubclass(type, memoryview):
            res = netnode.hashval(node, key)
            return res and memoryview(res)
        elif issubclass(type, bytes):
            res = netnode.hashval(node, key)
            return res and bytes(res)
        elif issubclass(type, six.string_types):
            return netnode.hashstr(node, key)
        elif issubclass(type, six.integer_types):
            return netnode.hashval_long(node, key)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, {!r}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), nodeidx, key, type, type))

    @classmethod
    def set(cls, nodeidx, key, value):
        '''Assign the provided `value` to the specified `key` for the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        # in my testing the type really doesn't matter
        if isinstance(value, memoryview):
            return netnode.hashset(node, key, value.tobytes())
        elif isinstance(value, bytes):
            return netnode.hashset(node, key, value)
        elif isinstance(value, six.string_types):
            return netnode.hashset_buf(node, key, value)
        elif isinstance(value, six.integer_types):
            return netnode.hashset_idx(node, key, value)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:#x}, {!r}, {!r}) : An unsupported type ({!r}) was specified for the netnode's hash.".format('.'.join([__name__, cls.__name__]), nodeidx, key, value, type(value)))

    @classmethod
    def remove(cls, nodeidx, key):
        '''Remove the value assigned to the specified `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node = netnode.get(nodeidx)
        return netnode.hashdel(node, key)

    @classmethod
    def fiter(cls, nodeidx):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        node = netnode.get(nodeidx)
        for key, _ in utils.fhash(node):
            yield key
        return

    @classmethod
    def riter(cls, nodeidx):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = netnode.get(nodeidx)
        for key, _ in utils.rhash(node):
            yield key
        return

    @classmethod
    def repr(cls, nodeidx):
        '''Display the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        res = []
        try:
            l1 = max(len(key or '') for key in cls.fiter(nodeidx))
            l2 = max(len("{!r}".format(cls.get(nodeidx, key))) for key in cls.fiter(nodeidx))
        except ValueError:
            l1, l2 = 0, 2

        for index, key in enumerate(cls.fiter(nodeidx)):
            value = "{:<{:d}s} : default={!r}, bytes={!r}, int={:#x}({:d})".format("{!r}".format(cls.get(nodeidx, key)), l2, cls.get(nodeidx, key, None), cls.get(nodeidx, key, bytes), cls.get(nodeidx, key, int), cls.get(nodeidx, key, int))
            res.append("[{:d}] {:<{:d}s} -> {:s}".format(index, key, l1, value))
        if not res:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:#x}) : The specified node ({:x}) does not have any hashvals.".format('.'.join([__name__, cls.__name__]), nodeidx, nodeidx))
        return '\n'.join(res)

# FIXME: implement a file-allocation-table based filesystem using the netnode wrappers defined above
class filesystem(object):
    ALLOCATION_TABLE = '$ file-allocation-table'
    SECTOR_TABLE = '$ sector-table'
    SECTOR = 1024
    def __init__(self, name):
        node = idaapi.netnode(name, 0, True)
