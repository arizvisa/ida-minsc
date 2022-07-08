"""
Netnode module (internal)

This module wraps IDA's netnode API and dumbs it down so that a user
can be mindless when reading/writing/enumerating data out of a netnode.
This is an internal module and is not expected to be used by the user.
"""

import six, operator
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

    # Although the following apis exist in 5.6 of the sdk, there's a chance that
    # they're not actually available in IDAPython. To deal with that uncertainty,
    # we'll explicitly check for it and assign if so, otherwise we have to use
    # the _ida_netnode.new_netnode function with its "do_create" parameter set
    # to false.
    exist = _ida_netnode.exist
    if hasattr(_ida_netnode, 'netnode_exist'):
        exist_name = _ida_netnode.netnode_exist
    else:
        exist_name = internal.utils.fcompose(internal.utils.frpartial(_ida_netnode.new_netnode, False, 0), _ida_netnode.netnode_index, internal.utils.fpartial(operator.ne, idaapi.BADADDR))

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

    # default tags (older versions of IDA use a char which we'll use as well)
    alttag = idaapi.atag
    suptag = idaapi.stag
    hashtag = idaapi.htag
    chartag = b'd' if idaapi.__version__ < 7.0 else 0x64    # found while reversing ida's shared library

class utils(object):
    """
    This namespace provides utilities for interacting with a netnode and each
    of the types that it may be composed of. Primarily, these functions allow
    one to iterate through the types contained within the netnode.
    """
    @classmethod
    def get(cls, index):
        '''Return the netnode for the provided `index`.'''
        return netnode.get(index)

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

        yield end, cls.get(end)
        while end != start:
            ok = netnode.prev(this)
            if not ok: break
            end = netnode.index(this)
            yield end, cls.get(end)
        return

    @classmethod
    def fenumerate(cls):
        '''Iterate through each netnode in the database in order, and yield the (nodeidx_t, netnode*) for each item found.'''
        start, end = cls.range()
        this = netnode.root()
        ok = netnode.start(this)
        if not ok:
            raise internal.exceptions.NetNodeNotFoundError(u"{:s}.fenumerate() : Unable to find the start node.".format('.'.join([__name__, cls.__name__])))

        yield start, cls.get(start)
        while start != end:
            ok = netnode.next(this)
            if not ok: break
            start = netnode.index(this)
            yield start, cls.get(start)
        return

    @classmethod
    def valfiter(cls, node, first, last, next, val, tag):
        '''Iterate through all of the values for a netnode in order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = first(node, tag), last(node, tag)
        if start in {None, idaapi.BADADDR}: return
        yield start, val(node, start, tag)
        while start != end:
            start = next(node, start, tag)
            yield start, val(node, start, tag)
        return

    @classmethod
    def valriter(cls, node, first, last, prev, val, tag):
        '''Iterate through all of the values for a netnode in reverse order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = first(node, tag), last(node, tag)
        if end in {None, idaapi.BADADDR}: return
        yield end, val(node, end, tag)
        while end != start:
            end = prev(node, end, tag)
            yield end, val(node, end, tag)
        return

    @classmethod
    def hfiter(cls, node, first, last, next, val, tag):
        '''Iterate through all of the hash values for a netnode in order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = first(node, tag), last(node, tag)

        # If the start key is None, and it's the same as the end key, then we
        # need to verify that there's no value stored for the empty key. If
        # there's no value for the empty key, then we can be sure that there's
        # no keys to iterate through and thus we can leave.
        if start is None and start == end and val(node, start or '', tag) is None:
            return

        # Otherwise we need to start at the first item and continue fetching
        # the next key until we end up at the last one.
        yield start or '', val(node, start or '', tag)
        while start != end:
            start = next(node, start or '', tag)
            yield start or '', val(node, start or '', tag)
        return

    @classmethod
    def hriter(cls, node, first, last, prev, val, tag):
        '''Iterate through all of the hash values for a netnode in reverse order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = first(node, tag), last(node, tag)

        # If the end key is None, and it's the same as the start key, then we
        # need to verify that there's no value stored for the empty key. If
        # there's no value for the empty key, then we can be sure that there's
        # no keys to iterate through and thus we can leave.
        if end is None and start == end and val(node, end or '', tag) is None:
            return

        # Otherwise we need to start at the last item and continue fetching the
        # previous key until we end up at the first one.
        yield end or '', val(node, end or '', tag)
        while end != start:
            end = prev(node, end or '', tag)
            yield end or '', val(node, end or '', tag)
        return

    @classmethod
    def falt(cls, node, tag=netnode.alttag):
        '''Iterate through each "altval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.altfirst, netnode.altlast, netnode.altnext, netnode.altval, tag=tag):
            yield item
        return
    @classmethod
    def ralt(cls, node, tag=netnode.alttag):
        '''Iterate through each "altval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.altfirst, netnode.altlast, netnode.altprev, netnode.altval, tag=tag):
            yield item
        return

    @classmethod
    def fsup(cls, node, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.supfirst, netnode.suplast, netnode.supnext, value or netnode.supval, tag=tag):
            yield item
        return
    @classmethod
    def rsup(cls, node, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.supfirst, netnode.suplast, netnode.supprev, value or netnode.supval, tag=tag):
            yield item
        return

    @classmethod
    def fhash(cls, node, value=None, tag=netnode.hashtag):
        '''Iterate through each "hashval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.hfiter(node, netnode.hashfirst, netnode.hashlast, netnode.hashnext, value or netnode.hashval, tag=tag):
            yield item
        return
    @classmethod
    def rhash(cls, node, value=None, tag=netnode.hashtag):
        '''Iterate through each "hashval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.hriter(node, netnode.hashfirst, netnode.hashlast, netnode.hashprev, value or netnode.hashval, tag=tag):
            yield item
        return

    @classmethod
    def fchar(cls, node, value=None, tag=netnode.chartag):
        '''Iterate through each "charval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in cls.valfiter(node, netnode.charfirst, netnode.charlast, netnode.charnext, value or netnode.charval, tag=tag):
            yield item
        return
    @classmethod
    def rchar(cls, node, value=None, tag=netnode.chartag):
        '''Iterate through each "charval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.charfirst, netnode.charlast, netnode.charprev, value or netnode.charval, tag=tag):
            yield item
        return

def new(name):
    '''Create a netnode with the given `name`, and return its identifier.'''
    res = internal.utils.string.to(name)
    node = netnode.new(res, len(res), True)
    return netnode.index(node)

def has(name):
    '''Return whether the netnode with the given `name` exists in the database or not.'''
    if isinstance(name, six.integer_types):
        node = utils.get(name)
        return netnode.exist(node)
    res = internal.utils.string.to(name)
    return netnode.exist_name(res)

def get(name):
    '''Get (or create) a netnode with the given `name`, and return its identifier.'''
    if isinstance(name, six.integer_types):
        node = utils.get(name)
        node = name
    elif isinstance(name, six.string_types):
        res = internal.utils.string.to(name)
        node = netnode.get(res, len(res))
    else:
        node = name
    return netnode.index(node)

def remove(nodeidx):
    '''Remove the netnode with the identifier `nodeidx`.'''
    node = utils.get(nodeidx)
    return netnode.kill(node)

### node name
class name(object):
    """
    This namespace is used to interact with the naming information for a given netnode.
    """

    @classmethod
    def has(cls, nodeidx):
        '''Return whether the node identified by `nodeidx` has a name associated with it.'''
        node = utils.get(nodeidx)
        res = netnode.name(node)
        return res is not None
    @classmethod
    def get(cls, nodeidx):
        '''Return the name of the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        res = netnode.name(node)
        return internal.utils.string.of(res)
    @classmethod
    def set(cls, nodeidx, string):
        '''Set the name of the netnode identified by `nodeidx` to `string`.'''
        node = utils.get(nodeidx)
        res = internal.utils.string.to(string)
        return netnode.rename(node, res)

### node value (?)
class value(object):
    """
    This namespace is used to interact with the value for a given netnode.
    """

    @classmethod
    def has(cls, nodeidx):
        '''Return whether the node identified by `nodeidx` has a value associated with it.'''
        node = utils.get(nodeidx)
        return netnode.value_exists(node)
    exists = internal.utils.alias(has, 'value')

    @classmethod
    def get(cls, nodeidx, type=None):
        '''Return the value for the netnode identified by `nodeidx` casted to the provided `type`.'''
        node = utils.get(nodeidx)
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
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's value.".format('.'.join([__name__, cls.__name__]), description, type, type))

    @classmethod
    def set(cls, nodeidx, value):
        '''Set the value for the netnode identified by `nodeidx` to the provided `value`.'''
        node = utils.get(nodeidx)
        if isinstance(value, memoryview):
            return netnode.set(nodeidx, value.tobytes())
        elif isinstance(value, bytes):
            return netnode.set(node, value)
        elif isinstance(value, six.string_types):
            return netnode.set(node, value)
        elif isinstance(value, six.integer_types):
            return netnode.set_long(node, value)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:#x}, {!r}) : An unsupported type ({!r}) was specified for the netnode's value.".format('.'.join([__name__, cls.__name__]), description, value, value.__class__))

    @classmethod
    def remove(cls, nodeidx):
        '''Remove the value for the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.delvalue(node)

    @classmethod
    def repr(cls, nodeidx):
        '''Display the value for the netnode identified by `nodeidx`.'''
        if not cls.has(nodeidx):
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}) : The specified node ({:s}) does not have any value.".format('.'.join([__name__, cls.__name__]), description, description))
        res, string, value = cls.get(nodeidx), cls.get(nodeidx, type=bytes), cls.get(nodeidx, type=int)
        return "{!r} {!r} {:#x}".format(res, string, value)

### node blob
class blob(object):
    """
    This namespace is used to interact with the blob assigned to a given netnode.
    """
    @classmethod
    def has(cls, nodeidx, tag):
        '''Return whether the node identified by `nodeidx` has a blob associated with it.'''
        node = utils.get(nodeidx)
        res = netnode.blobsize(node, 0, tag)
        return res > 0

    @classmethod
    def get(cls, nodeidx, tag, start=0):
        """Return the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then return the bytes from the specified offset.
        """
        node = utils.get(nodeidx)
        sz = netnode.blobsize(node, start, tag)
        res = netnode.getblob(node, start, tag)
        return None if res is None else res[:sz]

    @classmethod
    def set(cls, nodeidx, tag, value, start=0):
        """Assign the data provided by `value` to the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then store the provided `value` at the given offset.
        """
        node = utils.get(nodeidx)
        return netnode.setblob(node, value.tobytes() if isinstance(value, memoryview) else value, start, tag)

    @classmethod
    def remove(cls, nodeidx, tag, start=0):
        """Remove the data from the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then remove the data at the given offset.
        """
        node = utils.get(nodeidx)
        return netnode.delblob(node, start, tag)

    @classmethod
    def size(cls, nodeidx, tag, start=0):
        """Return the size of the blob stored in `tag` for the netnode identified by `nodeidx`.

        If an offset is provided as `start`, then return the size from the given offset.
        """
        node = utils.get(nodeidx)
        return netnode.blobsize(node, start, tag)

    @classmethod
    def repr(cls, nodeidx, tag):
        '''Display the blob stored in `tag` for the netnode identified by `nodeidx`.'''
        if cls.size(nodeidx, tag) == 0:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}, {!r}) : The tag {!r} for the specified node ({:s}) does not have a blob.".format('.'.join([__name__, cls.__name__]), description, tag, tag, description))
        res = cls.get(nodeidx, tag)
        return "{!r}".format(res)

### node iteration
def fiter():
    '''Iterate through each netnode index from the database in order.'''
    for nodeidx, _ in utils.fenumerate():
        yield nodeidx
    return
def riter():
    '''Iterate through each netnode index from the database in reverse order.'''
    for nodeidx, _ in utils.renumerate():
        yield nodeidx
    return

def fitems():
    '''Iterate through each netnode index and node from the database in order.'''
    for nodeidx, item in utils.fenumerate():
        yield nodeidx, item
    return
def ritems():
    '''Iterate through each netnode index and node from the database in reverse order.'''
    for nodeidx, item in utils.renumerate():
        yield nodeidx, item
    return

### node altval : sparse array[integer] = integer
class alt(object):
    """
    This namespace is used for interacting with the sparse array stored
    within a given netnode. This sparse array is used to store integers,
    and is referred to by IDA as an "altval".
    """

    @classmethod
    def has(cls, nodeidx, index, tag=None):
        '''Return whether the netnode identified by `nodeidx` has an "altval" for the specified `index`.'''
        return any(index == idx for idx in cls.fiter(nodeidx, tag=tag))

    @classmethod
    def get(cls, nodeidx, index, tag=None):
        '''Return the integer at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altval(node, index, tag or netnode.alttag)

    @classmethod
    def set(cls, nodeidx, index, value, tag=None):
        '''Assign the integer `value` at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altset(node, index, value, tag or netnode.alttag)

    @classmethod
    def remove(cls, nodeidx, index, tag=None):
        '''Remove the integer from the specified `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altdel(node, index, tag or netnode.alttag)

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nalt, _ in utils.falt(node, tag=tag or netnode.alttag):
            yield nalt
        return

    @classmethod
    def fitems(cls, nodeidx, tag=None):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.falt(node, tag=tag or netnode.alttag):
            yield nalt, altval
        return

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nalt, _ in utils.ralt(node, tag=tag or netnode.alttag):
            yield nalt
        return

    @classmethod
    def ritems(cls, nodeidx, tag=None):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.ralt(node, tag=tag or netnode.alttag):
            yield nalt, altval
        return

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "altval" array belonging to the netnode identified by `nodeidx`.'''
        res = []
        for index, value in cls.fitems(nodeidx, tag=tag):
            res.append("{0:x} : {1:#x} ({1:d})".format(index, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}) : The specified node ({:s}) does not have any altvals.".format('.'.join([__name__, cls.__name__]), description, description))
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
    def has(cls, nodeidx, index, tag=None):
        '''Return whether the netnode identified by `nodeidx` has a "supval" for the specified `index`.'''
        return any(index == item for item in cls.fiter(nodeidx, tag=tag))

    @classmethod
    def get(cls, nodeidx, index, type=None, tag=None):
        '''Return the value at the `index` of the "supval" array belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        node = utils.get(nodeidx)
        if type in {None}:
            return netnode.supval(node, index, tag or netnode.suptag)
        elif issubclass(type, memoryview):
            res = netnode.supval(node, index, tag or netnode.suptag)
            return res and memoryview(res)
        elif issubclass(type, bytes):
            return netnode.supstr(node, index, tag or netnode.suptag)
        elif issubclass(type, six.string_types):
            return netnode.supstr(node, index, tag or netnode.suptag)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, {:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, index, type, type))

    @classmethod
    def set(cls, nodeidx, index, value, tag=None):
        '''Assign the provided `value` to the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.supset(node, index, value.tobytes() if isinstance(value, memoryview) else value, tag or netnode.suptag)

    @classmethod
    def remove(cls, nodeidx, index, tag=None):
        '''Remove the value at the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.supdel(node, index, tag or netnode.suptag)

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nsup, _ in utils.fsup(node, tag=tag or netnode.suptag):
            yield nsup
        return

    @classmethod
    def fitems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        if type in {None}:
            value, transform = netnode.supval, internal.utils.fidentity
        elif issubclass(type, memoryview):
            value, transform = netnode.supval, memoryview
        elif issubclass(type, bytes):
            value, transform = netnode.supstr, internal.utils.fidentity
        elif issubclass(type, six.string_types):
            value, transform = netnode.supstr, internal.utils.fidentity
        else:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fitems({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, type))
        node = utils.get(nodeidx)
        for nsup, supval in utils.fsup(node, value, tag=tag or netnode.suptag):
            yield nsup, transform(supval)
        return

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nsup, _ in utils.rsup(node, tag=tag or netnode.suptag):
            yield nsup
        return

    @classmethod
    def ritems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        if type in {None}:
            value, transform = netnode.supval, internal.utils.fidentity
        elif issubclass(type, memoryview):
            value, transform = netnode.supval, memoryview
        elif issubclass(type, bytes):
            value, transform = netnode.supstr, internal.utils.fidentity
        elif issubclass(type, six.string_types):
            value, transform = netnode.supstr, internal.utils.fidentity
        else:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.ritems({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, type))
        node = utils.get(nodeidx)
        for nsup, supval in utils.rsup(node, value, tag=tag or netnode.suptag):
            yield nsup, transform(supval)
        return

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "supval" array belonging to the netnode identified by `nodeidx`.'''
        res = []
        for index, item in enumerate(cls.fiter(nodeidx, tag=tag)):
            value = cls.get(nodeidx, item, tag=tag)
            res.append("[{:d}] {:x} : {!r}".format(index, item, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}) : The specified node ({:s}) does not have any supvals.".format('.'.join([__name__, cls.__name__]), description, description))
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
    def has(cls, nodeidx, key, tag=None):
        '''Return whether the netnode identified by `nodeidx` has a "hashval" for the specified `key`.'''
        return any(key == item for item in cls.fiter(nodeidx, tag=tag))

    @classmethod
    def get(cls, nodeidx, key, type=None, tag=None):
        '''Return the value for the provided `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        node = utils.get(nodeidx)
        if type in {None}:
            return netnode.hashval(node, key, tag or netnode.hashtag)
        elif issubclass(type, memoryview):
            res = netnode.hashval(node, key, tag or netnode.hashtag)
            return res and memoryview(res)
        elif issubclass(type, bytes):
            res = netnode.hashval(node, key, tag or netnode.hashtag)
            return res and bytes(res)
        elif issubclass(type, six.string_types):
            return netnode.hashstr(node, key, tag or netnode.hashtag)
        elif issubclass(type, six.integer_types):
            return netnode.hashval_long(node, key, tag or netnode.hashtag)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:#x}, {!r}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, key, type, type))

    @classmethod
    def set(cls, nodeidx, key, value, tag=None):
        '''Assign the provided `value` to the specified `key` for the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        # in my testing the type really doesn't matter
        if isinstance(value, memoryview):
            return netnode.hashset(node, key, value.tobytes(), tag or netnode.hashtag)
        elif isinstance(value, bytes):
            return netnode.hashset(node, key, value, tag or netnode.hashtag)
        elif isinstance(value, six.string_types):
            return netnode.hashset_buf(node, key, value, tag or netnode.hashtag)
        elif isinstance(value, six.integer_types):
            return netnode.hashset_idx(node, key, value, tag or netnode.hashtag)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:#x}, {!r}, {!r}) : An unsupported type ({!r}) was specified for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, key, value, type(value)))

    @classmethod
    def remove(cls, nodeidx, key, tag=None):
        '''Remove the value assigned to the specified `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.hashdel(node, key, tag or netnode.hashtag)

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the keys of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for idx, _ in utils.fhash(node, tag=tag or netnode.hashtag):
            yield idx
        return

    @classmethod
    def fitems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        if type in {None}:
            value, transform = netnode.hashval, internal.utils.fidentity
        elif issubclass(type, memoryview):
            value, transform = netnode.hashval, memoryview
        elif issubclass(type, bytes):
            value, transform = netnode.hashval, bytes
        elif issubclass(type, six.string_types):
            value, transform = netnode.hashstr, internal.utils.fidentity
        elif issubclass(type, six.integer_types):
            value, transform = netnode.hashval_long, internal.utils.fidentity
        else:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fitems({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, type))
        node = utils.get(nodeidx)
        for idx, hashval in utils.fhash(node, value, tag=tag or netnode.hashtag):
            yield idx, transform(hashval)
        return

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the keys of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for idx, _ in utils.rhash(node, tag=tag or netnode.hashtag):
            yield idx
        return

    @classmethod
    def ritems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        if type in {None}:
            value, transform = netnode.hashval, internal.utils.fidentity
        elif issubclass(type, memoryview):
            value, transform = netnode.hashval, memoryview
        elif issubclass(type, bytes):
            value, transform = netnode.hashval, bytes
        elif issubclass(type, six.string_types):
            value, transform = netnode.hashstr, internal.utils.fidentity
        elif issubclass(type, six.integer_types):
            value, transform = netnode.hashval_long, internal.utils.fidentity
        else:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.ritems({:#x}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, type))
        node = utils.get(nodeidx)
        for idx, hashval in utils.rhash(node, value, tag=tag or netnode.hashtag):
            yield idx, transform(hashval)
        return

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        res = []
        try:
            l1 = max(len(key or '') for key in cls.fiter(nodeidx, tag=tag))
            l2 = max(len("{!r}".format(cls.get(nodeidx, key, tag=tag))) for key in cls.fiter(nodeidx, tag=tag))
        except ValueError:
            l1, l2 = 0, 2

        for index, key in enumerate(cls.fiter(nodeidx, tag=tag)):
            value = "{:<{:d}s} : default={!r}, bytes={!r}, int={:#x}({:d})".format("{!r}".format(cls.get(nodeidx, key, tag=tag)), l2, cls.get(nodeidx, key, None, tag=tag), cls.get(nodeidx, key, bytes, tag=tag), cls.get(nodeidx, key, int, tag=tag), cls.get(nodeidx, key, int, tag=tag))
            res.append("[{:d}] {:<{:d}s} -> {:s}".format(index, key, l1, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, six.integer_types) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}) : The specified node ({:s}) does not have any hashvals.".format('.'.join([__name__, cls.__name__]), description, description))
        return '\n'.join(res)

# FIXME: implement a file-allocation-table based filesystem using the netnode wrappers defined above
class filesystem(object):
    ALLOCATION_TABLE = '$ file-allocation-table'
    SECTOR_TABLE = '$ sector-table'
    SECTOR = 1024
    def __init__(self, name):
        node = idaapi.netnode(name, 0, True)
