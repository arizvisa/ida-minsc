"""
Netnode module (internal)

This module wraps IDA's netnode API and dumbs it down so that a user
can be mindless when reading/writing/enumerating data out of a netnode.
This is an internal module and is not expected to be used by the user.
"""

import functools, operator, itertools
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

    # We need the following api to explicitly look up a netnode by its address.
    if hasattr(_ida_netnode, 'exist'):
        exist = staticmethod(internal.utils.fcompose(_ida_netnode.new_netnode, _ida_netnode.exist))

    # If it didn't exist, though, then we need to call directly into the ida library.
    # We're fortunate here because netnodes are really just a pointer to an integer,
    # and the netnode_exist api takes a pointer and returns a straight-up boolean.
    else:
        import ctypes, ida
        ida.netnode_exist.restype, ida.netnode_exist.argtypes = ctypes.c_bool, [ctypes.POINTER(ctypes.c_long)]
        exist = staticmethod(internal.utils.fcompose(ctypes.c_long, ctypes.pointer, ida.netnode_exist))

    # There's a chance that this api doesn't exist in IDAPython, so if it does then
    # we can assign it as-is...otherwise we create a netnode with the desired name
    # and then see if we can grab its index to confirm its existence.
    if hasattr(_ida_netnode, 'netnode_exist'):
        exist_name = _ida_netnode.netnode_exist
    else:
        exist_name = staticmethod(internal.utils.fcompose(internal.utils.frpartial(_ida_netnode.new_netnode, False, 0), _ida_netnode.netnode_index, internal.utils.fpartial(operator.ne, idaapi.BADADDR)))

    # These apis should always exist and will hopefully never change.
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
    blobtag = b'B' if idaapi.__version__ < 7.0 else 0x42    # taking a guess at what we can use for this

# assign some globals based on the tags from the `netnode` namespace.
alttag = netnode.alttag
suptag = netnode.suptag
hashtag = netnode.hashtag
chartag = netnode.chartag
blobtag = netnode.blobtag

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
    def sbyte_pre70(cls, tag, default):
        '''Return the specified `tag` as a signed integer that can be used with the netnode api.'''
        res = default if tag is None else tag
        if isinstance(res, bytes):
            return res[:1]
        elif isinstance(res, internal.types.integer):
            return bytes(bytearray([res]))[:1]
        encoded = res.encode('latin1')
        return bytes(bytearray(encoded)[:1])

    @classmethod
    def sbyte_70(cls, tag, default):
        '''Return the specified `tag` as a signed integer that can be used with the netnode api.'''
        res = default if tag is None else tag
        if isinstance(res, (bytes, bytearray, internal.types.string)):
            encoded = res if isinstance(res, (bytes, bytearray)) else res.encode('latin1')
            res = bytearray(encoded)[0]
        return idaapi.as_signed(res, 8)
    sbyte = sbyte_pre70 if idaapi.__version__ < 7.0 else sbyte_70

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
        start, end = ((F(node, tag) if callable(F) else F) for F in [first, last])
        if start == end and start in {None, idaapi.BADNODE}: return
        yield start, val(node, start, tag)
        while start != end:
            start = next(node, start, tag)
            yield start, val(node, start, tag)
        return

    @classmethod
    def valriter(cls, node, first, last, prev, val, tag):
        '''Iterate through all of the values for a netnode in reverse order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = ((F(node, tag) if callable(F) else F) for F in [first, last])
        if start == end and start in {None, idaapi.BADNODE}: return
        yield end, val(node, end, tag)
        while end != start:
            end = prev(node, end, tag)
            yield end, val(node, end, tag)
        return

    @classmethod
    def hfiter(cls, node, first, last, next, val, tag):
        '''Iterate through all of the hash values for a netnode in order, and yield the (item, value) for each item that was found for the given tag.'''
        start, end = ((F(node, tag) if callable(F) else F) for F in [first, last])

        # If the start key is None, and it's the same as the end key, then we
        # need to verify that there's no value stored for the empty key. If
        # there's no value for the empty key, then we can be sure that there's
        # no keys to iterate through and thus we can leave.
        Fhashval = netnode.hashval
        if start is None and start == end and Fhashval(node, start or '', tag) is None:
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
        start, end = ((F(node, tag) if callable(F) else F) for F in [first, last])

        # If the end key is None, and it's the same as the start key, then we
        # need to verify that there's no value stored for the empty key. If
        # there's no value for the empty key, then we can be sure that there's
        # no keys to iterate through and thus we can leave.
        Fhashval = netnode.hashval
        if end is None and start == end and Fhashval(node, end or '', tag) is None:
            return

        # Otherwise we need to start at the last item and continue fetching the
        # previous key until we end up at the first one.
        yield end or '', val(node, end or '', tag)
        while end != start:
            end = prev(node, end or '', tag)
            yield end or '', val(node, end or '', tag)
        return

    @classmethod
    def valforward(cls, node, index, prev, next, last, tag):
        '''Return the next encountered value for a netnode from the specified `index`.'''
        stop = last(node, tag) if callable(last) else last
        backward, forward = (F(node, index, tag) for F in [prev, next])
        Freverse, nindex = (next, backward) if forward in {None, idaapi.BADNODE} else (prev, forward)
        if Freverse(node, nindex, tag) == index:
            return index
        return None if forward in {None, idaapi.BADNODE} and index >= stop else forward

    @classmethod
    def valbackward(cls, node, index, prev, next, first, tag):
        '''Return the previous encountered value for a netnode from the specified `index`.'''
        stop = first(node, tag) if callable(first) else first
        backward, forward = (F(node, index, tag) for F in [prev, next])
        Freverse, nindex = (prev, forward) if backward in {None, idaapi.BADNODE} else (next, backward)
        if Freverse(node, nindex, tag) == index:
            return index
        return None if backward in (None, idaapi.BADNODE) and index <= stop else backward

    @classmethod
    def hforward(cls, node, key, prev, next, last, tag):
        '''Return the next encountered hash value for a netnode from the specified `key`.'''
        stop = last(node, tag) if callable(last) else last
        backward, forward = (F(node, key or '', tag) for F in [prev, next])
        Freverse, nkey = (next, backward) if forward in {None, idaapi.BADNODE} else (prev, forward)
        if Freverse(node, nkey or '', tag) == key:
            return key
        return None if forward in {None, idaapi.BADNODE} else forward

    @classmethod
    def hbackward(cls, node, key, prev, next, first, tag):
        '''Return the previous encountered hash value for a netnode from the specified `key`.'''
        stop = first(node, tag) if callable(first) else first
        backward, forward = (F(node, key or '', tag) for F in [prev, next])
        Freverse, nkey = (prev, forward) if backward in {None, idaapi.BADNODE} else (next, backward)
        if Freverse(node, nkey or '', tag) == key:
            return key
        return None if backward in {None, idaapi.BADNODE} else backward

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
    def faltfrom(cls, node, index, tag=netnode.alttag):
        '''Iterate through each "altval" for a given `node` in order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valforward(node, index, netnode.altprev, netnode.altnext, netnode.altlast, tag=tag)
        if realindex is None:
            return
        for item in cls.valfiter(node, realindex, netnode.altlast, netnode.altnext, netnode.altval, tag=tag):
            yield item
        return
    @classmethod
    def raltfrom(cls, node, index, tag=netnode.alttag):
        '''Iterate through each "altval" for a given `node` in reverse order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valbackward(node, index, netnode.altprev, netnode.altnext, netnode.altfirst, tag=tag)
        if realindex is None:
            return
        for item in cls.valriter(node, netnode.altfirst, realindex, netnode.altprev, netnode.altval, tag=tag):
            yield item
        return

    @classmethod
    def faltvals(cls, node, tag=netnode.alttag):
        '''Return a list of all "altval" for a given `node` in order.'''
        result, Fnext, Fvalue = [], netnode.altnext, netnode.altval
        start, end = netnode.altfirst(node, tag), netnode.altlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((start, Fvalue(node, start, tag)))
        while start != end:
            start = Fnext(node, start, tag)
            result.append((start, Fvalue(node, start, tag)))
        return result
    @classmethod
    def raltvals(cls, node, tag=netnode.alttag):
        '''Return a list of all "altval" for a given `node` in reverse order.'''
        result, Fprev, Fvalue = [], netnode.altprev, netnode.altval
        start, end = netnode.altfirst(node, tag), netnode.altlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((end, Fvalue(node, end, tag)))
        while start != end:
            end = Fprev(node, end, tag)
            result.append((end, Fvalue(node, end, tag)))
        return result

    @classmethod
    def faltrange(cls, node, start, stop, tag=netnode.alttag):
        '''Return a list of all "altval" for a given `node` in order from `start` to `stop`.'''
        result, Fnext, Fvalue = [], netnode.altnext, netnode.altval
        end = netnode.altlast(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valforward(node, start, netnode.altprev, netnode.altnext, netnode.altlast, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if start <= end < stop else []

        current < stop and result.append((current, Fvalue(node, current, tag)))
        current = Fnext(node, current, tag)
        while current != end and current < stop:
            result.append((current, Fvalue(node, current, tag)))
            current = Fnext(node, current, tag)
        return result
    @classmethod
    def raltrange(cls, node, start, stop, tag=netnode.alttag):
        '''Return a list of all "altval" for a given `node` in reverse order from `start` to `stop`.'''
        result, Fprev, Fvalue = [], netnode.altprev, netnode.altval
        end = netnode.altfirst(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valbackward(node, stop, netnode.altprev, netnode.altnext, netnode.altfirst, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if stop >= end > start else []

        current > start and result.append((current, Fvalue(node, current, tag)))
        current = Fprev(node, current, tag)
        while current != end and current > start:
            result.append((current, Fvalue(node, current, tag)))
            current = Fprev(node, current, tag)
        return result

    @classmethod
    def fsup(cls, node, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in order, and yield each (item, value) that was found.'''
        for item in utils.valfiter(node, netnode.supfirst, netnode.suplast, netnode.supnext, value or netnode.supval, tag=tag):
            yield item
        return
    @classmethod
    def rsup(cls, node, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in reverse order, and yield each (item, value) that was found.'''
        for item in cls.valriter(node, netnode.supfirst, netnode.suplast, netnode.supprev, value or netnode.supval, tag=tag):
            yield item
        return
    @classmethod
    def fsupfrom(cls, node, index, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valforward(node, index, netnode.supprev, netnode.supnext, netnode.suplast, tag=tag)
        if realindex is None:
            return
        for item in utils.valfiter(node, realindex, netnode.suplast, netnode.supnext, value or netnode.supval, tag=tag):
            yield item
        return
    @classmethod
    def rsupfrom(cls, node, index, value=None, tag=netnode.suptag):
        '''Iterate through each "supval" for a given `node` in reverse order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valbackward(node, index, netnode.supprev, netnode.supnext, netnode.supfirst, tag=tag)
        if realindex is None:
            return
        for item in cls.valriter(node, netnode.supfirst, realindex, netnode.supprev, value or netnode.supval, tag=tag):
            yield item
        return

    @classmethod
    def fsupvals(cls, node, value=None, tag=netnode.suptag):
        '''Return a list of all "supval" for a given `node` in order.'''
        result, Fnext, Fvalue = [], netnode.supnext, value or netnode.supval
        start, end = netnode.supfirst(node, tag), netnode.suplast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((start, Fvalue(node, start, tag)))
        while start != end:
            start = Fnext(node, start, tag)
            result.append((start, Fvalue(node, start, tag)))
        return result
    @classmethod
    def rsupvals(cls, node, value=None, tag=netnode.suptag):
        '''Return a list of all "supval" for a given `node` in reverse order.'''
        result, Fprev, Fvalue = [], netnode.supprev, value or netnode.supval
        start, end = netnode.supfirst(node, tag), netnode.suplast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((end, Fvalue(node, end, tag)))
        while start != end:
            end = Fprev(node, end, tag)
            result.append((end, Fvalue(node, end, tag)))
        return result

    @classmethod
    def fsuprange(cls, node, start, stop, value=None, tag=netnode.suptag):
        '''Return a list of all "supval" for a given `node` in order from `start` to `stop`.'''
        result, Fnext, Fvalue = [], netnode.supnext, value or netnode.supval
        end = netnode.suplast(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valforward(node, start, netnode.supprev, netnode.supnext, netnode.suplast, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if start <= end < stop else []

        current < stop and result.append((current, Fvalue(node, current, tag)))
        current = Fnext(node, current, tag)
        while current != end and current < stop:
            result.append((current, Fvalue(node, current, tag)))
            current = Fnext(node, current, tag)
        return result
    @classmethod
    def rsuprange(cls, node, start, stop, value=None, tag=netnode.suptag):
        '''Return a list of all "supval" for a given `node` in reverse order from `start` to `stop`.'''
        result, Fprev, Fvalue = [], netnode.supprev, value or netnode.supval
        end = netnode.supfirst(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valbackward(node, stop, netnode.supprev, netnode.supnext, netnode.supfirst, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if stop >= end > start else []

        current > start and result.append((current, Fvalue(node, current, tag)))
        current = Fprev(node, current, tag)
        while current != end and current > start:
            result.append((current, Fvalue(node, current, tag)))
            current = Fprev(node, current, tag)
        return result

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
    def fhashfrom(cls, node, key, value=None, tag=netnode.hashtag):
        '''Iterate through each "hashval" for a given `node` in order from `key`, and yield each (item, value) that was found.'''
        realkey = cls.hforward(node, key or '', netnode.hashprev, netnode.hashnext, netnode.hashlast, tag=tag)
        if realkey is None:
            return
        for item in cls.hfiter(node, realkey or '', netnode.hashlast, netnode.hashnext, value or netnode.hashval, tag=tag):
            yield item
        return
    @classmethod
    def rhashfrom(cls, node, key, value=None, tag=netnode.hashtag):
        '''Iterate through each "hashval" for a given `node` in reverse order from `key`, and yield each (item, value) that was found.'''
        realkey = cls.hbackward(node, key or '', netnode.hashprev, netnode.hashnext, netnode.hashfirst, tag=tag)
        if realkey is None:
            return
        for item in cls.hriter(node, netnode.hashfirst, realkey or '', netnode.hashprev, value or netnode.hashval, tag=tag):
            yield item
        return

    @classmethod
    def fhashvals(cls, node, value=None, tag=netnode.hashtag):
        '''Return a list of all "hashval" for a given `node` in order.'''
        result, Fnext, Fvalue = [], netnode.hashnext, value or netnode.hashval
        start, end = netnode.hashfirst(node, tag), netnode.hashlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((start or '', Fvalue(node, start or '', tag)))
        while start != end:
            start = Fnext(node, start or '', tag)
            result.append((start or '', Fvalue(node, start or '', tag)))
        return result
    @classmethod
    def rhashvals(cls, node, value=None, tag=netnode.hashtag):
        '''Return a list of all "hashval" for a given `node` in reverse order.'''
        result, Fprev, Fvalue = [], netnode.hashprev, value or netnode.hashval
        start, end = netnode.hashfirst(node, tag), netnode.hashlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((end or '', Fvalue(node, end or '', tag)))
        while start != end:
            end = Fprev(node, end or '', tag)
            result.append((end or '', Fvalue(node, end or '', tag)))
        return result

    @classmethod
    def fhashrange(cls, node, start, stop, value=None, tag=netnode.hashtag):
        '''Return a list of all "hashval" for a given `node` in order from `start` to `stop`.'''
        result, Fnext, Fvalue = [], netnode.hashnext, value or netnode.hashval
        end = netnode.hashlast(node, tag)

        # if the last and first key are the same, then we need to verify that
        # there's no value stored for the empty key. if there's no value for the
        # empty key, then we can assume that there's nothing to iterate through.
        if end is None and netnode.hashfirst(node, tag) == end and Fvalue(node, end or '', tag) is None:
            return []

        # seek forward from start to find the first available key.
        start, stop = sorted([start or '', stop or ''])
        current = cls.hforward(node, start, netnode.hashprev, netnode.hashnext, netnode.hashlast, tag=tag)
        current_string = current or ''

        # keep collecting keys as long as they come before stop.
        current_string < stop and result.append((current_string, Fvalue(node, current_string, tag)))
        while current != end and current_string < stop:
            current = Fnext(node, current_string, tag)
            current_string = current or ''
            current_string < stop and result.append((current_string, Fvalue(node, current_string, tag)))
        return result
    @classmethod
    def rhashrange(cls, node, start, stop, value=None, tag=netnode.hashtag):
        '''Return a list of all "hashval" for a given `node` in reverse order from `start` to `stop`.'''
        result, Fprev, Fvalue = [], netnode.hashprev, value or netnode.hashval
        end = netnode.hashfirst(node, tag)

        # if the first and last key are the same, then we verify that there's no
        # value stored in the empty key. if there isn't one while the keys are
        # the same, then we assume that there aren't any hashvals being used.
        if end is None and netnode.hashlast(node, tag) == end and Fvalue(node, end or '', tag) is None:
            return []

        # seek backwards from stop until we find the previous key.
        start, stop = sorted([start or '', stop or ''])
        current = cls.hbackward(node, stop, netnode.hashprev, netnode.hashnext, netnode.hashfirst, tag=tag)
        current_string = current or ''

        # continue collecting keys as long as it doesn't come before the start.
        current_string > start and result.append((current_string, Fvalue(node, current_string, tag)))
        while current != end and current_string > start:
            current = Fprev(node, current_string, tag)
            current_string = current or ''
            current_string > start and result.append((current_string, Fvalue(node, current_string, tag)))
        return result

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
    @classmethod
    def fcharfrom(cls, node, index, value=None, tag=netnode.chartag):
        '''Iterate through each "charval" for a given `node` in order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valforward(node, index, netnode.charprev, netnode.charnext, netnode.charlast, tag=tag)
        if realindex is None:
            return
        for item in cls.valfiter(node, realindex, netnode.charlast, netnode.charnext, value or netnode.charval, tag=tag):
            yield item
        return
    @classmethod
    def rcharfrom(cls, node, index, value=None, tag=netnode.chartag):
        '''Iterate through each "charval" for a given `node` in reverse order from `index`, and yield each (item, value) that was found.'''
        realindex = cls.valbackward(node, index, netnode.charprev, netnode.charnext, netnode.charfirst, tag=tag)
        if realindex is None:
            return
        for item in cls.valriter(node, netnode.charfirst, realindex, netnode.charprev, value or netnode.charval, tag=tag):
            yield item
        return

    @classmethod
    def fcharvals(cls, node, value=None, tag=netnode.chartag):
        '''Return a list of all "charval" for a given `node` in order.'''
        result, Fnext, Fvalue = [], netnode.charnext, value or netnode.charval
        start, end = netnode.charfirst(node, tag), netnode.charlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((start, Fvalue(node, start, tag)))
        while start != end:
            start = Fnext(node, start, tag)
            result.append((start, Fvalue(node, start, tag)))
        return result
    @classmethod
    def rcharvals(cls, node, value=None, tag=netnode.chartag):
        '''Return a list of all "charval" for a given `node` in reverse order.'''
        result, Fprev, Fvalue = [], netnode.charprev, value or netnode.charval
        start, end = netnode.charfirst(node, tag), netnode.charlast(node, tag)
        if start == end and start in {None, idaapi.BADNODE}: return []
        result.append((end, Fvalue(node, end, tag)))
        while start != end:
            end = Fprev(node, end, tag)
            result.append((end, Fvalue(node, end, tag)))
        return result

    @classmethod
    def fcharrange(cls, node, start, stop, value=None, tag=netnode.chartag):
        '''Return a list of all "charval" for a given `node` in order from `start` to `stop`.'''
        result, Fnext, Fvalue = [], netnode.charnext, value or netnode.charval
        end = netnode.charlast(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valforward(node, start, netnode.charprev, netnode.charnext, netnode.charlast, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if start <= end < stop else []

        current < stop and result.append((current, Fvalue(node, current, tag)))
        current = Fnext(node, current, tag)
        while current != end and current < stop:
            result.append((current, Fvalue(node, current, tag)))
            current = Fnext(node, current, tag)
        return result
    @classmethod
    def rcharrange(cls, node, start, stop, value=None, tag=netnode.chartag):
        '''Return a list of all "charval" for a given `node` in reverse order from `start` to `stop`.'''
        result, Fprev, Fvalue = [], netnode.charprev, value or netnode.charval
        end = netnode.charfirst(node, tag)

        start, stop = sorted([start, stop])
        current = cls.valbackward(node, stop, netnode.charprev, netnode.charnext, netnode.charfirst, tag=tag)
        if current in {None, idaapi.BADNODE, end}:
            return [(end, Fvalue(node, end, tag))] if stop >= end > start else []

        current > start and result.append((current, Fvalue(node, current, tag)))
        current = Fprev(node, current, tag)
        while current != end and current > start:
            result.append((current, Fvalue(node, current, tag)))
            current = Fprev(node, current, tag)
        return result

    @classmethod
    def nextalt(cls, node, index, tag=netnode.alttag):
        '''Return the next "altval" for a given `node`.'''
        return netnode.altnext(node, index, tag)
    @classmethod
    def prevalt(cls, node, index, tag=netnode.alttag):
        '''Return the previous "altval" for a given `node`.'''
        return netnode.altprev(node, index, tag)

    @classmethod
    def nextsup(cls, node, index, tag=netnode.suptag):
        '''Return the next "supval" for a given `node`.'''
        return netnode.supnext(node, index, tag)
    @classmethod
    def prevsup(cls, node, index, tag=netnode.suptag):
        '''Return the previous "supval" for a given `node`.'''
        return netnode.supprev(node, index, tag)

    @classmethod
    def nexthash(cls, node, index, tag=netnode.hashtag):
        '''Return the next "hashval" for a given `node`.'''
        return netnode.hashnext(node, index, tag)
    @classmethod
    def prevhash(cls, node, index, tag=netnode.hashtag):
        '''Return the previous "hashval" for a given `node`.'''
        return netnode.hashprev(node, index, tag)

    @classmethod
    def nextchar(cls, node, index, tag=netnode.chartag):
        '''Return the next "charval" for a given `node`.'''
        return netnode.charnext(node, index, tag)
    @classmethod
    def prevchar(cls, node, index, tag=netnode.chartag):
        '''Return the previous "charval" for a given `node`.'''
        return netnode.charprev(node, index, tag)

def new(name):
    '''Create a netnode with the given `name`, and return its identifier.'''
    res = internal.utils.string.to(name)
    node = netnode.new(res, len(res), True)
    return netnode.index(node)

def has(name):
    '''Return whether the netnode with the given `name` exists in the database or not.'''
    if isinstance(name, internal.types.integer):
        return netnode.exist(name)
    res = internal.utils.string.to(name)
    return netnode.exist_name(res)

def get(name):
    '''Get (or create) a netnode with the given `name`, and return its identifier.'''
    if isinstance(name, internal.types.integer):
        node = utils.get(name)
    elif isinstance(name, internal.types.string):
        res = internal.utils.string.to(name)
        node = netnode.get(res, len(res))
    else:
        raise internal.exceptions.InvalidParameterError(u"{:s}.get({!r}) : An unsupported type ({!r}) was specified as the identity of the netnode to get.".format(__name__, name, name.__class__))
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
        elif issubclass(type, internal.types.memoryview):
            res = netnode.valobj(node)
            return res and internal.types.memoryview(res)
        elif issubclass(type, internal.types.bytes):
            res = netnode.valstr(node)
            return res and internal.types.bytes(res)
        elif issubclass(type, internal.types.string):
            return netnode.valstr(node)
        elif issubclass(type, internal.types.integer):
            return netnode.long_value(node)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:s}, type={!r}) : An unsupported type ({!r}) was requested for the netnode's value.".format('.'.join([__name__, cls.__name__]), description, type, type))

    @classmethod
    def set(cls, nodeidx, value):
        '''Set the value for the netnode identified by `nodeidx` to the provided `value`.'''
        node = utils.get(nodeidx)
        if isinstance(value, internal.types.memoryview):
            return netnode.set(nodeidx, value.tobytes())
        elif isinstance(value, (internal.types.bytes, internal.types.bytearray)):
            return netnode.set(node, bytes(value))
        elif isinstance(value, internal.types.string):
            return netnode.set(node, value)
        elif isinstance(value, internal.types.integer):
            return netnode.set_long(node, value)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:s}, {!r}) : An unsupported type ({!r}) was specified for the netnode's value.".format('.'.join([__name__, cls.__name__]), description, value, value.__class__))

    @classmethod
    def remove(cls, nodeidx):
        '''Remove the value for the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.delvalue(node)

    @classmethod
    def repr(cls, nodeidx):
        '''Display the value for the netnode identified by `nodeidx`.'''
        if not cls.has(nodeidx):
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}) : The specified node ({:s}) does not have any value.".format('.'.join([__name__, cls.__name__]), description, description))
        res, string, value = cls.get(nodeidx), cls.get(nodeidx, type=bytes), cls.get(nodeidx, type=int)
        return "{!r} {!r} {:#x}".format(res, string, value)

### node blob
class blob(object):
    """
    This namespace is used to interact with the blob assigned to a given netnode.
    """
    @classmethod
    def has(cls, nodeidx, index, tag=None):
        '''Return whether the node identified by `nodeidx` at the specified `index` has a blob associated with it.'''
        node = utils.get(nodeidx)
        res = netnode.blobsize(node, index, utils.sbyte(tag, netnode.blobtag))
        return res > 0

    @classmethod
    def get(cls, nodeidx, index, tag=None):
        '''Return the blob stored in `tag` at the specified `index` for the netnode identified by `nodeidx`.'''
        node, stag = utils.get(nodeidx), utils.sbyte(tag, netnode.blobtag)
        sz = netnode.blobsize(node, index, stag)
        res = netnode.getblob(node, index, stag)
        return None if res is None else res[:sz]

    @classmethod
    def set(cls, nodeidx, index, value, tag=None):
        '''Assign the data provided by `value` to the blob stored in `tag` at the specified `index` for the netnode identified by `nodeidx`.'''
        node, value = utils.get(nodeidx), value.tobytes(value) if isinstance(value, memoryview) else internal.types.bytes(value)
        return netnode.setblob(node, value, index, utils.sbyte(tag, netnode.blobtag))

    @classmethod
    def remove(cls, nodeidx, index, tag=None):
        '''Remove the data from the blob stored in `tag` at the specified `index` for the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.delblob(node, index, utils.sbyte(tag, netnode.blobtag))

    @classmethod
    def size(cls, nodeidx, index, tag=None):
        '''Return the size of the blob stored in `tag` at the specified `index` for the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.blobsize(node, index, utils.sbyte(tag, netnode.blobtag))

    @classmethod
    def repr(cls, nodeidx, index, tag=None):
        '''Display the blob stored in `tag` at the specified `index` for the netnode identified by `nodeidx`.'''
        if cls.size(nodeidx, index, utils.sbyte(tag, netnode.blobtag)) == 0:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}, {!r}, {:#x}) : The specified node ({:s}) does not have a blob at index {:#x} for the given tag ({!r}).".format('.'.join([__name__, cls.__name__]), description, tag, index, description, index, tag))
        res = cls.get(nodeidx, index, utils.sbyte(tag, netnode.blobtag))
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
        node = utils.get(nodeidx)
        res = netnode.altval(node, index, utils.sbyte(tag, netnode.alttag))
        return res != 0

    @classmethod
    def get(cls, nodeidx, index, tag=None):
        '''Return the integer at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altval(node, index, utils.sbyte(tag, netnode.alttag))

    @classmethod
    def set(cls, nodeidx, index, value, tag=None):
        '''Assign the integer `value` at the `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altset(node, index, value, utils.sbyte(tag, netnode.alttag))

    @classmethod
    def remove(cls, nodeidx, index, tag=None):
        '''Remove the integer from the specified `index` of the "altval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.altdel(node, index, utils.sbyte(tag, netnode.alttag))

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nalt, _ in utils.falt(node, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt
        return

    @classmethod
    def fitems(cls, nodeidx, tag=None):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.falt(node, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt, altval
        return

    @classmethod
    def forward(cls, nodeidx, index, tag=None):
        '''Iterate through the elements of the "altval" array belonging to the netnode identified by `nodeidx` in order from `index`.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.faltfrom(node, index, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt, altval
        return

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nalt, _ in utils.ralt(node, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt
        return

    @classmethod
    def ritems(cls, nodeidx, tag=None):
        '''Iterate through all of the elements of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.ralt(node, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt, altval
        return

    @classmethod
    def backward(cls, nodeidx, index, tag=None):
        '''Iterate through the elements of the "altval" array belonging to the netnode identified by `nodeidx` in reverse order from `index`.'''
        node = utils.get(nodeidx)
        for nalt, altval in utils.raltfrom(node, index, tag=utils.sbyte(tag, netnode.alttag)):
            yield nalt, altval
        return

    @classmethod
    def fall(cls, nodeidx, tag=None):
        '''Return a list of all elements for the "altval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        return utils.faltvals(node, tag=utils.sbyte(tag, netnode.alttag))

    @classmethod
    def rall(cls, nodeidx, tag=None):
        '''Return a list of all elements for the "altval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        return utils.raltvals(node, tag=utils.sbyte(tag, netnode.alttag))

    @classmethod
    def fbounds(cls, nodeidx, start, stop, tag=None):
        '''Return a list of all elements for the "altval" array belonging to the netnode identified by `nodeidx` in order from `start` to `stop`.'''
        node = utils.get(nodeidx)
        return utils.faltrange(node, start, stop, tag=utils.sbyte(tag, netnode.alttag))

    @classmethod
    def rbounds(cls, nodeidx, start, stop, tag=None):
        '''Return a list of all elements for the "altval" array belonging to the netnode identified by `nodeidx` in order from `start` to `stop`.'''
        node = utils.get(nodeidx)
        return utils.raltrange(node, start, stop, tag=utils.sbyte(tag, netnode.alttag))

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "altval" array belonging to the netnode identified by `nodeidx`.'''
        res = []
        for index, value in cls.fitems(nodeidx, tag=utils.sbyte(tag, netnode.alttag)):
            res.append("{0:x} : {1:#x} ({1:d})".format(index, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}{!s}) : The specified node ({:s}) does not have any altvals.".format('.'.join([__name__, cls.__name__]), description, '' if tag is None else ", tag={!s}".format(tag), description))
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
        node = utils.get(nodeidx)
        res = netnode.supval(node, index, utils.sbyte(tag, netnode.suptag))
        return res is not None

    @classmethod
    def __decode_string(cls, bytes):
        if isinstance(bytes, internal.types.string):
            return bytes
        return bytes.decode('utf-8', 'replace')
    decode_string = __decode_string

    @classmethod
    def __encode_string(cls, string):
        if isinstance(string, internal.types.string):
            return string.encode('utf-8', 'replace')
        return string
    encode_string = __encode_string

    @classmethod
    def __decode_integer(cls, bytes):
        data = bytearray(bytes or b'')
        return functools.reduce(lambda agg, by: agg * 0x100 + by, data[::-1], 0)
    decode_integer = __decode_integer

    @classmethod
    def __encode_integer(cls, integer):
        octets, count = [], internal.interface.database.bits() // 8
        integer &= pow(2, 8 * count) - 1
        while len(octets) < count:
            integer, octet = divmod(integer, 0x100)
            octets.append(octet)
        return bytearray(octets)
    encode_integer = __encode_integer

    @classmethod
    def __value_and_transform__(cls, type):
        true = internal.utils.fconstant(True)
        table = {
            None:                       (netnode.supval, true, None),
            internal.types.memoryview:  (netnode.supval, bool, internal.types.memoryview),
            internal.types.bytes:       (netnode.supval, bool, None),
            internal.types.bytearray:   (netnode.supval, bool, bytearray),
            internal.types.string:      (netnode.supstr, bool, None),
            internal.types.integer:     (netnode.supval, true, cls.decode_integer),
        }

        # netnode.supstr doesn't really allow us to check whether a string is
        # truly empty or not. so, we treat it as bytes and decode it ourselves.
        table[internal.types.string] = netnode.supval, bool, lambda bytes: cls.decode_string(bytes.rstrip(b'\0'))

        if type in table:
            return table[type]
        iterable = (result for subclass, result in table.items() if subclass and issubclass(type, subclass))
        return next(iterable, None)

    @classmethod
    def get(cls, nodeidx, index, type=None, tag=None):
        '''Return the value at the `index` of the "supval" array belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        value_transform = cls.__value_and_transform__(type)
        if not value_transform:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:s}, {:#x}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, index, type, '' if tag is None else ", tag={!s}".format(tag), type))

        node, [value, ok, transform] = utils.get(nodeidx), value_transform
        res = value(node, index, utils.sbyte(tag, netnode.suptag))
        return transform(res) if ok(res) and transform else res

    @classmethod
    def set(cls, nodeidx, index, value, tag=None):
        '''Assign the provided `value` to the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        if isinstance(value, memoryview):
            transformed = value.tobytes()
        elif isinstance(value, internal.types.integer):
            transformed = bytes(cls.encode_integer(value))
        elif isinstance(value, internal.types.string):
            encoded = cls.encode_string(value)
            transformed = encoded if encoded.endswith(b'\0') else encoded + b'\0'
        else:
            transformed = bytes(value)
        return netnode.supset(node, index, transformed, utils.sbyte(tag, netnode.suptag))

    @classmethod
    def remove(cls, nodeidx, index, tag=None):
        '''Remove the value at the specified `index` of the "supval" array belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        return netnode.supdel(node, index, utils.sbyte(tag, netnode.suptag))

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for nsup, _ in utils.fsup(node, tag=utils.sbyte(tag, netnode.suptag)):
            yield nsup
        return

    @classmethod
    def fitems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for nsup, supval in utils.fsup(node, value, tag=utils.sbyte(tag, netnode.suptag)):
                yield nsup, transform(supval) if transform else supval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fitems({:s}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def forward(cls, nodeidx, index, type=None, tag=None):
        '''Iterate through the elements of the "supval" array belonging to the netnode identified by `nodeidx` in order from `index`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for nsup, supval in utils.fsupfrom(node, index, value, tag=utils.sbyte(tag, netnode.suptag)):
                yield nsup, transform(supval) if transform else supval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.forward({:s}, {:#x}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, index, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the indexes of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for nsup, _ in utils.rsup(node, tag=utils.sbyte(tag, netnode.suptag)):
            yield nsup
        return

    @classmethod
    def ritems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for nsup, supval in utils.rsup(node, value, tag=utils.sbyte(tag, netnode.suptag)):
                yield nsup, transform(supval) if transform else supval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.ritems({:s}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def backward(cls, nodeidx, index, type=None, tag=None):
        '''Iterate through all of the elements of the "supval" array belonging to the netnode identified by `nodeidx` in reverse order from `index`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for nsup, supval in utils.rsupfrom(node, index, value, tag=utils.sbyte(tag, netnode.suptag)):
                yield nsup, transform(supval) if transform else supval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.backward({:s}, {:#x}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, index, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def fall(cls, nodeidx, type=None, tag=None):
        '''Return a list of all elements for the "supval" array belonging to the netnode identified by `nodeidx` in order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.fsupvals(node, value, tag=utils.sbyte(tag, netnode.suptag))
            return [(nsup, transform(supval)) for nsup, supval in result] if transform else result

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fall({:s}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def rall(cls, nodeidx, type=None, tag=None):
        '''Return a list of all elements for the "supval" array belonging to the netnode identified by `nodeidx` in reverse order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.rsupvals(node, value, tag=utils.sbyte(tag, netnode.suptag))
            return [(nsup, transform(supval)) for nsup, supval in result] if transform else result

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.rall({:s}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def fbounds(cls, nodeidx, start, stop, type=None, tag=None):
        '''Return a list of all elements for the "supval" array belonging to the netnode identified by `nodeidx` in order from `start` to `stop`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.fsuprange(node, start, stop, value, tag=utils.sbyte(tag, netnode.suptag))
            return [(nsup, transform(supval)) for nsup, supval in result] if transform else result

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fbounds({:s}, {:#x}, {:#x}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, start, stop, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def rbounds(cls, nodeidx, start, stop, type=None, tag=None):
        '''Return a list of all elements for the "supval" array belonging to the netnode identified by `nodeidx` in reverse order from `start` to `stop`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.rsuprange(node, start, stop, value, tag=utils.sbyte(tag, netnode.suptag))
            return [(nsup, transform(supval)) for nsup, supval in result] if transform else result

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.rbounds({:s}, {:#x}, {:#x}, type={!s}{!s}) : An unsupported type ({!r}) was requested for the netnode's supval.".format('.'.join([__name__, cls.__name__]), description, start, stop, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "supval" array belonging to the netnode identified by `nodeidx`.'''
        res, stag = [], utils.sbyte(tag, netnode.suptag)
        for index, item in enumerate(cls.fiter(nodeidx, tag=stag)):
            value = cls.get(nodeidx, item, tag=stag)
            res.append("[{:d}] {:x} : {!r}".format(index, item, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}{!s}) : The specified node ({:s}) does not have any supvals.".format('.'.join([__name__, cls.__name__]), description, '' if tag is None else ", tag={!s}".format(tag), description))
        return '\n'.join(res)

### node hashval : sparse dictionary[str * 510] = str * 1024
class hash(object):
    """
    This namespace is used for interacting with the dictionary stored
    within a given netnode. The dictionary is keyed by UTF-8 encoded
    strings with a maximum length of 510 characters. It allows storing
    multiple types, up to a maximum length of 1024 bytes (MAXSPECSIZE.

    The disassembler refers to this data structure as a "hashval".
    """

    @classmethod
    def has(cls, nodeidx, key, tag=None):
        '''Return whether the netnode identified by `nodeidx` has a "hashval" for the specified `key`.'''
        node, key_encoded = utils.get(nodeidx), cls.encode_key(key)
        res = netnode.hashval(node, key_encoded, utils.sbyte(tag, netnode.hashtag))
        return res is not None

    @classmethod
    def encode_key(cls, data):
        '''Encode the specified `data` into a string that can be returned from the "hashval" api.'''
        if isinstance(data, internal.types.string):
            return data
        return data.decode('utf-8', 'replace')

    @classmethod
    def decode_key(cls, string):
        '''Encode the specified `string` into a format that can be used with the "hashval" api.'''
        if isinstance(string, internal.types.string):
            return string
        return string.decode('utf-8', 'replace')

    @classmethod
    def __value_and_transform__(cls, type):
        true = internal.utils.fconstant(True)
        table = {
            None:                       (netnode.hashval,       true,   None),
            internal.types.memoryview:  (netnode.hashval,       bool,   internal.types.memoryview),
            internal.types.bytes:       (netnode.hashval,       bool,   internal.types.bytes),
            internal.types.bytearray:   (netnode.hashval,       bool,   internal.types.bytearray),
            internal.types.string:      (netnode.hashstr,       bool,   None),
            internal.types.integer:     (netnode.hashval_long,  true,   None),
        }
        if type in table:
            return table[type]
        iterable = (result for subclass, result in table.items() if subclass and issubclass(type, subclass))
        return next(iterable, None)

    @classmethod
    def get(cls, nodeidx, key, type=None, tag=None):
        '''Return the value for the provided `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx` casted as the specified `type`.'''
        value_transform = cls.__value_and_transform__(type)
        if not value_transform:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.get({:s}, {!r}, type={!r}{s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, key, type, '' if tag is None else ", tag={!s}".format(tag), type))

        key_encoded = cls.encode_key(key)
        node, [value, ok, transform] = utils.get(nodeidx), value_transform
        res = value(node, key_encoded, utils.sbyte(tag, netnode.hashtag))
        return transform(res) if ok(res) and transform else res

    @classmethod
    def set(cls, nodeidx, key, value, tag=None):
        '''Assign the provided `value` to the specified `key` for the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node, stag = utils.get(nodeidx), utils.sbyte(tag, netnode.hashtag)
        key_encoded = cls.encode_key(key)

        # in my testing the type really doesn't matter
        if isinstance(value, internal.types.memoryview):
            return netnode.hashset(node, key_encoded, value.tobytes(), stag)
        elif isinstance(value, (internal.types.bytes, internal.types.bytearray)):
            return netnode.hashset(node, key_encoded, bytes(value), stag)
        elif isinstance(value, internal.types.string):
            return netnode.hashset_buf(node, key_encoded, value, stag)
        elif isinstance(value, internal.types.integer):
            return netnode.hashset_idx(node, key_encoded, value, stag)
        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.set({:s}, {!r}, {!r}{!s}) : An unsupported type ({!r}) was specified for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, key, value, '' if tag is None else ", tag={!s}".format(tag), type(value)))

    @classmethod
    def remove(cls, nodeidx, key, tag=None):
        '''Remove the value assigned to the specified `key` of the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        node = utils.get(nodeidx)
        key_encoded = cls.encode_key(key)
        return netnode.hashdel(node, key_encoded, utils.sbyte(tag, netnode.hashtag))

    @classmethod
    def fiter(cls, nodeidx, tag=None):
        '''Iterate through all of the keys of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        node = utils.get(nodeidx)
        for key, _ in utils.fhash(node, tag=utils.sbyte(tag, netnode.hashtag)):
            key_decoded = cls.decode_key(key)
            yield key_decoded
        return

    @classmethod
    def fitems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for key, hashval in utils.fhash(node, value, tag=utils.sbyte(tag, netnode.hashtag)):
                key_decoded = cls.decode_key(key)
                yield key_decoded, transform(hashval) if transform else hashval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fitems({:s}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def forward(cls, nodeidx, key, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order from `key`.'''
        value_transform = cls.__value_and_transform__(type)
        key_encoded = cls.encode_key(key)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for key, hashval in utils.fhashfrom(node, key_encoded, value, tag=utils.sbyte(tag, netnode.hashtag)):
                key_decoded = cls.decode_key(key)
                yield key_decoded, transform(hashval) if transform else hashval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.forward({:s}, {!r}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, index, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def riter(cls, nodeidx, tag=None):
        '''Iterate through all of the keys of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        node = utils.get(nodeidx)
        for key, _ in utils.rhash(node, tag=utils.sbyte(tag, netnode.hashtag)):
            key_decoded = cls.decode_key(key)
            yield key_decoded
        return

    @classmethod
    def ritems(cls, nodeidx, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for key, hashval in utils.rhash(node, value, tag=utils.sbyte(tag, netnode.hashtag)):
                key_decoded = cls.decode_key(key)
                yield key_decoded, transform(hashval) if transform else hashval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.ritems({:s}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def backward(cls, nodeidx, key, type=None, tag=None):
        '''Iterate through all of the elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order from `key`.'''
        value_transform = cls.__value_and_transform__(type)
        key_encoded = cls.encode_key(key)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            for key, hashval in utils.rhashfrom(node, key_encoded, value, tag=utils.sbyte(tag, netnode.hashtag)):
                key_decoded = cls.decode_key(key)
                yield key_decoded, transform(hashval) if transform else hashval
            return

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.backward({:s}, {!r}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, key, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def fall(cls, nodeidx, type=None, tag=None):
        '''Return a list of all elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.fhashvals(node, value, tag=utils.sbyte(tag, netnode.hashtag))
            if transform:
                return [(cls.decode_key(hidx), transform(hval)) for hidx, hval in result]
            return [(cls.decode_key(hidx), hval) for hidx, hval in result]

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fall({:s}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def rall(cls, nodeidx, type=None, tag=None):
        '''Return a list of all elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.rhashvals(node, value, tag=utils.sbyte(tag, netnode.hashtag))
            if transform:
                return [(cls.decode_key(hidx), transform(hval)) for hidx, hval in result]
            return [(cls.decode_key(hidx), hval) for hidx, hval in result]

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.rall({:s}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def fbounds(cls, nodeidx, start, stop, type=None, tag=None):
        '''Return a list of all elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in order from `start` to `stop`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.fhashrange(node, cls.encode_key(start), cls.encode_key(stop), value, tag=utils.sbyte(tag, netnode.hashtag))
            if transform:
                return [(cls.decode_key(hidx), transform(hval)) for hidx, hval in result]
            return [(cls.decode_key(hidx), hval) for hidx, hval in result]

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fbounds({:s}, {!r}, {!r}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, start, stop, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def rbounds(cls, nodeidx, start, stop, type=None, tag=None):
        '''Return a list of all elements of the "hashval" dictionary belonging to the netnode identified by `nodeidx` in reverse order from `start` to `stop`.'''
        value_transform = cls.__value_and_transform__(type)

        if value_transform:
            node, [value, ok, transform] = utils.get(nodeidx), value_transform
            result = utils.rhashrange(node, cls.encode_key(start), cls.encode_key(stop), value, tag=utils.sbyte(tag, netnode.hashtag))
            if transform:
                return [(cls.decode_key(hidx), transform(hval)) for hidx, hval in result]
            return [(cls.decode_key(hidx), hval) for hidx, hval in result]

        description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.rbounds({:s}, {!r}, {!r}, type={!r}{!s}) : An unsupported type ({!r}) was requested for the netnode's hash.".format('.'.join([__name__, cls.__name__]), description, start, stop, type, '' if tag is None else ", tag={!s}".format(tag), type))

    @classmethod
    def repr(cls, nodeidx, tag=None):
        '''Display the "hashval" dictionary belonging to the netnode identified by `nodeidx`.'''
        res, stag = [], utils.sbyte(tag, netnode.hashtag)
        try:
            l1 = max(len("{!s}".format(key or '')) for key in cls.fiter(nodeidx, tag=stag))
            l2 = max(len("{!r}".format(cls.get(nodeidx, key, tag=stag))) for key in cls.fiter(nodeidx, tag=stag))
        except ValueError:
            l1, l2 = 0, 2

        for index, key in enumerate(cls.fiter(nodeidx, tag=stag)):
            value = "{:<{:d}s} : default={!r}, bytes={!r}, int={:#x}({:d})".format("{!r}".format(cls.get(nodeidx, key, tag=stag)), l2, cls.get(nodeidx, key, None, tag=stag), cls.get(nodeidx, key, bytes, tag=stag), cls.get(nodeidx, key, int, tag=stag), cls.get(nodeidx, key, int, tag=stag))
            res.append("[{:d}] {:<{:d}s} -> {:s}".format(index, "{!r}".format(key), l1, value))
        if not res:
            description = "{:#x}".format(nodeidx) if isinstance(nodeidx, internal.types.integer) else "{!r}".format(nodeidx)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.repr({:s}{!s}) : The specified node ({:s}) does not have any hashvals.".format('.'.join([__name__, cls.__name__]), description, '' if tag is None else ", tag={!s}".format(tag), description))
        return '\n'.join(res)

class hashbytes(hash):
    """
    This is a derivative of the `hash` namespace which is used to
    store string data within a given netnode. Specifically, this
    namespace is different from `hash` (which allows you to store
    a UTF-8 in a netnode) by allowing the user to specify their key
    as an arbitrary number of raw bytes up to 510.

    This results in a dictionary in where the key is encoded when
    written into its specified netnode. It allows storing bytes
    up to a maximum length of 1024 (MAXSPECSIZE).
    """

    # FIXME: we're not allowed to store any null bytes inside
    #        these due to the limitation that they are strings.
    @classmethod
    def encode_key(cls, data):
        if isinstance(data, internal.types.string):
            return data.encode('utf-8').decode('latin1', 'replace')
        return bytes(data).decode('latin1', 'replace')

    @classmethod
    def decode_key(cls, string):
        if isinstance(string, internal.types.string):
            return string.encode('latin1', 'replace')
        return bytes(string)

# FIXME: implement a file-allocation-table based filesystem using the netnode wrappers defined above
class filesystem(object):
    ALLOCATION_TABLE = '$ file-allocation-table'
    SECTOR_TABLE = '$ sector-table'
    SECTOR = 1024
    def __init__(self, name):
        node = idaapi.netnode(name, 0, True)
