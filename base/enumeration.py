"""
Enumeration module

This module exposes a number of tools that can be used to interact
with the enumerations or their members defined within the database.

The base argument type for interacting with an enumeration is the
enumeration identifier. This is an opaque integer id that will need
to be passed to the different tools in order to reference the
enumeration that the user is referring to.

There are a number of tools within the `member` namespace that can
be used to enumerate or locate the members of an enumeration. As
typically an enumeration is simply a constant, each result that is
returned will either be a value or a name.

To list the different enumerations available in the database, one
can use `enumeration.list(...)` specifying their preferred method
of filtering. This will list all of the available enumerations at
which point the user can then request it by passing an identifier
to `enumeration.by($$)`.
"""

import six
from six.moves import builtins

import functools, operator, itertools
import logging, sys, math
import fnmatch, re

import internal
from internal import utils

import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase(enum=six.integer_types)
def flags(enum):
    return idaapi.get_enum_flag(enum)
@utils.multicase(enum=six.integer_types, mask=six.integer_types)
def flags(enum, mask):
    return idaapi.get_enum_flag(enum) & mask

def by_name(name):
    '''Return the identifier for the enumeration with the given ``name``.'''
    res = idaapi.get_enum(name)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_name({!r}) : Unable to locate enumeration.".format(__name__, name))
    return res
byName = utils.alias(by_name)

def by_index(index):
    '''Return the identifier for the enumeration at the specified ``index``.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_index({:#x}) : Unable to locate enumeration.".format(__name__, index))
    return res
byIndex = utils.alias(by_index)

@utils.multicase(index=six.integer_types)
def by(index):
    bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
    highbyte = 0xff << (bits-8)
    if index & highbyte == highbyte:
        return index
    return by_index(index)
@utils.multicase(name=basestring)
def by(name):
    return by_name(name)
@utils.multicase()
def by(**type):
    """Search through all the enumerations within the database and return the first result.

    like = glob match
    regex = regular expression
    index = particular index
    identifier or id = internal id number
    """
    searchstring = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

    res = builtins.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, ("[{:d}] {:s} & {:#x} ({:d} members){:s}".format(idaapi.get_enum_idx(n), idaapi.get_enum_name(n), mask(n), len(builtins.list(members(n))), " // {:s}".format(comment(n)) if comment(n) else '') for i,n in enumerate(res)))
        logging.warn("{:s}.search({:s}) : Found {:d} matching results. Returning the first enumeration {!r}.".format(__name__, searchstring, len(res), res[0]))

    res = next(iter(res), None)
    if res is None:
        raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

def search(string):
    '''Search through all the enumerations using globbing.'''
    return by(like=string)

def keys(id):
    '''Return the names of all of the elements of the enumeration ``id``.'''
    return [member.name(n) for n in member.iterate(id)]

def values(id):
    '''Return the values of all of the elements of the enumeration ``id``.'''
    return [member.value(n) for n in member.iterate(id)]

## creation/deletion
def new(name, flags=0):
    '''Create an enumeration with the specified ``name``.'''
    idx = count()
    res = idaapi.add_enum(idx, name, flags)
    if res == idaapi.BADADDR:
        raise ValueError("{:s}.create : Unable to create enumeration named {:s}.".format(__name__, name))
    return res

@utils.multicase(id=six.integer_types)
def delete(id):
    return idaapi.del_enum(id)
@utils.multicase(name=basestring)
def delete(name):
    '''Delete the enumeration with the specified ``name``.'''
    eid = by_name(name)
    return delete(eid)
create,remove = utils.alias(new),utils.alias(delete)

## setting enum options
@utils.multicase()
def name(enum):
    '''Return the name of the enumeration identified by ``enum``.'''
    eid = by(enum)
    return idaapi.get_enum_name(eid)
@utils.multicase(name=basestring)
def name(enum, name):
    '''Rename the enumeration identified by ``enum`` to ``name``.'''
    eid = by(enum)
    return idaapi.set_enum_name(eid, name)

@utils.multicase()
def comment(enum, **repeatable):
    """Return the comment for the enumeration identified by ``enum``.

    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    return idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
@utils.multicase(comment=basestring)
def comment(enum, comment, **repeatable):
    """Set the comment for the enumeration identified by ``enum`` to ``comment``.

    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    eid = by(enum)
    return idaapi.set_enum_cmt(eid, comment, repeatable.get('repeatable', True))

@utils.multicase()
def size(enum):
    '''Return the number of bits for the enumeration identified by ``enum``.'''
    eid = by(enum)
    res = idaapi.get_enum_width(eid)
    return res * 8
@utils.multicase(width=six.integer_types)
def size(enum, width):
    '''Set the number of bits for the enumeration identified by ``enum`` to ``width``.'''
    eid = by(enum)
    res = math.trunc(math.ceil(width / 8.0))
    return idaapi.set_enum_width(eid, int(res))

def mask(enum):
    '''Return the bitmask for the enumeration identified by ``enum``.'''
    eid = by(enum)
    res = size(eid)
    return 2**res-1 if res > 0 else idaapi.BADADDR

def members(enum):
    '''Return the name of each member from the enumeration identified by ``enum``.'''
    eid = by(enum)
    for n in member.iterate(eid):
        yield member.name(n)
    return

def repr(enum):
    '''Return a printable summary of the enumeration identified by ``enum``.'''
    eid = by(enum)
    w = size(eid)*2
    result = [(member.name(n),member.value(n),member.mask(n),member.comment(n)) for n in member.iterate(eid)]
    aligned = max([len(n) for n,_,_,_ in result] or [0])
    return "<type 'enum'> {:s}\n".format(name(eid)) + '\n'.join(("[{:d}] {:<{align}s} : {:#0{width}x} & {:#0{width}x}".format(i, name, value, bmask, width=w+2, align=aligned)+((' # '+comment) if comment else '') for i,(name,value,bmask,comment) in enumerate(result)))

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.boolean('regex', re.search, idaapi.get_enum_name)
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_enum_name)
__matcher__.boolean('name', operator.eq, idaapi.get_enum_name)
__matcher__.attribute('id')
__matcher__.attribute('identifier')
__matcher__.predicate('pred')
__matcher__.predicate('predicate')

def __iterate__():
    '''Yield the identifier of each enumeration within the database.'''
    for n in six.moves.range(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(n)
    return

def iterate(**type):
    '''Iterate through the identifiers of all the enumerations defined in the database.'''
    if not type: type = {'predicate':lambda n: True}
    res = builtins.list(__iterate__())
    for key, value in six.iteritems(type):
        res = builtins.list(__matcher__.match(key, value, res))
    for item in res: yield item

@utils.multicase(string=basestring)
def list(string):
    '''List any enumerations that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
def list(**type):
    """List all the enumerations within the database.

    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    pred = function predicate
    """
    res = builtins.list(iterate(**type))

    maxindex = max(builtins.map(idaapi.get_enum_idx, res))
    maxname = max(builtins.map(utils.fcompose(idaapi.get_enum_name, len), res))
    maxsize = max(builtins.map(size, res))
    cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
    cmask = max(builtins.map(utils.fcompose(mask, utils.fcondition(utils.fpartial(operator.eq, 0))(utils.fconstant(1), utils.fidentity), math.log, functools.partial(operator.mul, 1.0/math.log(8)), math.ceil), res) or [database.config.bits()/4.0])

    for n in res:
        six.print_("[{:{:d}d}] {:>{:d}s} & {:<{:d}x} ({:d} members){:s}".format(idaapi.get_enum_idx(n), int(cindex), idaapi.get_enum_name(n), maxname, mask(n), int(cmask), len(builtins.list(members(n))), " // {:s}".format(comment(n)) if comment(n) else ''))
    return

## members
class member(object):
    """
    This namespace allows one to interact with the memberes of an
    enumeration once the enumeration's id has been determined.
    This allows one to iterate through all of the enmeration's
    members or add and remove values to the enumeration.

    Some examples of how to use this namespace can be::

        > e = enum.by('example_enumeration')
        > print enum.repr(e)
        > oldname = enum.member.rename(e, 'oldname', 'newname')
        > n = enum.member.add(e, 'name', 0x1000)
        > ok = enum.member.remove(n)
        > n = enum.member.byName(e, 'name')
        > n = enum.member.byValue(e, 0x1000)
        > oldname = enum.member.name(n, 'somename')
        > res = enum.member.value(n, 0x100)
        > oldcomment = enum.member.comment(n, 'This is an test value')
        > for m in enum.member.iterate(e): ...
        > enum.member.list(e)

    """

    @classmethod
    def parent(cls, mid):
        '''Return the enumeration identifier that owns the member ``mid``.'''
        return idaapi.get_enum_member_enum(mid)

    ## lifetime
    @classmethod
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member ``name`` with the specified ``value`` to the enumeration identified by ``enum``.

        If the int, ``bitmask``, is specified then used it as the bitmask for the enumeration.
        """
        eid = by(enum)
        bmask = bitmask.get('bitmask', idaapi.BADADDR & mask(eid))

        res = interface.tuplename(name) if isinstance(name, tuple) else name
        ok = idaapi.add_enum_member(eid, res, value, bmask)

        err = {getattr(idaapi, n) : n for n in ('ENUM_MEMBER_ERROR_NAME', 'ENUM_MEMBER_ERROR_VALUE', 'ENUM_MEMBER_ERROR_ENUM', 'ENUM_MEMBER_ERROR_MASK', 'ENUM_MEMBER_ERROR_ILLV')}
        if ok in err.viewkeys():
            raise ValueError("{:s}.add({:#x}, {!r}, {:#x}, bitmask={!r}) : Unable to add member to enumeration due to error {:s}({:d}).".format('.'.join((__name__,cls.__name__)), eid, name, value, bitmask, err[ok], ok))
        return cls.by_value(eid, value)
    new = create = utils.alias(add, 'member')

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def remove(cls, mid):
        '''Remove the enumeration member with the given ``mid``.'''
        value = cls.value(mid)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(cls.parent(mid), value, 0, idaapi.BADADDR & cls.mask(mid))
        if not res:
            raise LookupError("{:s}.member._remove({:#x}) : Unable to remove member from enumeration.".format(__name__, mid))
        return res
    @utils.multicase()
    @classmethod
    def remove(cls, enum, member):
        '''Remove the specified ``member`` of the enumeration ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.remove(mid)
    delete = destroy = utils.alias(remove, 'member')

    ## searching
    @classmethod
    def by_index(cls, enum, index):
        '''Return the member identifier for the member of the enumeration ``enum`` at the specified ``index``.'''
        eid = by(enum)
        try: return next(m for i,m in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration: pass
        raise LookupError("{:s}.by_index({:#x}, {:d}) : Unable to locate member by index.".format('.'.join((__name__,cls.__name__)), eid, index))

    @classmethod
    def by_identifier(cls, enum, mid):
        eid = by(enum)
        if cls.parent(mid) != eid:
            raise LookupError("{:s}.by_identifier({:#x}, {:d}) : Unable to locate member by id.".format('.'.join((__name__,cls.__name__)), eid, index))
        return mid

    @classmethod
    def by_value(cls, enum, value):
        '''Return the member identifier for the member of the enumeration ``enum`` with the specified ``value``.'''
        eid = by(enum)
        bmask = idaapi.BADADDR & mask(eid)
        res,_ = idaapi.get_first_serial_enum_member(eid, value, bmask)
        if res == idaapi.BADADDR:
            raise LookupError("{:s}.by_value({:#x}, {:d}) : Unable to locate member by value.".format('.'.join((__name__,cls.__name__)), eid, value))
        return res
    byValue = utils.alias(by_value, 'member')

    @classmethod
    def by_name(cls, enum, name):
        '''Return the member identifier for the member of the enumeration ``enum`` with the specified ``name``.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            if name == cls.name(mid):
                return mid
            continue
        return
    byName = utils.alias(by_name, 'member')

    @utils.multicase(n=six.integer_types)
    @classmethod
    def by(cls, enum, n):
        '''Return the member belonging to ``enum`` identified by its index, or its id.'''
        bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
        highbyte = 0xff << (bits-8)
        if n & highbyte == highbyte:
            return cls.by_identifier(enum, n)
        return cls.by_index(enum, n)
    @utils.multicase(member=basestring)
    @classmethod
    def by(cls, enum, member):
        '''Return the member with the given ``name`` belonging to ``enum``.'''
        return cls.by_name(enum, member)

    ## properties
    @utils.multicase(mid=six.integer_types)
    @classmethod
    def name(cls, mid):
        '''Return the name of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_name(mid)
    @utils.multicase()
    @classmethod
    def name(cls, enum, member):
        '''Return the name of the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.name(mid)
    @utils.multicase(mid=six.integer_types, name=(basestring, tuple))
    @classmethod
    def name(cls, mid, name):
        '''Rename the enumeration member ``mid`` to ``name``.'''
        res = interface.tuplename(*name) if isinstance(name, tuple) else name
        return idaapi.set_enum_member_name(mid, res)
    @utils.multicase(name=basestring)
    @classmethod
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration ``member`` of ``enum`` to ``name```.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        res = (name,) + suffix
        return cls.name(eid, interface.tuplename(*res))
    rename = utils.alias(name, 'member')

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def comment(cls, mid, **repeatable):
        """Return the comment for the enumeration member ``mid``.

        If the bool ``repeatable`` is specified, then return the repeatable comment.
        """
        return idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
    @utils.multicase(name=basestring)
    @classmethod
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, name)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=six.integer_types, comment=basestring)
    @classmethod
    def comment(cls, mid, comment, **repeatable):
        """Set the comment for the enumeration member id ``mid`` to ``comment``.

        If the bool ``repeatable`` is specified, then set the repeatable comment.
        """
        return idaapi.set_enum_member_cmt(mid, comment, kwds.get('repeatable', True))
    @utils.multicase(comment=basestring)
    @classmethod
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration ``member`` belonging to ``enum`` to the string ``comment``.'''
        eid = by(enum)
        mid = cls.by(eid, name)
        return cls.comment(mid, comment, **repeatable)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def value(cls, mid):
        '''Return the value of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_value(mid)
    @utils.multicase()
    @classmethod
    def value(cls, enum, member):
        '''Return the value of the specified ``member`` belonging to the enumeration ``enum``.'''
        eid = by(enum)
        mid = cls.by(member)
        return cls.value(mid)
    @utils.multicase(value=six.integer_types)
    @classmethod
    def value(cls, enum, member, value, **bitmask):
        """Set the ``value`` for the enumeration ``member`` belonging to ``enum``.

        If the integer ``bitmask`` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        eid = by(enum)
        mid = cls.by(enum, member)
        #bmask = bitmask.get('bitmask', idaapi.BADADDR & mask(eid))
        bmask = bitmask.get('bitmask', idaapi.BADADDR & cls.mask(mid))
        return idaapi.set_enum_member_value(mid, value, bmask)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def serial(cls, mid):
        '''Return the serial of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_serial(mid)
    @utils.multicase()
    @classmethod
    def serial(cls, enum, member):
        '''Return the serial of the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.serial(mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def mask(cls, mid):
        '''Return the bitmask for the enumeration member ``mid``.'''
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase()
    @classmethod
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.mask(mid)

    # FIXME: Implement a matcher class for enumeration members that can be used with .iterate and .list below.
    __member_matcher = utils.matcher()

    @classmethod
    def __iterate__(cls, eid):
        bmask = idaapi.BADADDR & mask(eid)
        res = idaapi.get_first_enum_member(eid, bmask)
        if res == idaapi.BADADDR: return
        yield res
        while res != idaapi.get_last_enum_member(eid, bmask):
            res = idaapi.get_next_enum_member(eid, res, bmask)
            yield res
        return

    @classmethod
    def iterate(cls, enum):
        '''Iterate through all the member ids associated with the enumeration ``enum``.'''
        eid = by(enum)
        bmask = idaapi.BADADDR & mask(eid)
        for v in cls.__iterate__(eid):
            res, _ = idaapi.get_first_serial_enum_member(eid, v, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    @classmethod
    def list(cls, enum):
        # FIXME: make this consistent with every other .list
        eid = by(enum)
        res = builtins.list(cls.iterate(eid))
        maxindex = max(builtins.map(utils.first, enumerate(res)) or [1])
        maxvalue = max(builtins.map(utils.fcompose(cls.value, "{:x}".format, len), res) or [1])
        for i, mid in enumerate(res):
             six.print_("[{:d}] {:>0{:d}x} {:s}".format(i, cls.value(mid), maxvalue, cls.name(mid)))
        return
