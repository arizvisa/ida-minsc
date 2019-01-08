"""
Enumeration module

This module exposes a number of tools that can be used to interact
with the enumerations or their members defined within the database.
The base argument type for interacting with an enumeration is the
enumeration identifier ``idaapi.enum_t``. This is an opaque integer
that will need to be passed to the different tools in order to
reference the enumeration that the user is referring to.

There are a number of tools within the ``member`` namespace that can
be used to enumerate or locate the members of an enumeration. As
typically an enumeration is simply a constant, each result that is
returned will either be a value or a name. The identifier for these
is a ``idaapi.uval_t``.

To list the different enumerations available in the database, one
can use ``enumeration.list(...)`` specifying their preferred method
of filtering. This will list all of the available enumerations at
which point the user can then request it by passing an identifier
to ``enumeration.by(...)``. The types that can be used to filter are
as follows:

    `name` - Match according to the enumeration name
    `like` - Filter the enumeration names according to a glob
    `regex` - Filter the enumeration names according to a regular-expression
    `index` - Match the enumeration by its index
    `identifier` or `id` - Match the enumeration by its identifier
    `predicate` - Filter the enumerations by passing their identifier to a callable

"""

import six
from six.moves import builtins

import functools, operator, itertools
import logging, sys, math
import fnmatch, re

import database

import internal
from internal import utils, interface, exceptions as E

import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase()
@document.parameters(enum='the enumeration to return the flags for')
def flags(enum):
    '''Return the flags for the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid)
@utils.multicase(mask=six.integer_types)
@document.parameters(enum='the enumeration to return the flags for', mask='the bit mask to apply to the flags')
def flags(enum, mask):
    '''Return the flags for the enumeration `enum` and masked with `mask`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid) & mask

@utils.string.decorate_arguments('name')
@document.aliases('byName')
@document.parameters(name='the name of the enumeration to return')
def by_name(name):
    '''Return the identifier for the enumeration with the given `name`.'''
    res = idaapi.get_enum(utils.string.to(name))
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_name({!r}) : Unable to locate enumeration by the name \"{:s}\".".format(__name__, name, utils.string.escape(name, '"')))
    return res
byName = utils.alias(by_name)

@document.aliases('byIndex')
@document.parameters(index='the index of the enumeration to return')
def by_index(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_index({:#x}) : Unable to locate enumeration by the index {:d}.".format(__name__, index, index))
    return res
byIndex = utils.alias(by_index)

@utils.multicase(index=six.integer_types)
@document.parameters(index='the index or id of the enumeration to return')
def by(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
    highbyte = 0xff << (bits-8)
    if index & highbyte == highbyte:
        return index
    return by_index(index)
@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(name='the name of the enumeration to return')
def by(name):
    '''Return the identifier for the enumeration with the specified `name`.'''
    return by_name(name)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to filter enumerations with')
def by(**type):
    '''Return the identifier for the first enumeration matching the keyword specified by `type`.'''
    searchstring = utils.string.kwargs(type)

    res = builtins.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, (u"[{:d}] {:s} & {:#x} ({:d} members){:s}".format(idaapi.get_enum_idx(n), idaapi.get_enum_name(n), mask(n), len(builtins.list(members(n))), u" // {:s}".format(comment(n)) if comment(n) else '') for i,n in enumerate(res)))
        logging.warn(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first enumeration {:#x}.".format(__name__, searchstring, len(res), res[0]))

    res = next(iter(res), None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string')
@document.parameters(string='the glob to match the enumeration name with')
def search(string):
    '''Return the identifier of the first enumeration that matches the glob `string`.'''
    return by(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to match an enumeration with')
def search(**type):
    '''Return the identifier of the first enumeration that matches the keyword specified by `type`.'''
    return by(**type)

@document.parameters(enum='the enumeration to return the names for')
def names(enum):
    '''Return a list of all the names belonging to the enumeration `enum`.'''
    return [member.name(n) for n in members.iterate(enum)]
keys = utils.alias(names)

@document.parameters(enum='the enumeration to return the values of')
def values(enum):
    '''Return a list of all the values belonging to the enumeration `enum`.'''
    return [member.value(n) for n in members.iterate(enum)]

## creation/deletion
@utils.string.decorate_arguments('name')
@document.aliases('create')
@document.parameters(name='the name of the new enumeration', flags='any extra flags to pass to `idaapi.add_enum`')
def new(name, flags=0):
    '''Create an enumeration with the specified `name` and `flags` using ``idaapi.add_enum``.'''
    idx = count()
    res = idaapi.add_enum(idx, utils.string.to(name), flags)
    if res == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({!r}, flags={:d}) : Unable to create enumeration named \"{:s}\".".format(__name__, name, flags, utils.string.escape(name, '"')))
    return res

@document.aliases('remove')
@document.parameters(enum='the enumeration to remove')
def delete(enum):
    '''Delete the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.del_enum(eid)
create, remove = utils.alias(new), utils.alias(delete)

## setting enum options
@utils.multicase()
@document.parameters(enum='the enumeration to return the name of')
def name(enum):
    '''Return the name of the enumeration `enum`.'''
    eid = by(enum)
    res = idaapi.get_enum_name(eid)
    return utils.string.of(res)
@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
@document.parameters(enum='the enumeration to rename', name='the name to rename the enumeration to')
def name(enum, name):
    '''Rename the enumeration `enum` to the string `name`.'''
    eid, res = by(enum), utils.string.to(name)
    return idaapi.set_enum_name(eid, res)

@utils.multicase()
@document.parameters(enum='the enumeration to return the comment for', repeatable='whether the returned comment should be repeatable or not')
def comment(enum, **repeatable):
    """Return the comment for the enumeration `enum`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    res = idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(comment=basestring)
@utils.string.decorate_arguments('comment')
@document.parameters(enum='the enumeration to modify the comment for', comment='the comment to apply', repeatable='whether the comment should be repeatable or not')
def comment(enum, comment, **repeatable):
    """Set the comment for the enumeration `enum` to `comment`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    eid, res = by(enum), utils.string.to(comment)
    return idaapi.set_enum_cmt(eid, res, repeatable.get('repeatable', True))

@utils.multicase()
@document.parameters(enum='the enumeration to return the width of')
def size(enum):
    '''Return the number of bits for the enumeration `enum`.'''
    eid = by(enum)
    res = idaapi.get_enum_width(eid)
    return res * 8
@utils.multicase(width=six.integer_types)
@document.parameters(enum='the enumeration to set the width for', width='the number of bits to set the enumeration width to')
def size(enum, width):
    '''Set the number of bits for the enumeration `enum` to `width`.'''
    eid = by(enum)
    res = math.trunc(math.ceil(width / 8.0))
    return idaapi.set_enum_width(eid, int(res))

@document.parameters(enum='the enumeration to return the bitmask for')
def mask(enum):
    '''Return the bitmask for the enumeration `enum`.'''
    eid = by(enum)
    res = size(eid)
    return 2**res-1 if res > 0 else idaapi.BADADDR

@document.parameters(enum='the enumeration to summarize')
def repr(enum):
    '''Return a printable summary of the enumeration `enum`.'''
    eid = by(enum)
    w = size(eid)*2
    res = [(member.name(n), member.value(n), member.mask(n), member.comment(n)) for n in members.iterate(eid)]
    aligned = max([len(n) for n, _, _, _ in res] or [0])
    return "<type 'enum'> {:s}\n".format(name(eid)) + '\n'.join(("[{:d}] {:<{align}s} : {:#0{width}x} & {:#0{width}x}".format(i, name, value, bmask, width=w+2, align=aligned)+((' // '+comment) if comment else '') for i,(name,value,bmask,comment) in enumerate(res)))   # XXX

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.boolean('regex', re.search, utils.fcompose(idaapi.get_enum_name, utils.string.of))
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(idaapi.get_enum_name, utils.string.of))
__matcher__.boolean('name', operator.eq, utils.fcompose(idaapi.get_enum_name, utils.string.of))
__matcher__.attribute('id')
__matcher__.attribute('identifier')
__matcher__.predicate('pred')
__matcher__.predicate('predicate')

def __iterate__():
    '''Yield the identifier of each enumeration within the database.'''
    for n in six.moves.range(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(n)
    return

@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to filter enumerations with')
def iterate(**type):
    '''Iterate through all of the enumerations in the database that match the keyword specified by `type`.'''
    if not type: type = {'predicate':lambda n: True}
    res = builtins.list(__iterate__())
    for key, value in six.iteritems(type):
        res = builtins.list(__matcher__.match(key, value, res))
    for item in res: yield item

@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string')
@document.parameters(string='the glob to filter the enumeration names with')
def list(string):
    '''List any enumerations that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
@document.parameters(type='any keyword that can be used to filter enumerations with')
def list(**type):
    '''List all of the enumerations within the database that match the keyword specified by `type`.'''
    res = builtins.list(iterate(**type))

    maxindex = max(builtins.map(idaapi.get_enum_idx, res) or [1])
    maxname = max(builtins.map(utils.fcompose(idaapi.get_enum_name, len), res) or [0])
    maxsize = max(builtins.map(size, res) or [0])
    cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
    try: cmask = max(builtins.map(utils.fcompose(mask, utils.fcondition(utils.fpartial(operator.eq, 0))(utils.fconstant(1), utils.fidentity), math.log, functools.partial(operator.mul, 1.0/math.log(8)), math.ceil), res) or [database.config.bits()/4.0])
    except: cmask = 0

    for n in res:
        name = idaapi.get_enum_name(n)
        six.print_(u"[{:{:d}d}] {:>{:d}s} & {:<{:d}x} ({:d} members){:s}".format(idaapi.get_enum_idx(n), int(cindex), utils.string.of(name), maxname, mask(n), int(cmask), len(builtins.list(members(n))), u" // {:s}".format(comment(n)) if comment(n) else ''))
    return

## members
@document.namespace
class members(object):
    """
    This namespace allows one to interact with the members belonging
    to an enumeration once the enumeration's id has been determined.
    This allows one to iterate through all of its members or add
    and remove values to the enumeration.

    By default this namespace will yield the names of all of the
    members of an enumeration.

    Some examples of using this namespace are::

        > eid = enum.by('example_enumeration')
        > mid = enum.members.add(eid, 'name', 0x1000)
        > ok = enum.members.remove(eid, mid)
        > mid = enum.members.by_name(eid, 'name')
        > mid = enum.members.by_value(eid, 0x1000)
        > for mid in enum.members.iterate(eid): ...
        > enum.members.list(e)

    """

    @document.parameters(enum='the enumeration to yield the names for')
    def __new__(cls, enum):
        '''Yield the name of each member from the enumeration `enum`.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            yield member.name(mid)
        return

    ## scope
    @document.aliases('member.new', 'member.create')
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration to add a member to', name='the name of the enumeration member', value='the value of the enumeration member', bitmask='if ``bitmask`` is specified as an integer, then use it as the bitmask for the enumeration')
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member `name` with the specified `value` to the enumeration `enum`.

        If the int, `bitmask`, is specified then used it as the bitmask for the enumeration.
        """
        eid = by(enum)
        bmask = bitmask.get('bitmask', idaapi.BADADDR & mask(eid))

        res = interface.tuplename(name) if isinstance(name, tuple) else name
        ok = idaapi.add_enum_member(eid, utils.string.to(res), value, bmask)

        err = {getattr(idaapi, n) : n for n in ('ENUM_MEMBER_ERROR_NAME', 'ENUM_MEMBER_ERROR_VALUE', 'ENUM_MEMBER_ERROR_ENUM', 'ENUM_MEMBER_ERROR_MASK', 'ENUM_MEMBER_ERROR_ILLV')}
        if ok in err.viewkeys():
            raise E.DisassemblerError(u"{:s}.add({:#x}, {!r}, {:#x}{:s}) : Unable to add member to enumeration due to error {:s}({:d}).".format('.'.join((__name__, cls.__name__)), eid, name, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else '', err[ok], ok))
        return eid
    new = create = utils.alias(add, 'members')

    @classmethod
    @document.parameters(enum='the enumeration containing the member to remove', member='the identifier or index of an enumeration member to remove')
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return member.remove(mid)
    delete = destroy = utils.alias(remove, 'members')

    ## aggregations
    @classmethod
    @document.parameters(enum='the enumeration to return the names for')
    def names(cls, enum):
        '''Return a set of all the names belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.name(mid) for mid in cls.iterate(eid) }

    @classmethod
    @document.parameters(enum='the enumeration to return the values of')
    def values(cls, enum):
        '''Return a set of all the values belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.value(mid) for mid in cls.iterate(eid) }

    @classmethod
    @document.parameters(enum='the enumeration containing the names and values to return')
    def mapping(cls, enum):
        '''Return a dictionary mapping all the values values to their names for the enumeration `enum`.'''
        eid = by(enum)
        return { member.value(mid) : member.name(mid) for mid in cls.iterate(eid) }

    ## searching
    @classmethod
    @document.parameters(enum='the enumeration to return a member for', index='the index of the enumeration member to return')
    def by_index(cls, enum, index):
        '''Return the member identifier for the member of the enumeration `enum` at the specified `index`.'''
        eid = by(enum)
        try: return next(mid for i, mid in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration: pass
        raise E.MemberNotFoundError(u"{:s}.by_index({:#x}, {:d}) : Unable to locate member by index.".format('.'.join((__name__, cls.__name__)), eid, index))

    @classmethod
    @document.parameters(enum='the enumeration to return a member for', mid='the identifier of the enumeration member to return')
    def by_identifier(cls, enum, mid):
        '''Return the member of the enumeration specified by `enum` and its `mid`.'''
        eid = by(enum)
        if member.parent(mid) != eid:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({:#x}, {:d}) : Unable to locate member by id.".format('.'.join((__name__, cls.__name__)), eid, mid))
        return mid

    @document.aliases('member.byValue')
    @classmethod
    @document.parameters(enum='the enumeration to return a member for', value='the value of the enumeration member to return')
    def by_value(cls, enum, value):
        '''Return the member identifier for the member of the enumeration `enum` with the specified `value`.'''
        eid = by(enum)
        bmask = idaapi.BADADDR & mask(eid)
        res, _ = idaapi.get_first_serial_enum_member(eid, value, bmask)
        if res == idaapi.BADADDR:
            raise E.MemberNotFoundError(u"{:s}.by_value({:#x}, {:d}) : Unable to locate member by value.".format('.'.join((__name__, cls.__name__)), eid, value))
        return res
    byValue = utils.alias(by_value, 'members')

    @document.aliases('member.byName')
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration to return a member for', name='the name of the enumeration member to return')
    def by_name(cls, enum, name):
        '''Return the member identifier for the member of the enumeration `enum` with the specified `name`.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            if name == member.name(mid):
                return mid
            continue
        return
    byName = utils.alias(by_name, 'members')

    @utils.multicase(n=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration to return a member for', n='an index or an identifier of the enumeration to return')
    def by(cls, enum, n):
        '''Return the member belonging to `enum` identified by its index or id in `n`.'''
        bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
        highbyte = 0xff << (bits-8)
        if n & highbyte == highbyte:
            return cls.by_identifier(enum, n)
        return cls.by_index(enum, n)
    @utils.multicase(member=basestring)
    @classmethod
    @utils.string.decorate_arguments('member')
    @document.parameters(enum='the enumeration to return a member for', member='the name of the member to return')
    def by(cls, enum, member):
        '''Return the member with the given `name` belonging to `enum`.'''
        return cls.by_name(enum, member)

    # FIXME: Implement a matcher class for enumeration members that can be used with .iterate and .list below.
    __member_matcher = utils.matcher()

    @classmethod
    @document.parameters(enum='the id of an enumeration')
    def __iterate__(cls, eid):
        '''Iterate through all the members of the enumeration identified by `eid`.'''
        bmask = idaapi.BADADDR & mask(eid)

        res = idaapi.get_first_enum_member(eid, bmask)
        if res == idaapi.BADADDR: return

        yield res

        while res != idaapi.get_last_enum_member(eid, bmask):
            res = idaapi.get_next_enum_member(eid, res, bmask)
            yield res
        return

    @classmethod
    @document.parameters(enum='the enumeration containing the members to iterate through')
    def iterate(cls, enum):
        '''Iterate through all ids of each member associated with the enumeration `enum`.'''
        eid = by(enum)
        bmask = idaapi.BADADDR & mask(eid)
        for value in cls.__iterate__(eid):
            res, _ = idaapi.get_first_serial_enum_member(eid, value, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    @classmethod
    @document.parameters(enum='the enumeration containing the members to list')
    def list(cls, enum):
        '''List all the members belonging to the enumeration identified by `enum`.'''
        # FIXME: make this consistent with every other .list using the matcher class
        eid = by(enum)
        res = builtins.list(cls.iterate(eid))
        maxindex = max(builtins.map(utils.first, enumerate(res)) or [1])
        maxvalue = max(builtins.map(utils.fcompose(member.value, "{:#x}".format, len), res) or [1])
        for i, mid in enumerate(res):
             six.print_(u"[{:d}] 0x{:>0{:d}x} {:s}".format(i, member.value(mid), maxvalue, member.name(mid)))
        return

@document.namespace
class member(object):
    """
    This namespace allows one to interact with a member belonging
    to an enumeration once the enumeration's id has been determined.
    This allows one to modify the property of any one of an
    enumeration's members.

    Some examples of how to use this namespace can be::

        > eid = enum.by('example_enumeration')
        > mid = enum.members.by_value(eid, 0x1000)
        > oldname = enum.member.name(mid, 'somename')
        > oldvalue = enum.member.value(mid, 0x100)
        > oldcomment = enum.member.comment(mid, 'This is an example comment')
        > ok = enum.member.remove(mid)

    """
    @classmethod
    @document.parameters(mid='the identifier of the member to return the enumeration for')
    def parent(cls, mid):
        '''Return the id of the enumeration that owns the member `mid`.'''
        return idaapi.get_enum_member_enum(mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of the member to remove')
    def remove(cls, mid):
        '''Remove the enumeration member with the given `mid`.'''
        eid, value = cls.parent(mid), cls.value(mid)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(eid, value, 0, idaapi.BADADDR & cls.mask(mid))
        if not res:
            raise E.DisassemblerError(u"{:s}.member.remove({:#x}) : Unable to remove member from enumeration.".format(__name__, mid))
        return res
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration to remove a member from', member='the member to remove')
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.remove(mid)

    ## properties
    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of the member to return the name for')
    def name(cls, mid):
        '''Return the name of the enumeration member `mid`.'''
        res = idaapi.get_enum_member_name(mid)
        return utils.string.of(res)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the name for', member='the member to return the name for')
    def name(cls, enum, member):
        '''Return the name of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.name(mid)
    @document.aliases('member.rename')
    @utils.multicase(mid=six.integer_types, name=(basestring, tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(mid='the identifier of an enumeration member', name='the name to rename the enumeration member to')
    def name(cls, mid, name):
        '''Rename the enumeration member `mid` to `name`.'''
        res = interface.tuplename(*name) if isinstance(name, tuple) else name
        return idaapi.set_enum_member_name(mid, utils.string.to(res))
    @document.aliases('member.rename')
    @utils.multicase(name=basestring)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    @document.parameters(enum='the enumeration containing the member to rename', member='the member to rename', name='the name to rename the enumeration member to', suffix='any other names to append to the new name')
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration `member` belonging to `enum` to `name`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        res = (name,) + suffix
        return idaapi.set_enum_member_name(mid, utils.string.to(interface.tuplename(*res)))

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the comment for', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, mid, **repeatable):
        """Return the comment for the enumeration member `mid`.

        If the bool `repeatable` is specified, then return the repeatable comment.
        """
        res = idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
        return utils.string.of(res)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the comment for', member='the member to return the comment for', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=six.integer_types, comment=basestring)
    @classmethod
    @utils.string.decorate_arguments('comment')
    @document.parameters(mid='the identifier of an enumeration containing the member to set the comment for', comment='the comment to apply', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, mid, comment, **repeatable):
        """Set the comment for the enumeration member id `mid` to `comment`.

        If the bool `repeatable` is specified, then set the repeatable comment.
        """
        res = utils.string.to(comment)
        return idaapi.set_enum_member_cmt(mid, res, repeatable.get('repeatable', True))
    @utils.multicase(comment=basestring)
    @classmethod
    @utils.string.decorate_arguments('comment')
    @document.parameters(enum='the enumeration containing the member to set the comment for', member='the member to set the comment for', comment='the comment to apply', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration `member` belonging to `enum` to the string `comment`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, comment, **repeatable)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the value of')
    def value(cls, mid):
        '''Return the value of the enumeration member `mid`.'''
        return idaapi.get_enum_member_value(mid)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the value of', member='the member to return the value of')
    def value(cls, enum, member):
        '''Return the value of the specified `member` belonging to the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid)
    @utils.multicase(mid=six.integer_types, value=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of the member to set the value of', value='the value to set the member to', bitmask='if ``bitmask`` is specified as an integer, then use it as the bitmask to assign to the value')
    def value(cls, mid, value, **bitmask):
        """Set the `value` for the enumeration `member` belonging to `enum`.

        If the integer `bitmask` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        bmask = bitmask.get('bitmask', idaapi.BADADDR & cls.mask(mid))
        return idaapi.set_enum_member_value(mid, value, bmask)
    @utils.multicase(value=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration containing the member to set the value for', member='the member to set the value of', value='the value to apply', bitmask='if ``bitmask`` is specified as an integer, then use it as the bitmask to assign to the value')
    def value(cls, enum, member, value, **bitmask):
        """Set the `value` for the enumeration `member` belonging to `enum`.

        If the integer `bitmask` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid, value, **bitmask)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the serial for')
    def serial(cls, mid):
        '''Return the serial of the enumeration member `mid`.'''
        return idaapi.get_enum_member_serial(mid)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the serial for', member='the member to return the serial of')
    def serial(cls, enum, member):
        '''Return the serial of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.serial(mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the bitmask of')
    def mask(cls, mid):
        '''Return the bitmask for the enumeration member `mid`.'''
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the bitmask for', member='the member to return the bitmask for')
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.mask(mid)
