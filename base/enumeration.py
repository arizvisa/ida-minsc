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

import six, builtins

import functools, operator, itertools
import logging, sys, math
import fnmatch, re

import database

import internal
from internal import utils, interface, exceptions as E

import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def has(enum):
    '''Return truth if the enumeration `enum` exists within the database.'''
    alts = {idaapi.BADADDR - item for item in [7, 4, 2]}
    available = {idx for idx, _ in internal.netnode.alt.fiter(enum)}
    return interface.node.is_identifier(enum) and available & alts == alts

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase()
def flags(enum):
    '''Return the flags for the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid)
@utils.multicase(mask=six.integer_types)
def flags(enum, mask):
    '''Return the flags for the enumeration `enum` and masked with `mask`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid) & mask

@utils.string.decorate_arguments('name')
def by_name(name):
    '''Return the identifier for the enumeration with the given `name`.'''
    string = utils.string.to(name)
    res = idaapi.get_enum(string)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_name({!s}) : Unable to locate the enumeration with the specified name ({!s}).".format(__name__, utils.string.repr(name), utils.string.repr(name)))
    return res
byname = utils.alias(by_name)

def by_index(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_index({:#x}) : Unable to locate the enumeration at index {:d}.".format(__name__, index, index))
    return res
byindex = utils.alias(by_index)

@utils.multicase(index=six.integer_types)
def by(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    return index if interface.node.is_identifier(index) else by_index(index)
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def by(name):
    '''Return the identifier for the enumeration with the specified `name`.'''
    return by_name(name)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def by(**type):
    '''Return the identifier for the first enumeration matching the keyword specified by `type`.'''
    searchstring = utils.string.kwargs(type)

    listable = [item for item in iterate(**type)]
    if len(listable) > 1:
        messages = (u"[{:d}] {:s} & {:#x} ({:d} members){:s}".format(idaapi.get_enum_idx(item), idaapi.get_enum_name(item), mask(item), len(builtins.list(members(item))), u" // {:s}".format(comment(item)) if comment(item) else '') for i, item in enumerate(listable))
        [ logging.info(msg) for msg in messages ]
        logging.warning(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first enumeration {:#x}.".format(__name__, searchstring, len(listable), listable[0]))

    iterable = (item for item in listable)
    res = next(iterable, None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def search(string):
    '''Return the identifier of the first enumeration that matches the glob `string`.'''
    return by(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def search(**type):
    '''Return the identifier of the first enumeration that matches the keyword specified by `type`.'''
    return by(**type)

def names(enum):
    '''Return a list of all the names belonging to the enumeration `enum`.'''
    return [member.name(item) for item in members.iterate(enum)]
keys = utils.alias(names)

def values(enum):
    '''Return a list of all the values belonging to the enumeration `enum`.'''
    return [member.value(item) for item in members.iterate(enum)]

## creation/deletion
@utils.string.decorate_arguments('name')
def new(name, flags=0):
    '''Create an enumeration with the specified `name` and `flags` using ``idaapi.add_enum``.'''
    idx, string = count(), utils.string.to(name)
    res = idaapi.add_enum(idx, string, flags)
    if res == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({!s}, flags={:d}) : Unable to create an enumeration with the specified name ({!s}).".format(__name__, utils.string.repr(name), flags, utils.string.repr(name)))
    return res

def delete(enum):
    '''Delete the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.del_enum(eid)
create, remove = utils.alias(new), utils.alias(delete)

## setting enum options
@utils.multicase()
def name(enum):
    '''Return the name of the enumeration `enum`.'''
    eid = by(enum)
    res = idaapi.get_enum_name(eid)
    return utils.string.of(res)
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def name(enum, name):
    '''Rename the enumeration `enum` to the string `name`.'''
    eid, string = by(enum), utils.string.to(name)
    res, ok = idaapi.get_enum_name(eid), idaapi.set_enum_name(eid, string)
    if not ok:
        raise E.DisassemblerError(u"{:s}.name({!r}, {!s}) : Unable to set the name for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, utils.string.repr(name), eid, utils.string.repr(name)))
    return utils.string.of(res)

@utils.multicase()
def comment(enum, **repeatable):
    """Return the comment for the enumeration `enum`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    res = idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(comment=six.string_types)
@utils.string.decorate_arguments('comment')
def comment(enum, comment, **repeatable):
    """Set the comment for the enumeration `enum` to `comment`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    eid, string = by(enum), utils.string.to(comment)
    res, ok = idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True)), idaapi.set_enum_cmt(eid, string, repeatable.get('repeatable', True))
    if not ok:
        adjective = (u'repeatable' if repeatable.get('repeatable', True) else u'non-repeatable') if repeatable else u''
        raise E.DisassemblerError(u"{:s}.comment({!r}, {!s}{:s}) : Unable to set the {:s}comment for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', u" {:s}".format(adjective) if adjective else u'', eid, utils.string.repr(comment)))
    return utils.string.of(res)

@utils.multicase()
def size(enum):
    '''Return the number of bytes for the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_width(eid)
@utils.multicase(width=six.integer_types)
def size(enum, width):
    '''Set the number of bytes for the enumeration `enum` to `width`.'''
    eid = by(enum)
    res, ok = idaapi.get_enum_width(eid), idaapi.set_enum_width(eid, width)
    if not ok:
        raise E.DisassemblerError(u"{:s}.size({!r}, {:#x}) : Unable to set the width for the specified enumeration ({:#x}) to {:d}.".format(__name__, enum, width, eid, width))
    return res

@utils.multicase()
def bits(enum):
    '''Return the number of bits for the enumeration `enum`.'''
    return 8 * size(enum)
@utils.multicase(width=six.integer_types)
def bits(enum, width):
    '''Set the number of bits for the enumeration `enum` to `width`.'''
    res = math.trunc(math.ceil(width / 8.0))
    return size(enum, math.trunc(res))

def mask(enum):
    '''Return the bitmask for the enumeration `enum`.'''
    eid = by(enum)
    res = bits(eid)
    return pow(2, res) - 1

def repr(enum):
    '''Return a printable summary of the enumeration `enum`.'''
    eid = by(enum)
    w, cmt = 2 * size(eid), comment(enum, repeatable=True) or comment(enum, repeatable=False)
    res = [(member.name(item), member.value(item), member.mask(item), member.comment(item, repeatable=True) or member.comment(item, repeatable=False)) for item in members.iterate(eid)]
    aligned = max([len(item) for item, _, _, _ in res] if res else [0])
    return "<type 'enum'> {:s}{:s}\n".format(name(eid), " // {:s}".format(cmt) if cmt else '') + '\n'.join("[{:d}] {:<{align}s} : {:#0{width}x} & {:#0{width}x}".format(i, name, value, bmask, width=2 + w, align=aligned) + (" // {:s}".format(comment) if comment else '') for i,(name,value,bmask,comment) in enumerate(res))

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_name, utils.string.of)
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_name, utils.string.of)
__matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), idaapi.get_enum_name, utils.string.of)
__matcher__.attribute('id')
__matcher__.attribute('identifier')
__matcher__.predicate('pred')
__matcher__.predicate('predicate')

def __iterate__():
    '''Yield the identifier of each enumeration within the database.'''
    for item in range(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(item)
    return

@utils.string.decorate_arguments('regex', 'like', 'name')
def iterate(**type):
    '''Iterate through all of the enumerations in the database that match the keyword specified by `type`.'''
    if not type: type = {'predicate': lambda item: True}
    listable = [item for item in __iterate__()]
    for key, value in type.items():
        listable = [item for item in __matcher__.match(key, value, listable)]
    for item in listable: yield item

@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def list(string):
    '''List any enumerations that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def list(**type):
    '''List all of the enumerations within the database that match the keyword specified by `type`.'''
    res = [item for item in iterate(**type)]

    maxindex = max(builtins.map(idaapi.get_enum_idx, res) if res else [1])
    maxname = max(builtins.map(utils.fcompose(idaapi.get_enum_name, len), res) if res else [0])
    maxsize = max(builtins.map(size, res) if res else [0])
    cindex = 1 + math.floor(math.log10(maxindex or 1))
    try: cmask = max(len("{:x}".format(mask(item))) for item in res) if res else database.config.bits() / 4.0
    except Exception: cmask = 0

    for item in res:
        name = idaapi.get_enum_name(item)
        six.print_(u"{:<{:d}s} {:>{:d}s} & {:<#{:d}x} ({:d} members){:s}".format("[{:d}]".format(idaapi.get_enum_idx(item)), 2 + math.trunc(cindex), utils.string.of(name), maxname, mask(item), 2 + math.trunc(cmask), len(builtins.list(members(item))), u" // {:s}".format(comment(item)) if comment(item) else ''))
    return

## members
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

    def __new__(cls, enum):
        '''Yield the name of each member from the enumeration `enum`.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            yield member.name(mid)
        return

    ## scope
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member `name` with the specified `value` to the enumeration `enum`.

        If the int, `bitmask`, is specified then used it as the bitmask for the enumeration.
        """
        eid = by(enum)
        bmask = bitmask.get('bitmask', idaapi.BADADDR & mask(eid))

        fullname = interface.tuplename(name) if isinstance(name, tuple) else name
        string = utils.string.to(fullname)
        ok = idaapi.add_enum_member(eid, string, value, bmask)

        err = {getattr(idaapi, item) : item for item in ['ENUM_MEMBER_ERROR_NAME', 'ENUM_MEMBER_ERROR_VALUE', 'ENUM_MEMBER_ERROR_ENUM', 'ENUM_MEMBER_ERROR_MASK', 'ENUM_MEMBER_ERROR_ILLV']}
        if ok in err.keys():
            raise E.DisassemblerError(u"{:s}.add({!r}, {!s}, {:#x}{:s}) : Unable to add a member to the enumeration ({:#x}) with the specified name ({!s}) and value ({:#x}) due to error {:s}({:d}).".format('.'.join([__name__, cls.__name__]), enum, utils.string.repr(name), value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', eid, utils.string.repr(fullname), value, err[ok], ok))
        return eid
    new = create = utils.alias(add, 'members')

    @classmethod
    @utils.multicase()
    def remove(cls, eid):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return member.remove(mid)
    @classmethod
    @utils.multicase()
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        value, serial, mask = idaapi.get_enum_member_value(mid), idaapi.get_enum_member_serial(mid), idaapi.get_enum_member_bmask(mid)
        ok = idaapi.del_enum_member(eid, value, serial, mask)
        if not ok:
            raise E.DisassemblerError(u"{:s}.remove({!r}, {!r}) : Unable to remove the specified member ({:#x}) having the value {:d} from the enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, member, mid, value, eid))
        return ok
    delete = destroy = utils.alias(remove, 'members')

    ## aggregations
    @classmethod
    def names(cls, enum):
        '''Return a set of all the names belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.name(mid) for mid in cls.iterate(eid) }

    @classmethod
    def values(cls, enum):
        '''Return a set of all the values belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.value(mid) for mid in cls.iterate(eid) }

    @classmethod
    def mapping(cls, enum):
        '''Return a dictionary mapping all the values values to their names for the enumeration `enum`.'''
        eid = by(enum)
        return { member.value(mid) : member.name(mid) for mid in cls.iterate(eid) }

    ## searching
    @classmethod
    def by_index(cls, enum, index):
        '''Return the member identifier for the member of the enumeration `enum` at the specified `index`.'''
        eid = by(enum)
        try:
            res = next(mid for i, mid in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration:
            raise E.MemberNotFoundError(u"{:s}.by_index({!r}, {:d}) : Unable to locate the member at index {:d} of the specified enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, index, index, eid))
        return res

    @classmethod
    def by_identifier(cls, enum, mid):
        '''Return the member of the enumeration specified by `enum` and its `mid`.'''
        eid = by(enum)
        if member.parent(mid) != eid:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({!r}, {:#x}) : Unable to locate a member in the enumeration ({:#x}) with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, mid, eid, mid))
        return mid

    @classmethod
    def by_value(cls, enum, value):
        '''Return the member identifier for the member of the enumeration `enum` with the specified `value`.'''
        eid = by(enum)
        bmask = idaapi.BADADDR & mask(eid)
        res, _ = idaapi.get_first_serial_enum_member(eid, value, bmask)
        if res == idaapi.BADADDR:
            raise E.MemberNotFoundError(u"{:s}.by_value({!r}, {:#x}) : Unable to locate a member in the enumeration ({:#x}) with the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, eid, value))
        return res
    byvalue = utils.alias(by_value, 'members')

    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, enum, name):
        '''Return the member identifier for the member of the enumeration `enum` with the specified `name`.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            if name == member.name(mid):
                return mid
            continue
        return
    byname = utils.alias(by_name, 'members')

    @utils.multicase(n=six.integer_types)
    @classmethod
    def by(cls, enum, n):
        '''Return the member belonging to `enum` identified by its index or id in `n`.'''
        return cls.by_identifier(enum, n) if interface.node.is_identifier(n) else cls.by_index(enum, n)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by(cls, enum, name):
        '''Return the member of the enumeration `enum` with the given `name`.'''
        return cls.by_name(enum, name)

    # FIXME: Implement a matcher class for enumeration members that can be used with .iterate and .list below.
    __member_matcher = utils.matcher()

    @classmethod
    def __iterate__(cls, eid):
        '''Iterate through all the members of the enumeration identified by `eid`.'''
        bmask = idaapi.BADADDR & mask(eid)

        # Fetch the first enumeration member, and then yield it
        # if there was no error while fetching it.
        item = idaapi.get_first_enum_member(eid, bmask)
        if item == idaapi.BADADDR:
            return
        yield item

        # Continue fetching and yielding members until we get
        # to the very last one of the enumeration.
        while item != idaapi.get_last_enum_member(eid, bmask):
            item = idaapi.get_next_enum_member(eid, item, bmask)
            yield item
        return

    @classmethod
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
    def list(cls, enum):
        '''List all the members belonging to the enumeration identified by `enum`.'''
        # FIXME: make this consistent with every other .list using the matcher class
        eid = by(enum)
        listable = [item for item in cls.iterate(eid)]
        maxindex = max(len("[{:d}]".format(index)) for index, _ in enumerate(listable)) if listable else 1
        maxvalue = max(builtins.map(utils.fcompose(member.value, "{:#x}".format, len), listable) if listable else [1])
        for i, mid in enumerate(listable):
             six.print_(u"{:<{:d}s} {:#0{:d}x} {:s}".format("[{:d}]".format(i), maxindex, member.value(mid), 2 + maxvalue, member.name(mid)))
        return

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
    def parent(cls, mid):
        '''Return the id of the enumeration that owns the member `mid`.'''
        return idaapi.get_enum_member_enum(mid)
    owner = utils.alias(parent, 'member')

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def remove(cls, mid):
        '''Remove the enumeration member with the given `mid`.'''
        eid, value, serial, mask = cls.parent(mid), cls.value(mid), cls.serial(mid), cls.mask(mid)
        ok = idaapi.del_enum_member(eid, value, serial, mask)
        if not ok:
            raise E.DisassemblerError(u"{:s}.remove({:#x}) : Unable to remove the specified member ({:#x}) having the value {:d} from the enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid, value, eid))
        return ok
    @utils.multicase()
    @classmethod
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.remove(mid)

    ## properties
    @utils.multicase(mid=six.integer_types)
    @classmethod
    def name(cls, mid):
        '''Return the name of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.name({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        res = idaapi.get_enum_member_name(mid)
        return utils.string.of(res)
    @utils.multicase()
    @classmethod
    def name(cls, enum, member):
        '''Return the name of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.name(mid)
    @utils.multicase(mid=six.integer_types, name=(six.string_types, tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    def name(cls, mid, name):
        '''Rename the enumeration member `mid` to `name`.'''
        fullname = interface.tuplename(*name) if isinstance(name, tuple) else name
        string = utils.string.to(fullname)
        res, ok = idaapi.get_enum_member_name(mid), idaapi.set_enum_member_name(mid, string)
        if not ok:
            raise E.DisassemblerError(u"{:s}.name({:#x}, {!s}) : Unable to set the name for the specified member ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(name), mid, utils.string.repr(fullname)))
        return utils.string.of(res)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration `member` belonging to `enum` to `name`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        fullname = (name,) + suffix
        return cls.name(mid, fullname)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def comment(cls, mid, **repeatable):
        """Return the comment for the enumeration member `mid`.

        If the bool `repeatable` is specified, then return the repeatable comment.
        """
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.comment({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        res = idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
        return utils.string.of(res)
    @utils.multicase()
    @classmethod
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=six.integer_types, comment=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('comment')
    def comment(cls, mid, comment, **repeatable):
        """Set the comment for the enumeration member id `mid` to `comment`.

        If the bool `repeatable` is specified, then set the repeatable comment.
        """
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.comment({:#x}, {!s}{:s}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', mid))
        string = utils.string.to(comment)
        res, ok = idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True)), idaapi.set_enum_member_cmt(mid, string, repeatable.get('repeatable', True))
        if not ok:
            adjective = (u'repeatable' if repeatable.get('repeatable', True) else u'non-repeatable') if repeatable else u''
            raise E.DisassemblerError(u"{:s}.comment({:#x}, {!s}{:s})) : Unable to set the {:s}comment for the specified member ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', u" {:s}".format(adjective) if adjective else u'', mid, utils.string.repr(comment)))
        return utils.string.of(res)

    @utils.multicase(comment=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('comment')
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration `member` belonging to `enum` to the string `comment`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, comment, **repeatable)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def value(cls, mid):
        '''Return the value of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        return idaapi.get_enum_member_value(mid)
    @utils.multicase()
    @classmethod
    def value(cls, enum, member):
        '''Return the value of the specified `member` belonging to the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid)
    @utils.multicase(mid=six.integer_types, value=six.integer_types)
    @classmethod
    def value(cls, mid, value, **bitmask):
        """Set the `value` for the enumeration `member` belonging to `enum`.

        If the integer `bitmask` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}, {:#x}{:s}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', mid))
        bmask = bitmask.get('bitmask', idaapi.BADADDR & cls.mask(mid))
        res, ok = idaapi.get_enum_member_value(mid), idaapi.set_enum_member_value(mid, value, bmask)
        if not ok:
            raise E.DisassemblerError(u"{:s}.value({:#x}, {:#x}{:s}) : Unable to set the value for the specified member ({:#x}) to {:#x}{:s}.".format('.'.join([__name__, cls.__name__]), mid, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', mid, value, u" & {:#x}".format(bmask) if bmask else u''))
        return res
    @utils.multicase(value=six.integer_types)
    @classmethod
    def value(cls, enum, member, value, **bitmask):
        """Set the `value` for the enumeration `member` belonging to `enum`.

        If the integer `bitmask` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid, value, **bitmask)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def serial(cls, mid):
        '''Return the serial of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.serial({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        return idaapi.get_enum_member_serial(mid)
    @utils.multicase()
    @classmethod
    def serial(cls, enum, member):
        '''Return the serial of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.serial(mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def mask(cls, mid):
        '''Return the bitmask for the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.mask({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase()
    @classmethod
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.mask(mid)
