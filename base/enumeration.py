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

@utils.multicase(enum=six.integer_types)
@document.parameters(enum='the enumeration identifier to check')
def has(enum):
    '''Return truth if an enumeration with the identifier `enum` exists within the database.'''
    ENUM_QTY_IDX, ENUM_FLG_IDX, ENUM_FLAGS, ENUM_ORDINAL = -1, -3, -5, -8
    return interface.node.is_identifier(enum) and idaapi.get_enum_idx(enum) != idaapi.BADADDR
@utils.multicase(name=six.string_types)
@document.parameters(name='the enumeration name to check')
def has(name):
    '''Return truth if an enumeration with the specified `name` exists within the database.'''
    string = utils.string.to(name)
    return idaapi.get_enum(string) != idaapi.BADADDR

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase()
@document.parameters(enum='the enumeration to return the flags for')
def flags(enum):
    '''Return the flags for the enumeration identified by `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid)
@utils.multicase(flags=six.integer_types)
@document.parameters(enum='the enumeration to return the flags for', flags='the flags to apply to the enumeration')
def flags(enum, flags):
    '''Set the flags for the enumeration `enum` to the value specified by `flags`.'''
    eid = by(enum)

    # Define some flags that we may later allow the user to set explicitly.
    ENUM_FLAGS_IS_BF, ENUM_FLAGS_HIDDEN, = 0x00000001, 0x00000002,
    ENUM_FLAGS_FROMTIL, ENUM_FLAGS_WIDTH = 0x00000004, 0x00000038

    # Fetch the previous flag, and assign the new ones.
    res, ok = idaapi.get_enum_flag(eid), idaapi.set_enum_flag(eid, flags)
    if not ok:
        raise E.DisassemblerError(u"{:s}.flags({!r}, {:#x}) : Unable to set the flags for the specified enumeration ({:#x}) to {:#x}.".format(__name__, enum, flags, eid, flags))
    return res

@utils.multicase()
@document.parameters(enum='the enumeration to return the index of')
def index(enum):
    '''Return the index in the enumeration list for the enumeration identified by `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_idx(eid)
@utils.multicase(index=six.integer_types)
@document.parameters(enum='the enumeration to set the index for', index='the index to change the enumeration to')
def index(enum, index):
    '''Set the position in the enumeration list for the enumeration `enum` to the specified `index`.'''
    eid = by(enum)
    res, ok = idaapi.get_enum_idx(eid), idaapi.set_enum_idx(eid, index)
    if not ok:
        raise E.DisassemblerError(u"{:s}.index({!r}, {:d}) : Unable to set the index for the specified enumeration ({:#x}) to {:#x}.".format(__name__, enum, index, eid, index))
    return res

@utils.string.decorate_arguments('name')
@document.aliases('byname')
@document.parameters(name='the name of the enumeration to return')
def by_name(name):
    '''Return the identifier for the enumeration with the given `name`.'''
    string = utils.string.to(name)
    res = idaapi.get_enum(string)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_name({!s}) : Unable to locate the enumeration with the specified name ({!s}).".format(__name__, utils.string.repr(name), utils.string.repr(name)))
    return res
byname = utils.alias(by_name)

@document.aliases('byindex')
@document.parameters(index='the index of the enumeration to return')
def by_index(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_index({:#x}) : Unable to locate the enumeration at index {:d}.".format(__name__, index, index))
    return res
byindex = utils.alias(by_index)

@document.aliases('byidentifier')
@document.parameters(eid='the identifier of the enumeration to return')
def by_identifier(eid):
    '''Return the identifier for the enumeration using the specified `eid`.'''
    if not has(eid):
        raise E.EnumerationNotFoundError(u"{:s}.by_identifier({!s}) : Unable to locate the enumeration with the specified identifier ({:#x}).".format(__name__, eid, eid))
    return eid
byidentifier = utils.alias(by_identifier)

@utils.multicase(index=six.integer_types)
@document.parameters(index='the index or id of the enumeration to return')
def by(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    return by_identifier(index) if interface.node.is_identifier(index) else by_index(index)
@utils.multicase(name=six.string_types)
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

    listable = [item for item in iterate(**type)]
    if len(listable) > 1:
        messages = (u"[{:d}] {:s}{:s} ({:d} members){:s}".format(idaapi.get_enum_idx(item), idaapi.get_enum_name(item), u" & {:#x}".format(mask(item)) if bitfield(item) else u'', len(builtins.list(members(item))), u" // {:s}".format(comment(item)) if comment(item) else u'') for i, item in enumerate(listable))
        [ logging.info(msg) for msg in messages ]
        logging.warning(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first enumeration {:#x}.".format(__name__, searchstring, len(listable), listable[0]))

    iterable = (item for item in listable)
    res = next(iterable, None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(string=six.string_types)
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
    '''Return a set of all of the names belonging to the enumeration `enum`.'''
    return {item for item in members.names(enum)}
keys = utils.alias(names)

@document.parameters(enum='the enumeration to return the values of')
def values(enum):
    '''Return a set of all of the values belonging to the enumeration `enum`.'''
    return {item for item in members.values(enum)}

## creation/deletion
@utils.string.decorate_arguments('name')
@document.aliases('create')
@document.parameters(name='the name of the new enumeration', flags='any extra flags to pass to `idaapi.add_enum`')
def new(name, flags=0):
    '''Create an enumeration with the specified `name` and `flags` using ``idaapi.add_enum``.'''
    idx, string = count(), utils.string.to(name)
    res = idaapi.add_enum(idx, string, flags)
    if res == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({!s}, flags={:d}) : Unable to create an enumeration with the specified name ({!s}).".format(__name__, utils.string.repr(name), flags, utils.string.repr(name)))
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
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
@document.parameters(enum='the enumeration to rename', name='the name to rename the enumeration to')
def name(enum, name):
    '''Rename the enumeration `enum` to the string `name`.'''
    eid, string = by(enum), utils.string.to(name)
    res, ok = idaapi.get_enum_name(eid), idaapi.set_enum_name(eid, string)
    if not ok:
        raise E.DisassemblerError(u"{:s}.name({!r}, {!s}) : Unable to set the name for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, utils.string.repr(name), eid, utils.string.repr(name)))
    return utils.string.of(res)

@utils.multicase()
@document.parameters(enum='the enumeration to return the comment for', repeatable='whether the returned comment should be repeatable or not')
def comment(enum, **repeatable):
    """Return the comment for the enumeration `enum`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    res = idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(comment=six.string_types)
@utils.string.decorate_arguments('comment')
@document.parameters(enum='the enumeration to modify the comment for', comment='the comment to apply', repeatable='whether the comment should be repeatable or not')
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
@utils.multicase(none=None.__class__)
def comment(enum, none, **repeatable):
    '''Remove the comment from the enumeration `enum`.'''
    return comment(enum, none or u'', **repeatable)

@utils.multicase()
@document.parameters(enum='the enumeration to return the width of')
def size(enum):
    '''Return the number of bytes for the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_width(eid)
@utils.multicase(width=six.integer_types)
@document.parameters(enum='the enumeration to set the width for', width='the number of bytes to set the enumeration width to')
def size(enum, width):
    '''Set the number of bytes for the enumeration `enum` to `width`.'''
    eid = by(enum)
    res, ok = idaapi.get_enum_width(eid), idaapi.set_enum_width(eid, width)
    if not ok:
        raise E.DisassemblerError(u"{:s}.size({!r}, {:#x}) : Unable to set the width for the specified enumeration ({:#x}) to {:d}.".format(__name__, enum, width, eid, width))
    return res

@utils.multicase()
@document.parameters(enum='the enumeration to return the width of')
def bits(enum):
    '''Return the number of bits for the enumeration `enum`.'''
    return 8 * size(enum)
@utils.multicase(width=six.integer_types)
@document.parameters(enum='the enumeration to set the width for', width='the number of bits to set the enumeration width to')
def bits(enum, width):
    '''Set the number of bits for the enumeration `enum` to `width`.'''
    res = math.trunc(math.ceil(width / 8.0))
    return size(enum, math.trunc(res))

@document.parameters(enum='the enumeration to return the bitmask for')
def mask(enum):
    '''Return the bitmask for the enumeration `enum`.'''
    eid = by(enum)
    res = bits(eid)
    return pow(2, res) - 1

@utils.multicase()
@document.parameters(enum='the enumeration to return the bitfield flag for')
def bitfield(enum):
    '''Return whether the enumeration identified by `enum` is a bitfield or not.'''
    eid = by(enum)
    return idaapi.is_bf(eid)
@utils.multicase(boolean=(six.integer_types, bool))
@document.parameters(enum='the enumeration to set the bitfield flag for', boolean='whether to set the flag or clear it')
def bitfield(enum, boolean):
    '''Toggle the bitfield setting of the enumeration `enum` depending on the value of `boolean`.'''
    eid = by(enum)
    res, ok = idaapi.is_bf(eid), idaapi.set_enum_bf(eid, True if boolean else False)
    if not ok:
        raise E.DisassemblerError(u"{:s}.bitfield({!r}, {!s}) : Unable to set the bitfield flag for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, boolean, eid, boolean))
    return res
bitflag = utils.alias(bitfield)

@document.parameters(enum='the enumeration to return references for')
def up(enum):
    '''Return all structure or frame members within the database that reference the specified `enum`.'''
    X, eid = idaapi.xrefblk_t(), by(enum)

    # IDA does not seem to create xrefs to enumeration identifiers.
    raise E.UnsupportedCapability(u"{:s}.up({:#x}) : Unable to locate any cross-references for the specified enumeration due to the disassembler not keeping track of them.".format(__name__, eid))

    # Grab the first reference to the enumeration.
    if not X.first_to(eid, idaapi.XREF_ALL):
        return []

    # Continue to grab all the rest of the refs to the enumeration.
    refs = [(X.frm, X.iscode, X.type)]
    while X.next_to():
        refs.append((X.frm, X.iscode, X.type))

    # Iterate through each xref and figure out if the enumeration id is
    # applied to a structure type.
    res = []
    for ref, _, _ in refs:

        # If the reference is not an identifier, then we don't care about
        # it because it's pointing to code and the member.refs function
        # should be used for grabbing those.
        if not interface.node.is_identifier(ref):
            continue

        # Get mptr, full member name, and sptr for the identifier we found.
        mpack = idaapi.get_member_by_id(ref)
        if mpack is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}.up({:#x}) : Unable to locate the member identified by {:#x}.".format(__name__, eid, ref))

        mptr, name, sptr = mpack
        if not interface.node.is_identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

        # Verify the type of the mptr is correct so that we can use it.
        if not isinstance(mptr, idaapi.member_t):
            cls, name = self.__class__, idaapi.get_member_fullname(ref)
            raise E.InvalidTypeOrValueError(u"{:s}.up({:#x}) : Unexpected type {!s} returned for member \"{:s}\".".format(__name__, eid, mptr.__class__, internal.utils.string.escape(name, '"')))

        # Use the mptr identifier to determine if we're referencing a frame.
        frname, _ = name.split('.', 1)
        frid = internal.netnode.get(frname)
        ea = idaapi.get_func_by_frame(frid)

        # If we couldn't find a frame for it, then this is a structure member
        # and we can just grab it using the structure module.
        if ea == idaapi.BADADDR:
            st = structure.by_identifier(sptr.id)
            mem = st.members.by_identifier(mptr.id)
            res.append(mem)
            continue

        # Otherwise, we know that this is a a function frame and
        # we can just grab it using idaapi.get_frame. We also
        # need the idaapi.func_t for it to get the frame size.
        fr = idaapi.get_frame(ea)
        if fr is None:
            cls = self.__class__
            raise E.MissingTypeOrAttribute(u"{:s}.up({:#x}) : The function at {:#x} for frame member {:#x} does not have a frame.".format(__name__, eid, ea, mptr.id))

        f = idaapi.get_func(ea)
        if f is None:
            cls = self.__class__
            raise E.FunctionNotFoundError(u"{:s}.up({:#x}) : Unable to locate the function for frame member {:#x} by address {:#x}.".format(__name__, eid, mptr.id, ea))

        # Now that we have everything we need, we use the structure
        # module and the idaapi.func_t we fetched to instantiate the
        # structure with the correct offset and then fetch the member
        # to aggregate to our list of results.
        st = structure.by_identifier(fr.id, offset=-f.frsize)
        mem = st.members.by_identifier(mptr.id)
        res.append(mem)
    return res

@document.parameters(enum='the enumeration to summarize')
def repr(enum):
    '''Return a printable summary of the enumeration `enum`.'''
    eid = by(enum)
    w, cmt = 2 * size(eid), comment(enum, repeatable=True) or comment(enum, repeatable=False)
    items = [(member.name(item), member.value(item), member.mask(item), member.comment(item, repeatable=True) or member.comment(item, repeatable=False)) for item in members.iterate(eid)]

    # Figure out the padding for each component belonging to a member of the
    # enumeration in order to keep them aligned properly when displaying them.
    maxindex = max(len("[{:d}]".format(index)) for index, _ in enumerate(items)) if items else 1
    maxname = max(len(name) for name, _, _, _ in items) if items else 0
    maxvalue = max(len("{:#{:d}x}".format(value, 2 + w)) for name, value, mask, _ in items) if items else 1
    maxbname = max(len(utils.string.of(idaapi.get_bmask_name(eid, mask)) if idaapi.get_bmask_name(eid, mask) else u'') for name, value, mask, _ in items) if items else 0

    # If the enumeration is a bitfield, then make sure to include the bitmask and
    # its name if one was defined.
    if bitfield(eid):
        iterable = (u"{:<{alignindex:d}s} {:<{alignname}s} : {:#0{alignvalue}x} & {:<{alignmask:d}s}".format(u"[{:d}]".format(i), name, value, u"{:s}({:#0{:d}x})".format(utils.string.of(idaapi.get_bmask_name(eid, bmask)), bmask, maxvalue) if utils.string.of(idaapi.get_bmask_name(eid, bmask)) else u"{:#0{:d}x}".format(bmask, maxvalue), alignindex=maxindex, alignname=maxname, alignvalue=maxvalue, alignmask=(maxbname + 2 if maxbname else 0) + maxvalue) + (u" // {:s}".format(comment) if comment else u'') for i, (name, value, bmask, comment) in enumerate(items))

    # Otherwise, we just need to emit each member with its comment added to the end.
    else:
        iterable = (u"{:<{alignindex:d}s} {:<{alignname}s} : {:#0{alignvalue}x}".format(u"[{:d}]".format(i), name, value, alignindex=maxindex, alignname=maxname, alignvalue=maxvalue) + (u" // {:s}".format(comment) if comment else u'') for i, (name, value, bmask, comment) in enumerate(items))

    # Return our newline-joined result to the caller. If it's a bitfield, then we need
    # to include the length for " & " in the calculation. Then, if the mask has a name,
    # then we also need to include the length for "()" in the resulting calculation.
    description = u"<type 'enum'> {:s}".format(name(eid))
    padding_mask = maxindex + 1 + maxname + 3 + maxvalue + 3 + maxvalue + (maxbname + 2 if maxbname else 0)
    padding_enum = maxindex + 1 + maxname + 3 + maxvalue

    # Now that we've figured out our header, format it and then join it together with
    # each item belonging to the enumeration/bitfield.
    header = "{:<{padding}s}{:s}".format(description, u" // {:s}".format(cmt) if cmt else u'', padding=padding_mask if bitfield(eid) else padding_enum)
    return u'\n'.join(itertools.chain([header], iterable))

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_name, utils.string.of)
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_name, utils.string.of)
__matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), idaapi.get_enum_name, utils.string.of)
__matcher__.boolean('bitfield', operator.eq, bitfield)
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
@document.parameters(type='any keyword that can be used to filter enumerations with')
def iterate(**type):
    '''Iterate through all of the enumerations in the database that match the keyword specified by `type`.'''
    if not type: type = {'predicate': lambda item: True}
    listable = [item for item in __iterate__()]
    for key, value in type.items():
        listable = [item for item in __matcher__.match(key, value, listable)]
    for item in listable: yield item

@utils.multicase(string=six.string_types)
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
    res = [item for item in iterate(**type)]

    maxindex = max(builtins.map(idaapi.get_enum_idx, res) if res else [1])
    maxname = max(builtins.map(utils.fcompose(idaapi.get_enum_name, len), res) if res else [0])
    maxsize = max(builtins.map(size, res) if res else [0])
    cindex = utils.string.digits(maxindex, 10)
    try: cmask = max(len("{:x}".format(mask(item))) for item in res) if res else database.config.bits() / 4.0
    except Exception: cmask = 0
    has_bitfield = any(map(bitfield, res)) if res else False

    for item in res:
        name, bitfieldQ = idaapi.get_enum_name(item), bitfield(item)
        if bitfieldQ:
            six.print_(u"{:<{:d}s} {:>{:d}s} & {:<#{:d}x} ({:d} members){:s}".format("[{:d}]".format(idaapi.get_enum_idx(item)), 2 + math.trunc(cindex), utils.string.of(name), maxname, mask(item), 2 + math.trunc(cmask), len(builtins.list(members(item))), u" // {:s}".format(comment(item)) if comment(item) else u''))
        else:
            six.print_(u"{:<{:d}s} {:>{:d}s}{:s} ({:d} members){:s}".format("[{:d}]".format(idaapi.get_enum_idx(item)), 2 + math.trunc(cindex), utils.string.of(name), maxname, ' '*(3 + 2 + math.trunc(cmask)) if has_bitfield else u'', len(builtins.list(members(item))), u" // {:s}".format(comment(item)) if comment(item) else u''))
        continue
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
        """Yield the name, and value of each member from the enumeration `enum`.

        If the enumeration `enum` is a bitfield, then yield each member's name, value, and bitmask.
        """
        eid = by(enum)
        for mid in cls.iterate(eid):

            # If this enumeration is a bitfield, then we need to yield the name,
            # value, and bitmask for each member that's being returned.
            if bitfield(eid):
                yield member.name(mid), member.value(mid), member.mask(mid)

            # If it's just a regular enumeration, then we can just return the name and value.
            else:
                yield member.name(mid), member.value(mid)
            continue
        return

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration to use', name='the name of the enumeration member to check')
    def has(cls, enum, name):
        '''Return whether the enumeration `enum` contains a member with the specified `name`.'''
        eid = by(enum)
        try:
            cls.by_name(eid, name)
        except E.MemberNotFoundError:
            return False
        return True
    @utils.multicase(value=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration to use', value='the value of the enumeration member to check', bitmask='if ``bitmask`` is specified as an integer, then check the value within the specified bitmask')
    def has(cls, enum, value, **bitmask):
        """Return whether the enumeration `enum` contains a member with the specified `value`.

        If an integral is provided for `bitmask` or `serial`, then only return true if the member is within the specified bitmask, or uses the provided serial.
        """
        eid = by(enum)
        iterable = (mid for mid in cls.iterate(eid))
        iterable = ((member.value(mid), member.mask(mid), member.serial(mid)) for mid in iterable)
        for item, mask, cid in iterable:
            if (item, mask) == (value, bitmask.get('bitmask', idaapi.DEFMASK)):
                if bitmask['serial'] == cid if 'serial' in bitmask else True:
                    return True
                continue
            continue
        return False

    ## scope
    @document.aliases('member.new', 'member.create')
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration to add a member to', name='the name of the enumeration member', value='the value of the enumeration member', bitmask='if ``bitmask`` is specified as an integer, then use it as the bitmask for the enumeration')
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member `name` with the specified `value` to the enumeration `enum`.

        If the integral, `bitmask`, is specified then use it as the bitmask for the enumeration.
        """
        eid = by(enum)
        bmask = bitmask.get('bitmask', idaapi.DEFMASK)

        fullname = interface.tuplename(name) if isinstance(name, tuple) else name
        string = utils.string.to(fullname)
        ok = idaapi.add_enum_member(eid, string, value, bmask)

        err = {getattr(idaapi, item) : item for item in ['ENUM_MEMBER_ERROR_NAME', 'ENUM_MEMBER_ERROR_VALUE', 'ENUM_MEMBER_ERROR_ENUM', 'ENUM_MEMBER_ERROR_MASK', 'ENUM_MEMBER_ERROR_ILLV']}
        if ok in err.keys():
            raise E.DisassemblerError(u"{:s}.add({!r}, {!s}, {:#x}{:s}) : Unable to add a member to the enumeration ({:#x}) with the specified name ({!s}) and value ({:#x}) due to error {:s}({:d}).".format('.'.join([__name__, cls.__name__]), enum, utils.string.repr(name), value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', eid, utils.string.repr(fullname), value, err[ok], ok))
        return eid
    new = create = utils.alias(add, 'members')

    @classmethod
    @utils.multicase(mid=six.integer_types)
    def remove(cls, mid):
        '''Remove the member identified by `mid` from the enumeration that owns it.'''
        eid = member.parent(mid)
        return member.remove(mid)
    @classmethod
    @utils.multicase()
    @document.parameters(enum='the enumeration containing the member to remove', member='the identifier or index of an enumeration member to remove')
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
    @document.parameters(enum='the enumeration to return the names for')
    def names(cls, enum):
        '''Return a set of all the names belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.name(mid) for mid in cls.iterate(eid) }

    @classmethod
    @document.parameters(enum='the enumeration to return the values of')
    def values(cls, enum):
        """Return a set of all the values belonging to the enumeration `enum`.

        If the enumeration is a bitfield, then each item in the result is the value and its bitmask.
        """
        eid = by(enum)
        if bitfield(eid):
            return { (member.value(mid), member.mask(mid)) for mid in cls.iterate(eid) }
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
        try:
            res = next(mid for i, mid in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration:
            raise E.MemberNotFoundError(u"{:s}.by_index({!r}, {:d}) : Unable to locate the member at index {:d} of the specified enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, index, index, eid))
        return res

    @classmethod
    @document.parameters(enum='the enumeration to return a member for', mid='the identifier of the enumeration member to return')
    def by_identifier(cls, enum, mid):
        '''Return the member of the enumeration specified by `enum` and its `mid`.'''
        eid = by(enum)
        if member.parent(mid) != eid:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({!r}, {:#x}) : Unable to locate a member in the enumeration ({:#x}) with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, mid, eid, mid))
        return mid

    @document.aliases('member.byvalue')
    @classmethod
    @document.parameters(enum='the enumeration to return a member for', value='the value of the enumeration member to return', filters='the filters to use when choosing the enumeration member')
    def by_value(cls, enum, value, **filters):
        """Return the member identifier for the member of the enumeration `enum` with the specified `value`.

        If the integrals, `bitmask` or `serial`, is specified then use them to filter the returned enumeration members.
        """
        eid  = by(enum)
        bitfieldQ = bitfield(eid)

        # First we need to figure out if this is a bitfield, because if
        # it is..then we need to figure out the masks to filter by.
        if bitfieldQ:
            results = [item for _, item in masks(eid)]

        # Otherwise, there's only one mask to search through, the DEFMASK.
        else:
            results = [idaapi.DEFMASK]

        # Now that we have all the masks, we need to figure out all of the
        # serial numbers for the desired value throughout all our masks.
        available = []
        for mask in results:

            # We start by getting the first serial number for the value
            # and mask. If we get a BADNODE, then we know it's not in this
            # mask and can skip to the next one.
            first = item, cid = mid, _ = idaapi.get_first_serial_enum_member(eid, value, mask)
            if item == idaapi.BADNODE:
                continue
            available.append((item, mask, cid))

            # Now we can get the id and serial number for the last value
            # and mask. If it matches to the first, then we can add it to
            # our results and proceed to the next mask continuing our search.
            last = idaapi.get_last_serial_enum_member(eid, value, mask)
            if first == last:
                continue

            # Otherwise, we need continue through all of the serials for
            # the value and add every single one of them before continuing.
            while [item, cid] != idaapi.get_last_serial_enum_member(eid, value, mask):
                item, cid = idaapi.get_next_serial_enum_member(mid, cid) if idaapi.__version__ < 7.0 else idaapi.get_next_serial_enum_member(cid, mid)
                if item == idaapi.BADNODE:
                    break
                available.append((item, mask, cid))
            continue

        # We should now have a list of all possible values in our results,
        # and we need to figure out whether we need to filter them. If it's
        # a bitfield, then we need to filter them according to the mask the
        # user has given us. If they haven't given us one, then we'll still
        # just process what we have because we might've actually found it.
        bitmask = filters.get('bitmask', idaapi.DEFMASK)
        if bitfieldQ and 'bitmask' in filters:
            filtered = [(item, mask, cid) for item, mask, cid in available if mask in {bitmask}]

        # Otherwise we just take everything from the matched so that way we
        # can do filter for the serial if the caller gave it to us.
        else:
            filtered = [(item, mask, cid) for item, mask, cid in available]

        # Next we need to check to see if the user gave us a serial to filter
        # our results. So we check our parameters, and then gather our results.
        serial = filters.get('serial', 0)
        if 'serial' in filters:
            results = [(item, mask, cid) for item, mask, cid in filtered if cid in {serial}]

        # Otherwise we now have our results ready to return to the caller.
        else:
            results = filtered[:]

        # If our results are empty, then we were unable to find what the user
        # was looking for and thus we need to let them know what's up.
        if not results:
            raise E.MemberNotFoundError(u"{:s}.by_value({!r}, {:#x}{:s}) : Unable to locate a member in the enumeration ({:#x}) with the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))

        # If we found more than one result, then we need to grab all the fields
        # that we plan on emitting so that we can just let the user know what
        # was found when raising our exception.
        elif len(results) > 1:
            iterable = ((mid, mask, cid, utils.string.of(idaapi.get_bmask_name(eid, mask)) or u'', utils.string.of(idaapi.get_enum_member_name(mid)) or u'') for mid, mask, cid in results)
            spec = u"[{serial:d}] {name!s} {value:#0{:d}x} & {mask:s}".format if bitfieldQ else u"[{serial:d}] {name!s} {value:#0{:d}x}".format
            formatter = utils.fpartial(spec, 2 + 2 * size(eid))
            messages = (formatter(serial=cid, name=name, mask=u"{:s}({:#0{:d}x})".format(maskname, mask, 2 + 2 * size(eid)) if maskname else u"{:#0{:d}x}".format(mask, 2 + 2 * size(eid)), value=idaapi.get_enum_member_value(mid)) for mid, mask, cid, maskname, name in iterable)
            logging.fatal(u"{:s}.by_value({!r}, {:#x}{:s}) : Multiple members with varying bitmask or serial were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))
            [ logging.warning(msg) for msg in messages ]
            if bitfieldQ:
                raise E.MemberNotFoundError(u"{:s}.by_value({!r}, {:#x}{:s}) : Multiple members with varying bitmask or serial were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))
            raise E.MemberNotFoundError(u"{:s}.by_value({!r}, {:#x}{:s}) : Multiple members with different serial numbers were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))

        # Otherwise there was only one item found, so we just need to unpack it.
        res, = results
        mid, _, _ = res
        return mid
    byvalue = utils.alias(by_value, 'members')

    @document.aliases('member.byname')
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
        raise E.MemberNotFoundError(u"{:s}.by_name({!r}, {!s}) : Unable to locate a member in the enumeration ({:#x}) with the specified name ({!s}).".format('.'.join([__name__, cls.__name__]), enum, utils.string.repr(name), eid, utils.string.repr(name)))
    byname = utils.alias(by_name, 'members')

    @utils.multicase(n=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration to return a member for', n='an index or an identifier of the enumeration to return')
    def by(cls, enum, n):
        '''Return the member belonging to `enum` identified by its index or id in `n`.'''
        return cls.by_identifier(enum, n) if interface.node.is_identifier(n) else cls.by_index(enum, n)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration to return a member for', name='the name of the member to return')
    def by(cls, enum, name):
        '''Return the member of the enumeration `enum` with the given `name`.'''
        return cls.by_name(enum, name)

    # FIXME: Implement a matcher class for enumeration members that can be used with .iterate and .list below.
    __member_matcher = utils.matcher()

    @classmethod
    @document.parameters(eid='the identifier of an enumeration')
    def __iterate__(cls, eid):
        '''Iterate through all the members of the enumeration identified by `eid` and yield their values.'''

        # First we need to define a closure that iterates through all of the
        # values for the masks inside an enumeration. This is because IDA
        # gives us values, and we need to conver these values to identifiers.
        def values(eid, bitmask):

            # We start with the first enumeration member (or value), and
            # then yield it if there was no error while fetching it. If
            # there was, then we just continue onto the next mask.
            value = idaapi.get_first_enum_member(eid, bitmask)
            if value == idaapi.BADADDR:
                return
            yield value

            # Continue fetching and yielding values until we get to the
            # very last one of the enumeration.
            while value != idaapi.get_last_enum_member(eid, bitmask):
                value = idaapi.get_next_enum_member(eid, value, bitmask)
                yield value
            return

        # Now we need to iterate through all of the masks, feeding them
        # to our "values" closure. Then with the values we can iterate
        # through all of the serials, and use that to get each identifier.
        for bitmask in masks.iterate(eid):
            for value in values(eid, bitmask):

                # Start out with the first serial for the member. We compare
                # this against idaapi.BADNODE in order to determine if there
                # was nothing found and we need to continue to the next value.
                item, cid = mid, _ = idaapi.get_first_serial_enum_member(eid, value, bitmask)
                if item == idaapi.BADNODE:
                    continue
                yield mid

                # Now we should be able to loop until we get to the last serial
                # number while yielding each valid identifier that we receive.
                while [item, cid] != idaapi.get_last_serial_enum_member(eid, value, bitmask):
                    item, cid = idaapi.get_next_serial_enum_member(mid, cid) if idaapi.__version__ < 7.0 else idaapi.get_next_serial_enum_member(cid, mid)
                    if item == idaapi.BADNODE:
                        break
                    yield item
                continue
            continue
        return

    @classmethod
    @document.parameters(enum='the enumeration containing the members to iterate through')
    def iterate(cls, enum):
        '''Iterate through all ids of each member associated with the enumeration `enum`.'''
        eid = by(enum)
        for item in cls.__iterate__(eid):
            yield item
        return

    @classmethod
    @document.parameters(enum='the enumeration containing the members to list')
    def list(cls, enum):
        '''List all the members belonging to the enumeration identified by `enum`.'''
        # FIXME: make this consistent with every other .list using the matcher class
        eid = by(enum)
        listable = [item for item in cls.iterate(eid)]
        maxindex = max(len("[{:d}]".format(index)) for index, _ in enumerate(listable)) if listable else 1
        maxvalue = max(builtins.map(utils.fcompose(member.value, "{:#x}".format, len), listable) if listable else [1])
        maxname = max(builtins.map(utils.fcompose(member.name, len), listable) if listable else [0])
        maxbname = max([len(utils.string.of(idaapi.get_bmask_name(eid, mask)) if idaapi.get_bmask_name(eid, mask) else u'') for mask in builtins.map(member.mask, listable)] if listable else [0])
        masksize = 2 * size(eid)

        # If this enumeration is a bitfield, then we need to consider the mask of
        # each enumeration member when writing them to the output.
        if bitfield(eid):
            for i, mid in enumerate(listable):
                bname = utils.string.of(idaapi.get_bmask_name(eid, member.mask(mid))) or u''
                cmt = member.comment(eid, mid, repeatable=True) or member.comment(eid, mid, repeatable=False)
                six.print_(u"{:<{:d}s} {:<{:d}s} {:#0{:d}x} & {:s}".format("[{:d}]".format(i), maxindex, member.name(mid), maxname, member.value(mid), maxvalue, u"{:s}({:#0{:d}x})".format(bname, member.mask(mid), 2 + masksize) if bname else "{:#0{:d}x}".format(member.mask(mid), 2 + masksize)) + (u" // {:s}".format(cmt) if cmt else u''))
            return

        # Otherwise this isn't a bitfield, and we don't need to worry about the mask.
        for i, mid in enumerate(listable):
            cmt = member.comment(eid, mid, repeatable=True) or member.comment(eid, mid, repeatable=False)
            six.print_(u"{:<{:d}s} {:<{:d}s} {:#0{:d}x}".format("[{:d}]".format(i), maxindex, member.name(mid), maxname, member.value(mid), maxvalue) + (u" // {:s}".format(cmt) if cmt else u''))
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
    @document.aliases('member.owner')
    @classmethod
    @document.parameters(mid='the identifier of the member to return the enumeration for')
    def parent(cls, mid):
        '''Return the id of the enumeration that owns the member `mid`.'''
        CONST_ENUM = -2
        return idaapi.get_enum_member_enum(mid)
    owner = utils.alias(parent, 'member')

    @classmethod
    @document.parameters(mid='the identifier of the member to return')
    def by(cls, mid):
        '''Return the enumeration member as specified by the provided `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.by({!s}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        eid = cls.parent(mid)
        return members.by_identifier(eid, mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of the member to remove')
    def remove(cls, mid):
        '''Remove the enumeration member with the given `mid`.'''
        eid, value, serial, mask = cls.parent(mid), cls.value(mid), cls.serial(mid), cls.mask(mid)
        ok = idaapi.del_enum_member(eid, value, serial, mask)
        if not ok:
            raise E.DisassemblerError(u"{:s}.remove({:#x}) : Unable to remove the specified member ({:#x}) having the value {:d} from the enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid, value, eid))
        return ok
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
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.name({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
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
    @utils.multicase(mid=six.integer_types, name=(six.string_types, tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(mid='the identifier of an enumeration member', name='the name to rename the enumeration member to')
    def name(cls, mid, name):
        '''Rename the enumeration member `mid` to `name`.'''
        fullname = interface.tuplename(*name) if isinstance(name, tuple) else name
        string = utils.string.to(fullname)
        res, ok = idaapi.get_enum_member_name(mid), idaapi.set_enum_member_name(mid, string)
        if not ok:
            raise E.DisassemblerError(u"{:s}.name({:#x}, {!s}) : Unable to set the name for the specified member ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(name), mid, utils.string.repr(fullname)))
        return utils.string.of(res)
    @document.aliases('member.rename')
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    @document.parameters(enum='the enumeration containing the member to rename', member='the member to rename', name='the name to rename the enumeration member to', suffix='any other names to append to the new name')
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration `member` belonging to `enum` to `name`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        fullname = (name,) + suffix
        return cls.name(mid, fullname)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the comment for', repeatable='whether the returned comment should be repeatable or not')
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
    @document.parameters(enum='the enumeration containing the member to return the comment for', member='the member to return the comment for', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=six.integer_types, comment=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('comment')
    @document.parameters(mid='the identifier of an enumeration containing the member to set the comment for', comment='the comment to apply', repeatable='whether the returned comment should be repeatable or not')
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
    @document.parameters(enum='the enumeration containing the member to set the comment for', member='the member to set the comment for', comment='the comment to apply', repeatable='whether the returned comment should be repeatable or not')
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration `member` belonging to `enum` to the string `comment`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, comment, **repeatable)
    @utils.multicase(none=None.__class__)
    @classmethod
    def comment(cls, enum, member, none, **repeatable):
        '''Remove the comment from the `member` belonging to the enumeration `enum`.'''
        return cls.comment(enum, member, none or u'', **repeatable)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the value of')
    def value(cls, mid):
        '''Return the value of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
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
    @document.parameters(mid='the identifier of the member to set the value of', value='the value to set the member to')
    def value(cls, mid, value):
        '''Assign the integer specified by `value` to the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}, {:#x}{:s}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', mid))
        eid = cls.parent(mid)

        # Figure out the actual altval index that contains the value we want to modify
        CONST_VALUE, CONST_BMASK = -3, -6
        altidx_value, altidx_bmask = (idaapi.as_signed(item, utils.string.digits(idaapi.BADADDR, 2)) & idaapi.BADADDR for item in [CONST_VALUE, CONST_BMASK])

        # Fetch the mask for the enumeration, and then for the actual member. We don't
        # actually let the user modify the bitmask because it seems that IDA's bmask
        # enumeration api doesn't work in the same way when an enumeration member's
        # CONST_BMASK altval is modified.
        emask, bmask = pow(2, size(eid) * 8) - 1 if size(eid) else idaapi.DEFMASK, internal.netnode.alt.get(mid, altidx_bmask) - 1 if internal.netnode.alt.has(mid, altidx_bmask) else idaapi.DEFMASK
        altval_value = emask & value & bmask

        # Now we can grab the previous value, and then assign the new one. After the
        # assignment, we can then just return our result and be good to go.
        res, ok = idaapi.get_enum_member_value(mid), internal.netnode.alt.set(mid, altidx_value, altval_value)
        if not ok:
            raise E.DisassemblerError(u"{:s}.value({:#x}, {:#x}{:s}) : Unable to set the value for the specified member ({:#x}) to {:#x}{:s}.".format('.'.join([__name__, cls.__name__]), mid, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', mid, value, u" & {:#x}".format(bmask) if bmask else u''))
        return res
    @utils.multicase(value=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration containing the member to set the value for', member='the member to set the value of', value='the value to apply', bitmask='if ``bitmask`` is specified as an integer, then use it as the bitmask to assign to the value')
    def value(cls, enum, member, value, **bitmask):
        '''Set the `value` for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid, value)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    @document.parameters(mid='the identifier of an enumeration member to return the serial for')
    def serial(cls, mid):
        '''Return the serial of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.serial({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        CONST_SERIAL = -7
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
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.mask({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        CONST_BMASK = -6
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration containing the member to return the bitmask for', member='the member to return the bitmask for')
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.mask(mid)

    @utils.multicase()
    @classmethod
    @document.parameters(mid='the enumeration member identifier to return references for')
    def refs(cls, mid):
        '''Return the `(address, opnum, type)` of all the instructions that reference the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.mask({:#x}) : Unable to locate a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        eid = cls.parent(mid)

        # Assign some constants that we'll use for verifying the references
        # available for each operand.
        NALT_ENUM0, NALT_ENUM1 = (getattr(idaapi, name, 0xb + idx) for idx, name in enumerate(['NALT_ENUM0', 'NALT_ENUM1']))
        Fnetnode, Fidentifier = (getattr(idaapi, api, utils.fidentity) for api in ['ea2node', 'node2ea'])

        # Check if there's an xref that points to the enumeration member
        # identifier. If there isn't one, then we return an empty list.
        X = idaapi.xrefblk_t()
        if not X.first_to(mid, idaapi.XREF_ALL):
            fullname = '.'.join([name(eid), cls.name(mid)])
            logging.warning(u"{:s}.refs({:#x}) : No references found to enumeration member {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, fullname, mid))
            return []

        # As we were able to find at least one, iterate through any others
        # that we found whilst gathering the 3 attributes that we care about.
        refs = [(X.frm, X.iscode, X.type)]
        while X.next_to():
            refs.append((X.frm, X.iscode, X.type))

        # Now that we have a list of xrefs, we need to convert each element
        # into an internal.opref_t. We do this by figuring out which operand
        # the member is in for each address. We double-verify that the member
        # from the operand actually belongs to the enumeration.
        res = []
        for ea, _, t in refs:
            ops = ((opnum, internal.netnode.alt.get(Fnetnode(ea), altidx)) for opnum, altidx in enumerate([NALT_ENUM0, NALT_ENUM1]) if internal.netnode.alt.has(Fnetnode(ea), altidx))
            ops = (opnum for opnum, mid in ops if cls.parent(Fidentifier(mid)) == eid)
            res.extend(interface.opref_t(ea, int(opnum), interface.reftype_t.of(t)) for opnum in ops)
        return res

    @utils.multicase()
    @classmethod
    @document.parameters(enum='the enumeration to use', member='the member name or identifier to return references for')
    def refs(cls, enum, member):
        '''Returns the `(address, opnum, type)` of all the instructions that reference the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.refs(mid)

@document.namespace
class masks(object):
    """
    This namespace allows one to interact with a masks that are within
    an enumeration with its "bitfield" flag set. This is a very basic
    namespace that provides some minor utilities to deal with the
    naming of the bitmasks in an enumeration.

    Some examples of how to use this namespace can be::

        > values = enum.masks('example_enumeration')
        > ok = enum.masks.has(eid, 'mask_name')
        > mask = enum.masks.by(eid, 'mask_name')
        > mask = enum.masks.by(eid, 0x1234)

    """
    @document.parameters(enum='the enumeration to return the masks of')
    def __new__(cls, enum):
        '''Iterate through all of the masks belonging to the enumeration `enum` and yield their name and value.'''
        eid = by(enum)
        for mask in cls.iterate(eid):
            yield cls.name(eid, mask), mask
        return

    @classmethod
    @document.parameters(enum='the enumeration to check the masks of', mask='the bitmask to confirm')
    def has(cls, enum, mask):
        '''Return whether the enumeration `enum` uses the specified `mask`.'''
        eid = by(enum)
        return any(item == mask for item in cls.iterate(eid))

    @classmethod
    @document.parameters(eid='the identifier of an enumeration to iterate through the masks of')
    def __iterate__(cls, eid):
        '''Iterate through all of the masks available in the enumeration identified by `eid` and yield their values.'''
        bmask = idaapi.get_first_bmask(eid)
        yield idaapi.DEFMASK if bmask == idaapi.BADADDR else bmask

        # Now we can continue fetching and yielding the masks until
        # we get to an idaapi.BADADDR. That way we'll know we're done.
        while bmask != idaapi.get_last_bmask(eid):
            bmask = idaapi.get_next_bmask(eid, bmask)
            yield bmask
        return

    @classmethod
    @document.parameters(enum='the enumeration to iterate through through the masks of')
    def iterate(cls, enum):
        '''Iterate through all of the masks belonging to the enumeration `enum`.'''
        eid = by(enum)
        for item in cls.__iterate__(eid):
            yield item
        return

    @utils.multicase(mask=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration containing the mask to fetch', mask='the mask to return the name of')
    def name(cls, enum, mask):
        '''Return the name for the given `mask` belonging to the enumeration `enum`.'''
        eid = by(enum)
        res = idaapi.get_bmask_name(eid, mask)
        return utils.string.of(res) or ''
    @utils.multicase(mask=six.integer_types, name=(six.string_types, tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    @document.parameters(enum='the enumeration containing the mask to rename', mask='the mask to set the name of', name='the name to use when renaming the mask')
    def name(cls, enum, mask, name):
        '''Set the name for the `mask` belonging to the enumeration `enum` to the provided `name`.'''
        eid = by(enum)
        fullname = interface.tuplename(*name) if isinstance(name, tuple) else name
        string = utils.string.to(fullname)
        res, ok = idaapi.get_bmask_name(eid, mask), idaapi.set_bmask_name(eid, mask, string)
        if not ok:
            raise E.DisassemblerError(u"{:s}.name({!r}, {:#x}, {!s}) : Unable to rename the mask ({:#x}) for the specified enumeration ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), enum, mask, utils.string.repr(name), 2 + 2 * size(eid), eid, utils.string.repr(fullname)))
        return utils.string.of(res)
    @utils.multicase(mask=six.integer_types, name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    @document.parameters(enum='the enumeration containing the mask to rename', mask='the mask to set the name of', name='the name to use when renaming the mask', suffix='any other strings to append to the name')
    def name(cls, enum, mask, name, *suffix):
        '''Set the name for the `mask` belonging to the enumeration `enum` to the provided `name`.'''
        eid = by(enum)
        fullname = (name,) + suffix
        return cls.name(eid, mask, fullname)

    @utils.multicase(mask=six.integer_types)
    @classmethod
    @document.parameters(enum='the enumeration to fetch a mask comment from', mask='the mask to fetch the comment from', repeatable='whether to return the repeatable comment or not')
    def comment(cls, enum, mask, **repeatable):
        """Return the comment for the `mask` belonging to the enumeration `enum`.

        If the bool `repeatable` is specified, then return the repeatable comment.
        """
        eid = by(enum)
        res = idaapi.get_bmask_cmt(eid, mask, repeatable.get('repeatable', True))
        return utils.string.of(res)
    @utils.multicase(mask=six.integer_types, comment=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('comment')
    @document.parameters(enum='the enumeration containing the mask to set the comment for', mask='the mask to set the comment of', comment='the comment to assign to the mask', repeatable='whether to set the repeatable comment or not')
    def comment(cls, enum, mask, comment, **repeatable):
        """Set the comment for the `mask` belonging to the enumeration `enum` to `comment`.

        If the bool `repeatable` is specified, then set the repeatable comment.
        """
        eid = by(enum)
        string = utils.string.to(comment)
        res, ok = idaapi.get_bmask_cmt(eid, mask, repeatable.get('repeatable', True)), idaapi.set_bmask_cmt(eid, mask, string, repeatable.get('repeatable', True))
        if not ok:
            adjective = (u'repeatable' if repeatable.get('repeatable', True) else u'non-repeatable') if repeatable else u''
            raise E.DisassemblerError(u"{:s}.comment({!r}, {:#x}, {!s}, {:s}) : Unable to set the {:s}comment for the specified mask ({:#0{:d}x}) from the enumeration ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), enum, mask, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', u" {:s}".format(adjective) if adjective else u'', mask, 2 + 2 * size(eid), eid, utils.string.repr(comment)))
        return utils.string.of(res)
    @utils.multicase(mask=six.integer_types, none=None.__class__)
    @classmethod
    @document.parameters(enum='the enumeration containing the mask to clear the comment of', mask='the mask to clear the comment of', none='the python value `None`', repeatable='whether to clear the repeatable comment or not')
    def comment(cls, enum, mask, none, **repeatable):
        '''Remove the comment for the `mask` belonging to the enumeration `enum`.'''
        return cls.comment(enum, mask, none or u'', **repeatable)

    @classmethod
    @document.parameters(enum='the enumeration containing the masks to list')
    def list(cls, enum):
        '''List all the masks belonging to the enumeration identified by `enum`.'''
        eid = by(enum)
        listable = [item for item in cls.iterate(eid)]

        maxindex = max(len("[{:d}]".format(index)) for index, _ in enumerate(listable)) if listable else 1
        maxname = max(len(cls.name(eid, mask)) for mask in listable) if listable else 0
        maxmask = max(listable) if listable else 1
        masksize = 2 * size(eid) if size(eid) else utils.string.digits(maxmask, 16)

        for i, mask in enumerate(listable):
            padding = 3 + maxname
            cmt = cls.comment(eid, mask, repeatable=True) or cls.comment(eid, mask, repeatable=False)
            item = u"{:<{:d}s} {:#0{:d}x}{:s}".format("[{:d}]".format(i), maxindex, mask, 2 + masksize, " : {:<{:d}s}".format(cls.name(eid, mask), maxname) if idaapi.get_bmask_name(eid, mask) else ' ' * padding)
            six.print_(item + (u" // {:s}".format(cmt) if cmt else u''))
        return
