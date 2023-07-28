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

    `name` - Filter the enumerations by a name or a list of names
    `like` - Filter the enumeration names according to a glob
    `regex` - Filter the enumeration names according to a regular-expression
    `index` - Match the enumeration by its index
    `identifier` or `id` - Filter the enumerations by an identifier or a list of identifers
    `predicate` - Filter the enumerations by passing their identifier to a callable

"""

import functools, operator, itertools, logging, six
import builtins, math, fnmatch, re

import database
import idaapi, internal
from internal import utils, interface, types, exceptions as E

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

@utils.multicase(enum=types.integer)
def has(enum):
    '''Return truth if an enumeration with the identifier `enum` exists within the database.'''
    ENUM_QTY_IDX, ENUM_FLG_IDX, ENUM_FLAGS, ENUM_ORDINAL = -1, -3, -5, -8
    return interface.node.is_identifier(enum) and idaapi.get_enum_idx(enum) != idaapi.BADADDR
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def has(name, *suffix):
    '''Return truth if an enumeration with the specified `name` exists within the database.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    return idaapi.get_enum(utils.string.to(string)) != idaapi.BADADDR

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def flags(enum):
    '''Return the flags for the enumeration identified by `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_flag(eid)
@utils.multicase(enum=(types.integer, types.string, types.tuple), flags=types.integer)
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

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def index(enum):
    '''Return the index in the enumeration list for the enumeration identified by `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_idx(eid)
@utils.multicase(enum=(types.integer, types.string, types.tuple), index=types.integer)
def index(enum, index):
    '''Set the position in the enumeration list for the enumeration `enum` to the specified `index`.'''
    eid = by(enum)
    res, ok = idaapi.get_enum_idx(eid), idaapi.set_enum_idx(eid, index)
    if not ok:
        raise E.DisassemblerError(u"{:s}.index({!r}, {:d}) : Unable to set the index for the specified enumeration ({:#x}) to {:#x}.".format(__name__, enum, index, eid, index))
    return res

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def by_name(name, *suffix):
    '''Return the identifier for the enumeration with the given `name`.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    res = idaapi.get_enum(utils.string.to(string))
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_name({!r}) : Unable to find an enumeration with the specified name ({!s}).".format(__name__, res if suffix else string, utils.string.repr(string)))
    return res
byname = utils.alias(by_name)

@utils.multicase(index=types.integer)
def by_index(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.by_index({:#x}) : Unable to find an enumeration at the specified index ({:d}).".format(__name__, index, index))
    return res
byindex = utils.alias(by_index)

@utils.multicase(eid=types.integer)
def by_identifier(eid):
    '''Return the identifier for the enumeration using the specified `eid`.'''
    if interface.node.is_identifier(eid) and idaapi.get_enum_idx(eid) != idaapi.BADADDR:
        return eid
    raise E.EnumerationNotFoundError(u"{:s}.by_identifier({:#x}) : Unable to find an enumeration with the specified identifier ({:#x}).".format(__name__, eid, eid))
byidentifier = utils.alias(by_identifier)

@utils.multicase(index=types.integer)
def by(index):
    '''Return the identifier for the enumeration at the specified `index`.'''
    return by_identifier(index) if interface.node.is_identifier(index) else by_index(index)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def by(name, *suffix):
    '''Return the identifier for the enumeration with the specified `name`.'''
    return by_name(name, *suffix)
@utils.multicase(fullname=types.tuple)
def by(fullname):
    '''Return the identifier for the enumeration with the packed `fullname`.'''
    return by_name(*fullname)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
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

@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string')
def search(string, *suffix):
    '''Return the identifier of the first enumeration that matches the glob `string`.'''
    res = (string,) + suffix
    return by(like=interface.tuplename(*res))
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def search(**type):
    '''Return the identifier of the first enumeration that matches the keyword specified by `type`.'''
    return by(**type)

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def names(enum):
    '''Return a set of all of the names belonging to the enumeration `enum`.'''
    return {item for item in members.names(enum)}
keys = utils.alias(names)

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def values(enum):
    '''Return a set of all of the values belonging to the enumeration `enum`.'''
    return {item for item in members.values(enum)}

## creation/deletion
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def new(name, *suffix, **bitfield):
    """Create an enumeration or `bitfield` within the database with the specified `name`.

    If the bool `bitfield` is true, then create a bitfield that supports bitmasks.
    If the integers `width` or `bits` is specified, then set the size of the created enumeration in either `bytes` or `bits`.
    """
    res = (name,) + suffix
    string = interface.tuplename(*res)

    # We take a bunch of keyword arguments, so check that they're a valid type.
    integers = ['width', 'bits', 'flags']
    if not all(isinstance(bitfield.get(kwarg, 0), types.integer) for kwarg in integers):
        invalid = next(kwarg for kwarg in integers if not isinstance(bitfield.get(kwarg, 0), types.integer))
        raise E.InvalidParameterError(u"{:s}.new({!r}{:s}) : Unable to create an enumeration with {:s} that are not an integer.".format(__name__, string, ", {:s}".format(utils.string.kwargs(bitfield)) if bitfield else '', invalid))

    # Calculate the width because we're going to use it as our default flags.
    choice = bitfield['bits'] if 'bits' in bitfield else 8 * bitfield.get('width', bitfield.get('bytes', 0))
    bytes, remainder = divmod(choice, 8)
    if remainder:
        logging.warning(u"{:s}.new({!r}{:s}) : Enumeration width has been truncated from {:d} bit{:s} to {:d} bits ({:d} byte{:s}).".format(__name__, string, ", {:s}".format(utils.string.kwargs(bitfield)) if bitfield else '', choice, '' if choice == 1 else 's', 8 * bytes, bytes, '' if bytes == 1 else 's'))

    # Figure out which bitmask parameter we were given and pre-assign it so we know what to do.
    is_bitmask = next((bitfield[kwarg] for kwarg in ['bitfield', 'bitmask'] if kwarg in bitfield), False)

    # If we're using an older version of IDA, then we can just convert our parameters to
    # flags and then we can just call the api with whatever we were given.
    if idaapi.__version__ < 7.0:
        flags = [8 * bytes, bitfield.get('flags', 0), getattr(idaapi, 'ENUM_FLAGS_IS_BF', 1) if is_bitmask else 0]

    # Otherwise the flags represent something different and they're pretty much unused.
    else:
        flags = [bitfield.get('flags', 0), idaapi.FF_SIGN if bitfield.get('signed', False) else 0]

    # Now we can create our enumeration and return it if we're an older (younger?) version.
    eid = new(idaapi.get_enum_qty(), string, functools.reduce(operator.or_, flags, 0))
    if idaapi.__version__ < 7.0:
        return eid

    # If we're using the newer API, then we need to explicitly apply the flags to the enum.
    if is_bitmask and not idaapi.set_enum_bf(eid, True if is_bitmask else False):
        logging.warning(u"{:s}.new({!r}{:s}) : Unable to set the bitfield flag for the created enumeration ({:#x}) to {!s}.".format(__name__, string, ", {:s}".format(utils.string.kwargs(bitfield)) if bitfield else '', eid, True if is_bitmask else False))
    if bytes and not idaapi.set_enum_width(eid, bytes):
        logging.warning(u"{:s}.new({!r}{:s}) : Unable to set the width for the created enumeration ({:#x}) to {:d} byte{:s}.".format(__name__, string, ", {:s}".format(utils.string.kwargs(bitfield)) if bitfield else '', eid, width, '' if width == 1 else 's'))
    return eid
@utils.multicase(index=types.integer, name=(types.string, types.tuple), flags=types.integer)
@utils.string.decorate_arguments('name')
def new(index, name, flags):
    '''Create an enumeration at the specified `index` of the database with the given `name` and `flags`.'''
    idx, string = count(), interface.tuplename(*name) if isinstance(name, tuple) else name

    # On older versions of IDA, there were actual flags which described the width, display
    # type, if it was a bitfield, etc. Nowadays, though, it seems to be just the number
    # format and hence it seems completely irrelevant to expose this to someone.
    res = idaapi.add_enum(index, utils.string.to(name), flags)
    if res == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({:d}, {!r}, flags={:d}) : Unable to create an enumeration with the specified name ({!s}).".format(__name__, index, name, flags, utils.string.repr(string)))
    return res
add = create = utils.alias(new)

@utils.multicase(name=types.string)
def remove(name, *suffix):
    '''Remove the enumeration with the given `name` from the database.'''
    eid = by_name(name, *suffix)
    if idaapi.del_enum(eid) or has(eid):
        res = (name,) + suffix
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to remove the specified enumeration ({:#x}) from the database.".format(__name__, interface.tuplename(*res), eid))
    return eid
@utils.multicase(enum=(types.integer, types.string, types.tuple))
def remove(enum):
    '''Remove the enumeration specified by `enum` from the database.'''
    eid = by(enum)
    if idaapi.del_enum(eid) or has(eid):
        raise E.DisassemblerError(u"{:s}.remove({!s}) : Unable to remove the specified enumeration ({:#x}) from the database.".format(__name__, "{:#x}".format(enum) if isinstance(enum, types.integer) else "{!r}".format(enum), eid))
    return eid
delete = utils.alias(remove)

## setting enum options
@utils.multicase(enum=(types.integer, types.string, types.tuple))
def name(enum):
    '''Return the name of the enumeration `enum`.'''
    eid = by(enum)
    res = idaapi.get_enum_name(eid)
    return utils.string.of(res)
@utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def name(enum, name, *suffix):
    '''Rename the enumeration `enum` to the string `name`.'''
    packed = (name,) + suffix
    eid, string = by(enum), interface.tuplename(*packed)
    res, ok = idaapi.get_enum_name(eid), idaapi.set_enum_name(eid, utils.string.to(string))
    if not ok:
        raise E.DisassemblerError(u"{:s}.name({!r}, {!r}) : Unable to set the name for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, packed if suffix else string, eid, utils.string.repr(string)))
    return utils.string.of(res)

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def comment(enum, **repeatable):
    """Return the comment for the enumeration `enum`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    res = idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(enum=(types.integer, types.string, types.tuple), comment=types.string)
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
@utils.multicase(enum=(types.integer, types.string, types.tuple), none=types.none)
def comment(enum, none, **repeatable):
    '''Remove the comment from the enumeration `enum`.'''
    return comment(enum, none or u'', **repeatable)

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def size(enum):
    '''Return the number of bytes for the enumeration `enum`.'''
    eid = by(enum)
    return idaapi.get_enum_width(eid)
@utils.multicase(enum=(types.integer, types.string, types.tuple), width=types.integer)
def size(enum, width):
    '''Set the number of bytes for the enumeration `enum` to `width`.'''
    eid = by(enum)
    res, ok = idaapi.get_enum_width(eid), idaapi.set_enum_width(eid, width)
    if not ok:
        raise E.DisassemblerError(u"{:s}.size({!r}, {:#x}) : Unable to set the width for the specified enumeration ({:#x}) to {:d}.".format(__name__, enum, width, eid, width))
    return res

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def bits(enum):
    '''Return the number of bits for the enumeration `enum`.'''
    return 8 * size(enum)
@utils.multicase(enum=(types.integer, types.string, types.tuple), width=types.integer)
def bits(enum, width):
    '''Set the number of bits for the enumeration `enum` to `width`.'''
    res = math.trunc(math.ceil(width / 8.0))
    return size(enum, math.trunc(res))

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def mask(enum):
    '''Return the bitmask for the enumeration `enum`.'''
    eid = by(enum)
    res = bits(eid)
    return pow(2, res) - 1

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def bitfield(enum):
    '''Return whether the enumeration identified by `enum` is a bitfield or not.'''
    eid = by(enum)
    return idaapi.is_bf(eid)
@utils.multicase(enum=(types.integer, types.string, types.tuple), boolean=(types.integer, types.bool))
def bitfield(enum, boolean):
    '''Toggle the bitfield setting of the enumeration `enum` depending on the value of `boolean`.'''
    eid = by(enum)
    res, ok = idaapi.is_bf(eid), idaapi.set_enum_bf(eid, True if boolean else False)
    if not ok:
        raise E.DisassemblerError(u"{:s}.bitfield({!r}, {!s}) : Unable to set the bitfield flag for the specified enumeration ({:#x}) to {!s}.".format(__name__, enum, boolean, eid, boolean))
    return res
bitflag = utils.alias(bitfield)

@utils.multicase(enum=(types.integer, types.string, types.tuple))
def up(enum):
    '''Return all structure or frame members within the database that reference the specified `enum`.'''
    X, eid = idaapi.xrefblk_t(), by(enum)

    # IDA does not seem to create xrefs to enumeration identifiers.
    raise E.UnsupportedCapability(u"{:s}.up({:#x}) : Unable to find any cross-references for the specified enumeration due to the disassembler not keeping track of them.".format(__name__, eid))

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
            raise E.MemberNotFoundError(u"{:s}.up({:#x}) : Unable to find the member identified by {:#x}.".format(__name__, eid, ref))

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
            raise E.FunctionNotFoundError(u"{:s}.up({:#x}) : Unable to find the function for frame member {:#x} with address {:#x}.".format(__name__, eid, mptr.id, ea))

        # Now that we have everything we need, we use the structure
        # module and the idaapi.func_t we fetched to instantiate the
        # structure with the correct offset and then fetch the member
        # to aggregate to our list of results.
        st = structure.by_identifier(fr.id, offset=-idaapi.frame_off_args(f))
        mem = st.members.by_identifier(mptr.id)
        res.append(mem)
    return res

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def refs(name, *suffix):
    '''Return a list of the references to the enumeration with the specified `name`.'''
    eid = by_name(name, *suffix)
    return refs(eid)
@utils.multicase(enum=types.integer)
def refs(enum):
    '''Return a list of the references to the enumeration with the identifier `enum`.'''
    if not interface.node.is_identifier(enum) or idaapi.get_enum_idx(enum) == idaapi.BADADDR:
        raise E.EnumerationNotFoundError(u"{:s}.refs({:#x}) : Unable to find an enumeration with the specified identifier ({:#x}).".format(__name__, enum, enum))

    # Start out by collecting all of the members for the enumeration, and then
    # collect absolutely all of their references into a single list of xrefs.
    eid, mids = enum, {mid for mid in members.__iterate__(enum)}
    refs = [packed_frm_iscode_type for packed_frm_iscode_type in itertools.chain(*(interface.xref.to(mid, idaapi.XREF_DATA) for mid in mids))]
    if not refs:
        fullname = utils.string.of(idaapi.get_enum_name(eid))
        logging.warning(u"{:s}.refs({:#x}) : No references found for the {:d} member{:s} belonging to the enumeration \"{:s}\".".format(__name__, eid, len(mids), '' if len(mids) == 1 else 's', utils.string.escape(fullname, '"')))
        return []

    # Now we have all of the xrefs for the enumeration members. The only thing that
    # we really need to do is to figure out which operand number has the enumeration
    # applied to it, and then convert our results to a list of interface.opref_t.
    res = []
    for ea, xiscode, xrtype in refs:
        flags = interface.address.flags(ea)
        ops = [(opnum, interface.instruction.opinfo(ea, opnum)) for opnum, operand in enumerate(interface.instruction.operands(ea)) if idaapi.is_enum(flags, opnum)]
        ops = [opnum for opnum, info in ops if info and info.tid == eid]
        res.extend(interface.opref_t(ea, int(opnum), interface.access_t(xrtype, xiscode)) for opnum in ops)
    return res

@utils.multicase(enum=(types.integer, types.string, types.tuple))
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
__matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), idaapi.get_enum_name, utils.string.of, operator.methodcaller('lower'))
__matcher__.boolean('bitfield', operator.eq, idaapi.is_bf, operator.truth)
__matcher__.attribute('identifier'), __matcher__.alias('id', 'identifier')
__matcher__.predicate('predicate'), __matcher__.alias('pred', 'predicate')

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

@utils.multicase(string=types.string)
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
class members(object):
    """
    This namespace allows one to interact with the members belonging
    to an enumeration once the enumeration's id has been determined.
    This allows one to iterate through all of its members or add
    and remove values to the enumeration.

    By default this namespace will yield the names of all of the
    members of an enumeration.

    The different types that one can list members with are the following:

        `name` - Match the members by their name or a list of names
        `like` - Filter the member names according to a glob
        `regex` - Filter the member names according to a regular-expression
        `comment` - Filter the members with a comment or by applying a glob to its comment
        `repeatable` - Filter the members with a repeatable comment or by applying a glob
        `value` - Match members that have a specific value or a list of values
        `mask` - Match members within a specific bitmask
        `predicate` - Filter the members by passing their id (``idaapi.uval_t``) to a callable

    Some examples of using this namespace are::

        > eid = enum.by('example_enumeration')
        > mid = enum.members.add(eid, 'name', 0x1000)
        > mid = enum.members.remove(eid, mid)
        > mid = enum.members.by_name(eid, 'name')
        > mid = enum.members.by_value(eid, 0x1000)
        > for mid in enum.members.iterate(eid, like='*ERROR*'): ...
        > enum.members.list(eid, value=range(10))

    """

    @classmethod
    def __iterate__(cls, eid):
        '''Iterate through all the members of the enumeration identified by `eid` and yield their values.'''

        # First we need to define a closure that iterates through all of the
        # values for the masks inside an enumeration. This is because enumerations
        # are actually values, and we need to convert these values into identifiers.
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

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    def __new__(cls, enum, **type):
        '''Return a list of the identifiers for each member associated with the enumeration `enum`.'''
        eid = by(enum)
        return [mid for mid in cls.iterate(eid, **type)]

    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def has(cls, enum, name, *suffix):
        '''Return whether the enumeration `enum` contains a member with the specified `name`.'''
        eid = by(enum)
        try:
            cls.by_name(eid, name, *suffix)
        except E.MemberNotFoundError:
            return False
        return True
    @utils.multicase(enum=(types.integer, types.string, types.tuple), value=types.integer)
    @classmethod
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
    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=(types.string, types.tuple), value=types.integer)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, enum, name, value, **bitmask):
        """Add a member `name` to the enumeration `enum` with the specified `value`.

        If the integral, `bitmask`, is specified then use it as the bitmask for the enumeration.
        """
        bmask = bitmask.get('mask', bitmask.get('bitmask', idaapi.DEFMASK))
        return cls.add(enum, name, value, bmask)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), fullname=types.tuple, value=types.integer, mask=types.integer)
    @classmethod
    @utils.string.decorate_arguments('fullname')
    def add(cls, enum, fullname, value, mask):
        '''Add a member with the given `fullname` to the enumeration `enum` with the specified `value`.'''
        eid, string = by(enum), interface.tuplename(*fullname)
        return cls.add(eid, string, value, mask)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string, value=types.integer, mask=types.integer)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, enum, name, value, mask):
        '''Add a member `name` for the given `mask` to the enumeration `enum` with the specified `value`.'''
        eid, err = by(enum), {getattr(idaapi, item) : item for item in ['ENUM_MEMBER_ERROR_NAME', 'ENUM_MEMBER_ERROR_VALUE', 'ENUM_MEMBER_ERROR_ENUM', 'ENUM_MEMBER_ERROR_MASK', 'ENUM_MEMBER_ERROR_ILLV']}
        rc = idaapi.add_enum_member(eid, utils.string.to(name), value, mask)
        if rc in err:
            raise E.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:#x}, {:#x}) : Unable to add a member to the enumeration ({:#x}) with the specified name ({!s}) and value ({:#x}) due to error {:s}({:d}).".format('.'.join([__name__, cls.__name__]), eid, utils.string.repr(name), value, mask, eid, utils.string.repr(name), value, err[rc], rc))
        return eid
    new = create = utils.alias(add, 'members')

    @utils.multicase(mid=types.integer)
    @classmethod
    def remove(cls, mid):
        '''Remove the member identified by `mid` from the enumeration that owns it.'''
        eid = member.parent(mid)
        return member.remove(mid)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        value, serial, mask = idaapi.get_enum_member_value(mid), idaapi.get_enum_member_serial(mid), idaapi.get_enum_member_bmask(mid)
        if not idaapi.del_enum_member(eid, value, serial, mask):
            raise E.DisassemblerError(u"{:s}.remove({:#x}, {!r}) : Unable to remove the specified member ({:#x}) having the value {:d} from the enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, member, mid, value, eid))
        return mid
    delete = destroy = utils.alias(remove, 'members')

    ## aggregations
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def names(cls, enum):
        '''Return a set of all the names belonging to the enumeration `enum`.'''
        eid = by(enum)
        return { member.name(mid) for mid in cls.iterate(eid) }

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def values(cls, enum):
        """Return a set of all the values belonging to the enumeration `enum`.

        If the enumeration is a bitfield, then each item in the result is the value and its bitmask.
        """
        eid = by(enum)
        if bitfield(eid):
            return { (member.value(mid), member.mask(mid)) for mid in cls.iterate(eid) }
        return { member.value(mid) for mid in cls.iterate(eid) }

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def mapping(cls, enum):
        '''Return a dictionary mapping all the values values to their names for the enumeration `enum`.'''
        eid = by(enum)
        return { member.value(mid) : member.name(mid) for mid in cls.iterate(eid) }

    ## searching
    @utils.multicase(enum=(types.integer, types.string, types.tuple), index=types.integer)
    @classmethod
    def by_index(cls, enum, index):
        '''Return the member identifier for the member of the enumeration `enum` at the specified `index`.'''
        eid = by(enum)
        try:
            res = next(mid for i, mid in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration:
            raise E.MemberNotFoundError(u"{:s}.by_index({:#x}, {:d}) : Unable to find the member at index {:d} of the specified enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, index, index, eid))
        return res

    @utils.multicase(enum=(types.integer, types.string, types.tuple), mid=types.integer)
    @classmethod
    def by_identifier(cls, enum, mid):
        '''Return the member of the enumeration specified by `enum` and its `mid`.'''
        eid = by(enum)
        if member.parent(mid) != eid:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({:#x}, {:#x}) : Unable to find a member in the enumeration ({:#x}) with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, mid, eid, mid))
        return mid

    @utils.multicase(enum=(types.integer, types.string, types.tuple), value=types.integer)
    @classmethod
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
            raise E.MemberNotFoundError(u"{:s}.by_value({:#x}, {:#x}{:s}) : Unable to find a member in the enumeration ({:#x}) with the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), enum, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))

        # If we found more than one result, then we need to grab all the fields
        # that we plan on emitting so that we can just let the user know what
        # was found when raising our exception.
        elif len(results) > 1:
            iterable = ((mid, mask, cid, utils.string.of(idaapi.get_bmask_name(eid, mask)) or u'', utils.string.of(idaapi.get_enum_member_name(mid)) or u'') for mid, mask, cid in results)
            spec = u"[{serial:d}] {name!s} {value:#0{:d}x} & {mask:s}".format if bitfieldQ else u"[{serial:d}] {name!s} {value:#0{:d}x}".format
            formatter = utils.fpartial(spec, 2 + 2 * size(eid))
            messages = (formatter(serial=cid, name=name, mask=u"{:s}({:#0{:d}x})".format(maskname, mask, 2 + 2 * size(eid)) if maskname else u"{:#0{:d}x}".format(mask, 2 + 2 * size(eid)), value=idaapi.get_enum_member_value(mid)) for mid, mask, cid, maskname, name in iterable)
            logging.fatal(u"{:s}.by_value({:#x}, {:#x}{:s}) : Multiple members with varying bitmask or serial were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))
            [ logging.warning(msg) for msg in messages ]
            if bitfieldQ:
                raise E.MemberNotFoundError(u"{:s}.by_value({:#x}, {:#x}{:s}) : Multiple members with varying bitmask or serial were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))
            raise E.MemberNotFoundError(u"{:s}.by_value({:#x}, {:#x}{:s}) : Multiple members with different serial numbers were found in the enumeration ({:#x}) for the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), eid, value, u", {:s}".format(utils.string.kwargs(filters)) if filters else u'', eid, value))

        # Otherwise there was only one item found, so we just need to unpack it.
        res, = results
        mid, _, _ = res
        return mid
    byvalue = utils.alias(by_value, 'members')

    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def by_name(cls, enum, name, *suffix):
        '''Return the member identifier for the member of the enumeration `enum` with the specified `name`.'''
        res = (name,) + suffix
        eid, string = by(enum), interface.tuplename(*res)
        for mid in cls.iterate(eid):
            if string == member.name(mid):
                return mid
            continue
        raise E.MemberNotFoundError(u"{:s}.by_name({:#x}, {!s}) : Unable to find a member in the enumeration ({:#x}) with the specified name ({!s}).".format('.'.join([__name__, cls.__name__]), eid, utils.string.repr(name), eid, utils.string.repr(name)))
    byname = utils.alias(by_name, 'members')

    @utils.multicase(enum=(types.integer, types.string, types.tuple), n=types.integer)
    @classmethod
    def by(cls, enum, n):
        '''Return the member belonging to `enum` identified by its index or id in `n`.'''
        return cls.by_identifier(enum, n) if interface.node.is_identifier(n) else cls.by_index(enum, n)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def by(cls, enum, name, *suffix):
        '''Return the member of the enumeration `enum` with the given `name`.'''
        return cls.by_name(enum, name, *suffix)

    # FIXME: Implement a matcher class for enumeration members that can be used with .iterate and .list below.
    __members_matcher = utils.matcher()
    __members_matcher.combinator('name', utils.fcondition(utils.finstance(types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), types.set, utils.fpartial(utils.fpartial, operator.contains))), idaapi.get_enum_member_name, utils.string.of, operator.methodcaller('lower'))
    __members_matcher.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_member_name, utils.string.of)
    __members_matcher.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_enum_member_name, utils.string.of)
    __members_matcher.combinator('comment', utils.fcondition(utils.finstance(types.string))(utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), utils.fcondition(operator.truth)(utils.fconstant(operator.truth), utils.fconstant(operator.not_))), utils.frpartial(idaapi.get_enum_member_cmt, False), utils.string.of, utils.fdefault(''))
    __members_matcher.alias('comments', 'comment')
    __members_matcher.combinator('repeatable', utils.fcondition(utils.finstance(types.string))(utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), utils.fcondition(operator.truth)(utils.fconstant(operator.truth), utils.fconstant(operator.not_))), utils.frpartial(idaapi.get_enum_member_cmt, True), utils.string.of, utils.fdefault(''))
    __members_matcher.combinator('value', utils.fcondition(utils.finstance(types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_enum_member_value)
    __members_matcher.combinator('mask', utils.fcondition(utils.finstance(types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_enum_member_bmask)
    __members_matcher.alias('bitmask', 'mask')
    __members_matcher.predicate('predicate'), __members_matcher.alias('pred', 'predicate')

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def iterate(cls, enum, **type):
        '''Iterate through all ids of each member associated with the enumeration `enum`.'''
        eid = by(enum)
        iterable = cls.__iterate__(eid)
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__members_matcher.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def list(cls, enum, **type):
        '''List all the members belonging to the enumeration identified by `enum`.'''
        # FIXME: make this consistent with every other .list using the matcher class
        eid = by(enum)
        listable = [item for item in cls.iterate(eid, **type)]
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

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    def __new__(cls, enum, member):
        '''Return a tuple containing the name and value for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls(mid)
    @utils.multicase(mid=types.integer)
    def __new__(cls, mid):
        """Return a tuple containing the name and value for the enumeration member `mid`.

        If the enumeration owning the member is a bitfield, then the member bitmask is included in the result.
        """
        eid = cls.parent(mid)
        if bitfield(eid):
            return cls.name(mid), cls.value(mid), cls.mask(mid)
        return cls.name(mid), cls.value(mid)

    @utils.multicase(mid=types.integer)
    @classmethod
    def parent(cls, mid):
        '''Return the id of the enumeration that owns the member `mid`.'''
        CONST_ENUM = -2
        return idaapi.get_enum_member_enum(mid)
    owner = utils.alias(parent, 'member')

    @utils.multicase(mid=types.integer)
    @classmethod
    def by(cls, mid):
        '''Return the enumeration member as specified by the provided `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.by({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        eid = cls.parent(mid)
        return members.by_identifier(eid, mid)

    @utils.multicase(mid=types.integer)
    @classmethod
    def remove(cls, mid):
        '''Remove the enumeration member with the given `mid`.'''
        eid, value, serial, mask = cls.parent(mid), cls.value(mid), cls.serial(mid), cls.mask(mid)
        if not idaapi.del_enum_member(eid, value, serial, mask):
            raise E.DisassemblerError(u"{:s}.remove({:#x}) : Unable to remove the specified member ({:#x}) having the value {:d} from the enumeration ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid, value, eid))
        return mid
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def remove(cls, enum, member):
        '''Remove the specified `member` of the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.remove(mid)

    ## properties
    @utils.multicase(mid=types.integer)
    @classmethod
    def name(cls, mid):
        '''Return the name of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.name({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        res = idaapi.get_enum_member_name(mid)
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def name(cls, enum, member):
        '''Return the name of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.name(mid)
    @utils.multicase(mid=types.integer, name=(types.string, types.tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    def name(cls, mid, name):
        '''Rename the enumeration member `mid` to `name`.'''
        fullname = interface.tuplename(*name) if isinstance(name, types.tuple) else name
        string = utils.string.to(fullname)
        res, ok = idaapi.get_enum_member_name(mid), idaapi.set_enum_member_name(mid, string)
        if not ok:
            raise E.DisassemblerError(u"{:s}.name({:#x}, {!s}) : Unable to set the name for the specified member ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(name), mid, utils.string.repr(fullname)))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration `member` belonging to `enum` to `name`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        fullname = (name,) + suffix
        return cls.name(mid, fullname)

    @utils.multicase(mid=types.integer)
    @classmethod
    def comment(cls, mid, **repeatable):
        """Return the comment for the enumeration member `mid`.

        If the bool `repeatable` is specified, then return the repeatable comment.
        """
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.comment({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        res = idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=types.integer, comment=types.string)
    @classmethod
    @utils.string.decorate_arguments('comment')
    def comment(cls, mid, comment, **repeatable):
        """Set the comment for the enumeration member id `mid` to `comment`.

        If the bool `repeatable` is specified, then set the repeatable comment.
        """
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.comment({:#x}, {!s}{:s}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', mid))
        string = utils.string.to(comment)
        res, ok = idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True)), idaapi.set_enum_member_cmt(mid, string, repeatable.get('repeatable', True))
        if not ok:
            adjective = (u'repeatable' if repeatable.get('repeatable', True) else u'non-repeatable') if repeatable else u''
            raise E.DisassemblerError(u"{:s}.comment({:#x}, {!s}{:s})) : Unable to set the {:s}comment for the specified member ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', u" {:s}".format(adjective) if adjective else u'', mid, utils.string.repr(comment)))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), comment=types.string)
    @classmethod
    @utils.string.decorate_arguments('comment')
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration `member` belonging to `enum` to the string `comment`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.comment(mid, comment, **repeatable)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), none=types.none)
    @classmethod
    def comment(cls, enum, member, none, **repeatable):
        '''Remove the comment from the `member` belonging to the enumeration `enum`.'''
        return cls.comment(enum, member, none or u'', **repeatable)

    @utils.multicase(mid=types.integer)
    @classmethod
    def value(cls, mid):
        '''Return the value of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        return idaapi.get_enum_member_value(mid)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def value(cls, enum, member):
        '''Return the value of the specified `member` belonging to the enumeration `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid)
    @utils.multicase(mid=types.integer, value=types.integer)
    @classmethod
    def value(cls, mid, value):
        '''Assign the integer specified by `value` to the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.value({:#x}, {:#x}{:s}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, value, u", {:s}".format(utils.string.kwargs(bitmask)) if bitmask else u'', mid))
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
    @utils.multicase(enum=(types.integer, types.string, types.tuple), value=types.integer)
    @classmethod
    def value(cls, enum, member, value, **bitmask):
        '''Set the `value` for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.value(mid, value)

    @utils.multicase(mid=types.integer)
    @classmethod
    def serial(cls, mid):
        '''Return the serial of the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.serial({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        CONST_SERIAL = -7
        return idaapi.get_enum_member_serial(mid)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def serial(cls, enum, member):
        '''Return the serial of the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.serial(mid)

    @utils.multicase(mid=types.integer)
    @classmethod
    def mask(cls, mid):
        '''Return the bitmask for the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.mask({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        CONST_BMASK = -6
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.mask(mid)

    @utils.multicase(mid=types.integer)
    @classmethod
    def refs(cls, mid):
        '''Return the `(address, opnum, type)` of all the instructions that reference the enumeration member `mid`.'''
        if not interface.node.is_identifier(mid):
            raise E.MemberNotFoundError(u"{:s}.mask({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, mid))
        eid = cls.parent(mid)

        # Collect all of the data references for the enumeration member id.
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mid, idaapi.XREF_DATA)]
        if not refs:
            fullname = '.'.join([name(eid), cls.name(mid)])
            logging.warning(u"{:s}.refs({:#x}) : No references found to enumeration member {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), mid, fullname, mid))
            return []

        # Now that we have a list of xrefs, we need to convert each element
        # into an interface.opref_t. We do this by figuring out which operand
        # the member is in for each address. We double-verify that the member
        # from the operand actually belongs to the enumeration.
        res = []
        for ea, xiscode, xrtype in refs:
            flags = interface.address.flags(ea)
            ops = [(opnum, interface.instruction.opinfo(ea, opnum)) for opnum, operand in enumerate(interface.instruction.operands(ea)) if idaapi.is_enum(flags, opnum)]
            ops = [opnum for opnum, info in ops if info and info.tid == eid]
            res.extend(interface.opref_t(ea, int(opnum), interface.access_t(xrtype, xiscode)) for opnum in ops)
        return res

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def refs(cls, enum, member):
        '''Returns the `(address, opnum, type)` of all the instructions that reference the enumeration `member` belonging to `enum`.'''
        eid = by(enum)
        mid = members.by(eid, member)
        return cls.refs(mid)

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
    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    def __new__(cls, enum):
        '''Iterate through all of the masks belonging to the enumeration `enum` and yield their name and value.'''
        eid = by(enum)
        for mask in cls.iterate(eid):
            yield cls.name(eid, mask), mask
        return

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def has(cls, enum, mask):
        '''Return whether the enumeration `enum` uses the specified `mask`.'''
        eid = by(enum)
        return any(item == mask for item in cls.iterate(eid))

    @classmethod
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

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
    def iterate(cls, enum):
        '''Iterate through all of the masks belonging to the enumeration `enum`.'''
        eid = by(enum)
        for item in cls.__iterate__(eid):
            yield item
        return

    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer)
    @classmethod
    def name(cls, enum, mask):
        '''Return the name for the given `mask` belonging to the enumeration `enum`.'''
        eid = by(enum)
        res = idaapi.get_bmask_name(eid, mask)
        return utils.string.of(res) or ''
    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer, name=(types.string, types.tuple))
    @classmethod
    @utils.string.decorate_arguments('name')
    def name(cls, enum, mask, name):
        '''Set the name for the `mask` belonging to the enumeration `enum` to the provided `name`.'''
        eid = by(enum)
        fullname = interface.tuplename(*name) if isinstance(name, types.tuple) else name
        string = utils.string.to(fullname)
        res, ok = idaapi.get_bmask_name(eid, mask), idaapi.set_bmask_name(eid, mask, string)
        if not ok:
            raise E.DisassemblerError(u"{:s}.name({:#x}, {:#x}, {!s}) : Unable to rename the mask ({:#x}) for the specified enumeration ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), eid, mask, utils.string.repr(name), 2 + 2 * size(eid), eid, utils.string.repr(fullname)))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer, name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def name(cls, enum, mask, name, *suffix):
        '''Set the name for the `mask` belonging to the enumeration `enum` to the provided `name`.'''
        eid = by(enum)
        fullname = (name,) + suffix
        return cls.name(eid, mask, fullname)

    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer)
    @classmethod
    def comment(cls, enum, mask, **repeatable):
        """Return the comment for the `mask` belonging to the enumeration `enum`.

        If the bool `repeatable` is specified, then return the repeatable comment.
        """
        eid = by(enum)
        res = idaapi.get_bmask_cmt(eid, mask, repeatable.get('repeatable', True))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer, comment=types.string)
    @classmethod
    @utils.string.decorate_arguments('comment')
    def comment(cls, enum, mask, comment, **repeatable):
        """Set the comment for the `mask` belonging to the enumeration `enum` to `comment`.

        If the bool `repeatable` is specified, then set the repeatable comment.
        """
        eid = by(enum)
        string = utils.string.to(comment)
        res, ok = idaapi.get_bmask_cmt(eid, mask, repeatable.get('repeatable', True)), idaapi.set_bmask_cmt(eid, mask, string, repeatable.get('repeatable', True))
        if not ok:
            adjective = (u'repeatable' if repeatable.get('repeatable', True) else u'non-repeatable') if repeatable else u''
            raise E.DisassemblerError(u"{:s}.comment({:#x}, {:#x}, {!s}, {:s}) : Unable to set the {:s}comment for the specified mask ({:#0{:d}x}) from the enumeration ({:#x}) to {!s}.".format('.'.join([__name__, cls.__name__]), eid, mask, utils.string.repr(comment), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else u'', u" {:s}".format(adjective) if adjective else u'', mask, 2 + 2 * size(eid), eid, utils.string.repr(comment)))
        return utils.string.of(res)
    @utils.multicase(enum=(types.integer, types.string, types.tuple), mask=types.integer, none=types.none)
    @classmethod
    def comment(cls, enum, mask, none, **repeatable):
        '''Remove the comment for the `mask` belonging to the enumeration `enum`.'''
        return cls.comment(enum, mask, none or u'', **repeatable)

    @utils.multicase(enum=(types.integer, types.string, types.tuple))
    @classmethod
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
