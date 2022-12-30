"""
Structure module

This module exposes a number of tools and defines some classes that
can be used to interacting with the structures defined in the database.
The classes defined by this module wrap IDAPython's structure API and expose
a simpler interface that can be used to perform various operations
against a structure such as renaming or enumerating the structure's
members.

The base argument type for getting a ``structure_t`` can be either a name,
an identifier, or an index. Typically one will call ``structure.by``
with either identifier type which will then return an instance of their
``structure_t``.

To list the different structures available in the database, one can use
``structure.list`` with their chosen method of filtering. This will
list all of the available structures at which point the user can then
request it by passing an identifer to ``structure.by``. The chosen
methods of filtering are:

    `name` - Filter the structures by a name or a list of names
    `like` - Filter the structure names according to a glob
    `regex` - Filter the structure names according to a regular-expression
    `index` - Filter the structures by an index or a list of indices
    `identifier` or `id` - Match the structure by its id which is an ``idaapi.uval_t``
    `size` - Filter the structures for any matching a size or a list of sizes
    `greater` or `ge` - Match structures that are larger (inclusive) than the specified size
    `gt` - Match structures that are larger (exclusive) than the specified size
    `less` or `le` - Match structures that are smaller (inclusive) than the specified size
    `lt` - Match structures that are smaller (exclusive) than the specified size
    `predicate` - Filter the structures by passing the id (``idaapi.uval_t``) to a callable

Some examples of using these keywords are as follows::

    > structure.list('my*')
    > iterable = structure.iterate(regex='__.*')
    > result = structure.search(index=42)

"""

import builtins, functools, operator, itertools, logging, six
import re, fnmatch

import database, instruction, ui
import idaapi, internal
from internal import utils, interface, types, exceptions as E
structure_t, member_t = internal.structure.structure_t, internal.structure.member_t

__matcher__ = utils.matcher()
__matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.attribute('index', 'id', idaapi.get_struc_idx)
__matcher__.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), 'name', operator.methodcaller('lower'))
__matcher__.attribute('size', 'size')
__matcher__.boolean('greater', operator.le, 'size'), __matcher__.boolean('ge', operator.le, 'size')
__matcher__.boolean('gt', operator.lt, 'size')
__matcher__.boolean('less', operator.ge, 'size'), __matcher__.boolean('le', operator.ge, 'size')
__matcher__.boolean('lt', operator.gt, 'size')
__matcher__.predicate('predicate')
__matcher__.predicate('pred')

def __iterate__():
    '''Iterate through all structures defined in the database.'''
    res = idaapi.get_first_struc_idx()
    if res == idaapi.BADADDR: return

    while res not in { idaapi.get_last_struc_idx(), idaapi.BADADDR }:
        id = idaapi.get_struc_by_idx(res)
        yield by_identifier(id)
        res = idaapi.get_next_struc_idx(res)

    res = idaapi.get_last_struc_idx()
    if res != idaapi.BADADDR:
        yield by_identifier(idaapi.get_struc_by_idx(res))
    return

@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def iterate(string, *suffix):
    '''Iterate through all of the structures in the database with a glob that matches `string`.'''
    res = string if isinstance(string, types.tuple) else (string,)
    return iterate(like=interface.tuplename(*(res + suffix)))
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def iterate(**type):
    '''Iterate through all of the structures that match the keyword specified by `type`.'''
    if not type: type = {'predicate': lambda item: True}
    listable = [item for item in __iterate__()]
    for key, value in type.items():
        listable = [item for item in __matcher__.match(key, value, listable)]
    for item in listable: yield item

@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def list(string, *suffix):
    '''List any structures that match the glob in `string`.'''
    res = string if isinstance(string, types.tuple) else (string,)
    return list(like=interface.tuplename(*(res + suffix)))
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def list(**type):
    '''List all the structures within the database that match the keyword specified by `type`.'''
    res = [item for item in iterate(**type)]

    maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) if res else [1])
    maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), utils.fdefault(''), len), res) if res else [1])
    maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) if res else [1])

    for st in res:
        six.print_(u"[{:{:d}d}] {:>{:d}s} {:<+#{:d}x} ({:d} members){:s}".format(idaapi.get_struc_idx(st.id), maxindex, st.name, maxname, st.size, maxsize, len(st.members), u" // {!s}".format(st.tag() if '\n' in st.comment else st.comment) if st.comment else ''))
    return

@utils.multicase(tag=types.string)
@utils.string.decorate_arguments('And', 'Or')
def select(tag, *And, **boolean):
    '''Query all of the structure tags for the specified `tag` and any others specified as `And`.'''
    res = {tag} | {item for item in And}
    boolean['And'] = {item for item in boolean.get('And', [])} | res
    return select(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or')
def select(**boolean):
    """Query all the structures (linearly) for any tags specified by `boolean`. Yields each address found along with the matching tags as a dictionary.

    If `And` contains an iterable then require the returned structure contains them.
    If `Or` contains an iterable then include any other tags that are specified.
    """
    boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

    # User is not asking for anything specifically, so just yield all the
    # structures that are available.
    if not boolean:
        for st in __iterate__():
            content = st.tag()

            # If we have any content, then the structure and its content
            # can be yielded to the user.
            if content:
                yield st, content
            continue
        return

    # Collect the tags we're supposed to look for in the typical lame way.
    Or, And = ({item for item in boolean.get(B, [])} for B in ['Or', 'And'])

    # Now we slowly iterate through our structures looking for matches,
    # while ensuring that we pop off any typeinfo since its not relevant.
    for st in __iterate__():
        collected, content = {}, st.tag()

        # Simply collect all tagnames being queried with Or(|).
        collected.update({key : value for key, value in content.items() if key in Or})

        # And(&) is a little more specific...
        if And:
            if And & six.viewkeys(content) == And:
                collected.update({key : value for key, value in content.items() if key in And})
            else: continue

        # That's all folks. Yield it if you got it.
        if collected: yield st, collected
    return

@utils.multicase(string=(types.string, types.tuple))
@utils.string.decorate_arguments('string', 'suffix')
def new(string, *suffix, **offset):
    """Create a new structure or union using the name specified by `string` and return it.

    If the boolean `union` is provided, then create a union instead of a structure.
    If the integer `offset` is provided, then use it as the base offset for the newly created structure.
    """
    res = string if isinstance(string, types.tuple) else (string,)
    name = interface.tuplename(*(res + suffix))

    # add a structure with the specified name
    realname = utils.string.to(name)
    id = idaapi.add_struc(idaapi.BADADDR, realname, offset.get('union', False))
    if id == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({:s}{:s}) : Unable to add a new {:s} to the database with the specified name ({!r}).".format(__name__, ', '.join(map("{!r}".format, res + suffix)), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', 'union' if offset.get('union', False) else 'structure', name))

    # return a new instance using the specified identifier
    return internal.structure.new(id, offset.get('offset', 0))

@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def search(string, *suffix):
    '''Search through all the structure names matching the glob `string`.'''
    res = string if isinstance(string, types.tuple) else (string,)
    return by(like=interface.tuplename(*(res + suffix)))
@utils.multicase()
def search(**type):
    '''Search through all of the structures and return the first result matching the keyword specified by `type`.'''
    return by(**type)

@utils.string.decorate_arguments('name', 'suffix')
def by_name(name, *suffix, **offset):
    '''Return an instance of a structure by its name.'''
    string = name if isinstance(name, types.tuple) else (name,)
    res = utils.string.to(interface.tuplename(*(string + suffix)))

    # try and find the structure id according to its name
    id = idaapi.get_struc_id(res)
    if id == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by_name(\"{:s}\"{:s}) : Unable to locate structure with given name.".format(__name__, utils.string.escape(res, '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else ''))

    # grab an instance of the structure by its id that we found
    return internal.structure.new(id, offset.get('offset', 0))
byname = utils.alias(by_name)

def by_index(index, **offset):
    '''Return an instance of a structure by its index.'''
    id = idaapi.get_struc_by_idx(index)
    if id == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by_index({:d}{:s}) : Unable to locate structure at given index.".format(__name__, index, u", {:s}".format(utils.string.kwargs(offset)) if offset else ''))

    # grab an instance of the structure by the id we found
    return internal.structure.new(id, offset.get('offset', 0))
byindex = utils.alias(by_index)

def by_identifier(identifier, **offset):
    '''Return an instance of the structure identified by `identifier`.'''
    return internal.structure.new(identifier, offset.get('offset', 0))

by_id = byidentifier = byId = utils.alias(by_identifier)

### Functions that are related to finding and using a structure_t.
@utils.multicase(id=types.integer)
def has(id):
    '''Return whether a structure with the specified `id` exists within the database.'''
    return internal.structure.has(id)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def has(name, *suffix):
    '''Return if a structure with the specified `name` exists within the database.'''
    string = name if isinstance(name, types.tuple) else (name,)
    res = utils.string.to(interface.tuplename(*(string + suffix)))
    return has(idaapi.get_struc_id(res))
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def has(structure):
    '''Return whether the database includes the provided `structure`.'''
    return has(structure.id)
@utils.multicase(tinfo=idaapi.tinfo_t)
def has(tinfo):
    '''Return whether the database includes a structure for the specified `tinfo`.'''
    if any([tinfo.is_struct(), tinfo.is_union()]):
        return has(tinfo.get_type_name())

    # If there's no details, then just bail because there nowhere to go
    # if we want to proceed to find a structure type.
    elif not tinfo.has_details():
        return False

    # If the type information we were given is a pointer, then dereference it
    # and recurse until we get to a structure type of some sort.
    pi = idaapi.ptr_type_data_t()
    if tinfo.is_ptr() and tinfo.get_ptr_details(pi):
        return has(pi.obj_type)

    # If the type information we were given is an array, then get its element
    # type and recurse until we get to a structure type of some sort.
    ai = idaapi.array_type_data_t()
    if tinfo.is_array() and tinfo.get_array_details(ai):
        return has(ai.elem_type)
    return False

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def by(name, *suffix, **offset):
    '''Return the structure with the given `name`.'''
    return by_name(name, *suffix, **offset)
@utils.multicase(id=types.integer)
def by(id, **offset):
    '''Return the structure with the specified `id` or index.'''
    if interface.node.identifier(id):
        return internal.structure.new(id, offset.get('offset', 0))
    return by_index(id, **offset)
@utils.multicase(sptr=(idaapi.struc_t, structure_t))
def by(sptr, **offset):
    '''Return the structure for the specified `sptr`.'''
    return internal.structure.new(sptr.id, offset.get('offset', 0))
@utils.multicase(tinfo=idaapi.tinfo_t)
def by(tinfo, **offset):
    '''Return the structure for the specified `tinfo`.'''
    if any([tinfo.is_struct(), tinfo.is_union()]):
        return by_name(tinfo.get_type_name(), **offset)

    # If there are no details, then raise an exception because we need to
    # some sort of details in order to figure out the real name.
    elif not tinfo.has_details():
        raise E.DisassemblerError(u"{:s}.by(\"{:s}\"{:s}) : The provided type information ({!r}) does not contain any details.".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', "{!s}".format(tinfo)))

    # If our type is a pointer, then we need to extract the pointer details
    # from it so that we can dereference the type and recurse into ourselves.
    if tinfo.is_ptr():
        pi = idaapi.ptr_type_data_t()
        if not tinfo.get_ptr_details(pi):
            raise E.DisassemblerError(u"{:s}.by(\"{:s}\"{:s}) : Unable to get the pointer target from the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', "{!s}".format(tinfo)))
        recurse_tinfo = pi.obj_type

    # If our type is an array, then we need to extract the array details so
    # that we can figure out the element type and recurse into ourselves.
    elif tinfo.is_array():
        ai = idaapi.array_type_data_t()
        if not tinfo.get_array_details(ai):
            raise E.DisassemblerError(u"{:s}.by(\"{:s}\"{:s}) : Unable to get the array element from the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', "{!s}".format(tinfo)))
        recurse_tinfo = ai.elem_type

    # Any other type is pretty much unknown and so we just bail the search.
    else:
        raise E.InvalidTypeOrValueError(u"{:s}.by(\"{:s}\"{:s}) : Unable to determine the structure for the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', "{!s}".format(tinfo)))
    return by(recurse_tinfo, **offset)

@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def by(**type):
    '''Return the structure matching the keyword specified by `type`.'''
    searchstring = utils.string.kwargs(type)

    listable = [item for item in iterate(**type)]
    if len(listable) > 1:
        messages = ((u"[{:d}] {:s}".format(idaapi.get_struc_idx(st.id), st.name)) for i, st in enumerate(listable))
        [ logging.info(msg) for msg in messages ]
        logging.warning(u"{:s}.search({:s}) : Found {:d} matching results, returning the first one {!s}.".format(__name__, searchstring, len(listable), listable[0]))

    iterable = (item for item in listable)
    res = next(iterable, None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(id=types.integer)
def name(id):
    '''Return the name of the structure identified by `id`.'''
    res = idaapi.get_struc_name(id)
    return utils.string.of(res)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def name(structure):
    '''Return the name of the given `structure`.'''
    return name(structure.id)
@utils.multicase(id=types.integer, string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(id, string, *suffix):
    '''Set the name of the structure identified by `id` to `string`.'''
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # convert the specified string into a form that IDA can handle
    ida_string = utils.string.to(string)

    # validate the name
    res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.SN_IDBENC)
    if ida_string and ida_string != res:
        logging.info(u"{:s}.name({!r}, {!r}) : Stripping invalid chars from the structure name \"{:s}\" resulted in \"{:s}\".".format(__name__, id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
        ida_string = res

    # now we can set the name of the structure
    return idaapi.set_struc_name(id, ida_string)
@utils.multicase(structure=(idaapi.struc_t, structure_t), string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(structure, string, *suffix):
    '''Set the name of the specified `structure` to `string`.'''
    return name(structure.id, string, *suffix)
@utils.multicase(tinfo=idaapi.tinfo_t)
def name(tinfo):
    '''Return the name of the structure specified by `tinfo`.'''
    structure = by(tinfo)
    return name(structure.ptr)
@utils.multicase(tinfo=idaapi.tinfo_t, string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(tinfo, string, *suffix):
    '''Set the name of the structure represented by `tinfo` to `string`.'''
    structure = by(tinfo)
    return name(structure.ptr, string, *suffix)

@utils.multicase(id=types.integer)
def comment(id, **repeatable):
    """Return the comment of the structure identified by `id`.

    If the bool `repeatable` is specified, return the repeatable comment.
    """
    res = idaapi.get_struc_cmt(id, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def comment(structure, **repeatable):
    '''Return the comment for the specified `structure`.'''
    return comment(structure.id, **repeatable)
@utils.multicase(structure=(idaapi.struc_t, structure_t), cmt=types.string)
@utils.string.decorate_arguments('cmt')
def comment(structure, cmt, **repeatable):
    '''Set the comment to `cmt` for the specified `structure`.'''
    return comment(structure.id, cmt, **repeatable)
@utils.multicase(structure=(idaapi.struc_t, structure_t), none=types.none)
def comment(structure, none, **repeatable):
    '''Remove the comment from the specified `structure`.'''
    return comment(structure.id, none or '', **repeatable)
@utils.multicase(id=types.integer, cmt=types.string)
@utils.string.decorate_arguments('cmt')
def comment(id, cmt, **repeatable):
    """Set the comment of the structure identified by `id` to `cmt`.

    If the bool `repeatable` is specified, set the repeatable comment.
    """
    res = utils.string.to(cmt)
    return idaapi.set_struc_cmt(id, res, repeatable.get('repeatable', True))
@utils.multicase(id=types.integer, none=types.none)
def comment(id, none, **repeatable):
    '''Remove the comment from the structure identified by `id`.'''
    return comment(id, none or '', **repeatable)
@utils.multicase(tinfo=idaapi.tinfo_t)
def comment(tinfo, **repeatable):
    '''Return the comment from the structure specified by `tinfo`.'''
    structure = by(tinfo)
    return comment(structure.ptr, **repeatable)
@utils.multicase(tinfo=idaapi.tinfo_t, cmt=(types.string, types.none))
def comment(tinfo, cmt, **repeatable):
    '''Modify or remove the comment from the structure specified by `tinfo`.'''
    structure = by(tinfo)
    return comment(structure.ptr, cmt, **repeatable)

@utils.multicase(id=types.integer)
def index(id):
    '''Return the position of the structure identified by `id`.'''
    return idaapi.get_struc_idx(id)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def index(structure):
    '''Return the position of the specified `structure`.'''
    return index(structure.id)
@utils.multicase(id=types.integer, position=types.integer)
def index(id, position):
    '''Move the structure identified by `id` to the specified `position` of the structure list.'''
    return idaapi.set_struc_idx(id, position)
@utils.multicase(structure=(idaapi.struc_t, structure_t), position=types.integer)
def index(structure, position):
    '''Move the specified `structure` to the specified `position` of the structure list.'''
    return index(structure.id, position)
@utils.multicase(tinfo=idaapi.tinfo_t)
def index(tinfo):
    '''Return the index of the structure specified by `tinfo`.'''
    structure = by(tinfo)
    return index(structure.ptr)
@utils.multicase(tinfo=idaapi.tinfo_t, position=types.integer)
def index(tinfo, position):
    '''Move the structure represented by `tinfo` to the specified `position` of the structure list.'''
    structure = by(tinfo)
    return index(structure.ptr, position)

@utils.multicase(structure=(idaapi.struc_t, structure_t, types.integer))
def size(structure):
    '''Return the size of the specified `structure`.'''
    res = structure.id if isinstance(structure, (idaapi.struc_t, structure_t)) else structure
    id = res if interface.node.identifier(res) else idaapi.get_struc_by_idx(res)
    if id == idaapi.BADADDR:
        number, description = ("{:#x}".format(res), 'with the given identifier') if isinstance(structure, (idaapi.struc_t, structure_t)) else ("{:d}".format(res), 'at the specified index')
        raise E.StructureNotFoundError(u"{:s}.size({:s}) : Unable to locate the structure {:s} ({:s}).".format(__name__, number, description, number))
    return idaapi.get_struc_size(id)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def size(name, *suffix):
    '''Return the size of the structure with the specified `name`.'''
    string = name if isinstance(name, types.tuple) else (name,)
    res = interface.tuplename(*(string + suffix))
    id = idaapi.get_struc_id(utils.string.to(res))
    if id == idaapi.BADADDR:
        description = (("{:#x}".format(item) if isinstance(item, types.integer) else "{!r}".format(item)) for item in suffix)
        raise E.StructureNotFoundError(u"{:s}.size({!r}) : Unable to locate a structure with the name \"{:s}\".".format(__name__, name, ", {:s}".format(', '.join(description)) if suffix else '', utils.string.escape(res, '"')))
    return idaapi.get_struc_size(id)
@utils.multicase(tinfo=idaapi.tinfo_t)
def size(tinfo):
    '''Return the size of the structure represented by `tinfo`.'''
    structure = by(tinfo)
    return size(structure.ptr)

class type(object):
    """
    This namespace is for determining information about the type of
    a structure. The functions within this namespace allow one to
    determine certain attributes of a structure such as whether it's
    a union, used as the frame of a function, or a variable-length
    structure definition.

    This namespace is also aliased as ``database.t``.

    Some examples of using this namespace can be::

        > st = structure.by('some-structure-name')
        > print( structure.type.union(st) )
        > print( structure.type.frame(st) )
        > print( structure.type.listed(st) )

    """

    @utils.multicase(id=types.integer)
    @classmethod
    def union(cls, id):
        '''Return whether the structure identified by `id` is a union or not.'''
        sptr = idaapi.get_struc(id)
        if not sptr:
            raise E.StructureNotFoundError(u"{:s}.union({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return cls.union(sptr)
    @utils.multicase(structure=(idaapi.struc_t, structure_t))
    @classmethod
    def union(cls, structure):
        '''Return whether the provided `structure` is defined as a union.'''
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        return internal.structure.union(sptr)
    @utils.multicase(tinfo=idaapi.tinfo_t)
    @classmethod
    def union(cls, tinfo):
        '''Return whether the structure represented by `tinfo` is defined as a union.'''
        structure = by(tinfo)
        return cls.union(structure.ptr)
    is_union = utils.alias(union, 'type')

    @utils.multicase(id=types.integer)
    @classmethod
    def frame(cls, id):
        '''Return whether the structure identified by `id` is a frame or not.'''
        sptr = idaapi.get_struc(id)
        if not sptr:
            raise E.StructureNotFoundError(u"{:s}.frame({!r}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return cls.frame(sptr)
    @utils.multicase(structure=(idaapi.struc_t, structure_t))
    @classmethod
    def frame(cls, structure):
        '''Return whether the provided `structure` is a frame or not.'''
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        return internal.structure.frame(sptr)
    is_frame = utils.alias(frame, 'type')

    @utils.multicase(id=types.integer)
    @classmethod
    def listed(cls, id):
        '''Return whether the structure identified by `id` is listed.'''
        sptr = idaapi.get_struc(id)
        if not sptr:
            raise E.StructureNotFoundError(u"{:s}.listed({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return cls.listed(sptr)
    @utils.multicase(structure=(idaapi.struc_t, structure_t))
    @classmethod
    def listed(cls, structure):
        '''Return whether the provided `structure` is listed.'''
        SF_NOLIST = getattr(idaapi, 'SF_NOLIST', 0x8)
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        return False if sptr.props & SF_NOLIST else True
    @utils.multicase(tinfo=idaapi.tinfo_t)
    @classmethod
    def listed(cls, tinfo):
        '''Return whether the structure represented by `tinfo` is listed.'''
        structure = by(tinfo)
        return cls.listed(structure.ptr)
    @utils.multicase(structure=(structure_t, types.integer, idaapi.tinfo_t))
    @classmethod
    def listed(cls, structure, boolean):
        '''Update the specified `structure` so that it is listed if the given `boolean` is true.'''
        st = by(structure)
        return cls.listed(st.ptr, boolean)
    @utils.multicase(sptr=idaapi.struc_t)
    @classmethod
    def listed(cls, sptr, boolean):
        '''Update the structure in `sptr` so that it is listed if the given `boolean` is true.'''
        result, _ = cls.listed(spr), idaapi.set_struc_listed(sptr, boolean)
        return result
    is_listed = utils.alias(listed, 'type')
is_union, is_frame, is_listed = utils.alias(type.union, 'type'), utils.alias(type.frame, 'type'), utils.alias(type.listed, 'type')

@utils.multicase(structure=(idaapi.tinfo_t, structure_t, types.string, types.integer))
def members(structure, **base):
    '''Yield each member of the given `structure` as a tuple containing its attributes.'''
    st = by(structure)
    return members(st.ptr, **base)
@utils.multicase(sptr=idaapi.struc_t)
def members(sptr, **base):
    """Yield each member of the structure in `sptr` as a tuple of containing its `(offset, size, tags)`.

    If the integer `base` is defined, then the offset of each member will be translated by the given value.
    """
    st, struc = (F(sptr.id) for F in [idaapi.get_struc, by])

    # If we couldn't get the structure, then blow up in the user's face.
    if st is None:
        raise E.StructureNotFoundError(u"{:s}.members({:#x}) : Unable to find the requested structure ({:#x}).".format(__name__, sptr.id, sptr.id))

    # Grab some attributes like the structure's size, and whether or not
    # it's a union so that we can figure out each member's offset.
    size, unionQ = idaapi.get_struc_size(st), type.union(st)

    # Iterate through all of the member in the structure.
    offset, translated = 0, next((base[key] for key in ['offset', 'base', 'baseoffset'] if key in base), 0)
    for i in range(st.memqty):
        m, mem = st.get_member(i), struc.members[i]

        # Grab the member and its properties.
        msize, munionQ = idaapi.get_member_size(m), m.props & idaapi.MF_UNIMEM

        # Figure out the boundaries of the member. If our structure is a union, then
        # the starting offset never changes since IDA dual-uses it as the member index.
        left, right = offset if unionQ else m.soff, m.eoff

        # If our current offset does not match the member's starting offset, then this
        # is an empty field, or undefined. We yield this to the caller so that they
        # know that there's some padding they need to know about.
        if offset < left:
            yield translated + offset, left - offset, {}
            offset = left

        # Grab the attributes about the member that we plan on yielding and make sure
        # that we force any critical implicit tags for identification (like the name).
        items = mem.tag()
        items.setdefault('__name__', idaapi.get_member_name(m.id))

        # That was everything that our caller should likely care about, so we can
        # just yield our item and proceed onto the next member.
        yield translated + offset, msize, items

        # If we're a union, then the offset just never changes and thus we don't need
        # to adjust the offset like we have to do for a regular member.
        offset += 0 if unionQ else msize
    return

@utils.multicase(structure=(idaapi.struc_t, idaapi.tinfo_t, structure_t, types.integer, types.string), offset=types.integer)
def fragment(structure, offset, **base):
    '''Yield each member of the given `structure` from the specified `offset` as a tuple containing its attributes.'''
    st = by(structure)
    return fragment(st.ptr, offset, st.size, **base)
@utils.multicase(structure=(idaapi.tinfo_t, structure_t, types.integer, types.string), offset=types.integer, size=types.integer)
def fragment(structure, offset, size, **base):
    '''Yield each member of the given `structure` from the specified `offset` up to `size` as a tuple containing its attributes.'''
    st = by(structure)
    return fragment(st.ptr, offset, size, **base)
@utils.multicase(sptr=idaapi.struc_t, offset=types.integer, size=types.integer)
def fragment(sptr, offset, size, **base):
    """Yield each member of the structure in `sptr` from the given `offset` up to `size` as a tuple containing its `(offset, size, tags)`.

    If the integer `base` is defined, then the offset of each member will be translated by the given value.
    """
    iterable, unionQ = members(sptr.id, **base), type.union(sptr.id)

    # seek
    for item in iterable:
        m_offset, m_size, state = item

        left, right = m_offset, m_offset + m_size
        if (offset >= left) and (offset < right):
            delta = max(m_offset, offset) - m_offset
            yield m_offset + delta, m_size - delta, state
            size -= 0 if unionQ else m_size
            break
        continue

    # return
    for item in iterable:
        if size > 0:
            m_offset, m_size, state = item
            yield m_offset, m_size, state
            size -= 0 if unionQ else m_size
        continue
    return

@utils.multicase(structure=(idaapi.struc_t, structure_t))
def remove(structure):
    '''Remove the specified `structure` from the database.'''
    sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
    if not idaapi.del_struc(sptr):
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to remove the requested structure ({:#x}).".format(__name__, structure, structure.id))
    return True
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def remove(name, *suffix):
    '''Remove the structure with the specified `name`.'''
    res = by_name(name, *suffix)
    return remove(res)
@utils.multicase(tinfo=idaapi.tinfo_t)
def remove(tinfo):
    '''Remove the structure represented by the given `tinfo`.'''
    structure = by(tinfo)
    return remove(structure.ptr)
@utils.multicase(id=types.integer)
def remove(id):
    '''Remove a structure by its index or `id`.'''
    sptr = idaapi.get_struc(id)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.remove({!r}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
    return remove(sptr)
@utils.multicase()
def remove(**type):
    '''Remove the first structure that matches the result described by `type`.'''
    res = by(**type)
    return remove(res)
delete = utils.alias(remove)
