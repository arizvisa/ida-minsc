"""
Structure module

This module exposes a number of tools and defines some classes that
can be used to interacting with the structures, unions, and frames
defined within the database. The classes returned by this module wrap
the disassembler's structure API and expose a more-manageable interface
that can be used to perform various operations against a structure.
These operations can include things such as the addition, removal,
or enumeration of members, the modification of many of the attributes
associated with a member, and fetching reference information related
to any part of the structure.

The base parameter type for getting a ``structure_t`` can be either a
name, an identifier, an index, or a type. Generally this is accomplished
by calling the ``structure.by`` function with either suggested identifier
type which will then return an instance of the desired ``structure_t``.

To list the different structures within the database, one can use
``structure.list`` with their chosen method of filtering. This will
list each of the available structures which may then be used with
the ``structure.by`` function to return the desired structure.

When listing structures that are matched, the following legend can be
used to identify certain characteristics about the returned items.

    `+` - The structure has been been explicitly tagged
    `.` - The structure has some fields that have been tagged
    `*` - The structure and its fields have been tagged
    `P` - The structure is not used by any other structures
    `L` - The structure has come from a type library
    `^` - The structure has been folded out of view
    `?` - The structure is not displayed within the structure list
    `S` - The structure is defined as a regular structure
    `U` - The structure is defined as a union
    `V` - The structure is defined as a variable-length structure
    `@` - The fields of the structure are contiguous
    `0` - The structure has a hole as one of its fields

The different types that one can filter structures with are the following:

    `name` - Filter the structures by a name or a list of names
    `like` - Filter the structure names according to a glob
    `regex` - Filter the structure names according to a regular-expression
    `iregex` - Filter the structure names according to a case-insensitive regular-expression
    `index` - Filter the structures by an index or a list of indices
    `identifier` or `id` - Match the structure by its id which is an ``idaapi.uval_t``
    `size` - Filter the structures for any matching a size or a list of sizes
    `greater` or `ge` - Match structures that are larger (inclusive) than the specified size
    `gt` - Match structures that are larger (exclusive) than the specified size
    `less` or `le` - Match structures that are smaller (inclusive) than the specified size
    `lt` - Match structures that are smaller (exclusive) than the specified size
    `visible` - Match structures that are not hidden or folded within the structure list
    `folded` - Match structures that have been folded within the structure list
    `union` - Match structures that are defined as a union
    `library` - Match structures that originate from a type library
    `variable` - Match structures that have a variable-size
    `parent` - Filter structures that are not nested as members of other structures
    `tagged` - Filter structures for any that use or has fields with the specified tag(s)
    `members` - Filter structures by the number of members, a name, or specified name(s)
    `contiguous` - Filter structures that are laid out contiguously (no holes)
    `structure` - Filter the structures by their ``structure_t`` or a list of ``structure_t``
    `predicate` - Filter the structures by passing them to a callable

Some examples of using these keywords are as follows::

    > structure.list('my*')
    > structure.list(index=range(20))
    > structure.list(library=False, parent=True, tagged=True)
    > structure.list(visible=True, tagged='note')
    > iterable = structure.iterate(regex='__.*', contiguous=False)
    > result = structure.search(index=42)

"""

import builtins, functools, operator, itertools, logging, six
import re, fnmatch

import database, instruction, ui
import idaapi, internal, internal.structure
from internal import utils, interface, types, exceptions as E
structure_t, member_t = internal.structure.structure_t, internal.structure.member_t

__matcher__ = utils.matcher()
__matcher__.combinator('iregex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.combinator('regex', utils.fcompose(re.compile, operator.attrgetter('match')), 'name')
__matcher__.attribute('index', 'id', idaapi.get_struc_idx)
__matcher__.attribute('identifier', 'id'), __matcher__.alias('id', 'identifier')
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.combinator('name', utils.fcondition(utils.finstance(types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), types.set, utils.fpartial(utils.fpartial, operator.contains))), 'name', operator.methodcaller('lower'))
__matcher__.combinator('size', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.attrgetter('ptr'), idaapi.get_struc_size)
__matcher__.boolean('ge', operator.le, operator.attrgetter('ptr'), idaapi.get_struc_size)
__matcher__.boolean('gt', operator.lt, operator.attrgetter('ptr'), idaapi.get_struc_size), __matcher__.alias('greater', 'gt')
__matcher__.boolean('le', operator.ge, operator.attrgetter('ptr'), idaapi.get_struc_size)
__matcher__.boolean('lt', operator.gt, operator.attrgetter('ptr'), idaapi.get_struc_size), __matcher__.alias('less', 'lt')
__matcher__.mapping('visible', operator.not_, operator.attrgetter('ptr'), operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_NOLIST', 0x8) | getattr(idaapi, 'SF_HIDDEN', 0x20)))
__matcher__.mapping('folded', operator.truth, operator.attrgetter('ptr'), operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_HIDDEN', 0x20)))
__matcher__.mapping('union', operator.truth, operator.attrgetter('ptr'), operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_UNION', 0x2)))
__matcher__.mapping('library', operator.truth, operator.attrgetter('ptr'), operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_GHOST', 0x1000) | getattr(idaapi, 'SF_TYPLIB', 0x10)))
__matcher__.mapping('variable', operator.truth, operator.attrgetter('ptr'), operator.attrgetter('props'), functools.partial(operator.and_, idaapi.SF_VAR))
__matcher__.mapping('parent', operator.not_, operator.attrgetter('ptr'), operator.attrgetter('id'), interface.xref.to, functools.partial(builtins.map, operator.itemgetter(0)), functools.partial(builtins.filter, idaapi.get_member_by_id), functools.partial(builtins.map, utils.fcompose(idaapi.get_member_by_id, operator.itemgetter(2))), functools.partial(builtins.filter, utils.fcompose(internal.structure.frame, operator.not_)), types.list)
__matcher__.boolean('tagged', lambda parameter, keys: parameter == any(not key.startswith('__') for key in keys) if isinstance(parameter, types.bool) else operator.contains(keys, parameter) if isinstance(parameter, types.string) else keys & types.set(parameter), utils.fmap(utils.fcompose(operator.methodcaller('tag'), functools.partial(builtins.filter, utils.fcompose(functools.partial(operator.contains, {'__name__', '__typeinfo__'}), operator.not_)), types.set), utils.fcompose(operator.methodcaller('select'), functools.partial(builtins.map, utils.fcompose(operator.itemgetter(1), types.set)), utils.freverse(functools.partial(functools.reduce, operator.or_), types.set()))), utils.funpack(operator.or_))
__matcher__.alias('tag', 'tagged')
__matcher__.boolean('members', lambda parameter, names: len(names) == parameter if isinstance(parameter, types.integer) else fnmatch.filter(names, parameter) if isinstance(parameter, types.string) else all(operator.contains(names, name) for name in parameter), operator.attrgetter('members'), functools.partial(builtins.map, operator.attrgetter('name')), types.list)
__matcher__.mapping('contiguous', functools.partial(operator.le, 0), operator.attrgetter('ptr'), utils.fcondition(internal.structure.union)(utils.fconstant(0), utils.fcompose(utils.fmap(utils.fcompose(operator.attrgetter('members'), functools.partial(functools.partial, operator.getitem)), utils.fcompose(operator.attrgetter('memqty'), builtins.range)), utils.funpack(builtins.map), utils.freverse(functools.partial(functools.reduce, lambda eoff, member: member.eoff if member.soff == eoff else -1), 0))))
__matcher__.combinator('structure', utils.fcondition(utils.finstance(idaapi.struc_t, internal.structure.structure_t))(utils.fcompose(operator.attrgetter('id'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(filter, utils.finstance(idaapi.struc_t, internal.structure.structure_t)), utils.fpartial(map, operator.attrgetter('id')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), 'id')
__matcher__.alias('structures', 'structure')
__matcher__.predicate('predicate'), __matcher__.alias('pred', 'predicate')

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
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
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
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def list(**type):
    '''List all the structures within the database that match the keyword specified by `type`.'''
    listable = [item for item in iterate(**type)]

    maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), listable) if listable else [1])
    maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), utils.fdefault(''), len), listable) if listable else [1])
    maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), listable) if listable else [1])

    SF_TYPELIB = getattr(idaapi, 'SF_TYPLIB', 0x10) | getattr(idaapi, 'SF_GHOST', 0x1000)
    SF_NOLIST = getattr(idaapi, 'SF_NOLIST', 0x8)
    SF_HIDDEN = getattr(idaapi, 'SF_HIDDEN', 0x20)
    for item in listable:
        sptr, tags = item.ptr, item.tag()

        [tags.pop(name, None) for name in ['__name__', '__typeinfo__']]
        mtags = any(any(not item.startswith('__') for item in items) for _, items in item.select())
        ftagged = '*' if tags and mtags else '+' if tags else '.' if mtags else '-'
        flibrary = 'L' if sptr.props & SF_TYPELIB else '^' if sptr.props & SF_HIDDEN else '?' if sptr.props & SF_NOLIST else '-'
        fstructype = 'U' if internal.structure.union(sptr) else 'V' if sptr.props & idaapi.SF_VAR else 'S'

        fcontiguous = '@' if internal.structure.union(sptr) or functools.reduce(lambda eoff, item: item.ptr.eoff if item.ptr.soff == eoff else -1, builtins.map(functools.partial(operator.getitem, item.members), builtins.range(sptr.memqty)), 0) >= 0 else '0'

        iterable = (idaapi.get_member_by_id(id) for id, _, _ in interface.xref.to(sptr.id) if idaapi.get_member_by_id(id))
        users = (sptr for _, _, sptr in iterable if not internal.structure.frame(sptr))
        fparent = '-' if any(users) else 'P'

        flags = itertools.chain(fparent, fstructype, flibrary, fcontiguous, ftagged)

        six.print_(u"{:<{:d}s} {:>{:d}s} {:<+#{:d}x} : {:s} : ({:d} members){:s}".format(
            "[{:d}]".format(idaapi.get_struc_idx(item.id)), 2 + maxindex,
            item.name, maxname,
            item.size, maxsize,
            ''.join(flags),
            sptr.memqty, u" // {!s}".format(item.tag() if '\n' in item.comment else item.comment) if item.comment else ''
        ))
    return

@utils.multicase(tag=types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(tag, *required, **boolean):
    '''Query the structures in the database for the given `tag` and any others that may be `required`.'''
    res = {tag} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return select(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(**boolean):
    """Query the structures in the database for the tags specified by `boolean` and yield a tuple for each matching structure with selected tags and values.

    If `require` is given as an iterable of tag names then require that each returned structure uses them.
    If `include` is given as an iterable of tag names then include the tags for each returned structure if available.
    """
    boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

    # user doesn't want anything specific, so yield all of them and their tags.
    if not boolean:
        for item in __iterate__():
            content = item.tag()

            # if the structure had some content (tags), then we have a match
            # and can yield the structure and its content to the user.
            if content:
                yield item, content
            continue
        return

    # collect the tagnames we're supposed to look for in the typical lame way.
    included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])

    # now we just slowly iterate through our structures looking for any matches.
    for item in __iterate__():
        collected, content = {}, item.tag()

        # included is the equivalent of Or(|) and yields the structure if any of the tagnames are used.
        collected.update({key : value for key, value in content.items() if key in included})

        # required is the equivalent of And(&) which yields the structure only if it uses all of the tagnames.
        if required:
            if required & six.viewkeys(content) == required:
                collected.update({key : value for key, value in content.items() if key in required})
            else: continue

        # that's all folks.. yield it if you got it.
        if collected: yield item, collected
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
        raise E.StructureNotFoundError(u"{:s}.by_name(\"{:s}\"{:s}) : Unable to locate a structure with the specified name.".format(__name__, utils.string.escape(res, '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else ''))

    # grab an instance of the structure by its id that we found
    return internal.structure.new(id, offset.get('offset', 0))
byname = utils.alias(by_name)

def by_index(index, **offset):
    '''Return an instance of a structure by its index.'''
    sptr = internal.structure.by_index(index)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.by_index({:d}{:s}) : Unable to locate a structure with the specified index ({:#x}).".format(__name__, index, u", {:s}".format(utils.string.kwargs(offset)) if offset else '', index))
    return internal.structure.new(sptr.id, offset.get('offset', 0))
byindex = utils.alias(by_index)

def by_identifier(identifier, **offset):
    '''Return an instance of the structure identified by `identifier`.'''
    sptr = internal.structure.by_index(identifier)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.by_identifier({:#x}{:s}) : Unable to locate a structure with the specified identifier ({:#x}).".format(__name__, identifier, u", {:s}".format(utils.string.kwargs(offset)) if offset else '', identifier))
    return internal.structure.new(sptr.id, offset.get('offset', 0))

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
    '''Return whether the database includes the given `structure`.'''
    return has(structure.id)
@utils.multicase(member=(idaapi.member_t, member_t))
def has(member):
    '''Return whether the database contains the structure used or referenced by the given `member.'''
    DT_TYPE, FF_STRUCT = idaapi.as_uint32(idaapi.DT_TYPE), idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
    packed = idaapi.get_member_by_id(member.id)
    if not packed:
        name = utils.string.of(idaapi.get_member_fullname(member.id))
        raise E.MemberNotFoundError(u"{:s}.has({:#x}) : Unable to locate the given structure member (\"{:s}\").".format(__name__, member.id, utils.string.escape(name, '"')))
    mptr, _, sptr = packed

    # If the member's flag says its a structure, then we're good.
    if mptr.flag & DT_TYPE == FF_STRUCT:
        return True

    # Otherwise, we need the type information so that we can check it.
    name = utils.string.of(idaapi.get_member_fullname(mptr.id))
    tinfo = internal.structure.member.get_typeinfo(mptr)

    # Loop while our type has details that we can continue with. If any iteration
    # of this loop lands us on a structure or union, then we found a structure.
    while tinfo.has_details():
        if tinfo.is_struct() or tinfo.is_union():
            return True

        # If we landed on an array, then we just need to unpack
        # the type from it and then we can try again.
        elif tinfo.is_array():
            data = idaapi.array_type_data_t()
            if not tinfo.get_array_details(data):
                raise E.DisassemblerError(u"{:s}.has({:#x}) : Unable to get the array element from the type information ({!r}) within the given structure member (\"{:s}\").".format(__name__, mptr.id, "{!s}".format(tinfo), utils.string.escape(name, '"')))
            tinfo = data.elem_type

        # If we landed on a pointer, then only need to
        # extract its target from the details, and try again.
        elif tinfo.is_ptr():
            data = idaapi.ptr_type_data_t()
            if not tinfo.get_ptr_details(data):
                raise E.DisassemblerError(u"{:s}.has({:#x}) : Unable to get the pointer target from the type information ({!r}) within the given structure member (\"{:s}\").".format(__name__, mptr.id, "{!s}".format(tinfo), utils.string.escape(name, '"')))
            tinfo = data.obj_type

        # If we don't know the details due to it being a bitfield, enumeration,
        # or a function pointer, then it's definitely not a structure.
        else:
            break
        continue
    return False

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
@utils.multicase(member=(idaapi.member_t, member_t))
def by(member):
    '''Return the structure used by the given `member` or the type that it points to.'''
    DT_TYPE, FF_STRUCT = idaapi.as_uint32(idaapi.DT_TYPE), idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
    packed = idaapi.get_member_by_id(member.id)
    if not packed:
        name = utils.string.of(idaapi.get_member_fullname(member.id))
        raise E.MemberNotFoundError(u"{:s}.by({:#x}) : Unable to locate the given structure member (\"{:s}\").".format(__name__, member.id, utils.string.escape(name, '"')))
    mptr, _, sptr = packed
    flag, dtype, offset = mptr.flag, mptr.flag & DT_TYPE, member.offset if isinstance(member, member_t) else 0 if internal.structure.union(sptr) else mptr.soff

    # If the member is defined as a structure, then we'll need
    # to construct an opinto_t to retrieve the member info.
    if dtype == FF_STRUCT:
        opinfo = idaapi.opinfo_t()
        res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
        if res and res.tid != idaapi.BADADDR:
            return internal.structure.new(res.tid, offset)

        name = utils.string.of(idaapi.get_member_fullname(mptr.id))
        raise E.DisassemblerError(u"{:s}.by({:#x}) : Unable to retrieve the structure for the given member (\"{:s}\").".format(__name__, mptr.id, utils.string.escape(name, '"')))

    # Otherwise, we need to extract the type information and check that instead.
    name = utils.string.of(idaapi.get_member_fullname(mptr.id))
    tinfo = internal.structure.member.get_typeinfo(mptr)

    # Complex types (structures, arrays, pointers, etc.) will always have details for their
    # contents. Therefore, we'll loop while the details exist until we get to a structure/union.
    while tinfo.has_details():
        if tinfo.is_struct() or tinfo.is_union():
            break

        # If our type is an array, then we'll extract the element type and try again.
        elif tinfo.is_array():
            data = idaapi.array_type_data_t()
            if not tinfo.get_array_details(data):
                raise E.DisassemblerError(u"{:s}.by({:#x}) : Unable to get the array element from the type information ({!r}) within the given structure member (\"{:s}\").".format(__name__, mptr.id, "{!s}".format(tinfo), utils.string.escape(name, '"')))
            tinfo = data.elem_type

        # If it's a pointer, then dereference the type from its target and try again.
        elif tinfo.is_ptr():
            data = idaapi.ptr_type_data_t()
            if not tinfo.get_ptr_details(data):
                raise E.DisassemblerError(u"{:s}.by({:#x}) : Unable to get the pointer target from the type information ({!r}) within the given structure member (\"{:s}\").".format(__name__, mptr.id, "{!s}".format(tinfo), utils.string.escape(name, '"')))
            tinfo = data.obj_type

        # Any other type that has details should be a bitfield, enumeration or
        # a function pointer. So, there's no way to continue and we can just bail
        else:
            break
        continue

    # Now we should have a type that points to a structure or something
    # else. If it's something else, then we can just completely bail.
    if not(tinfo.is_struct() or tinfo.is_union()):
        raise E.StructureNotFoundError(u"{:s}.by({:#x}) : Unable to retrieve the structure from the type information for the given member (\"{:s}\").".format(__name__, mptr.id, utils.string.escape(name, '"')))

    # The only thing we have left to do, is to figure out what structure
    # our type information references, and use it to return the structure.
    typename = tinfo.get_type_name()
    identifier = idaapi.get_struc_id(typename)
    if identifier == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by({:#x}) : Unable to find a structure using the name ({:s}) from the type information for member \"{:s}\" u.".format(__name__, mptr.id, typename, utils.string.escape(name, '"')))
    return internal.structure.new(identifier, offset)

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
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
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
    '''Return the name of the structure with the specified `id`.'''
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.name({:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, description, number))
    return utils.string.of(idaapi.get_struc_name(sptr.id))
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
        logging.info(u"{:s}.name({:d}, {!r}) : Stripping invalid chars from the structure name \"{:s}\" resulted in \"{:s}\".".format(__name__, id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
        ida_string = res

    # now we can set the name of the structure
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.name({:s}, {!r}) : Unable to locate structure with the specified {:s} ({:s}).".format(__name__, number, string, description, number))

    res, ok = idaapi.get_struc_name(sptr.id), idaapi.set_struc_name(sptr.id, ida_string)
    if not ok:
        raise E.DisassemblerError(u"{:s}.name({:d}, {!r}) : Unable to set the name of the specified structure ({:#x}) to \"{:s}\".".format(__name__, id, string, id, utils.string.escape(utils.string.of(ida_string), '"')))
    return utils.string.of(res)
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
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.comment({:s}{:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', description, number))
    res = idaapi.get_struc_cmt(sptr.id, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def comment(structure, **repeatable):
    '''Return the comment for the specified `structure`.'''
    return comment(structure.id, **repeatable)
@utils.multicase(structure=(idaapi.struc_t, structure_t), string=types.string)
@utils.string.decorate_arguments('string')
def comment(structure, string, **repeatable):
    '''Set the comment for the specified `structure` to `string`.'''
    return comment(structure.id, string, **repeatable)
@utils.multicase(structure=(idaapi.struc_t, structure_t), none=types.none)
def comment(structure, none, **repeatable):
    '''Remove the comment from the specified `structure`.'''
    return comment(structure.id, none or '', **repeatable)
@utils.multicase(id=types.integer, string=types.string)
@utils.string.decorate_arguments('string')
def comment(id, string, **repeatable):
    """Set the comment of the structure identified by `id` to the specified `string`.

    If the bool `repeatable` is specified, set the repeatable comment.
    """
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.comment({:s}, {!r}, {:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, string, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', description, number))

    res, ok = idaapi.get_struc_cmt(sptr.id, repeatable.get('repeatable', True)), idaapi.set_struc_cmt(sptr.id, utils.string.to(string), repeatable.get('repeatable', True))
    if not ok:
        raise E.StructureNotFoundError(u"{:s}.comment({:#x}, {!r}, {:s}) : Unable to set the comment of the specified structure ({:#x}) to \"{:s}\".".format(__name__, id, string, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', id, utils.string.escape(string, '"')))
    return utils.string.of(res)
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
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.index({:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, description, number))
    return idaapi.get_struc_idx(sptr.id)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def index(structure):
    '''Return the position of the specified `structure`.'''
    return index(structure.id)
@utils.multicase(id=types.integer, position=types.integer)
def index(id, position):
    '''Move the structure identified by `id` to the specified `position` of the structure list.'''
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.index({:s}, {:d}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, position, description, number))

    res, ok = idaapi.get_struc_idx(sptr.id), idaapi.set_struc_idx(sptr, position)
    if not ok:
        raise E.DisassemblerError(u"{:s}.index({:#x}, {:d}) : Unable to set the index for the specified structure ({:#x}) to {:d}.".format(__name__, id, position, id, position))
    return res
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

@utils.multicase(structure=(idaapi.struc_t, structure_t))
def size(structure):
    '''Return the size of the specified `structure`.'''
    id = structure.id
    if not interface.node.identifier(id):
        raise E.StructureNotFoundError(u"{:s}.size({:#x}) : Unable to locate the structure with the specified identifier ({:#x}).".format(__name__, id, id))
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
@utils.multicase(index=types.integer)
def size(index):
    '''Return the size of the structure at the specified `index`.'''
    sptr = internal.structure.by_index(index)
    if not sptr:
        number, description = ("{:#x}".format(index), 'with the given identifier') if interface.node.identifier(index) else ("{:d}".format(index), 'at the specified index')
        raise E.StructureNotFoundError(u"{:s}.size({:s}) : Unable to locate a structure {:s} ({:s}).".format(__name__, number, description, number))
    return idaapi.get_struc_size(sptr.id)
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

@utils.multicase(structure=(idaapi.struc_t, structure_t))
def remove(structure):
    '''Remove the specified `structure` from the database.'''
    sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
    identifier, index, name, size = (F(sptr.id) for F in [utils.fidentity, idaapi.get_struc_idx, idaapi.get_struc_name, idaapi.get_struc_size])
    if not idaapi.del_struc(sptr):
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to remove the requested structure ({:#x}).".format(__name__, structure, structure.id))
    return identifier, name, size
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
    '''Remove the structure at the specified index or `id` from the database.'''
    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.remove({:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, description, number))
    return remove(sptr)
@utils.multicase()
def remove(**type):
    '''Remove the first structure that matches the result described by `type`.'''
    res = by(**type)
    return remove(res)
delete = utils.alias(remove)

@utils.multicase(offset=types.integer, layout=types.list)
def left(offset, layout):
    '''Return the items in `layout` with the beginning of the first item aligned contiguously to the specified `offset`.'''
    iterable = interface.contiguous.left(offset, layout)
    return [item for item in iterable]
@utils.multicase(layout=types.list)
def left(anchor, layout):
    '''Return the beginning of the items in `layout` aligned contiguously from the end of the specified `anchor`, preserving the anchor's offset.'''
    offset, size = interface.contiguous.start(anchor), interface.contiguous.size(anchor if isinstance(anchor, types.list) else [anchor])
    iterable = interface.contiguous.left(offset, itertools.chain(anchor if isinstance(anchor, types.list) else [anchor], layout))
    return [item for item in iterable]

@utils.multicase(offset=types.integer, layout=types.list)
def right(offset, layout):
    '''Return the items in `layout` with the end of the last item aligned contiguously to the specified `offset`.'''
    iterable = interface.contiguous.right(offset, layout)
    return [item for item in iterable]
@utils.multicase(layout=types.list)
def right(anchor, layout):
    '''Return the ending of the items in `layout` aligned contiguously to the start of the specified `anchor`, preserving the anchor's offset.'''
    offset, size = interface.contiguous.start(anchor), interface.contiguous.size(anchor if isinstance(anchor, types.list) else [anchor])
    iterable = interface.contiguous.right(offset + size, itertools.chain(layout, anchor if isinstance(anchor, types.list) else [anchor]))
    return [item for item in iterable]

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def up(name, *suffix):
    '''Return the structure members or references that use the structure with the specified `name`.'''
    string = name if isinstance(name, types.ordered) else (name,)
    res = interface.tuplename(*tuple(itertools.chain(string, suffix)))
    sid = idaapi.get_struc_id(utils.string.to(res))
    if sid == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.up({:s}) : Unable to find a structure using the name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
    sptr = idaapi.get_struc(sid)
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]
@utils.multicase(id=types.integer)
def up(id):
    '''Return the structure members or references that use the structure with the specified `index` or `id`.'''
    sid = id if interface.node.identifier(id) else idaapi.get_struc_by_idx(id)
    sptr = idaapi.get_struc(sid)
    if not sptr:
        if interface.node.identifier(sid):
            raise E.StructureNotFoundError(u"{:s}.up({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.up({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]
@utils.multicase(structure=(structure_t, idaapi.struc_t))
def up(structure):
    '''Return the structure members or references that use the given `structure`.'''
    sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def references(name, *suffix):
    '''Return the operand references that reference the structure with the specified `name`.'''
    string = name if isinstance(name, types.ordered) else (name,)
    res = interface.tuplename(*tuple(itertools.chain(string, suffix)))
    sid = idaapi.get_struc_id(utils.string.to(res))
    if sid == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.references({:s}) : Unable to find a structure using the name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
    sptr = idaapi.get_struc(sid)
    return internal.structure.members.references(sptr)
@utils.multicase(id=types.integer)
def references(id):
    '''Return the operand references that reference the structure with the given `id` or index.'''
    sid = id if interface.node.identifier(id) else idaapi.get_struc_by_idx(id)
    sptr = idaapi.get_struc(sid)
    if not sptr:
        if interface.node.identifier(sid):
            raise E.StructureNotFoundError(u"{:s}.references({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.references({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))
    return internal.structure.members.references(sptr)
@utils.multicase(structure=(structure_t, idaapi.struc_t))
def references(structure):
    '''Return the operand references that reference the given `structure` or its members.'''
    sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
    return internal.structure.members.references(sptr)
@utils.multicase(member=(member_t, idaapi.member_t))
def references(member):
    '''Return the operand references that reference the specified `member`.'''
    mptr = member if isinstance(member, idaapi.member_t) else member.ptr
    return internal.structure.member.references(mptr)
refs = utils.alias(references)

class members(object):
    """
    This namespace is essentially a shortcut for accessing the members of
    a structure or a union. It's functionality is the same as accessing
    the "members" property of a structure that has been fetched.
    """
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea):
        '''Return the members of the structure belonging to the address specified by `ea`.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        ea = interface.address.head(ea)
        if interface.function.has(ea):
            ok, result = True, interface.function.frame(ea)
        elif interface.node.identifier(ea):
            ok, result = True, internal.structure.new(ea, 0)
        elif interface.address.flags(ea, idaapi.DT_TYPE) == FF_STRUCT:
            tid = interface.address.structure(ea)
            ok, result = not(tid == idaapi.BADADDR), None if tid == idaapi.BADADDR else internal.structure.new(tid, ea)
        else:
            ok = False
        if not ok:
            raise E.StructureNotFoundError(u"{:s}.members({:#x}) : Unable to locate a structure at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))
        return result.members
    @utils.multicase(name=types.string)
    @utils.string.decorate_arguments('name', 'suffix')
    def __new__(cls, name, *suffix):
        '''Return the members of the structure with the specified `name`.'''
        string = name if isinstance(name, types.tuple) else (name,)
        res = utils.string.to(interface.tuplename(*(string + suffix)))
        id = idaapi.get_struc_id(res)
        if id == idaapi.BADADDR:
            raise E.StructureNotFoundError(u"{:s}.members({!r}) : Unable to locate a structure with the specified name.".format(__name__, utils.string.escape(res, '"')))
        return internal.structure.new(id, 0).members
    @utils.multicase(sptr=(idaapi.struc_t, structure_t))
    def __new__(cls, sptr):
        '''Return the members of the structure specified by `sptr`.'''
        offset = sptr.baseoffset if isinstance(sptr, structure_t) else 0
        return internal.structure.new(sptr.id, offset).members

    # XXX The following functions should actually be deprecated as there are
    #     now much better ways to get the contiguous layout of a structure.
    @utils.multicase(structure=(idaapi.tinfo_t, structure_t, types.string, types.integer))
    @classmethod
    def layout(cls, structure, **base):
        '''Yield each member of the given `structure` as a tuple containing its attributes.'''
        st = by(structure)
        return cls.layout(st.ptr, **base)
    @utils.multicase(sptr=idaapi.struc_t)
    @classmethod
    def layout(cls, sptr, **base):
        """Yield each member of the structure in `sptr` as a tuple of containing its `(offset, size, tags)`.

        If the integer `base` is defined, then the offset of each member will be translated by the given value.
        """
        st, struc = (F(sptr.id) for F in [idaapi.get_struc, by])

        # If we couldn't get the structure, then blow up in the user's face.
        if st is None:
            raise E.StructureNotFoundError(u"{:s}.layout({:#x}) : Unable to find the requested structure ({:#x}).".format('.'.join([cls.__name__, __name__]), sptr.id, sptr.id))

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
    @classmethod
    def fragment(cls, structure, offset, **base):
        '''Yield each member of the given `structure` from the specified `offset` as a tuple containing its attributes.'''
        st = by(structure)
        return cls.fragment(st.ptr, offset, st.size, **base)
    @utils.multicase(structure=(idaapi.tinfo_t, structure_t, types.integer, types.string), offset=types.integer, size=types.integer)
    @classmethod
    def fragment(cls, structure, offset, size, **base):
        '''Yield each member of the given `structure` from the specified `offset` up to `size` as a tuple containing its attributes.'''
        st = by(structure)
        return cls.fragment(st.ptr, offset, size, **base)
    @utils.multicase(sptr=idaapi.struc_t, offset=types.integer, size=types.integer)
    @classmethod
    def fragment(cls, sptr, offset, size, **base):
        """Yield each member of the structure in `sptr` from the given `offset` up to `size` as a tuple containing its `(offset, size, tags)`.

        If the integer `base` is defined, then the offset of each member will be translated by the given value.
        """
        iterable, unionQ = cls.layout(sptr.id, **base), type.union(sptr.id)

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
