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
    `visible` - Match structures that are not hidden (listed) within the structure list
    `folded` - Match structures that have been folded within the structure list
    `union` - Match structures that are defined as a union
    `library` - Match structures that originate from a type library
    `variable` - Match structures that have a variable-size
    `parent` - Match structures that are nested (true) or not (false) as members of other structures
    `tagged` - Filter structures for any with the specified tag(s)
    `members` - Filter structures for any containing members with the specified tag(s)
    `count` - Filter structures by the number of members
    `anonymous` - Filter structures that are anonymously named
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

logging = logging.getLogger(__name__)
structure_t, member_t = internal.structure.structure_t, internal.structure.member_t

__matcher__ = utils.matcher()
__matcher__.combinator('iregex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(-1), internal.structure.naming.get)
__matcher__.combinator('regex', utils.fcompose(re.compile, operator.attrgetter('match')), operator.itemgetter(-1), internal.structure.naming.get)
__matcher__.attribute('index', operator.itemgetter(0))
__matcher__.attribute('identifier', operator.itemgetter(-1), 'id'), __matcher__.alias('id', 'identifier')
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(-1), internal.structure.naming.get)
__matcher__.combinator('name', utils.fcondition(utils.finstance(types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(utils.itermap, operator.methodcaller('lower')), types.set, utils.fpartial(utils.fpartial, operator.contains))), operator.itemgetter(-1), internal.structure.naming.get, operator.methodcaller('lower'))
__matcher__.combinator('size', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(interface.tinfo.size, getattr(idaapi, 'get_struc_size', utils.fconstant(idaapi.BADSIZE))))
__matcher__.boolean('ge', operator.le, operator.itemgetter(-1), utils.fcondition(utils.finstance(idaapi.tinfo_t))(interface.tinfo.size, getattr(idaapi, 'get_struc_size', utils.fconstant(idaapi.BADSIZE))))
__matcher__.boolean('gt', operator.lt, operator.itemgetter(-1), utils.fcondition(utils.finstance(idaapi.tinfo_t))(interface.tinfo.size, getattr(idaapi, 'get_struc_size', utils.fconstant(idaapi.BADSIZE)))), __matcher__.alias('greater', 'gt')
__matcher__.boolean('le', operator.ge, operator.itemgetter(-1), utils.fcondition(utils.finstance(idaapi.tinfo_t))(interface.tinfo.size, getattr(idaapi, 'get_struc_size', utils.fconstant(idaapi.BADSIZE))))
__matcher__.boolean('lt', operator.gt, operator.itemgetter(-1), utils.fcondition(utils.finstance(idaapi.tinfo_t))(interface.tinfo.size, getattr(idaapi, 'get_struc_size', utils.fconstant(idaapi.BADSIZE)))), __matcher__.alias('less', 'lt')
__matcher__.mapping('visible', operator.not_, operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(utils.fconstant(True), utils.fcompose(operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_NOLIST', 0x8)))))
__matcher__.mapping('folded', operator.truth, operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(utils.fconstant(False), utils.fcompose(operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_HIDDEN', 0x20)))))
__matcher__.mapping('union', operator.truth, operator.itemgetter(-1), 'ptr', internal.structure.union)
__matcher__.mapping('library', operator.truth, operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(utils.fconstant(True), utils.fcompose(operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_GHOST', 0x1000) | getattr(idaapi, 'SF_TYPLIB', 0x10)))))
__matcher__.mapping('variable', operator.truth, operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(operator.methodcaller('is_varstruct'), utils.fcompose(operator.attrgetter('props'), functools.partial(operator.and_, getattr(idaapi, 'SF_VAR', 1)))))

# FIXME: is it better to rename this to "nested" which makes much more sense?
__matcher__.mapping('parent', operator.truth, operator.itemgetter(-1), 'ptr', utils.fcondition(utils.finstance(idaapi.tinfo_t))(utils.fcompose(interface.tinfo.identifier, interface.xref.to, functools.partial(utils.itermap, operator.itemgetter(0)), functools.partial(utils.iterfilter, internal.structure.has_member), functools.partial(utils.itermap, utils.fcompose(internal.structure.v9members.by, operator.itemgetter(0)))), utils.fcompose(operator.attrgetter('id'), interface.xref.to, functools.partial(utils.itermap, operator.itemgetter(0)), functools.partial(utils.iterfilter, internal.structure.has_member), functools.partial(utils.itermap, utils.fcompose(idaapi.get_member_by_id, operator.itemgetter(2)) if hasattr(idaapi, 'get_member_by_id') else utils.fconstant(idaapi.BADADDR)))), functools.partial(utils.iterfilter, utils.fcompose(internal.structure.frame, operator.not_)), types.list)
__matcher__.combinator('count', utils.fcondition(utils.finstance(internal.types.unordered), utils.finstance(internal.types.bool))(utils.fcompose(internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(operator.truth, utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fcompose, utils.fpartial(operator.lt, 0))), utils.fcompose(utils.fpartial(utils.fpartial, operator.eq))), operator.itemgetter(-1), operator.attrgetter('members'), utils.icount)

__matcher__.combinator('tagged', utils.fcompose(utils.fcompose, utils.fcondition(utils.finstance(internal.types.bool, internal.types.integer), utils.finstance(internal.types.string))(utils.fcondition(operator.truth)(utils.fcompose(utils.fdiscard(internal.tags.select.structures), utils.fpartial(utils.imap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(utils.fdiscard(internal.tags.select.structures), utils.fpartial(utils.imap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, utils.fcompose(operator.contains, operator.not_)))), utils.fcompose(internal.tags.select.structures, utils.fpartial(utils.itermap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(internal.types.set, internal.tags.select.structures, utils.fpartial(utils.itermap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)))), operator.itemgetter(-1), 'id')
__matcher__.alias('tag', 'tagged'), __matcher__.alias('tags', 'tagged')
__matcher__.combinator('members', utils.fcompose(utils.fcompose, utils.fcondition(utils.finstance(internal.types.bool, internal.types.integer), utils.finstance(internal.types.string))(utils.fcondition(operator.truth)(utils.fcompose(utils.fdiscard(internal.tags.select.owners), utils.fpartial(utils.imap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(utils.fdiscard(internal.tags.select.owners), utils.fpartial(utils.imap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, utils.fcompose(operator.contains, operator.not_)))), utils.fcompose(internal.tags.select.owners, utils.fpartial(utils.itermap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(internal.types.set, internal.tags.select.owners, utils.fpartial(utils.itermap, operator.itemgetter(0)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)))), operator.itemgetter(-1), 'id')

# FIXME: should we split the names up by namespace ('::') and check each
#        one to figure out if its an anonymous name? we could also verify
#        that the character set (ucase hex) and length (32) is correct.
__matcher__.mapping('anonymous', operator.truth, operator.itemgetter(-1), internal.structure.naming.get, operator.methodcaller('startswith', '$'))

__matcher__.mapping('contiguous', functools.partial(operator.le, 0), operator.itemgetter(-1), utils.fcondition(internal.structure.union)(utils.fconstant(0), utils.fcompose(utils.fmap(utils.fcompose(operator.attrgetter('members'), functools.partial(functools.partial, operator.getitem)), utils.fcompose(operator.attrgetter('ptr'), utils.fcondition(utils.finstance(idaapi.tinfo_t))(internal.structure.v9members.count, internal.structure.members.count), builtins.range)), utils.funpack(builtins.map), utils.freverse(functools.partial(functools.reduce, lambda right, member: member.right if member.left == right else -1), 0))))
__matcher__.combinator('structure', utils.fcondition(utils.finstance(internal.structure.structuretypes))(utils.fcompose(operator.attrgetter('id'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(utils.iterfilter, utils.finstance(internal.structure.structuretypes)), utils.fpartial(utils.itermap, operator.attrgetter('id')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), operator.itemgetter(-1), 'id')
__matcher__.alias('structures', 'structure')
__matcher__.predicate('predicate'), __matcher__.alias('pred', 'predicate')

@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def __iterate__(**type):
    if not type: type = {'predicate': lambda item: True}
    iterable = ((index, sptr) for index, sptr in internal.structure.iterate())
    listable = [(index, internal.structure.new(sptr, 0)) for index, sptr in iterable]
    for key, value in type.items():
        listable = [item for item in __matcher__.match(key, value, listable)]
    for item in listable: yield item

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
    for _, item in __iterate__(**type):
        yield item
    return

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
    listable = [(index, item) for index, item in __iterate__(**type)]

    maxindex = max(builtins.map(utils.fcompose(operator.itemgetter(0), "{:d}".format, len), listable) if listable else [1])
    maxname = max(builtins.map(utils.fcompose(operator.itemgetter(-1), operator.attrgetter('name'), utils.fdefault(''), len), listable) if listable else [1])
    maxsize = max(builtins.map(utils.fcompose(operator.itemgetter(-1), operator.attrgetter('size'), "{:+#x}".format, len), listable) if listable else [1])

    SF_TYPELIB = getattr(idaapi, 'SF_TYPLIB', 0x10) | getattr(idaapi, 'SF_GHOST', 0x1000)
    SF_NOLIST = getattr(idaapi, 'SF_NOLIST', 0x8)
    SF_HIDDEN = getattr(idaapi, 'SF_HIDDEN', 0x20)
    for index, item in listable:
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

    # if we were given some parameters to use when querying, unpack them into
    # separate variables, and use them with `internal.tags.structure`. If there
    # wasn't any parameters given, then just avoid using them to get everything.
    if boolean:
        included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])
        iterable = internal.tags.select.structures(required, included)
    else:
        iterable = internal.tags.select.structures()

    # FIXME: we need to check if the structure is a frame or has a base offset
    #        stashed somewhere. not sure if it's _actually_ useful though.
    for sid, res in iterable:
        yield internal.structure.new(sid, 0), res
    return

@utils.multicase(tag=types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def selectmembers(tag, *required, **boolean):
    '''Query the structures in the database using the given `tag` in its members and any others that may be `required`.'''
    res = {tag} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return selectmembers(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def selectmembers(**boolean):
    """Query the structures in the database using the tags specified by `boolean` in its members and yield a tuple for each matching structure with selected tags.

    If `require` is given as an iterable of tag names then require that each returned structure uses them in its members.
    If `include` is given as an iterable of tag names then include the tags for each returned structure if available.
    """
    boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

    # if we were given some parameters to use when querying, unpack them into
    # separate variables, and use them with `internal.tags.structure`. If there
    # wasn't any parameters given, then just avoid using them to get everything.
    if boolean:
        included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])
        iterable = internal.tags.select.owners(required, included)
    else:
        iterable = internal.tags.select.owners()

    # FIXME: we need to check if the structure is a frame or has a base offset
    #        stashed somewhere. not sure if it's _actually_ useful though.
    for sid, res in iterable:
        yield internal.structure.new(sid, 0), res
    return

@utils.string.decorate_arguments('string', 'suffix')
def new(*string, **offset):
    """Create a new structure or union using the name specified by `string` and return it.

    If the boolean `union` is provided, then create a union instead of a structure.
    If the integer `offset` is provided, then use it as the base offset for the newly created structure.
    """
    iterable = itertools.chain(*((part if isinstance(part, internal.types.tuple) else [part]) for part in string))
    packed = tuple(iterable)
    name = interface.tuplename(*packed)
    sptr = internal.structure.create(name, offset.get('union', False))
    if not sptr:
        raise E.DisassemblerError(u"{:s}.new({:s}{:s}) : Unable to add a new {:s} to the database with the name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, packed)), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', 'union' if offset.get('union', False) else 'structure', utils.string.escape(name, '"')))
    return internal.structure.new(sptr, offset.get('offset', 0))

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
    res = interface.tuplename(*(string + suffix))
    sptr = internal.structure.by_name(res)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.by_name({!r}{:s}) : Unable to locate a structure with the specified name \"{:s}\".".format(__name__, res, u", {:s}".format(utils.string.kwargs(offset)) if offset else '', utils.string.escape(res, '"')))
    return internal.structure.new(sptr, offset.get('offset', 0))
byname = utils.alias(by_name)

def by_index(index, **offset):
    '''Return an instance of a structure by its index.'''
    sptr = internal.structure.by_index(index)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.by_index({:d}{:s}) : Unable to locate a structure with the specified index ({:#x}).".format(__name__, index, u", {:s}".format(utils.string.kwargs(offset)) if offset else '', index))
    return internal.structure.new(sptr, offset.get('offset', 0))
byindex = utils.alias(by_index)

def by_identifier(identifier, **offset):
    '''Return an instance of the structure identified by `identifier`.'''
    sptr = internal.structure.by_index(identifier)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.by_identifier({:#x}{:s}) : Unable to locate a structure with the specified identifier ({:#x}).".format(__name__, identifier, u", {:s}".format(utils.string.kwargs(offset)) if offset else '', identifier))
    return internal.structure.new(sptr, offset.get('offset', 0))
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
    return internal.structure.has(res)
@utils.multicase(structure=internal.structure.structuretypes)
def has(structure):
    '''Return whether the database includes the given `structure`.'''
    return internal.structure.has(structure)
@utils.multicase(member=internal.structure.membertypes)
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
    res = interface.tinfo.structure(tinfo)
    return internal.structure.has(res) if res else False
@utils.multicase(tinfo=idaapi.tinfo_t)
def has(tinfo):
    '''Return whether the database includes a structure for the specified `tinfo`.'''
    res = interface.tinfo.structure(tinfo)
    return internal.structure.has(res) if res else False
@utils.multicase(pythonic=(types.tuple, types.list))
def has(pythonic):
    '''Return whether the specified `pythonic` type is related to a structure.'''
    element, count = pythonic
    while isinstance(element, (types.tuple, types.list)):
        element, count = element
    return isinstance(element, (internal.structure.structuretypes, idaapi.tinfo_t)) and has(element)

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
@utils.multicase(structure=internal.structure.structuretypes)
def by(structure, **offset):
    '''Return the specified `structure` at the given `offset`.'''
    sptr = getattr(structure, 'ptr', structure)
    return internal.structure.new(sptr.id, offset.get('offset', 0))
@utils.multicase(member=internal.structure.membertypes)
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
    res = interface.tinfo.structure(tinfo)
    if not res:
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
    res = interface.tinfo.structure(tinfo)
    if res:
        return internal.structure.new(res, offset.get('offset', 0))
    raise E.InvalidTypeOrValueError(u"{:s}.by(\"{:s}\"{:s}) : Unable to determine the structure from the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', "{!s}".format(tinfo)))
@utils.multicase(pythonic=(types.tuple, types.list))
def by(pythonic, **offset):
    '''Return the structure for the specified `pythonic` type.'''
    element, count = pythonic
    while isinstance(element, (types.tuple, types.list)):
        element, count = element
    return isinstance(element, (internal.structure.structuretypes, idaapi.tinfo_t)) and by(element, **offset)

@utils.multicase()
@utils.string.decorate_arguments('regex', 'iregex', 'like', 'name')
def by(**type):
    '''Return the structure matching the keyword specified by `type`.'''
    searchstring = utils.string.kwargs(type)

    listable = [(index, item) for index, item in __iterate__(**type)]
    if len(listable) > 1:
        messages = ((u"[{:d}] {:s}".format(index, st.name)) for index, st in listable)
        [ logging.info(msg) for msg in messages ]
        logging.warning(u"{:s}.search({:s}) : Found {:d} matching results, returning the first one {!s}.".format(__name__, searchstring, len(listable), listable[0]))

    iterable = ((index, item) for (index, item) in listable)
    _, res = next(iterable, None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(id=types.integer)
def name(id):
    '''Return the name of the structure with the specified `id`.'''
    if interface.node.identifier(id) and internal.structure.has(id):
        return internal.structure.naming.get(id)

    sptr = internal.structure.by_index(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.name({!s}) : Unable to locate a structure with the specified {:s} ({!s}).".format(__name__, number, description, number))
    return internal.structure.naming.get(sptr)
@utils.multicase(structure=internal.structure.structuretypes)
def name(structure):
    '''Return the name of the given `structure`.'''
    return internal.structure.naming.get(structure)
@utils.multicase(id=types.integer, string=(types.string, types.tuple))
@utils.string.decorate_arguments('string', 'suffix')
def name(id, string, *suffix):
    '''Set the name of the structure identified by `id` to `string`.'''
    sptr = internal.structure.by_index_or_identifier(id)
    res = string if isinstance(string, types.ordered) else [string]
    string = interface.tuplename(*itertools.chain(res, suffix))

    # convert the specified string into a form that IDA can handle
    ida_string = utils.string.to(string)

    # validate the name of the structure as an identifier.
    res = interface.name.identifier(ida_string[:])
    if ida_string and ida_string != res:
        logging.info(u"{:s}.name({:#x}, {!r}) : Stripping invalid chars from the structure name \"{:s}\" resulted in \"{:s}\".".format(__name__, id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
        ida_string = res

    # now we can set the name of the structure
    return internal.structure.naming.set(sptr, ida_string)
@utils.multicase(structure=internal.structure.structuretypes, string=(types.string, types.tuple))
@utils.string.decorate_arguments('string', 'suffix')
def name(structure, string, *suffix):
    '''Set the name of the specified `structure` to `string`.'''
    return internal.structure.naming.set(structure.ptr, interface.tuplename(string, *suffix))
@utils.multicase(tinfo=idaapi.tinfo_t)
def name(tinfo):
    '''Return the name of the structure specified by `tinfo`.'''
    if tinfo.is_udt():
        return internal.structure.naming.get(tinfo)
    raise E.StructureNotFoundError(u"{:s}.name({!r}) : Unable to locate a structure using the specified type {!s}.".format(__name__, "{!s}".format(tinfo), interface.tinfo.quoted(tinfo)))
@utils.multicase(tinfo=idaapi.tinfo_t, string=(types.string, types.tuple))
@utils.string.decorate_arguments('string', 'suffix')
def name(tinfo, string, *suffix):
    '''Set the name of the structure represented by `tinfo` to `string`.'''
    structure = by(tinfo)
    return internal.structure.naming.set(structure.ptr, interface.tuplename(string, *suffix))

@utils.multicase(id=types.integer)
def comment(id, **repeatable):
    """Return the comment of the structure identified by `id`.

    If the bool `repeatable` is specified, return the repeatable comment.
    """
    if interface.node.identifier(id) and internal.structure.has(id):
        return internal.structure.comment.get(id, **repeatable)
    sptr = internal.structure.by_index(id)
    if sptr:
        return internal.structure.comment.get(sptr, **repeatable)
    number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
    raise E.StructureNotFoundError(u"{:s}.comment({:s}{!s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', description, number))
@utils.multicase(structure=internal.structure.structuretypes)
def comment(structure, **repeatable):
    '''Return the comment for the specified `structure`.'''
    sptr = getattr(structure, 'ptr', structure)
    return internal.structure.comment.get(sptr, **repeatable)
@utils.multicase(structure=internal.structure.structuretypes, string=types.string)
@utils.string.decorate_arguments('string')
def comment(structure, string, **repeatable):
    '''Set the comment for the specified `structure` to `string`.'''
    return internal.structure.comment.set(structure.ptr, string, **repeatable)
@utils.multicase(structure=internal.structure.structuretypes, none=types.none)
def comment(structure, none, **repeatable):
    '''Remove the comment from the specified `structure`.'''
    return internal.structure.comment.remove(structure.ptr, **repeatable)
@utils.multicase(id=types.integer, string=types.string)
@utils.string.decorate_arguments('string')
def comment(id, string, **repeatable):
    """Set the comment of the structure identified by `id` to the specified `string`.

    If the bool `repeatable` is specified, set the repeatable comment.
    """
    if interface.node.identifier(id) and internal.structure.has(id):
        return internal.structure.comment.set(id, string, **repeatable)
    sptr = internal.structure.by_index(id)
    if sptr:
        return internal.structure.comment.set(sptr, string, **repeatable)
    number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
    raise E.StructureNotFoundError(u"{:s}.comment({:s}, {!r}{!s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, string, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', description, number))
@utils.multicase(id=types.integer, none=types.none)
def comment(id, none, **repeatable):
    '''Remove the comment from the structure identified by `id`.'''
    if interface.node.identifier(id) and internal.structure.has(id):
        return internal.structure.comment.remove(id, **repeatable)
    sptr = internal.structure.by_index(id)
    if sptr:
        return internal.structure.comment.remove(sptr, **repeatable)
    number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
    raise E.StructureNotFoundError(u"{:s}.comment({:s}, {!s}{!s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, none, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', description, number))
@utils.multicase(tinfo=idaapi.tinfo_t)
def comment(tinfo, **repeatable):
    '''Return the comment from the structure specified by `tinfo`.'''
    if tinfo.is_udt():
        return internal.structure.comment.get(tinfo)
    raise E.StructureNotFoundError(u"{:s}.comment({!r}{!s}) : Unable to locate a structure using the specified type {!s}.".format(__name__, "{!s}".format(tinfo), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', interface.tinfo.quoted(tinfo)))
@utils.multicase(tinfo=idaapi.tinfo_t, cmt=(types.string, types.none))
def comment(tinfo, cmt, **repeatable):
    '''Modify or remove the comment from the structure specified by `tinfo`.'''
    structure = by(tinfo)
    return internal.structure.comment.set(structure.ptr, cmt, **repeatable)

@utils.multicase(id=types.integer)
def index(id):
    '''Return the position of the structure identified by `id`.'''
    sptr = internal.structure.by_index_or_identifier(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.index({:s}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, description, number))
    elif isinstance(sptr, idaapi.tinfo_t):
        return interface.tinfo.ordinal(sptr.ptr)
    return idaapi.get_struc_idx(sptr.id)
@utils.multicase(structure=internal.structure.structuretypes)
def index(structure):
    '''Return the position of the specified `structure`.'''
    if isinstance(getattr(structure, 'ptr', structure), idaapi.tinfo_t):
        return interface.tinfo.ordinal(structure.ptr)
    return idaapi.get_struc_idx(structure.id)
@utils.multicase(id=types.integer, position=types.integer)
def index(id, position):
    '''Move the structure identified by `id` to the specified `position` of the structure list.'''
    sptr = internal.structure.by_index_or_identifier(id)
    if not sptr:
        number, description = ("{:#x}".format(id), 'identifier') if interface.node.identifier(id) else ("{:d}".format(id), 'index')
        raise E.StructureNotFoundError(u"{:s}.index({:s}, {:d}) : Unable to locate a structure with the specified {:s} ({:s}).".format(__name__, number, position, description, number))

    # If the structure we got is an `idaapi.tinfo_t`, then abort completely.
    elif idaapi.__version__ > 8.4:
        number = "{:#x}".format(id) if interface.node.identifier(id) else "{:d}".format(id)
        raise E.UnsupportedCapability(u"{:s}.index({:s}, {:d}) : Unable to change the ordinal of a structure that is backed by an `{:s}`.".format(__name__, number, position, internal.utils.pycompat.fullname(idaapi.tinfo_t)))

    elif isinstance(sptr, idaapi.tinfo_t):
        sptr = idaapi.get_struc(sptr)

    # Otherwise, we can just go ahead and fuck with the index.
    res, ok = idaapi.get_struc_idx(sptr.id), idaapi.set_struc_idx(sptr, position)
    if not ok:
        raise E.DisassemblerError(u"{:s}.index({:#x}, {:d}) : Unable to set the index for the specified structure ({:#x}) to {:d}.".format(__name__, sptr.id, position, sptr.id, position))
    return res
@utils.multicase(structure=internal.structure.structuretypes, position=types.integer)
def index(structure, position):
    '''Move the specified `structure` to the specified `position` of the structure list.'''
    sptr, sid = getattr(structure, 'ptr', structure), structure.id
    if idaapi.__version__ > 8.4 and isinstance(sptr, idaapi.tinfo_t):
        raise E.UnsupportedCapability(u"{:s}.index({:#x}, {:d}) : Unable to change the ordinal of a structure that is backed by an `{:s}`.".format(__name__, sid, position, internal.utils.pycompat.fullname(idaapi.tinfo_t)))
    return index(sid, position)
@utils.multicase(tinfo=idaapi.tinfo_t)
def index(tinfo):
    '''Return the index of the structure specified by `tinfo`.'''
    if not tinfo.is_udt():
        raise E.StructureNotFoundError(u"{:s}.index({!r}) : Unable to locate a structure using the specified type {!s}.".format(__name__, "{!s}".format(tinfo), interface.tinfo.quoted(tinfo)))
    id = interface.tinfo.identifier(tinfo)
    return index(id)
@utils.multicase(tinfo=idaapi.tinfo_t, position=types.integer)
def index(tinfo, position):
    '''Move the structure represented by `tinfo` to the specified `position` of the structure list.'''
    if not tinfo.is_udt():
        raise E.StructureNotFoundError(u"{:s}.index({!r}, {:d}) : Unable to locate a structure using the specified type {!s}.".format(__name__, "{!s}".format(tinfo), position, interface.tinfo.quoted(tinfo)))
    id = interface.tinfo.identifier(tinfo)
    return index(id, position)

@utils.multicase(structure=internal.structure.structuretypes)
def size(structure):
    '''Return the size of the specified `structure`.'''
    sptr = getattr(structure, 'ptr', structure)
    if isinstance(sptr, idaapi.tinfo_t):
        return interface.tinfo.size(sptr)
    sid = sptr.id
    if interface.node.identifier(sid) and internal.structure.has(sid):
        return idaapi.get_struc_size(sid)
    raise E.StructureNotFoundError(u"{:s}.size({:#x}) : Unable to locate the structure with the specified identifier ({:#x}).".format(__name__, sid, osid))
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def size(name, *suffix):
    '''Return the size of the structure with the specified `name`.'''
    string = name if isinstance(name, types.tuple) else (name,)
    res = interface.tuplename(*(string + suffix))
    if not internal.structure.has(res):
        description = (("{:#x}".format(item) if isinstance(item, types.integer) else "{!r}".format(item)) for item in suffix)
        raise E.StructureNotFoundError(u"{:s}.size({!r}) : Unable to locate a structure with the name \"{:s}\".".format(__name__, name, ", {:s}".format(', '.join(description)) if suffix else '', utils.string.escape(res, '"')))
    sptr = by_name(res)
    if isinstance(sptr.ptr, idaapi.tinfo_t):
        return interface.tinfo.size(sptr.ptr)
    return idaapi.get_struc_size(sptr.id)
@utils.multicase(index=types.integer)
def size(index):
    '''Return the size of the structure at the specified `index`.'''
    sptr = internal.structure.by_index(index)
    if not sptr:
        number, description = ("{:#x}".format(index), 'with the given identifier') if interface.node.identifier(index) else ("{:d}".format(index), 'at the specified index')
        raise E.StructureNotFoundError(u"{:s}.size({:s}) : Unable to locate a structure {:s} ({:s}).".format(__name__, number, description, number))
    if isinstance(sptr, idaapi.tinfo_t):
        return interface.tinfo.size(sptr)
    return idaapi.get_struc_size(sptr.id)
@utils.multicase(tinfo=idaapi.tinfo_t)
def size(tinfo):
    '''Return the size of the structure represented by `tinfo`.'''
    res = interface.tinfo.structure(tinfo)
    if not res:
        raise E.StructureNotFoundError(u"{:s}.size({!r}) : Unable to locate a structure using the specified type {!s}.".format(__name__, "{!s}".format(tinfo), interface.tinfo.quoted(tinfo)))
    return interface.tinfo.size(res)
@utils.multicase(pythonic=(types.tuple, types.list))
def size(pythonic):
    '''Return the size of the structure specified as a `pythonic` type.'''
    if not has(pythonic):
        raise E.StructureNotFoundError(u"{:s}.size({!s}) : Unable to locate a structure using the specified pythonic type.".format(__name__, pythonic))
    return interface.typemap.size(pythonic)

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
        if not internal.structure.has(id):
            raise E.StructureNotFoundError(u"{:s}.union({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return internal.structure.union(id)
    @utils.multicase(structure=internal.structure.structuretypes)
    @classmethod
    def union(cls, structure):
        '''Return whether the provided `structure` is defined as a union.'''
        sptr = getattr(structure, 'ptr', structure)
        return internal.structure.union(sptr)
    @utils.multicase(tinfo=idaapi.tinfo_t)
    @classmethod
    def union(cls, tinfo):
        '''Return whether the structure represented by `tinfo` is defined as a union.'''
        return internal.structure.union(tinfo)
    is_union = utils.alias(union, 'type')

    @utils.multicase(id=types.integer)
    @classmethod
    def frame(cls, id):
        '''Return whether the structure identified by `id` is a frame or not.'''
        if not internal.structure.has(id):
            raise E.StructureNotFoundError(u"{:s}.frame({!r}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return internal.structure.frame(id)
    @utils.multicase(structure=internal.structure.structuretypes)
    @classmethod
    def frame(cls, structure):
        '''Return whether the provided `structure` is a frame or not.'''
        sptr = getattr(structure, 'ptr', structure)
        return internal.structure.frame(sptr)
    is_frame = utils.alias(frame, 'type')

    @utils.multicase(id=types.integer)
    @classmethod
    def listed(cls, id):
        '''Return whether the structure identified by `id` is listed.'''
        sptr = internal.structure.by_index_or_identifier(id)
        if not sptr:
            raise E.StructureNotFoundError(u"{:s}.listed({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        return cls.listed(sptr)
    @utils.multicase(structure=internal.structure.structuretypes)
    @classmethod
    def listed(cls, structure):
        '''Return whether the provided `structure` is listed.'''
        sptr, sid = getattr(structure, 'ptr', structure), structure.id
        if idaapi.__version__ < 8.5 and isinstance(sptr, idaapi.tinfo_t):
            sptr = internal.structure.by_index_or_identifier(sid)
        if not isinstance(sptr, idaapi.tinfo_t):
            SF_NOLIST = getattr(idaapi, 'SF_NOLIST', 0x8)
            return False if sptr.props & SF_NOLIST else True
        return True
    @utils.multicase(tinfo=idaapi.tinfo_t)
    @classmethod
    def listed(cls, tinfo):
        '''Return whether the structure represented by `tinfo` is listed.'''
        sptr, sid = tinfo, interface.tinfo.identifier(tinfo)
        if idaapi.__version__ < 8.5:
            sptr = internal.structure.by_index_or_identifier(sid)
        return True if isinstance(sptr, idaapi.tinfo_t) else cls.listed(sptr)
    @utils.multicase(id=types.integer)
    @classmethod
    def listed(cls, id, boolean):
        '''Update the structure specified by `id` so that it is listed if the given `boolean` is true.'''
        sptr = internal.structure.by_index_or_identifier(id)
        if not sptr:
            raise E.StructureNotFoundError(u"{:s}.listed({:#x}, {!s}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, True if boolean else False, id))
        if idaapi.__version__ < 8.5 and isinstance(sptr, idaapi.tinfo_t):
            sptr = idaapi.get_struc(id)
        elif isinstance(sptr, idaapi.tinfo_t):
            raise E.UnsupportedCapability(u"{:s}.listed({:#x}, {!s}) : This functionality is not supported on your version ({!s}) and is only supported on versions prior to {!s}.".format(__name__, id, True if boolean else False, idaapi.__version__, 8.4))
        return cls.listed(sptr, boolean)
    @utils.multicase(tinfo=idaapi.tinfo_t)
    @classmethod
    def listed(cls, tinfo, boolean):
        '''Update the structure represented by `tinfo` so that it is listed if the given `boolean` is true.'''
        sptr, sid = tinfo, interface.tinfo.identifier(tinfo)
        if idaapi.__version__ > 8.4 and isinstance(tinfo, idaapi.tinfo_t):
            raise E.UnsupportedCapability(u"{:s}.listed({:#x}, {!s}) : This functionality is not supported on your version ({!s}) and is only supported on versions prior to {!s}.".format(__name__, sid, True if boolean else False, idaapi.__version__, 8.4))
        sptr = internal.structure.by_index_or_identifier(sid)
        return cls.listed(sid if isinstance(sptr, idaapi.tinfo_t) else sptr, boolean)
    @utils.multicase(structure=internal.structure.structuretypes)
    @classmethod
    def listed(cls, structure, boolean):
        '''Update the specified `structure` so that it is listed if the given `boolean` is true.'''
        sptr, sid = getattr(structure, 'ptr', structure), structure.id
        if isinstance(sptr, idaapi.tinfo_t):
            return cls.listed(sptr, boolean)
        result, _ = cls.listed(sptr), idaapi.set_struc_listed(sptr, boolean)
        return result
is_union, is_frame, is_listed = utils.alias(type.union, 'type'), utils.alias(type.frame, 'type'), utils.alias(type.listed, 'type')

@utils.multicase(structure=internal.structure.structuretypes)
def remove(structure):
    '''Remove the specified `structure` from the database.'''
    sptr, sid = getattr(structure, 'ptr', structure), structure.id
    if idaapi.__version__ < 8.5 and not isinstance(sptr, idaapi.tinfo_t):
        identifier, index, name, size = (F(sptr.id) for F in [utils.fidentity, idaapi.get_struc_idx, idaapi.get_struc_name, idaapi.get_struc_size])
        if not idaapi.del_struc(sptr):
            raise E.DisassemblerError(u"{:s}.remove({:#x}) : Unable to remove the requested structure ({:#x}).".format(__name__, sid, sid))
        return identifier, name, size
    return remove(sptr)
@utils.multicase(name=(types.string, types.tuple))
@utils.string.decorate_arguments('name', 'suffix')
def remove(name, *suffix):
    '''Remove the structure with the specified `name`.'''
    realname = interface.tuplename(*itertools.chain(name if isinstance(name, types.tuple) else [name], suffix))
    sptr = internal.structure.by_name(realname)
    if not sptr:
        raise E.StructureNotFoundError(u"{:s}.remove({!r}) : Unable to locate a structure with the name \"{:s}\".".format(__name__, realname, utils.string.escape(name, '"')))
    return remove(sptr)
@utils.multicase(tinfo=idaapi.tinfo_t)
def remove(tinfo):
    '''Remove the structure represented by the given `tinfo`.'''
    sid = interface.tinfo.identifier(tinfo)
    if not tinfo.is_udt() or not internal.structure.has(sid):
        raise E.InvalidTypeOrValueError(u"{:s}.remove({!r}) : Unable to determine the ordinal for a type that is not a structure or a union.".format(__name__, "{!s}".format(tinfo)))
    elif idaapi.__version__ < 8.5:
        sptr = idaapi.get_struc(sid)
        return remove(sptr)
    elif interface.tinfo.ordinal(tinfo):
        ordinal = interface.tinfo.ordinal(tinfo)
    else:
        description = 'union' if interface.structure.union(tinfo) else 'structure'
        raise E.StructureNotFoundError(u"{:s}.remove({!r}) : Unable to determine the ordinal for a {:s} with the type {!s}.".format(__name__, "{!s}".format(tinfo), description, interface.tinfo.quoted(tinfo)))

    # now we can go ahead and remove the type from the type library.
    res = interface.tinfo.at_ordinal(ordinal)
    library = interface.tinfo.library(res)
    if res and not idaapi.del_numbered_type(library, ordinal):
        description = 'union' if interface.structure.union(res) else 'structure'
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to remove the {:s} at ordinal {:d} of the current type library.".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), description, ordinal))
    elif not res:
        description = 'union' if interface.structure.union(res) else 'structure'
        raise E.LocalTypeNotFoundError(u"{:s}.remove({!r}) : Unable to get the {:s} at ordinal {:d} of the current type library.".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), description, ordinal))
    Fs = interface.tinfo.identifier, operator.methodcaller('get_type_name'), interface.tinfo.size
    return tuple(F(res) for F in Fs)
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

    # If we don't have the `struc_t` available, then we're using the new
    # structure api which is based on `idaapi.tinfo_t`. So, we start by getting
    # the type and then verifying that it actually is a structure.
    if not hasattr(idaapi, 'struc_t'):
        ti = interface.tinfo.for_name(res)
        if not ti:
            raise E.StructureNotFoundError(u"{:s}.up({:s}) : Unable to find a structure using the specified name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
        elif not ti.is_udt():
            raise E.InvalidTypeOrValueError(u"{:s}.up({:s}) : The type returned for the specified name \"{:s}\" is not a structure or a union.".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))

        # Just pass this through to `xref.structure` which supports both.
        sptr = ti

    # Otherwise, we need to use the older structure api which requires us to use
    # the name to get an identifier that we can check the references of.
    else:
        sid = idaapi.get_struc_id(utils.string.to(res))
        if sid == idaapi.BADADDR:
            raise E.StructureNotFoundError(u"{:s}.up({:s}) : Unable to find a structure using the name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
        sptr = idaapi.get_struc(sid)
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]
@utils.multicase(id=types.integer)
def up(id):
    '''Return the structure members or references that use the structure with the specified `index` or `id`.'''
    if interface.node.identifier(id):
        sid = id

    # If we weren't given an identifier, then we were given an index which
    # depends on whether we're using the old or new structure api.
    elif hasattr(idaapi, 'get_struc_by_idx'):
        sid = idaapi.get_struc_by_idx(id)
    elif interface.tinfo.has_ordinal(id):
        ti = interface.tinfo.for_ordinal(id)
        sid = interface.tinfo.identifier(ti)
    else:
        sid = idaapi.BADADDR

    # If we error'd out, then figure out what we were given to throw an error.
    if sid == idaapi.BADADDR:
        if interface.node.identifier(id):
            raise E.StructureNotFoundError(u"{:s}.up({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.up({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))

    # If we can't use the old structure api, then we need to grab the type and
    # then return the references to it using the regular `xref.structure` api.
    if not hasattr(idaapi, 'struc_t'):
        ordinal = interface.tinfo.by_identifier(id)
        ti = interface.tinfo.for_ordinal(ordinal)
        return [reference_or_member for reference_or_member in internal.structure.xref.structure(ti)]

    # Otherwise, we can just go and use the old structure api.
    sptr = idaapi.get_struc(sid)
    if not sptr:
        if interface.node.identifier(sid):
            raise E.StructureNotFoundError(u"{:s}.up({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.up({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]
@utils.multicase(structure=(idaapi.tinfo_t, internal.structure.structuretypes))
def up(structure):
    '''Return the structure members or references that use the given `structure`.'''
    sptr = structure if isinstance(structure, idaapi.tinfo_t) else getattr(structure, 'ptr', structure)
    return [reference_or_member for reference_or_member in internal.structure.xref.structure(sptr)]

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def references(name, *suffix):
    '''Return the operand references that reference the structure with the specified `name`.'''
    string = name if isinstance(name, types.ordered) else (name,)
    res = interface.tuplename(*tuple(itertools.chain(string, suffix)))

    # If there's no `struc_t`, then we're using a version of the disassembler
    # that requires using the `tinfo_t`-backed version of the structure api.
    if not hasattr(idaapi, 'struc_t'):
        ti = interface.tinfo.for_name(res)
        if not ti:
            raise E.StructureNotFoundError(u"{:s}.references({:s}) : Unable to find a structure using the specified name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
        elif not ti.is_udt():
            raise E.InvalidTypeOrValueError(u"{:s}.references({:s}) : The type returned for the specified name \"{:s}\" is not a structure or a union.".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
        return internal.structure.v9members.references(ti)

    # Otherwise we can go ahead and use the older structure api to do things.
    sid = idaapi.get_struc_id(utils.string.to(res))
    if sid == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.references({:s}) : Unable to find a structure using the name \"{:s}\".".format(__name__, ', '.join(map("{!r}".format, itertools.chain(name if isinstance(name, types.ordered) else [name], suffix))), utils.string.escape(res, '"')))
    sptr = idaapi.get_struc(sid)
    return internal.structure.members.references(sptr)
@utils.multicase(id=types.integer)
def references(id):
    '''Return the operand references that reference the structure with the given `id` or index.'''
    if interface.node.identifier(id):
        sid = id
    elif hasattr(idaapi, 'get_struc_by_idx'):
        sid = idaapi.get_struc_by_idx(id)
    elif interface.tinfo.has_ordinal(id):
        ti = interface.tinfo.for_ordinal(id)
        sid = interface.tinfo.identifier(ti)
    else:
        sid = idaapi.BADADDR

    # Now we have an identifier that we need to check. If it's an error value,
    # then we need to distinguish whether it's an identifier or an index.
    if sid == idaapi.BADADDR:
        if interface.node.identifier(id):
            raise E.StructureNotFoundError(u"{:s}.references({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.references({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))

    # Check if the `struc_t` exists to check if the old structure api is
    # available. If it doesn't exist, then we need to grab the type and return
    # the references to it using the regular `member.references` api.
    if not hasattr(idaapi, 'struc_t'):
        ordinal = interface.tinfo.by_identifier(id)
        ti = interface.tinfo.for_ordinal(ordinal)
        return internal.structure.v9members.references(ti)

    # Otherwise we can just go ahead and use the old structure api. Since we can
    # be given any kind of identifier, we check if it's a structure first. If
    # that failed, then we can try to see if it belongs to a member.
    sptr = idaapi.get_struc(sid) or idaapi.get_member_by_id(sid)
    if not sptr:
        if interface.node.identifier(sid):
            raise E.StructureNotFoundError(u"{:s}.references({:#x}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, id, id))
        raise E.StructureNotFoundError(u"{:s}.references({:d}) : Unable to find a structure at the specified index ({:d}).".format(__name__, id, id))

    # If we got a tuple back, then we can just go and unpack the mptr from it so
    # that we can use it with the `internal.structure.member.references` api.
    elif isinstance(sptr, internal.types.tuple):
        mptr, fullname, sptr = sptr
        return internal.structure.member.references(mptr)
    return internal.structure.members.references(sptr)
@utils.multicase(structure=(idaapi.tinfo_t, internal.structure.structuretypes))
def references(structure):
    '''Return the operand references that reference the given `structure` or its members.'''
    sptr = getattr(structure, 'ptr', structure)
    if isinstance(sptr, idaapi.tinfo_t):
        return internal.structure.v9members.references(sptr)
    return internal.structure.members.references(sptr)
@utils.multicase(member=internal.structure.membertypes)
def references(member):
    '''Return the operand references that reference the specified `member`.'''
    if isinstance(member, internal.structure.member_t) and isinstance(member.parent.ptr, idaapi.tinfo_t):
        return internal.structure.v9member.references(member.id)
    mptr = getattr(member, 'ptr', member)
    return internal.structure.member.references(mptr)
refs = utils.alias(references)

def tags():
    '''Return the tag names used by all of the structures within the database.'''
    return internal.tags.reference.structure.usage()

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
    @utils.multicase(sptr=internal.structure.structuretypes)
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

    @utils.multicase(structure=(internal.structure.structuretypes, idaapi.tinfo_t, types.integer, types.string), offset=types.integer)
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

    @classmethod
    def tags(cls):
        '''Return the tag names used by all of the members from structures within the database.'''
        return internal.tags.reference.members.usage()
