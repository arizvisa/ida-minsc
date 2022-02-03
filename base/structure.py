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

    `name` - Match the structures to a structure name
    `like` - Filter the structure names according to a glob
    `regex` - Filter the structure names according to a regular-expression
    `index` - Match the structures by its index
    `identifier` or `id` - Match the structure by its id which is a ``idaapi.uval_t``
    `size` - Filter the structures for any matching the specified size
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

import six, builtins

import functools, operator, itertools, types
import sys, logging
import re, fnmatch

import database, instruction
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

@utils.multicase(id=six.integer_types)
def has(id):
    '''Return whether a structure with the specified `id` exists within the database.'''
    return True if interface.node.is_identifier(id) and idaapi.get_struc(id) else False
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def has(name):
    '''Return if a structure with the specified `name` exists within the database.'''
    res = utils.string.to(name)
    return has(idaapi.get_struc_id(res))
@utils.multicase(structure=idaapi.struc_t)
def has(structure):
    '''Return whether the database includes the provided `structure`.'''
    return has(structure.id)

def __instance__(identifier, **options):
    '''Create a new instance of the structure identified by `identifier`.'''
    return structure_t(identifier, **options)

__matcher__ = utils.matcher()
__matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.mapping('index', idaapi.get_struc_idx, 'id')
__matcher__.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
__matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
__matcher__.boolean('name', lambda name, item: item.lower() == name.lower(), 'name')
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
        yield __instance__(id)
        res = idaapi.get_next_struc_idx(res)

    res = idaapi.get_last_struc_idx()
    if res != idaapi.BADADDR:
        yield __instance__(idaapi.get_struc_by_idx(res))
    return

@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def iterate(string):
    '''Iterate through all of the structures in the database with a glob that matches `string`.'''
    return iterate(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def iterate(**type):
    '''Iterate through all of the structures that match the keyword specified by `type`.'''
    if not type: type = {'predicate': lambda item: True}
    listable = [item for item in __iterate__()]
    for key, value in type.items():
        listable = [item for item in __matcher__.match(key, value, listable)]
    for item in listable: yield item

@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def list(string):
    '''List any structures that match the glob in `string`.'''
    return list(like=string)
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

@utils.multicase(string=(six.string_types, tuple))
@utils.string.decorate_arguments('string', 'suffix')
def new(string, *suffix, **offset):
    """Return a new structure using the name specified by `string`.

    If the integer `offset` is provided, then use it as the base offset for the newly created structure.
    """
    res = string if isinstance(string, tuple) else (string,)
    name = interface.tuplename(*(res + suffix))

    # add a structure with the specified name
    realname = utils.string.to(name)
    id = idaapi.add_struc(idaapi.BADADDR, realname)
    if id == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({:s}{:s}) : Unable to add a new structure to the database with the specified name ({!r}).".format(__name__, ', '.join(map("{!r}".format, res + suffix)), u", {:s}".format(utils.string.kwargs(offset)) if offset else '', name))

    # return a new instance using the specified identifier
    return __instance__(id, **offset)

@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def by(name, **options):
    '''Return the structure with the given `name`.'''
    return by_name(name, **options)
@utils.multicase(id=six.integer_types)
def by(id, **options):
    '''Return the structure with the specified `id` or index.'''
    if interface.node.is_identifier(id):
        return __instance__(id, **options)
    return by_index(id, **options)
@utils.multicase(sptr=idaapi.struc_t)
def by(sptr, **options):
    '''Return the structure for the specified `sptr`.'''
    return __instance__(sptr.id, **options)
@utils.multicase(tinfo=idaapi.tinfo_t)
def by(tinfo, **options):
    '''Return the structure for the specified `tinfo`.'''
    if tinfo.is_struct():
        return by_name(tinfo.get_type_name(), **options)

    # If the type information is not a pointer, then we really don't know what
    # to do with this and so we raise an exception.
    elif not tinfo.is_ptr():
        raise E.InvalidTypeOrValueError(u"{:s}.by(\"{:s}\"{:s}) : Unable to locate structure for the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', "{!s}".format(tinfo)))

    # If there are no details, then raise an exception because we need to
    # dereference the pointer to get the real name.
    if not tinfo.has_details():
        raise E.DisassemblerError(u"{:s}.by(\"{:s}\"{:s}) : The provided type information ({!r}) does not contain any details.".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', "{!s}".format(tinfo)))

    # Now we can grab our pointer and extract the object from it, At this
    # point we continue by recursing back into ourselves. This way we can
    # repeatedly dereference a pointer until we get to a structure.
    pi = idaapi.ptr_type_data_t()
    if not tinfo.get_ptr_details(pi):
        raise E.DisassemblerError(u"{:s}.by(\"{:s}\"{:s}) : Unable to get the pointer target from the provided type information ({!r}).".format(__name__, utils.string.escape("{!s}".format(tinfo), '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', "{!s}".format(tinfo)))
    return by(pi.obj_type, **options)
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

@utils.multicase(string=six.string_types)
def search(string):
    '''Search through all the structure names matching the glob `string`.'''
    return by(like=string)
@utils.multicase()
def search(**type):
    '''Search through all of the structures and return the first result matching the keyword specified by `type`.'''
    return by(**type)

@utils.string.decorate_arguments('name')
def by_name(name, **options):
    '''Return a structure by its name.'''
    res = utils.string.to(name)

    # try and find the structure id according to its name
    id = idaapi.get_struc_id(res)
    if id == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by_name(\"{:s}\"{:s}) : Unable to locate structure with given name.".format(__name__, utils.string.escape(name, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else ''))

    # grab an instance of the structure by its id that we found
    return __instance__(id, **options)
byname = utils.alias(by_name)

def by_index(index, **options):
    '''Return a structure by its index.'''
    id = idaapi.get_struc_by_idx(index)
    if id == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by_index({:d}{:s}) : Unable to locate structure at given index.".format(__name__, index, u", {:s}".format(utils.string.kwargs(options)) if options else ''))

    # grab an instance of the structure by the id we found
    return __instance__(id, **options)
byindex = utils.alias(by_index)

def by_identifier(identifier, **options):
    '''Return the structure identified by `identifier`.'''
    return __instance__(identifier, **options)

by_id = byidentifier = byId = utils.alias(by_identifier)

### structure_t abstraction
class structure_t(object):
    """
    This object is an abstraction around an IDA structure type. This
    allows for one to treat an IDA structure as a regular python object.
    A number of methods and properties are provided in order to access
    certain attributes of the structure.

    To access the members belonging to the structure, one can use the
    ``.members`` property. This property is intended to be treated as an
    array in order to access the different elements available. This
    property also allows a user to create a new member or remove an
    already existing one.
    """
    __slots__ = ('__ptr__', '__name__', '__members__')

    def __init__(self, sptr, offset=0):
        if not isinstance(sptr, (idaapi.struc_t, six.integer_types)):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({!s}, offset={:+#x}) : Unable to instantiate a structure using the provided type ({!s}).".format('.'.join([__name__, cls.__name__]), sptr, offset, sptr))

        # Use the type of our parameter in order to get a proper
        # struc_t. If we didn't get one, then we likely got an identifier
        # that we need to use with idaapi.get_struc to get our sptr.
        ptr = sptr if isinstance(sptr, idaapi.struc_t) else idaapi.get_struc(sptr)
        if ptr is None:
            cls = self.__class__
            raise E.StructureNotFoundError(u"{:s}({!s}, offset={:+#x}) : Unable to locate the structure with the specified parameter ({!s}).".format('.'.join([__name__, cls.__name__]), sptr, offset, sptr))

        # After we verified our parameter and got a proper type, then
        # grab the name using its id. We cache both the sptr and the
        # structure's name in case one of them changes. This way we
        # can figure out the other one in that situation.
        name = idaapi.get_struc_name(ptr.id)
        self.__ptr__, self.__name__ = ptr, name

        # The final thing to do is instantiate the members property
        # so that users can interact with the structure members.
        self.__members__ = members_t(self, baseoffset=offset)

    @utils.multicase()
    def tag(self):
        '''Return the tags associated with the structure.'''
        repeatable = True

        # grab the repeatable and non-repeatable comment for the structure
        res = utils.string.of(idaapi.get_struc_cmt(self.id, False))
        d1 = internal.comment.decode(res)
        res = utils.string.of(idaapi.get_struc_cmt(self.id, True))
        d2 = internal.comment.decode(res)

        # check for duplicate keys
        if six.viewkeys(d1) & six.viewkeys(d2):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment() : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('.'.join([__name__, cls.__name__]), self.id, ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it (XXX: return a dictionary that automatically updates the comment when it's updated)
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]
        return res
    @utils.multicase(key=six.string_types)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the structure.'''
        res = self.tag()
        return res[key]
    @utils.multicase(key=six.string_types)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the structure.'''
        state = self.tag()
        repeatable, res, state[key] = True, state.get(key, None), value
        ok = idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), repeatable)
        return res
    @utils.multicase(key=six.string_types, none=None.__class__)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the structure.'''
        state = self.tag()
        repeatable, res = True, state.pop(key)
        ok = idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), repeatable)
        return res

    def destroy(self):
        '''Remove the structure from the database.'''
        return idaapi.del_struc(self.ptr)

    def field(self, offset):
        '''Return the member at the specified offset.'''
        return self.members.by_offset(offset + self.members.baseoffset)

    def copy(self, name):
        '''Copy members into the structure `name`.'''
        raise NotImplementedError

    def contains(self, offset):
        '''Return whether the specified `offset` is contained by the structure.'''
        res, cb = self.members.baseoffset, idaapi.get_struc_size(self.ptr)
        return res <= offset < res + cb

    def refs(self):
        '''Return all the structure members and operand references which reference this specific structure.'''
        Fnetnode = getattr(idaapi, 'ea2node', utils.fidentity)
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # First collect all of our identifiers referenced by this structure,
        # whilst making sure to include all the members too.
        iterable = itertools.chain([self.id], map(Fnetnode, map(operator.attrgetter('id'), self.members)))
        items = [identifier for identifier in iterable]

        # Now we need to iterate through all of our members and grab references
        # to those identifiers too.
        refs = []
        for identifier in items:
            X = idaapi.xrefblk_t()

            # Grab the very first reference for the given identifier.
            if not X.first_to(identifier, idaapi.XREF_ALL) or X.frm == idaapi.BADADDR:
                continue
            refs.append((X.frm, X.iscode, X.type))

            # Continue and grab the rest of the references too.
            while X.next_to():
                refs.append((X.frm, X.iscode, X.type))
            continue

        # That should've given us absolutely every reference related to this
        # structure, so the last thing to do is to filter our list for references
        # to addresses within the database.
        results, matches = {item for item in []}, {identifier for identifier in items}
        for xrfrom, xriscode, xrtype in refs:

            # If the reference is an identifier, then it's not what we're looking
            # for as this method only cares about database addresses.
            if interface.node.is_identifier(xrfrom):
                continue

            # We need to figure out whether this is code or not, because if so
            # then this'll be ref'd by an operand and we'll need to figure it out.
            if database.type.is_code(xrfrom):

                # Iterate through all of its operands and only care about the
                # ones that have operand information for it. We also keep track
                # of any operands that have a refinfo_t so we can add those too.
                references = {item for item in []}
                for opnum, _ in enumerate(instruction.operands(xrfrom)):
                    opinfo = instruction.opinfo(xrfrom, opnum)
                    if opinfo is None:
                        continue

                    # Collect the operand information into a proper path in case
                    # the opinfo_t is damaged...which happens sometimes.
                    ofs, path = interface.node.get_stroff_path(xrfrom, opnum)

                    # If we grabbed a path, then we can use it to grab the
                    # structure and all of its member identifiers.
                    if path:
                        _, members = interface.node.calculate_stroff_path(ofs, path)

                        # Now we need to convert these pairs into a set so that we can
                        # test their membership.
                        iterable = itertools.chain(*(map(operator.attrgetter('id'), pair) for pair in members))
                        candidates = {identifier for identifier in iterable}

                        # Verify that one of our ids is contained within it.
                        if candidates & matches:
                            state = instruction.op_state(xrfrom, opnum)
                            item = interface.opref_t(xrfrom, opnum, interface.reftype_t.of_action(state))
                            results.add(item)
                        continue

                    # Otherwise this is likely a refinfo, and we need to follow
                    # the reference in order to grab _all_ of its references.
                    drefs = [ea for ea in database.xref.down(xrfrom) if not interface.node.is_identifier(ea)]
                    references |= {ea for ea in itertools.chain(*map(database.xref.up, drefs))}

                # Last thing to do is to add the references that we collected while
                # searching through the operands.
                for ea in references:
                    for opnum in filter(functools.partial(instruction.op_refinfo, ea), range(instruction.ops_count(ea))):
                        state = instruction.op_state(ea, opnum)
                        results.add(interface.opref_t(ea, opnum, interface.reftype_t.of_action(state)))
                    continue

            # Anything else is data which doesn't have an operand associated with
            # it, so we can just use the regular ref_t for this case. We use '*'
            # for the reference type since this is being applied to an address.
            else:
                item = interface.ref_t(xrfrom, None, interface.reftype_t.of_action('*'))
                results.add(item)
            continue
        return sorted(results)

    def up(self):
        '''Return all structure or frame members within the database that reference this particular structure.'''
        X, sid = idaapi.xrefblk_t(), self.id

        # Grab the first reference to the structure.
        if not X.first_to(sid, idaapi.XREF_ALL):
            return []

        # Continue to grab all the rest of its references.
        refs = [(X.frm, X.iscode, X.type)]
        while X.next_to():
            refs.append((X.frm, X.iscode, X.type))

        # Iterate through each reference figuring out if our structure's id is
        # applied to another structure type.
        res = []
        for ref, _, _ in refs:

            # If the reference is not an identifier, then we don't care about it because
            # it's pointing to code and the structure_t.refs method is for those refs.
            if not interface.node.is_identifier(ref):
                continue

            # Get mptr, full member name, and sptr for the reference (which should
            # totally be an identifier due to the previous conditional).
            mpack = idaapi.get_member_by_id(ref)
            if mpack is None:
                cls = self.__class__
                raise E.MemberNotFoundError(u"{:s}({:#x}).refs() : Unable to locate the member identified by {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, ref))

            mptr, name, sptr = mpack
            if not interface.node.is_identifier(sptr.id):
                sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

            # Validate that the type of the mptr is what we're expecting.
            if not isinstance(mptr, idaapi.member_t):
                cls, name = self.__class__, idaapi.get_member_fullname(ref)
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}).refs() : Unexpected type {!s} returned for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, mptr.__class__, internal.utils.string.escape(name, '"')))

            # Figure out from mptr identifier if we're referencing a function frame.
            frname, _ = name.split('.', 1)
            frid = internal.netnode.get(frname)
            ea = idaapi.get_func_by_frame(frid)

            # If we were unable to get the function frame, then we must be
            # referencing the member of another structure.
            if ea == idaapi.BADADDR:
                st = by_identifier(sptr.id)
                mem = st.members.by_identifier(mptr.id)
                res.append(mem)
                continue

            # Otherwise we're referencing a frame member, and we need to grab
            # the frame for that function.
            fr = idaapi.get_frame(ea)
            if fr is None:
                cls = self.__class__
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}).refs() : The function at {:#x} for frame member {:#x} does not have a frame.".format('.'.join([__name__, cls.__name__]), self.id, ea, mptr.id))

            # We'll also need the idaapi.func_t for the function.
            f = idaapi.get_func(ea)
            if f is None:
                cls = self.__class__
                raise E.FunctionNotFoundError(u"{:s}({:#x}).refs() : Unable to locate the function for frame member {:#x} by address {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, mptr.id, ea))

            # So we can instantiate the structure with the correct offset
            # and then grab the member that was being referenced.
            st = by_identifier(fr.id, offset=-f.frsize)
            mem = st.members.by_identifier(mptr.id)
            res.append(mem)
        return res

    ### Properties
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.struc_t``.'''
        ptr, name = self.__ptr__, self.__name__

        # Verify if our ptr is still within scope by verifying
        # that its identifier is valid. Otherwise we need to use
        # the name that we've cached to fetch it.
        identifier = ptr.id if interface.node.is_identifier(ptr.id) else idaapi.get_struc_id(name)

        # Now we can check if we okay with returning the ptr. We also
        # update our cached name with whatever the current name is.
        if identifier == ptr.id:
            result, self.__name__ = ptr, idaapi.get_struc_name(identifier)

        # Otherwise we need to use the identifier to grab the
        # sptr from the identifier we just grabbed.
        else:
            result = self.__ptr__ = idaapi.get_struc(identifier)
        return result

    @property
    def id(self):
        '''Return the identifier of the structure.'''
        return self.ptr.id
    @property
    def properties(self):
        '''Return the properties for the current structure.'''
        return self.ptr.props
    @property
    def members(self):
        '''Return the members belonging to the structure.'''
        return self.__members__

    @property
    def name(self):
        '''Return the name of the structure.'''
        res = idaapi.get_struc_name(self.id)
        return utils.string.of(res)
    @name.setter
    @utils.string.decorate_arguments('string')
    def name(self, string):
        '''Set the name of the structure to `string`.'''
        if isinstance(string, tuple):
            string = interface.tuplename(*string)

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.VNT_VISIBLE)
        if ida_string and ida_string != res:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name({!r}) : Stripping invalid chars from structure name \"{:s}\" resulted in \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the structure
        oldname = idaapi.get_struc_name(self.id)
        if not idaapi.set_struc_name(self.id, ida_string):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).name({!r}) : Unable to assign the specified name ({:s}) to the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.repr(ida_string), utils.string.repr(oldname)))

        # verify that the name was actually assigned properly
        assigned = idaapi.get_struc_name(self.id) or ''
        if utils.string.of(assigned) != utils.string.of(ida_string):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name({!r}) : The name ({:s}) that was assigned to the structure does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.repr(utils.string.of(assigned)), utils.string.repr(ida_string)))
        return assigned

    @property
    def comment(self, repeatable=True):
        '''Return the repeatable comment for the structure.'''
        res = idaapi.get_struc_cmt(self.id, repeatable) or idaapi.get_struc_cmt(self.id, not repeatable)
        return utils.string.of(res)
    @comment.setter
    @utils.string.decorate_arguments('value')
    def comment(self, value, repeatable=True):
        '''Set the repeatable comment for the structure to `value`.'''
        res = utils.string.to(value or '')
        if not idaapi.set_struc_cmt(self.id, res, repeatable):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).comment(..., repeatable={!s}) : Unable to assign the provided comment to the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(self.name)))

        # verify that the comment was actually assigned
        assigned = idaapi.get_struc_cmt(self.id, repeatable)
        if utils.string.of(assigned) != utils.string.of(res):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment(..., repeatable={!s}) : The comment ({:s}) that was assigned to the structure does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(utils.string.of(assigned)), utils.string.repr(res)))
        return assigned

    @property
    def size(self):
        '''Return the size of the structure.'''
        return idaapi.get_struc_size(self.ptr)
    @size.setter
    def size(self, size):
        '''Expand the structure to the new `size` that is specified.'''
        res = idaapi.get_struc_size(self.ptr)
        if not idaapi.expand_struc(self.ptr, 0, size - res, True):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).size({:+d}) : Unable to resize structure \"{:s}\" from {:#x} bytes to {:#x} bytes.".format('.'.join([__name__, cls.__name__]), self.id, size, utils.string.escape(self.name, '"'), res, size))

        res = idaapi.get_struc_size(self.ptr)
        if res != size:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).size({:+d}) : The size that was assigned to the structure ({:+d}) does not match what was requested ({:+d}).".format('.'.join([__name__, cls.__name__]), self.id, size, res, size))
        return res

    @property
    def offset(self):
        '''Return the base offset of the structure.'''
        return self.members.baseoffset
    @offset.setter
    def offset(self, offset):
        '''Set the base offset of the structure to `offset`.'''
        res, self.members.baseoffset = self.members.baseoffset, offset
        return res
    @property
    def index(self):
        '''Return the index of the structure.'''
        return idaapi.get_struc_idx(self.id)
    @index.setter
    def index(self, index):
        '''Set the index of the structure to `idx`.'''
        res = idaapi.get_struc_idx(self.id)
        if not idaapi.set_struc_idx(self.ptr, index):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).index({:+d}) : Unable to modify the index of structure \"{:s}\" from {:d} to index {:d}.".format('.'.join([__name__, cls.__name__]), self.id, index, utils.string.escape(self.name, '"'), res, index))

        res = idaapi.get_struc_idx(self.id)
        if res != index:
            logging.info(u"{:s}({:#x}).index({:+d}) : The index that the structure was moved to ({:#x}) does not match what was requested ({:d}).".format('.'.join([__name__, cls.__name__]), self.id, index, res, index))
        return res

    @property
    def typeinfo(self):
        '''Return the type information of the current structure.'''
        ti = database.type(self.id)

        # If there was no type information found for the member, then raise
        # an exception to the caller because structures _are_ types and thus
        # this should never fail.
        if ti is None:
            cls = self.__class__
            raise E.MissingTypeOrAttribute(u"{:s}({:#x}).typeinfo : Unable to determine the type information for structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, self.name))

        # Otherwise it worked and we can return it to the caller.
        return ti
    @typeinfo.setter
    def typeinfo(self, info):
        '''Sets the type information of the current structure to `info`.'''
        try:
            ti = database.type(self.id, info)

        # If we caught a TypeError, then we received a parsing error that
        # we should re-raise for the user.
        except E.InvalidTypeOrValueError:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo({!s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), info))

        # If we caught an exception trying to get the typeinfo for the
        # structure, then port it to our class and re-raise.
        except E.DisassemblerError:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to apply `idaapi.tinfo_t()` to structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), self.name))
        return

    @property
    def realbounds(self):
        sptr = self.ptr
        return interface.bounds_t(0, idaapi.get_struc_size(self.ptr))

    @property
    def bounds(self):
        bounds, base = self.realbounds, self.members.baseoffset
        return bounds.translate(base)

    ### Private methods
    def __str__(self):
        '''Render the current structure in a readable format.'''
        sptr, name, offset, size, comment, tag = self.ptr, self.name, self.offset, self.size, self.comment or '', self.tag()
        return "<class '{:s}' name={!s}{:s} size={:#x}>{:s}".format('union' if sptr.is_union() else 'structure', utils.string.repr(name), (" offset={:#x}".format(offset) if offset != 0 else ''), size, " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __unicode__(self):
        '''Render the current structure in a readable format.'''
        sptr, name, offset, size, comment, tag = self.ptr, self.name, self.offset, self.size, self.comment or '', self.tag()
        return u"<class '{:s}' name={!s}{:s} size={:#x}>{:s}".format('union' if sptr.is_union() else 'structure', utils.string.repr(name), (" offset={:#x}".format(offset) if offset != 0 else ''), size, " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __repr__(self):
        return u"{!s}".format(self)

    def __getattr__(self, name):
        return getattr(self.members, name)

    def __contains__(self, member):
        '''Return whether the specified `member` is contained by this structure.'''
        if not isinstance(member, member_t):
            raise TypeError(member)
        return member in self.members

    ## Hashable
    def __hash__(self):
        return self.ptr.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, idaapi.struc_t):
            return self.ptr.id == other.id
        elif isinstance(other, structure_t):
            return self.ptr.id == other.ptr.id
        return False

    ## Serialization
    def __getstate__(self):
        cmtt, cmtf = map(functools.partial(idaapi.get_struc_cmt, self.id), [True, False])

        # decode the comments that we found in the structure
        res = (utils.string.of(cmt) for cmt in [cmtt, cmtf])

        # FIXME: perhaps we should preserve the get_struc_idx result too
        return (self.name, tuple(res), self.members)
    def __setstate__(self, state):
        name, (cmtt, cmtf), members = state

        # try and find the structure in the database by its name
        res = utils.string.to(name)
        identifier = idaapi.get_struc_id(res)

        # if we didn't find it, then just add it and notify the user
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.info(u"{:s}({:#x}) : Creating structure \"{:s}\" with {:d} fields and the comment \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, utils.string.escape(name, '"'), len(members), utils.string.escape(cmtf or cmtt or '', '"')))
            res = utils.string.to(name)
            identifier = idaapi.add_struc(idaapi.BADADDR, res)

        # now we can apply the comments to it
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtt), True)
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtf), False)

        # and set its attributes properly
        self.__ptr__, self.__name__ = idaapi.get_struc(identifier), name
        self.__members__ = members
        return

@utils.multicase()
def name(id):
    '''Return the name of the structure identified by `id`.'''
    res = idaapi.get_struc_name(id)
    return utils.string.of(res)
@utils.multicase(structure=structure_t)
def name(structure):
    return name(structure.id)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(id, string, *suffix):
    '''Set the name of the structure identified by `id` to `string`.'''
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # convert the specified string into a form that IDA can handle
    ida_string = utils.string.to(string)

    # validate the name
    res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.VNT_VISIBLE)
    if ida_string and ida_string != res:
        logging.info(u"{:s}.name({!r}, {!r}) : Stripping invalid chars from the structure name \"{:s}\" resulted in \"{:s}\".".format(__name__, id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
        ida_string = res

    # now we can set the name of the structure
    return idaapi.set_struc_name(id, ida_string)
@utils.multicase(structure=structure_t, string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(structure, string, *suffix):
    '''Set the name of the specified `structure` to `string`.'''
    return name(structure.id, string, *suffix)

@utils.multicase(id=six.integer_types)
def comment(id, **repeatable):
    """Return the comment of the structure identified by `id`.

    If the bool `repeatable` is specified, return the repeatable comment.
    """
    res = idaapi.get_struc_cmt(id, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(structure=structure_t)
def comment(structure, **repeatable):
    '''Return the comment for the specified `structure`.'''
    return comment(structure.id, **repeatable)
@utils.multicase(structure=structure_t, cmt=six.string_types)
@utils.string.decorate_arguments('cmt')
def comment(structure, cmt, **repeatable):
    '''Set the comment to `cmt` for the specified `structure`.'''
    return comment(structure.id, cmt, **repeatable)
@utils.multicase(structure=structure_t, none=None.__class__)
def comment(structure, none, **repeatable):
    '''Remove the comment from the specified `structure`.'''
    return comment(structure.id, none or '', **repeatable)
@utils.multicase(id=six.integer_types, cmt=six.string_types)
@utils.string.decorate_arguments('cmt')
def comment(id, cmt, **repeatable):
    """Set the comment of the structure identified by `id` to `cmt`.

    If the bool `repeatable` is specified, set the repeatable comment.
    """
    res = utils.string.to(cmt)
    return idaapi.set_struc_cmt(id, res, repeatable.get('repeatable', True))
@utils.multicase(id=six.integer_types, none=None.__class__)
def comment(id, none, **repeatable):
    '''Remove the comment from the structure identified by `id`.'''
    return comment(id, none or '', **repeatable)

@utils.multicase(id=six.integer_types)
def index(id):
    '''Return the index of the structure identified by `id`.'''
    return idaapi.get_struc_idx(id)
@utils.multicase(structure=structure_t)
def index(structure):
    '''Return the index of the specified `structure`.'''
    return index(structure.id)
@utils.multicase(id=six.integer_types, index=six.integer_types)
def index(id, index):
    '''Move the structure identified by `id` to the specified `index` in the structure list.'''
    return idaapi.set_struc_idx(id, index)
@utils.multicase(structure=structure_t, index=six.integer_types)
def index(structure, index):
    '''Move the specified `structure` to the specified `index` in the structure list.'''
    return index(structure.id, index)

@utils.multicase(structure=structure_t)
def size(structure):
    '''Return the size of the specified `structure`.'''
    return size(structure.id)
@utils.multicase(id=six.integer_types)
def size(id):
    '''Return the size of the structure identified by `id`.'''
    return idaapi.get_struc_size(id)

@utils.multicase(id=six.integer_types)
def is_union(id):
    '''Return whether the structure identified by `id` is a union or not.'''
    structure = idaapi.get_struc(id)
    return is_union(structure)
@utils.multicase(structure=(idaapi.struc_t, structure_t))
def is_union(structure):
    '''Return whether the provided `structure` is defined as a union.'''
    if isinstance(structure, structure_t):
        return is_union(structure.ptr)
    return structure.is_union()
unionQ = isunion = utils.alias(is_union)

@utils.multicase(structure=structure_t)
def members(structure):
    '''Yield each member of the specified `structure`.'''
    return members(structure.id)
@utils.multicase(id=six.integer_types)
def members(id):
    """Yield each member of the structure identified by `id`.

    Each iteration yields the `((offset, size), (name, comment, repeatable-comment))` of each member.
    """

    st = idaapi.get_struc(id)

    # If we couldn't get the structure, then blow up in the user's face.
    if st is None:
        raise E.StructureNotFoundError(u"{:s}.members({:#x}) : Unable to find the requested structure ({:#x}).".format(__name__, id, id))

    # Grab some attributes like the structure's size, and whether or not
    # it's a union so that we can figure out each member's offset.
    size, unionQ = idaapi.get_struc_size(st), st.is_union()

    # Iterate through all of the member in the structure.
    offset = 0
    for i in range(st.memqty):

        # Grab the member and its properties.
        m = st.get_member(i)
        msize, munionQ = idaapi.get_member_size(m), m.props & idaapi.MF_UNIMEM

        # Figure out the boundaries of the member. If our structure is a union,
        # then the starting offset never changes since IDA dual-uses it as the
        # member index.
        left, right = offset if unionQ else m.soff, m.eoff

        # If our current offset does not match the member's starting offset,
        # then this is an empty field, or undefined. We yield this to the caller
        # so that they know that there's some padding they need to know about.
        if offset < left:
            yield (offset, left - offset), (None, None, None)
            offset = left

        # Grab the attributes about the member that we plan on yielding.
        iterable = (utils.string.of(cmt) for cmt in [idaapi.get_member_name(m.id), idaapi.get_member_cmt(m.id, 0), idaapi.get_member_cmt(m.id, 1)])
        items = builtins.tuple(iterable)

        # That was everything that our caller should care about, so we can
        # just yield it and continue onto the next member.
        yield (offset, msize), items

        # If we're a union, then the offset just never changes. Continue onto
        # the next member without updating it.
        if unionQ:
            continue

        # Otherwise we're a regular member and we need to move onto the next
        # offset in our structure.
        offset += msize
    return

@utils.multicase(structure=structure_t, offset=six.integer_types, size=six.integer_types)
def fragment(structure, offset, size):
    '''Yield each member of the specified `structure` from the `offset` up to the `size`.'''
    return fragment(structure.id, offset, size)
@utils.multicase(id=six.integer_types, offset=six.integer_types, size=six.integer_types)
def fragment(id, offset, size):
    """Yield each member of the structure identified by `id` from the `offset` up to the `size`.

    Each iteration yields a tuple of the following format for each
    member within the requested bounds. This allows one to select
    certain fragments of a structure which can then be used to export
    to other programs or applications.

    `((offset, size), (name, comment, repeatable))`

    In this tuple, the field `comment` represents the non-repeatable
    comment whereas `repeatable` contains the member's `repeatable`
    comment.
    """
    iterable, unionQ = members(id), is_union(id)

    # seek
    for item in iterable:
        (m_offset, m_size), (m_name, m_cmt, m_rcmt) = item

        left, right = m_offset, m_offset + m_size
        if (offset >= left) and (offset < right):
            yield (m_offset, m_size), (m_name, m_cmt, m_rcmt)
            size -= 0 if unionQ else m_size
            break
        continue

    # return
    for item in iterable:
        if size > 0:
            (m_offset, m_size), (m_name, m_cmt, m_rcmt) = item
            yield (m_offset, m_size), (m_name, m_cmt, m_rcmt)
            size -= 0 if unionQ else m_size
        continue
    return

@utils.multicase(structure=structure_t)
def remove(structure):
    '''Remove the specified `structure` from the database.'''
    if not idaapi.del_struc(structure.ptr):
        raise E.StructureNotFoundError(u"{:s}.remove({!r}) : Unable to remove structure {:#x}.".format(__name__, structure, structure.id))
    return True
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def remove(name):
    '''Remove the structure with the specified `name`.'''
    res = by_name(name)
    return remove(res)
@utils.multicase(id=six.integer_types)
def remove(id):
    '''Remove a structure by its index or `id`.'''
    res = by(id)
    return remove(res)
@utils.multicase()
def remove(**type):
    '''Remove the first structure that matches the result described by `type`.'''
    res = by(**type)
    return remove(res)
delete = utils.alias(remove)

class members_t(object):
    """
    This object is an abstraction around all the members belonging to
    a specific IDA structure. This object is implicitly part of a
    ``structure_t`` and allows one to access each member of the structure
    by its index as well as create new members and remove existing ones
    from the structure.

    To list the different members available in the structure, one can
    use ``structure.list`` with a chosen method of filtering. This will
    list all of the available members that match the keyword that they
    specified. The keywords that are available to filter members are:

        `name` - Match the structure member by a name
        `offset` - Match the structure member by its offset
        `like` - Filter the structure members according to a glob
        `regex` - Filter the structure members according to a regular-expression
        `index` - Match the structure member by its index
        `fullname` - Filter the structure members by matching its full name according to a glob
        `comment` or `comments` - Filter the structure members by applying a glob to its comment
        `identifier` or `id` - Match the structure member by its identifier
        `greater` or `ge` - Filter the structure members for any after the specified offset (inclusive)
        `gt` - Filter the structure members for any after the specified offset (exclusive)
        `less` or `le` - Filter the structure members for any before the specified offset (inclusive)
        `lt` - Filter the structure members for any before the specified offset (exclusive)
        `predicate` - Filter the structure members by passing the ``member_t`` to a callable

    Some examples of using these keywords are as follows::

        > st.members.list('field_4*')
        > iterable = st.members.iterate(like='p_*')
        > result = st.members.by(offset=0x2a)

    """
    __slots__ = ('__owner__', 'baseoffset')

    def __init__(self, owner, baseoffset=0):
        self.__owner__ = owner
        self.baseoffset = baseoffset

    @utils.multicase()
    def iterate(self, **type):
        '''Iterate through all of the members in the structure that match the keyword specified by `type`.'''
        if not type: type = {'predicate': lambda item: True}
        listable = [item for item in self.__iterate__()]
        for key, value in type.items():
            listable = [item for item in self.__members_matcher.match(key, value, listable)]
        for item in listable: yield item
    @utils.multicase(string=six.string_types)
    @utils.string.decorate_arguments('string')
    def iterate(self, string):
        '''Iterate through all of the members in the structure with a name that matches the glob in `string`.'''
        return self.iterate(like=string)

    @utils.multicase(string=six.string_types)
    @utils.string.decorate_arguments('string')
    def list(self, string):
        '''List any members that match the glob in `string`.'''
        return self.list(like=string)
    @utils.multicase()
    @utils.string.decorate_arguments('regex', 'name', 'like', 'fullname', 'comment', 'comments')
    def list(self, **type):
        '''List all the members within the structure that match the keyword specified by `type`.'''
        res = [item for item in self.iterate(**type)]

        maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) if res else [1])
        maxoffset = max(builtins.map(utils.fcompose(operator.attrgetter('offset'), "{:x}".format, len), res) if res else [1])
        maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) if res else [1])
        maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), utils.string.repr, len), res) if res else [1])
        maxtype = max(builtins.map(utils.fcompose(operator.attrgetter('type'), utils.string.repr, len), res) if res else [1])
        maxtypeinfo = max(builtins.map(utils.fcompose(operator.attrgetter('typeinfo'), "{!s}".format, operator.methodcaller('replace', ' *', '*'), len), res) if res else [0])

        for m in res:
            six.print_(u"[{:{:d}d}] {:>{:d}x}:{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {:<{:d}s} (flag={:x},dt_type={:x}{:s}){:s}".format(m.index, maxindex, m.offset, int(maxoffset), m.size, maxsize, "{!s}".format(m.typeinfo.dstr()).replace(' *', '*'), int(maxtypeinfo), utils.string.repr(m.name), int(maxname), utils.string.repr(m.type), int(maxtype), m.flag, m.dt_type, '' if m.typeid is None else ",typeid={:x}".format(m.typeid), u" // {!s}".format(m.tag() if '\n' in m.comment else m.comment) if m.comment else ''))
        return

    @utils.multicase()
    @utils.string.decorate_arguments('regex', 'name', 'like', 'fullname', 'comment', 'comments')
    def by(self, **type):
        '''Return the member that matches the keyword specified by `type`.'''
        searchstring = utils.string.kwargs(type)
        owner = self.owner

        listable = [item for item in self.iterate(**type)]
        if len(listable) > 1:
            cls = self.__class__
            messages = ((u"[{:d}] {:x}{:+#x} {:s} '{:s}' {!r}".format(m.index, m.offset, m.size, "{!s}".format(m.typeinfo.dstr()).replace(' *', '*'), utils.string.escape(m.name, '\''), utils.string.repr(m.type))) for m in listable)
            [ logging.info(msg) for msg in messages ]
            logging.warning(u"{:s}({:#x}).members.by({:s}) : Found {:d} matching results. Returning the member at index {:d} offset {:x}{:+#x} with the name \"{:s}\" and typeinfo \"{:s}\".".format('.'.join([__name__, cls.__name__]), owner.ptr.id, searchstring, len(listable), listable[0].index, listable[0].offset, listable[0].size, utils.string.escape(listable[0].fullname, '"'), utils.string.escape("{!s}".format(listable[0].typeinfo.dstr()).replace(' *', '*'), '"')))

        iterable = (item for item in listable)
        res = next(iterable, None)
        if res is None:
            cls = self.__class__
            raise E.SearchResultsError(u"{:s}({:#x}).members.by({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, searchstring))
        return res
    @utils.multicase(name=six.string_types)
    @utils.string.decorate_arguments('name')
    def by(self, name):
        '''Return the member with the specified `name`.'''
        return self.by_name(name)
    @utils.multicase(offset=six.integer_types)
    def by(self, offset):
        '''Return the member at the specified `offset`.'''
        return self.by_offset(offset)

    @utils.string.decorate_arguments('name')
    def by_name(self, name):
        '''Return the member with the specified `name`.'''
        res = utils.string.to(name)
        owner = self.owner

        # grab the member_t of the structure by its name
        mem = idaapi.get_member_by_name(owner.ptr, res)
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_name({!r}) : Unable to find member with requested name.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name))

        # figure out the index of the member so we can return the member_t we've cached
        index = self.index(mem)
        return self[index]
    byname = utils.alias(by_name, 'members_t')

    @utils.string.decorate_arguments('fullname')
    def by_fullname(self, fullname):
        '''Return the member with the specified `fullname`.'''
        res = utils.string.to(fullname)
        owner = self.owner

        # grab the member_t of the structure by its fullname
        member = idaapi.get_member_by_fullname(res)
        mem, _ = (None, None) if member is None else member
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_fullname({!r}) : Unable to find member with full name.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, fullname))

        # figure out the index of the member so we can return the member_t we've cached
        index = self.index(mem)
        return self[index]
    byfullname = utils.alias(by_fullname, 'members_t')

    def by_offset(self, offset):
        '''Return the member at the specified `offset` from the base offset of the structure.'''
        owner = self.owner

        # Start out by getting our bounds, and translating them to our relative
        # offset.
        minimum, maximum = map(functools.partial(operator.add, self.baseoffset), owner.realbounds)

        # Make sure that the requested offset is within the boundaries of our
        # structure, and bail if it isn't.
        if not (minimum <= offset < maximum):
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_offset({:+#x}) : Unable to find member at specified offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset))

        # Chain to the realoffset implementation.. This is just a wrapper.
        return self.by_realoffset(offset - self.baseoffset)
    byoffset = utils.alias(by_offset, 'members_t')

    def index(self, member):
        '''Return the index of the specified `member`.'''
        owner = self.owner
        if not hasattr(member, 'id'):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.index({!r}) : An invalid type ({!s}) was specified for the member to search for.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, member, member.__class__))

        for i in range(owner.ptr.memqty):
            if member.id == self[i].id:
                return i
            continue
        cls, Fnetnode = self.__class__, getattr(idaapi, 'ea2node', utils.fidentity)
        raise E.MemberNotFoundError(u"{:s}({:#x}).members.index({!s}) : The requested member ({!s}) is not in the members list.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, "{:#x}".format(member.id) if isinstance(member, (member_t, idaapi.member_t)) else "{!r}".format(member), internal.netnode.name.get(Fnetnode(member.id))))

    def by_realoffset(self, offset):
        '''Return the member at the specified `offset` of the structure.'''
        owner = self.owner
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # Start by getting our bounds which only requires us to know the structure's size
        # regardless of whether or not it's a union. Just to be safe, we guard this against
        # a potential OverflowError that would be raised by SWIG's type-checker.
        minimum, maximum = 0, idaapi.get_struc_size(owner.ptr)
        if maximum < minimum:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Received an unexpected size ({:#x}) for the given structure ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, maximum, owner.ptr.id))

        if not (minimum <= offset < maximum):
            cls = self.__class__
            raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Requested offset ({:#x}) is not within the structure's boundaries ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset, minimum, minimum + maximum))

        # Now we call our members_t.__members_at__ helper-method so that we can check the
        # members that are returned to verify that they're within our search boundaries.
        items, unionQ = [], owner.ptr.is_union
        for mptr in self.__members_at__(offset):
            mleft, mright = 0 if unionQ() else mptr.soff, mptr.eoff

            # Check the offset is within our current member's boundaries, and add it to
            # our list if it is so that we can count our results later.
            if mleft <= offset < mright:
                items.append(mptr)
            continue

        # If we didn't find any items, then we need to throw up an exception because
        # we're unable to proceed any farther without any members to search through.
        if not items:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Unable to find member at the specified offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset))

        # If we found more than one result, then we need to warn the user about it
        # because we're going to have to make a decision on their behalf. This really
        # should only be happening when we're a union type.
        if len(items) > 1:
            cls = self.__class__
            iterable = (idaapi.get_member_fullname(mptr.id) for mptr in items)
            logging.warning(u"{:s}({:#x}).members.by_realoffset({:+#x}) : The specified offset ({:#x}) is currently occupied by more than one member ({:s}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset, ', '.join(map(utils.string.to, iterable))))

            # Grab the type information for each member so we can determine if the
            # requested offset points at an array or a structure. We also grab
            # the operand information via the idaapi.retrieve_member_info api.
            # If there's no operand information available, we use None as a
            # placeholder. Fortunately, the api also returns None as failure so
            # we can just blindly add its result to our list of candidates.
            candidates = []
            for mptr in items:
                opinfo = idaapi.opinfo_t()
                res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
                candidates.append((mptr, mptr.flag, res and res.tid, idaapi.get_member_size(mptr)))

            # Now iterate through all of our candidates to see how we can narrow
            # them down into the ones we want to select.
            selected = []
            for mptr, flags, tid, size in candidates:
                dt = idaapi.as_uint32(flags & idaapi.DT_TYPE)
                res = interface.typemap.dissolve(flags, tid, size)

                # Adjust the offset so it points directly into the member.
                realoffset = offset - (0 if unionQ() else mptr.soff)

                # First we need to check to see if it's an array, because this
                # might actually be an array of structures which we'll need to
                # check the requested offset against.
                if isinstance(res, builtins.list):
                    type, length = res

                    # If we received a tuple, then we can extract the member size
                    # directly to see if it aligns properly.
                    if isinstance(type, builtins.tuple):
                        _, msize = type
                        index, byte = divmod(realoffset, msize)

                    # Otherwise this must be an array of structures, and we need
                    # to extract its size to see if it aligns.
                    elif isinstance(type, structure_t):
                        msize = idaapi.get_struc_size(type.id)
                        index, byte = divmod(realoffset, msize)

                    # We have no idea what this is, which is a very unexpected
                    # situation. So, we'll just raise an exception here so that
                    # it can be debugged later.
                    else:
                        raise NotImplementedError(mptr.id, type, length)

                    # Now that we have our index and byte offset, we can check
                    # and see if it divided evenly into the member size. If so,
                    # then we can push it to the front of the list. Otherwise,
                    # it goes to the very very back.
                    selected.append(mptr) if byte else selected.insert(0, mptr)

                # Next we need to check if it's a structure, because if so then
                # we need to find out if it directly aligns with a particular
                # member.
                elif isinstance(res, structure_t) and res.ptr.is_union():
                    selected.append(mptr) if realoffset else selected.insert(0, mptr)

                # Finally, check if it's a structure and our real offset points
                # directly to a particular member. If it does, then this is
                # a legitimate candidate.
                elif isinstance(res, structure_t):
                    mem = idaapi.get_member(res.ptr, realoffset)
                    selected.append(mptr) if mem and realoffset - mem.soff else selected.insert(0, mptr)

                # If it's a tuple, then this only matches if we're pointing
                # directly to the member.
                elif isinstance(res, builtins.tuple):
                    selected.append(mptr) if realoffset else selected.insert(0, mptr)

                # Anything else and we have no idea what this is, so simply
                # raise an exception so it can be debugger later.
                else:
                    raise NotImplementedError(mptr, res)
                continue

            # Now log the order of members that we've sorted out just in case
            # this "algorithm" is totally busted and we want to figure out
            # where it's busted.
            iterable = ((mptr, idaapi.get_member_fullname(mptr.id)) for mptr in selected)
            messages = (u"[{:d}] {:s} {:#x}{:+#x}".format(1 + i, fullname, mptr.soff, mptr.eoff) for i, (mptr, fullname) in enumerate(iterable))
            [ logging.info(msg) for msg in messages ]

            # Grab the first element from our sorted list, as that's the one
            # that we're going to actually use.
            items = selected[:1]

        # Now we can extract the member from our list of results, and then
        # figure out its index so that we can return it. Hopefully we found
        # what the user was expecting.
        member, = items
        index = self.index(member)
        return self[index]
    byrealoffset = utils.alias(by_realoffset, 'members_t')

    def by_identifier(self, id):
        '''Return the member in the structure that has the specified `id`.'''
        owner = self.owner

        # get the member from the id we were given
        res = idaapi.get_member_by_id(id)
        if res is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_id({:#x}) : Unable to find member with specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, id, id))

        # unpack the member out of the result
        mptr, fullname, sptr = res
        if not interface.node.is_identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

        # search through our members for the specified member
        index = self.index(mptr)
        return self[index]
    by_id = byid = byidentifier = utils.alias(by_identifier, 'members_t')

    def near_offset(self, offset):
        '''Return the member nearest to the specified `offset` from the base offset of the structure.'''
        owner = self.owner

        # This was just a wrapper anyways...
        return self.near_realoffset(offset - self.baseoffset)
    near = nearoffset = utils.alias(near_offset, 'members_t')

    def near_realoffset(self, offset):
        '''Return the member nearest to the specified `offset`.'''
        owner = self.owner

        # Start by getting our bounds.
        minimum, maximum = owner.realbounds
        if not (minimum <= offset < maximum):
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).members.near_realoffset({:+#x}) : Requested offset ({:#x}) is not within the bounds ({:#x}<->{:#x}) of the structure and will result in returning the nearest member.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset, minimum, maximum))

        # If there aren't any elements in the structure, then there's no members
        # to search through in here. So just raise an exception and bail.
        if not len(self):
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.near_realoffset({:+#x}) : Unable to find member near offset.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset))

        # Grab all of the members at the specified offset so we can determine
        # if there's an exact member that can be found.
        members = [mptr for mptr in self.__members_at__(offset)]

        # If we found more than one member, then try and filter the exact one
        # using the members_t.by_realoffset method.
        if len(members):
            return self.by_realoffset(offset)

        # We couldn't find any members, so now we'll try and search for the
        # member that is nearest to the offset that was requested.
        def recurse(offset, available):
            if len(available) == 1:
                return available[0]
            index = len(available) // 2
            return recurse(offset, available[:index]) if offset <= available[index].realoffset else recurse(offset, available[index:])

        # This should already be sorted for us, so descend into it looking
        # for the nearest member.
        mem = recurse(offset, [item for item in self])

        # Now we can return the exact member that was found.
        index = self.index(mem)
        return self[index]

    # adding/removing members
    @utils.multicase(name=(six.string_types, tuple))
    @utils.string.decorate_arguments('name')
    def add(self, name):
        '''Append the specified member `name` with the default type at the end of the structure.'''
        return self.add(name, int)
    @utils.multicase(name=(six.string_types, tuple))
    @utils.string.decorate_arguments('name')
    def add(self, name, type):
        '''Append the specified member `name` with the given `type` at the end of the structure.'''
        owner = self.owner

        # If this structure is a union, then the offset should always be 0.
        # This means that when translated to our baseoffset, will always
        # result in the baseoffset itself.
        if is_union(owner.ptr):
            return self.add(name, type, self.baseoffset)

        # Otherwise, it's not a union and so we'll just calculate
        # the offset to add the member at, and proceed as asked.
        offset = owner.size + self.baseoffset
        return self.add(name, type, offset)
    @utils.multicase(name=(six.string_types, tuple), offset=six.integer_types)
    @utils.string.decorate_arguments('name')
    def add(self, name, type, offset):
        """Add a member at `offset` with the given `name` and `type`.

        To specify a particular size, `type` can be a tuple with the second element referring to the size.
        """
        owner = self.owner
        flag, typeid, nbytes = interface.typemap.resolve(type)

        # If the member is being added to a union, then the offset doesn't
        # matter because it's always zero. We need to check this however because
        # we're aiming to be an "intuitive" piece of software.
        if owner.ptr.is_union():

            # If the offset is zero, then maybe the user does know what they're
            # doing, but they don't know that they need to use the base offset.
            if offset == 0:
                pass

            # If the user really is trying to add a member with a non-zero offset
            # to our union, then we need to warn the user so that they know not
            # to do it again in the future.
            elif offset != self.baseoffset:
                cls = self.__class__
                logging.warning(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Corrected the invalid offset ({:#x}) being used when adding member ({!s}) to union \"{:s}\", and changed it to {:+#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, type, offset, offset, name, owner.name, self.baseoffset))

            # Now we can actually correct the offset they gave us.
            offset = self.baseoffset

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        realoffset = offset - self.baseoffset

        # If they didn't give us a name, then we figure out a default name
        # using a sort-of hungarian notation as the prefix, and the field's
        # offset as the suffix.
        if name is None:
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Name is undefined, defaulting to offset {:+#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, type, offset, realoffset))
            name = 'field', realoffset

        # If we were given a tuple, then we need to concatenate it into a string.
        if isinstance(name, builtins.tuple):
            name = interface.tuplename(*name)

        # Finally we can use IDAPython to add the structure member with the
        # parameters that we were given and/or figured out.
        res = idaapi.add_struc_member(owner.ptr, utils.string.to(name), realoffset, flag, opinfo, nbytes)

        # Now we can check whether the addition was succesful or not. If the
        # addition didn't return an error code, then log the success in order
        # to assist with debugging.
        if res == idaapi.STRUC_ERROR_MEMBER_OK:
            cls = self.__class__
            logging.debug(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `idaapi.add_struc_member(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})` returned success.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, type, offset, utils.string.escape(owner.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes))

        # If we received a failure error code, then we convert the error code to
        # an error message so that we can raise an exception that actually means
        # something and enables the user to correct it.
        else:
            error = {
                idaapi.STRUC_ERROR_MEMBER_NAME : 'Duplicate field name',
                idaapi.STRUC_ERROR_MEMBER_OFFSET : 'Invalid offset',
                idaapi.STRUC_ERROR_MEMBER_SIZE : 'Invalid size',
            }
            e = E.DuplicateItemError if res == idaapi.STRUC_ERROR_MEMBER_NAME else E.DisassemblerError
            callee = u"idaapi.add_struc_member(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})".format(utils.string.escape(owner.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes)
            cls = self.__class__
            raise e(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `{:s}` returned {:s}".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, type, offset, callee, error.get(res, u"Error code {:#x}".format(res))))

        # We added the member, but now we need to return it to the caller. Since
        # all we get is an error code from IDAPython's api, we try and fetch the
        # member that was just added by the offset it's supposed to be at.
        mptr = idaapi.get_member(owner.ptr, realoffset)
        if mptr is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Unable to locate recently created member \"{:s}\" at offset {:s}{:+#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, type, offset, utils.string.escape(name, '"'), realoffset, nbytes))

        # If we successfully grabbed the member, then we need to figure out its
        # actual index in our structure. Then we can use the index to instantiate
        # a member_t that we'll return back to the caller.
        idx = self.index(mptr)
        return member_t(owner, idx)

    def pop(self, index):
        '''Remove the member at the specified `index`.'''
        item = self[index]
        return self.remove(item.offset - self.baseoffset)

    @utils.multicase()
    def remove(self, offset):
        '''Remove the member at `offset` from the structure.'''
        owner, items = self.owner, [mptr for mptr in self.__members_at__(offset - self.baseoffset)]

        # If there are no items at the requested offset, then we bail.
        if not items:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.remove({:+#x}) : Unable to find member at the specified offset ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset))

        # If more than one item was found, then we also need to bail.
        if len(items) > 1:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).members.remove({:+#x}) : Refusing to remove more than {:d} member{:s} ({:d}) at offset {:#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, 1, '' if len(items) == 1 else 's', len(items), offset))

        # Now we know exactly what we can remove.
        mptr = items[0]
        result, = self.remove(self.baseoffset + mptr.soff, mptr.eoff - mptr.soff)
        return result
    @utils.multicase()
    def remove(self, offset, size):
        '''Remove all the members from the structure from the specified `offset` up to `size` bytes.'''
        sptr, soffset = self.owner.ptr, offset - self.baseoffset
        if not sptr.memqty:
            logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : The structure has no members that are able to be removed.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size))
            return []

        # If we're a union, then we need to raise an exception because
        # there's a likely chance that the user might empty out the
        # union entirely.
        if sptr.is_union():
            raise E.InvalidParameterError(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Refusing to remove members from the specified union by the specified offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, offset))

        # First we'll need to figure out the index of the member that
        # we will start removing things at. This way we can start
        # collecting the members that'll be removed.
        index = idaapi.get_prev_member_idx(sptr, soffset) + 1
        if sptr.memqty < index:
            logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to find the member at the specified offset ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, offset))
            return []

        # Next we need to collect each member that will be removed so
        # that we can return them back to the caller after removal.
        items = []
        while index < sptr.memqty and sptr.members[index].soff < soffset + size:
            mptr = sptr.members[index]
            items.append(mptr)
            index += 1

        # Now we know what will need to be removed, so we'll need to
        # collect their attributes so that the user can recreate them
        # if necessary.
        result = []
        for mptr in items:
            name = utils.string.of(idaapi.get_member_name(mptr.id) or '')
            moffset, msize = mptr.soff + self.baseoffset, idaapi.get_member_size(mptr)

            # now we need to grab the type information in order to pythonify
            # our type before we remove it.
            opinfo = idaapi.opinfo_t()
            if idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr):
                tid = opinfo.tid
            else:
                tid = idaapi.BADADDR

            # now we can dissolve it, and than append things to our results.
            type = interface.typemap.dissolve(mptr.flag, tid, msize)
            result.append((mptr.id, name, type, moffset))

        # Figure out whether we're just going to remove one element, or
        # multiple elements so that we can call the correct api and figure
        # out how to compare the number of successfully removed members.
        if len(items) > 1:
            count = idaapi.del_struc_members(sptr, soffset, soffset + size)
        elif len(items):
            count = 1 if idaapi.del_struc_member(sptr, soffset) else 0
        else:
            count = 0

        # If we didn't remove anything and we were supposed to, then let
        # the user know that it didn't happen.
        if result and not count:
            logging.fatal(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove the requested elements ({:+#x}<>{:+#x}) from the structure.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, result[0].soff, result[-1].eoff))
            return []

        # If our count matches what was expected, then we're good and can
        # just return our results to the user.
        if len(result) == count:
            return [(name, type, offset) for _, name, type, offset in result]

        # Otherwise, we only removed some of the elements and we need to
        # figure out what happened so we can let the user know.
        removed, expected = {id for id in []}, {id : (name, type, offset) for id, name, type, offset in result}
        for id, name, _, offset in result:
            if idaapi.get_member(sptr, offset - self.baseoffset):
                logging.debug(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove member {:s} at offset {:+#x} with the specified id ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, name, offset, id))
                continue
            removed.add(id)

        # We have the list of identities that were removed. So let's proceed
        # with our warnings and return whatever we successfully removed.
        logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove {:d} members out of an expected {:d} members within the specified range ({:+#x}<>{:+#x}) of the structure.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, len(expected) - len(removed), len(expected), result[0].soff, result[-1].eoff))
        return [(name, type, offset) for id, name, type, offset in result if id in removed]

    ### Properties
    @property
    def owner(self):
        '''Return the owner ``structure_t`` for this ``members_t``.'''
        return self.__owner__

    @property
    def ptr(self):
        '''Return the pointer to the ``idaapi.member_t`` that contains all the members.'''
        owner = self.owner
        return owner.ptr.members

    ### Private methods containing internal utilities
    def __members_at__(self, realoffset):
        """Yield all the members at the specified `realoffset` of the current structure.

        This returns members whilst keeping in mind whether the structure is a union and may have more than one field at the same offset.
        """
        owner = self.owner

        # If this structure is not a union, then this is simple because there'll
        # be only one member at any given offset. It appears that IDAPython's api
        # seems to figure everything out for us and so we can just use it to
        # fetch the things we need to yield, and then return immediately after.
        if not owner.ptr.is_union():
            mptr = idaapi.get_member(owner.ptr, realoffset)
            if mptr:
                yield mptr
            return

        # Otherwise, start at the very first member index, and check that we actually
        # have some members that we can iterate through.
        index = idaapi.get_struc_first_offset(owner.ptr)
        if index == idaapi.BADADDR:
            return

        # Now we can iterate through the union from the very first index while grabbing
        # each member so that we can filter it according to its bounds and then discard
        # anything that doesn't match.
        while index != -1 and index <= idaapi.get_struc_last_offset(owner.ptr):
            mptr = idaapi.get_member(owner.ptr, index)
            if mptr is None:
                cls = self.__class__
                raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Unable to find union member at the specified index ({:+#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, realoffset, index))

            # If the request offset is within the boundaries of our union member,
            # then we're good and this matches what we were looking for.
            if realoffset < mptr.eoff:
                yield mptr

            # Proceed to the next union member by asking IDAPython for the next index.
            index = idaapi.get_struc_next_offset(owner.ptr, mptr.soff)
        return

    def __walk_to_realoffset__(self, offset, filter=lambda sptr, items: items):
        """Descend into the structure collecting the fields to get to the specified `offset`.

        If a closure is passed as the `filter` parameter, then use the function to filter the members to use when descending into a structure.
        """
        owner = self.owner

        # Define a closure that grabs the type information for a particular
        # member, and converts it to a pythonic-type. This way it's easier
        # for us to determine both the member's type and its size.
        def dissolve(mptr):
            opinfo = idaapi.opinfo_t()
            res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            tid = res.tid if res else idaapi.BADADDR
            return interface.typemap.dissolve(mptr.flag, tid, idaapi.get_member_size(mptr))

        # Start out by finding all of the members at our current offset.
        items = []
        for mptr in self.__members_at__(offset):
            mleft, mright = 0 if owner.ptr.is_union() else mptr.soff, mptr.eoff

            # Check the offset is within our current member's boundaries, and
            # add it to our list if it is so that we can count our results later.
            if mleft <= offset < mright:
                items.append(mptr)
            continue
        members = items

        # If we received multiple members for this specific offset, which
        # should only happen if we're in a union, then we need to do some
        # special processing in order to figure out which member we should
        # use. We do this by using our filter parameter when we find more
        # than one member in order to allow the caller to explicitly filter
        # our discovered candidates.
        F = filter or (lambda structure, items: items)
        filtered = F(owner.ptr, members) if len(members) > 1 else members

        # If we didn't get exactly one member after filtering our path,
        # then either we hit a union (multiple members) or an undefined
        # field.
        if len(filtered) != 1:

            # If it's a union, then we just return an offset relative to
            # the structure itself. Generally, the caller needs to tell
            # us which union member to choose using the filter parameter.
            if owner.ptr.is_union():
                return (), offset

            # Otherwise, grab the nearest member to the offset and check
            # if the member can be used to describe the offset by verifying
            # that the member is located in front of the offset. This way
            # we can use the nearest member to adjust the offset, and then
            # return it along with the adjusted offset to the caller.
            nearest = self.near_realoffset(offset)
            if offset >= nearest.realoffset:
                return (nearest,), offset - nearest.realoffset

            # Otherwise, our offset is going to be relative to the
            # structure itself and we need to return an empty path.
            return (), offset

        # Otherwise we found a single item, then we just need to know if
        # we need to continue recursing into something and what exactly
        # we're recursing into.
        mptr, = filtered
        mtype, moffset = dissolve(mptr), 0 if owner.ptr.is_union() else mptr.soff

        # If our member type is an array, then we need to do some things
        # to try and figure out which index we're actually going to be
        # at. Before that, we need to take our dissolved type and unpack it.
        if isinstance(mtype, builtins.list):
            item, length = mtype
            _, size = (item, item.size) if isinstance(item, structure_t) else item
            prefix = [self.by_identifier(item.id) for item in [mptr]]

            # We now need to do some calculations to figure out which index
            # and byte offset that our requested offset is pointing to, and
            # then we can actually calculate our real distance.
            index, bytes = divmod(offset - moffset, size or 1)
            res = index * size

            # If it's just an atomic type, then we can return the difference
            # between our target offset and the member offset since it's up
            # to the caller to figure out what the index actually means.
            if isinstance(item, builtins.tuple):
                return prefix, offset - moffset

            # If our array type is a structure, we will need to recurse in
            # order to figure out what the next field will be, and then we
            # can adjust the returned offset so that it corresponds to the
            # offset into the array.
            sptr = idaapi.get_sptr(mptr)
            if sptr:
                st = __instance__(sptr.id, offset=self.baseoffset + moffset + res)
                suffix, nextoffset = st.members.__walk_to_realoffset__(bytes, filter=filter)
                return prefix + [item for item in suffix], offset - (moffset + res + bytes - nextoffset)

            # We have no idea what type this is, so just bail.
            raise TypeError(mptr, item)

        # Otherwise this is just a single type, and we need to check whether
        # we handle it as a structure which requires us to recurse, or not
        # which means we just return the offset relative to our member.)
        sptr = idaapi.get_sptr(mptr)
        if not sptr:
            prefix = (self.by_identifier(item.id) for item in [mptr])
            return builtins.tuple(prefix), offset - moffset

        # Otherwise, the member type is a structure, and we'll need
        # to recurse in order to figure out which field should be at
        # the relative offset from the member.
        st = __instance__(sptr.id, offset=self.baseoffset + moffset)
        result, nextoffset = st.members.__walk_to_realoffset__(offset - moffset, filter=filter)

        # If we haven't encountered a list yet, then our prefix will
        # still be a tuple and we need to ensure it's the correct type.
        iterable = (self.by_identifier(item.id) for item in [mptr])
        if isinstance(result, builtins.tuple):
            prefix = builtins.tuple(iterable)

        # If our result was a list, then we've encountered an array
        # and we need to preserve its type.
        elif isinstance(result, builtins.list):
            prefix = builtins.list(iterable)

        # Bail if we don't know what the type is.
        else:
            raise TypeError(result)

        # Now we can concatenate our prefix to our current results,
        # and then return what we've aggregated back to our caller.
        return prefix + result, nextoffset

    ## Matching
    __members_matcher = utils.matcher()
    __members_matcher.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
    __members_matcher.attribute('index', 'index')
    __members_matcher.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
    __members_matcher.attribute('offset', 'offset')
    __members_matcher.boolean('name', lambda name, item: item.lower() == name.lower(), 'name')
    __members_matcher.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
    __members_matcher.combinator('fullname', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'fullname')
    __members_matcher.combinator('comment', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match'), utils.fpartial(utils.fcompose, utils.fdefault(''))), 'comment')
    __members_matcher.combinator('comments', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match'), utils.fpartial(utils.fcompose, utils.fdefault(''))), 'comment')
    __members_matcher.boolean('greater', operator.le, lambda member: member.offset + member.size)
    __members_matcher.boolean('ge', operator.le, lambda member: member.offset + member.size)
    __members_matcher.boolean('gt', operator.lt, lambda member: member.offset + member.size)
    __members_matcher.boolean('less', operator.ge, 'offset')
    __members_matcher.boolean('le', operator.ge, 'offset')
    __members_matcher.boolean('lt', operator.gt, 'offset')
    __members_matcher.predicate('predicate'), __members_matcher.predicate('pred')

    def __iterate__(self):
        '''Yield each of the members within the structure.'''
        for idx in range(len(self)):
            yield member_t(self.owner, idx)
        return

    ### Private methods
    def __str__(self):
        '''Render all of the fields within the current structure.'''
        res = []
        mn, ms, mti = 0, 0, 0
        for i in range(len(self)):
            m = self[i]
            name, t, ti, ofs, size, comment, tag = m.name, m.type, m.typeinfo, m.offset, m.size, m.comment, m.tag()
            res.append((i, name, t, ti, ofs, size, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(size)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))

        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1

        if len(self):
            mo = max(map(len, map("{:x}".format, [self.baseoffset, self[-1].offset + self[-1].size])))
            return "{!r}\n{:s}".format(self.owner, '\n'.join("[{:{:d}d}] {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s} {:s}".format(i, mi, o, mo, s, ms, "{!s}".format(ti.dstr()).replace(' *','*'), mti, utils.string.repr(n), mn+2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else utils.string.to(c)) if c else '') for i, n, t, ti, o, s, c, T in res))
        return "{!r}".format(self.owner)

    def __unicode__(self):
        '''Render all of the fields within the current structure.'''
        res = []
        mn, ms, mti = 0, 0, 0
        for i in range(len(self)):
            m = self[i]
            name, t, ti, ofs, size, comment, tag = m.name, m.type, m.typeinfo, m.offset, m.size, m.comment, m.tag()
            res.append((i, name, t, ti, ofs, size, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(size)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))

        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1

        if len(self):
            mo = max(map(len, map("{:x}".format, (self.baseoffset, self[-1].offset + self[-1].size))))
            return u"{!r}\n{:s}".format(self.owner, '\n'.join("[{:{:d}d}] {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s} {:s}".format(i, mi, o, mo, s, ms, "{!s}".format(ti.dstr()).replace(' *','*'), mti, utils.string.repr(n), mn+2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else utils.string.to(c)) if c else '') for i, n, t, ti, o, s, c, T in res))
        return u"{!r}".format(self.owner)

    def __repr__(self):
        return u"{!s}".format(self)

    def __len__(self):
        '''Return the number of members within the structure.'''
        owner = self.owner
        return 0 if owner.ptr is None else owner.ptr.memqty

    def __getitem__(self, index):
        '''Return the member at the specified `index`.'''
        owner = self.owner
        if isinstance(index, six.integer_types):
            index = owner.ptr.memqty + index if index < 0 else index
            res = member_t(owner, index) if 0 <= index < owner.ptr.memqty else None
        elif isinstance(index, six.string_types):
            res = self.by_name(index)
        elif isinstance(index, slice):
            sliceable = [self[idx] for idx in range(owner.ptr.memqty)]
            res = sliceable[index]
        else:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__getitem__({!r}) : An invalid type ({!s}) was specified for the index.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, index.__class__))

        if res is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.__getitem__({!r}) : Unable to find the member that was requested.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index))
        return res

    def __delitem__(self, index):
        '''Remove the member at the specified `index`.'''
        return self.pop(index)

    def __iter__(self):
        '''Yield all the members within the structure.'''
        for idx in range(len(self)):
            yield member_t(self.owner, idx)
        return

    def __contains__(self, member):
        '''Return whether the specified `member` is contained by this structure.'''
        if not isinstance(member, member_t):
            raise TypeError(member)

        # Just use members_t.by_identifier to see if it raises an exception.
        try:
            self.by_identifier(member.id)

        # It raised an exception, so the member wasn't found.
        except E.MemberNotFoundError:
            return False
        return True

    ## Serialization
    def __getstate__(self):
        items = [self[idx] for idx in range(len(self))]
        return (self.owner.name, self.baseoffset, items)
    def __setstate__(self, state):
        ownername, baseoffset, _ = state

        # grab the structure containing our members so we can instantiate it
        res = utils.string.to(ownername)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.info(u"{:s}({:#x}) : Creating `members_t` for `structure_t` \"{:s}\" with no members.".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(ownername, '"')))
            identifier = idaapi.add_struc(idaapi.BADADDR, res)

        # assign the properties for our new member using the instance we figured out
        self.baseoffset = baseoffset
        self.__owner__ = __instance__(identifier, offset=baseoffset)
        return

class member_t(object):
    """
    This object is an abstraction around a single member belonging to
    a structure. A member within a structue contains a number of
    properties which this object will expose. Some of these properties
    allow for a user to modify the member's ``type`` or ``name``. The
    ``tag`` method is also provided to allow for a user to annotate the
    member similar to the database or a function's contents. Another
    method, ``refs`` will allow one to enumerate everything in the
    database that references said member.
    """
    __slots__ = ('__parent__', '__index__')

    def __init__(self, parent, index):
        '''Create a member_t for the field in the structure `parent` at `index`.'''
        self.__index__ = index
        self.__parent__ = parent

    @utils.multicase()
    def tag(self):
        '''Return the tags associated with the member.'''
        repeatable = True

        # grab the repeatable and non-repeatable comment
        res = utils.string.of(idaapi.get_member_cmt(self.id, False))
        d1 = internal.comment.decode(res)
        res = utils.string.of(idaapi.get_member_cmt(self.id, True))
        d2 = internal.comment.decode(res)

        # check for duplicate keys
        if six.viewkeys(d1) & six.viewkeys(d2):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('.'.join([__name__, cls.__name__]), self.id, ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it
        # XXX: it'd be cool to return an object with a dictionary
        #      that automatically synchronizes itself to the
        #      comment when a value is actually updated.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]
        return res
    @utils.multicase(key=six.string_types)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the member.'''
        res = self.tag()
        return res[key]
    @utils.multicase(key=six.string_types)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the member.'''
        state = self.tag()
        repeatable, res, state[key] = True, state.get(key, None), value
        if not idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), repeatable):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).comment(..., repeatable={!s}) : Unable to assign the provided comment to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(self.name)))
        return res
    @utils.multicase(key=six.string_types, none=None.__class__)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the member.'''
        state = self.tag()
        repeatable, res, = True, state.pop(key)
        if not idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), repeatable):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).comment(..., repeatable={!s}) : Unable to assign the provided comment to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(self.name)))
        return res

    def refs(self):
        """Return the `(address, opnum, type)` of all the code and data references to this member within the database.

        If `opnum` is ``None``, then the returned `address` has the structure applied to it.
        If `opnum` is defined, then the instruction at the returned `address` references a field that contains the specified structure.
        """
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        Fnetnode, Fidentifier = (getattr(idaapi, api, utils.fidentity) for api in ['ea2node', 'node2ea'])

        # if structure is a frame..
        if interface.node.is_identifier(self.parent.id) and internal.netnode.name.get(Fnetnode(self.parent.id)).startswith('$ '):
            name, mptr = self.fullname, self.ptr
            sptr = idaapi.get_sptr(mptr)

            # get frame, func_t
            frname, _ = name.split('.', 1)
            frid = Fidentifier(internal.netnode.get(frname))
            ea = idaapi.get_func_by_frame(frid)
            f = idaapi.get_func(ea)

            # now find all xrefs to member within function
            xl = idaapi.xreflist_t()
            idaapi.build_stkvar_xrefs(xl, f, mptr)

            # now we can add it
            res = []
            for xr in xl:
                ea, opnum = xr.ea, int(xr.opnum)
                ref = interface.opref_t(ea, opnum, interface.reftype_t(xr.type, instruction.op_state(ea, opnum)))
                res.append(ref)
            return res

        # otherwise, it's a structure..which means we need to specify the member to get refs for
        X, mid = idaapi.xrefblk_t(), self.id
        if not X.first_to(mid, idaapi.XREF_ALL):
            return []

        # collect all references available
        refs = [(X.frm, X.iscode, X.type)]
        while X.next_to():
            refs.append((X.frm, X.iscode, X.type))

        # collect all structure references that might reference us just in case
        # we need to verify that a globally defined address is using a structure
        # that contains our member
        identifiers = { self.parent } | { member.parent for member in self.parent.up() if isinstance(member, member_t) }
        while True:
            current = identifiers.copy()

            # iterate through every single structure that we have, and gather
            # its member_t references
            for item in current.copy():
                for member in item.refs():
                    if isinstance(item, member_t):
                        current.add(item)
                    continue
                continue

            # if nothing changed, then we're good to leave this crazy loop
            if current == identifiers:
                break

            # otherwise, merge our findings and try again
            identifiers |= current

        # okay, now we can convert this set into a set of identifiers
        identifiers = { item.id for item in identifiers }

        # now figure out which operand has the structure member applied to it
        res = []
        for ea, _, t in refs:
            iterable = ((idx, internal.netnode.sup.get(Fnetnode(ea), 0xf + idx, type=memoryview)) for idx in range(idaapi.UA_MAXOP) if internal.netnode.sup.has(Fnetnode(ea), 0xf + idx))
            listable = [(idx, view.tobytes()) for idx, view in iterable]

            # check if we found any ops that point directly to this member
            if any(listable):
                iterable = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx, val in listable)
                iterable = (idx for idx, (_, ids) in iterable if self.parent.id in ids)    # sanity
                res.extend(interface.opref_t(ea, int(opnum), interface.reftype_t.of(t)) for opnum in iterable)

            # otherwise our reference is implicitly pointing to our member, so
            # now we need to figure out which operand is the one.
            else:
                fl = database.type.flags(ea)
                iterable = ((opnum, instruction.opinfo(ea, opnum)) for opnum, _ in enumerate(instruction.operands(ea)))
                iterable = ((opnum, info) for opnum, info in iterable if isinstance(info, idaapi.opinfo_t))

                # now that we got all the opinfo_t for each operand, we need to
                # distinguish which operands are capable of being calculated to
                # determine which ones point to our structure member.
                iterable = ((opnum, info.ri, instruction.op(ea, opnum)) for opnum, info in iterable if info.ri.is_target_optional())

                # now we can do some math to determine if the operands really
                # are pointing to our structure member.
                # pointing at our member exactly..
                for opnum, ri, opvalue in iterable:
                    offset = opvalue if isinstance(opvalue, six.integer_types) else builtins.next((getattr(opvalue, attribute) for attribute in {'offset', 'address'} if hasattr(opvalue, attribute)), None)

                    # check if we got a valid offset, because if not then we just
                    # need to skip to the next iteration
                    if offset is None or not database.within(offset):
                        continue

                    # align the offset, and check if our address is using one
                    # of our structure identifiers
                    offset = interface.address.head(offset, silent=True)
                    if database.type.flags(offset, idaapi.DT_TYPE) == FF_STRUCT and database.type.structure.id(offset) in identifiers:
                        res.append(interface.opref_t(ea, opnum, interface.reftype_t.of(t)))
                    continue
                continue
            continue
        return res

    ### Properties
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.member_t``.'''
        parent = self.parent
        return parent.ptr.get_member(self.__index__)
    @property
    def id(self):
        '''Return the identifier of the member.'''
        return self.ptr.id
    @property
    def properties(self):
        '''Return the properties for the current member.'''
        return self.ptr.props
    @property
    def size(self):
        '''Return the size of the member.'''
        return idaapi.get_member_size(self.ptr)
    @property
    def realoffset(self):
        '''Return the real offset of the member.'''
        parent, member = self.parent.ptr, self.ptr
        return 0 if parent.is_union() else member.get_soff()
    @property
    def offset(self):
        '''Return the offset of the member.'''
        parent = self.parent
        return self.realoffset + parent.members.baseoffset
    @property
    def flag(self):
        '''Return the "flag" attribute of the member.'''
        mptr = idaapi.get_member(self.parent.ptr, self.offset - self.parent.members.baseoffset)
        return 0 if mptr is None else mptr.flag
    @property
    def fullname(self):
        '''Return the fullname of the member.'''
        res = idaapi.get_member_fullname(self.id)
        return utils.string.of(res)
    @property
    def typeid(self):
        '''Return the identifier of the type of the member.'''
        opinfo = idaapi.opinfo_t()
        res = idaapi.retrieve_member_info(self.ptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, self.ptr)
        if res:
            return None if res.tid == idaapi.BADADDR else res.tid
        return None
    @property
    def index(self):
        '''Return the index of the member.'''
        return self.__index__
    @property
    def left(self):
        '''Return the beginning offset of the member.'''
        left, _ = self.bounds
        return left
    @property
    def right(self):
        '''Return the ending offset of the member.'''
        _, right = self.bounds
        return right
    @property
    def realbounds(self):
        '''Return the real boundaries of the member.'''
        sptr, mptr = self.parent.ptr, self.ptr
        return interface.bounds_t(0 if sptr.is_union() else mptr.soff, mptr.eoff)
    @property
    def bounds(self):
        '''Return the boundaries of the member.'''
        parent = self.parent
        bounds, base = self.realbounds, parent.members.baseoffset
        return bounds.translate(base)
    @property
    def parent(self):
        '''Return the structure_t that owns the member.'''
        return self.__parent__
    @property
    def dt_type(self):
        '''Return the `dt_type` attribute of the member.'''
        m = idaapi.get_member(self.parent.ptr, self.offset - self.parent.members.baseoffset)
        if m is None:
            return 0
        flag = m.flag & idaapi.DT_TYPE
        return idaapi.as_uint32(flag)
    dtype = dt_type

    ## Readable/Writeable Properties
    @property
    def name(self):
        '''Return the name of the member.'''
        res = idaapi.get_member_name(self.id) or ''
        return utils.string.of(res)
    @name.setter
    @utils.string.decorate_arguments('string')
    def name(self, string):
        '''Set the name of the member to `string`.'''
        if isinstance(string, tuple):
            string = interface.tuplename(*string)

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.VNT_VISIBLE)
        if ida_string and ida_string != res:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name : Stripping invalid chars from structure member name (\"{:s}\") resulted in \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the member at the specified offset
        oldname = self.name
        if not idaapi.set_member_name(self.parent.ptr, self.offset - self.parent.members.baseoffset, ida_string):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).name : Unable to assign the specified name ({:s}) to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(ida_string), utils.string.repr(oldname)))

        # verify that the name was actually assigned properly
        assigned = idaapi.get_member_name(self.id) or ''
        if utils.string.of(assigned) != utils.string.of(ida_string):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name : The name ({:s}) that was assigned to the structure member does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(utils.string.of(assigned)), utils.string.repr(ida_string)))
        return assigned

    @property
    def comment(self, repeatable=True):
        '''Return the repeatable comment of the member.'''
        res = idaapi.get_member_cmt(self.id, repeatable) or idaapi.get_member_cmt(self.id, not repeatable)
        return utils.string.of(res)
    @comment.setter
    @utils.string.decorate_arguments('value')
    def comment(self, value, repeatable=True):
        '''Set the repeatable comment of the member to `value`.'''
        res = utils.string.to(value or '')
        if not idaapi.set_member_cmt(self.ptr, res, repeatable):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).comment(..., repeatable={!s}) : Unable to assign the provided comment to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(self.name)))

        # verify that the comment was actually assigned properly
        assigned = idaapi.get_member_cmt(self.id, repeatable)
        if utils.string.of(assigned) != utils.string.of(res):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment(..., repeatable={!s}) : The comment ({:s}) that was assigned to the structure member does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, repeatable, utils.string.repr(utils.string.of(assigned)), utils.string.repr(res)))
        return assigned

    @property
    def type(self):
        '''Return the type of the member in its pythonic form.'''
        res = interface.typemap.dissolve(self.flag, self.typeid, self.size)
        if isinstance(res, structure_t):
            res = __instance__(res.id, offset=self.offset)
        elif isinstance(res, tuple):
            t, sz = res
            if isinstance(t, structure_t):
                t = __instance__(t.id, offset=self.offset)
            elif isinstance(t, builtins.list) and isinstance(t[0], structure_t):
                t[0] = __instance__(t[0].id, offset=self.offset)
            res = t, sz
        return res
    @type.setter
    def type(self, type):
        '''Set the type of the member to the provided `type`.'''
        flag, typeid, nbytes = interface.typemap.resolve(type)

        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        if not idaapi.set_member_type(self.parent.ptr, self.offset - self.parent.members.baseoffset, flag, opinfo, nbytes):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).type({!s}) : Unable to assign the provided type ({!s}) to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, type, type, utils.string.repr(self.name)))

        items = flag, typeid, nbytes
        newflag, newtypeid, newsize = self.flag, self.typeid or idaapi.BADADDR, self.size
        if newflag != flag:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).type({!s}) : The provided flags ({:#x}) were incorrectly assigned as {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, items, flags, newflags))

        if newtypeid != typeid:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).type({!s}) : The provided typeid ({:#x}) was incorrectly assigned as {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, items, typeid, newtypeid))

        if newsize != nbytes:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).type({!s}) : The provided size ({:+#x}) was incorrectly assigned as {:+#x}.".format('.'.join([__name__, cls.__name__]), self.id, items, nbytes, newsize))

        return newflag, newtypeid, newsize

    @property
    def typeinfo(self):
        '''Return the type information of the current member.'''
        ti = idaapi.tinfo_t()

        # Guess the typeinfo for the current member. If we're unable to get the
        # typeinfo, then raise a critical exception because members need to have
        # types and it doesn't make sense for them to not.
        ok = idaapi.get_or_guess_member_tinfo2(self.ptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, self.ptr)
        if not ok:
            cls = self.__class__
            raise E.MissingTypeOrAttribute(u"{:s}({:#x}).typeinfo : Unable to determine the type information for member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, self.name))

        # Return the typeinfo back to the caller.
        return ti
    @typeinfo.setter
    def typeinfo(self, info):
        '''Set the type information of the current member to `info`.'''

        if idaapi.__version__ < 7.0:
            set_member_tinfo = idaapi.set_member_tinfo2
        else:
            set_member_tinfo = idaapi.set_member_tinfo

        # Parse our into parameter into a tinfo_t for us, so that we can assign it to the
        # typeinfo for the member.
        ti = internal.declaration.parse(info)
        if ti is None:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo({!s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), info))

        # Now we can pass our tinfo_t along with the member information to IDA.
        res = set_member_tinfo(self.parent.ptr, self.ptr, self.ptr.get_soff(), ti, 0)
        if res == idaapi.SMT_OK:
            return

        # We failed, so just raise an exception for the user to handle.
        elif res == idaapi.SMT_FAILED:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the type information ({!s}) to structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), utils.string.repr(info), utils.string.repr(self.name)))

        # If we received an alternative return code, then build a relevant
        # message that we can raise with our exception.
        if res == idaapi.SMT_BADARG:
            message = 'invalid parameters'
        elif res == idaapi.SMT_NOCOMPAT:
            message = 'incompatible type'
        elif res == idaapi.SMT_WORSE:
            message = 'worse type'
        elif res == idaapi.SMT_SIZE:
            message = 'invalid type for member size'
        elif res == idaapi.SMT_ARRAY:
            message = 'setting function argument as an array is illegal'
        elif res == idaapi.SMT_OVERLAP:
            message = 'the specified type would result in member overlap'
        elif res == idaapi.SMT_KEEP:
            message = 'the specified type is not ideal'
        else:
            message = "unknown error {:#x}".format(res)

        # Finally we can raise our exception so that the user knows whats up.
        cls = self.__class__
        raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the type information ({!s}) to structure member {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), utils.string.repr(info), utils.string.repr(self.name), message))

    ### Private methods
    def __str__(self):
        '''Render the current member in a readable format.'''
        id, name, typ, comment, tag, typeinfo = self.id, self.fullname, self.type, self.comment or '', self.tag(), "{!s}".format(self.typeinfo.dstr()).replace(' *', '*')
        return "<member '{:s}' index={:d} offset={:-#x} size={:+#x}{:s}>{:s}".format(utils.string.escape(name, '\''), self.index, self.offset, self.size, " typeinfo='{:s}'".format(typeinfo) if len("{:s}".format(typeinfo)) else '', " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __unicode__(self):
        '''Render the current member in a readable format.'''
        id, name, typ, comment, tag, typeinfo = self.id, self.fullname, self.type, self.comment or '', self.tag(), "{!s}".format(self.typeinfo.dstr()).replace(' *', '*')
        return u"<member '{:s}' index={:d} offset={:-#x} size={:+#x}{:s}>{:s}".format(utils.string.escape(name, '\''), self.index, self.offset, self.size, " typeinfo='{:s}'".format(typeinfo) if len("{:s}".format(typeinfo)) else '', " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __repr__(self):
        return u"{!s}".format(self)

    ## Serialization
    def __getstate__(self):
        t, ti = (self.flag, None if self.typeid is None else __instance__(self.typeid), self.size), self.typeinfo

        # grab its typeinfo and serialize it
        typeinfo = t, ti.serialize()

        # grab its comments
        cmtt = idaapi.get_member_cmt(self.id, True)
        cmtf = idaapi.get_member_cmt(self.id, False)
        res = (utils.string.of(cmt) for cmt in [cmtt, cmtf])

        # now we can return them
        ofs = self.offset - self.__parent__.members.baseoffset
        return self.__parent__.name, self.__index__, self.name, tuple(res), ofs, typeinfo
    def __setstate__(self, state):
        parentname, index, name, (cmtt, cmtf), ofs, typeinfo = state
        cls, fullname = self.__class__, '.'.join([parentname, name])

        # get the structure owning the member by the name we stored
        # creating it if necessary.
        res = utils.string.to(parentname)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            logging.info(u"{:s}({:#x}, offset={:+#x}) : Creating structure ({:s}) for member named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, ofs, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, res)

        if identifier == idaapi.BADADDR:
            raise E.DisassemblerError(u"{:s}({:#x}, offset={:+#x}) : Unable to get structure ({:s}) for member named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, ofs, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))

        parent = __instance__(identifier, offset=0)

        # extract the type information of the member so that we can
        # construct the opinfo_t and deserialize the tinfo_t for it.
        t, ti_ = typeinfo
        flag, mytype, nbytes = t

        ti = idaapi.tinfo_t()
        if ti.deserialize(None, *ti_):
            logging.info(u"{:s}({:#x}, offset={:+#x}): Successfully parsed type information for member \"{:s}\" as \"{!s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, utils.string.escape(fullname, '"'), ti))

        else:
            ti, _ = None, logging.warning(u"{:s}({:#x}, offset={:+#x}): Skipping corrupted type information {!r} for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, ti_, utils.string.escape(fullname, '"')))

        # create an opinfo_t for the member's type
        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = 0 if mytype is None else mytype.id

        # add the member to the database, and then check whether there was a naming
        # issue of some sort so that we can warn the user or resolve it.
        res = utils.string.to(name)
        mem = idaapi.add_struc_member(parent.ptr, res, ofs, flag, opinfo, nbytes)

        # FIXME: handle these naming errors properly
        # duplicate name
        if mem == idaapi.STRUC_ERROR_MEMBER_NAME:
            if idaapi.get_member_by_name(parent.ptr, res).soff != ofs:
                newname = u"{:s}_{:x}".format(res, ofs)
                logging.warning(u"{:s}({:#x}, offset={:+#x}): Duplicate name found for member \"{:s}\" of structure ({:s}), renaming to \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, utils.string.escape(name, '"'), parentname, utils.string.escape(newname, '"')))
                idaapi.set_member_name(parent.ptr, ofs, utils.string.to(newname))
            else:
                logging.info(u"{:s}({:#x}, offset={:+#x}): Field at {:+#x} of structure ({:s}) contains the same name \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, ofs, parentname, utils.string.escape(name, '"')))

        # duplicate field
        elif mem == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            logging.info(u"{:s}({:#x}, offset={:+#x}): Already existing field found at {:+#x} of structure ({:s}). Overwriting with \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, ofs, parentname, utils.string.escape(name, '"')))
            idaapi.set_member_type(parent.ptr, ofs, flag, opinfo, nbytes)
            idaapi.set_member_name(parent.ptr, ofs, res)

        # invalid size
        elif mem == idaapi.STRUC_ERROR_MEMBER_SIZE:
            logging.warning(u"{:s}({:#x}, offset={:+#x}): Error code {:#x} returned while trying to create member \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, mem, utils.string.escape(fullname, '"')))

        # unknown
        elif mem != idaapi.STRUC_ERROR_MEMBER_OK:
            logging.warning(u"{:s}({:#x}, offset={:+#x}): Error code {:#x} returned while trying to create member \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, mem, utils.string.escape(fullname, '"')))

        # now that we know our parent exists, assign both that and our
        # index that we deserialized.
        self.__parent__, self.__index__ = parent, index

        # update both of the member's comments prior to fixing its type.
        idaapi.set_member_cmt(self.ptr, utils.string.to(cmtt), True)
        idaapi.set_member_cmt(self.ptr, utils.string.to(cmtf), False)

        # try and assign the typeinfo that we previously deserialized
        try:
            if ti:
                self.typeinfo = ti

        except Exception:
            logging.warning(u"{:s}({:#x}, offset={:+#x}): Unable to apply type information ({!s}) to member \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, ofs, ti, utils.string.escape(fullname, '"')), exc_info=True)
        return
