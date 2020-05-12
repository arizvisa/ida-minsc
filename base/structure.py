"""
Structure module

This module exposes a number of tools and defines some classes that
can be used to interacting with the structures defined in the database.
The classes defined by this module wrap IDA's structure API and expose
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

import six
from six.moves import builtins

import functools, operator, itertools, types
import sys, logging
import re, fnmatch

import database, instruction
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

def __instance__(identifier, **options):
    '''Create a new instance of the structure identified by `identifier`.'''
    # check to see if the structure cache has been initialized
    # XXX: this structure cache is needed in order to retain the "offset" that
    #      is kept for a function frame. we need some better solution to this,
    #      maybe we can stash this in a netnode for the structure's id
    # FIXME: this cache needs to be refreshed when the database changes
    try:
        cache = __instance__.cache
    except AttributeError:
        # create it and try again if it hasn't
        __instance__.cache = {}
        return __instance__(identifier, **options)

    # try and fetch the structure from the cache
    res = cache.setdefault(identifier, structure_t(identifier, **options))
    if 'offset' in options:
        res.offset = options['offset']
    return res

__matcher__ = utils.matcher()
__matcher__.boolean('regex', re.search, 'name')
__matcher__.mapping('index', idaapi.get_struc_idx, 'id')
__matcher__.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
__matcher__.boolean('like', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'name')
__matcher__.boolean('name', operator.eq, 'name')
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

@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string')
def iterate(string):
    '''Iterate through all of the structures in the database with a glob that matches `string`.'''
    return iterate(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def iterate(**type):
    '''Iterate through all of the structures that match the keyword specified by `type`.'''
    if not type: type = {'predicate':lambda n: True}
    res = builtins.list(__iterate__())
    for key, value in six.iteritems(type):
        res = builtins.list(__matcher__.match(key, value, res))
    for item in res: yield item

@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string')
def list(string):
    '''List any structures that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def list(**type):
    '''List all the structures within the database that match the keyword specified by `type`.'''
    res = builtins.list(iterate(**type))

    maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) or [1])
    maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), utils.fdefault(''), len), res) or [1])
    maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) or [1])

    for st in res:
        six.print_(u"[{:{:d}d}] {:>{:d}s} {:<+#{:d}x} ({:d} members){:s}".format(idaapi.get_struc_idx(st.id), maxindex, st.name, maxname, st.size, maxsize, len(st.members), u" // {!s}".format(st.tag() if '\n' in st.comment else st.comment) if st.comment else ''))
    return

@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
def new(name):
    '''Returns a new structure `name`.'''
    return new(name, 0)
@utils.multicase(name=basestring, offset=six.integer_types)
@utils.string.decorate_arguments('name')
def new(name, offset):
    '''Returns a new structure `name` using `offset` as its base offset.'''
    res = utils.string.to(name)

    # add a structure with the specified name
    id = idaapi.add_struc(idaapi.BADADDR, res)
    if id == idaapi.BADADDR:
        raise E.DisassemblerError(u"{:s}.new({!r}, {:#x}) : Unable to add a new structure to the database.".format(__name__, name, offset))

    # FIXME: we should probably move the new structure to the end of the list via idaapi.set_struc_idx

    # Create a new instance in the structure cache with the specified id
    return __instance__(id, offset=offset)

@utils.multicase(name=basestring)
@utils.string.decorate_arguments('name')
def by(name, **options):
    '''Return a structure by its name.'''
    return by_name(name, **options)
@utils.multicase(id=six.integer_types)
def by(id, **options):
    '''Return a structure by its index or id.'''
    if interface.node.is_identifier(id):
        return __instance__(id, **options)
    return by_index(id, **options)
@utils.multicase()
@utils.string.decorate_arguments('regex', 'like', 'name')
def by(**type):
    '''Return the structure matching the keyword specified by `type`.'''
    searchstring = utils.string.kwargs(type)

    res = builtins.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, ((u"[{:d}] {:s}".format(idaapi.get_struc_idx(st.id), st.name)) for i, st in enumerate(res)))
        logging.warn(u"{:s}.search({:s}) : Found {:d} matching results, returning the first one {!s}.".format(__name__, searchstring, len(res), res[0]))

    res = next(iter(res), None)
    if res is None:
        raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

@utils.multicase(string=basestring)
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
byName = utils.alias(by_name)

def by_index(index, **options):
    '''Return a structure by its index.'''
    id = idaapi.get_struc_by_idx(index)
    if id == idaapi.BADADDR:
        raise E.StructureNotFoundError(u"{:s}.by_index({:d}{:s}) : Unable to locate structure at given index.".format(__name__, index, u", {:s}".format(utils.string.kwargs(options)) if options else ''))

    # grab an instance of the structure by the id we found
    return __instance__(id, **options)
byIndex = utils.alias(by_index)

def by_identifier(identifier, **options):
    '''Return the structure identified by `identifier`.'''
    return __instance__(identifier, **options)

by_id = byIdentifier = byId = utils.alias(by_identifier)

## FIXME: need to add support for a union_t. add_struc takes another parameter
##        that defines whether a structure is a union or not.

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
    __slots__ = ('__id__', '__members__')

    def __init__(self, id, offset=0):
        self.__id__ = id
        if self.ptr is None:
            cls = self.__class__
            raise E.StructureNotFoundError(u"{:s}({:#x}, offset={:+#x}) : Unable to locate the structure with the specified identifier.".format('.'.join((__name__, cls.__name__)), id, offset))
        self.__members__ = members_t(self, baseoffset=offset)

    def up(self):
        '''Return all the structure members and addresses that reference this specific structure.'''
        x, sid = idaapi.xrefblk_t(), self.id

        # grab first structure that references this one
        ok = x.first_to(sid, 0)
        if not ok or x.frm == idaapi.BADADDR:
            return []

        # continue collecting all structures that references this one
        res = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            res.append((x.frm, x.iscode, x.type))

        # walk through all references figuring out if its a structure member or an address
        refs = []
        for xrfrom, xriscode, xrtype in res:
            # if it's an address, then just create a regular reference
            if database.contains(xrfrom):
                refs.append( interface.OREF(xrfrom, xriscode, interface.ref_t.of(xrtype)) )
                continue

            # so it's not, which means this must be a member id
            fullname = idaapi.get_member_fullname(xrfrom)

            sptr = idaapi.get_member_struc(fullname)
            if not sptr:
                cls = self.__class__
                logging.warn(u"{:s}({:#x}).up() : Unable to find structure from member name \"{:s}\" while trying to handle reference for {:#x}.".format('.'.join((__name__, cls.__name__)), self.id, utils.string.escape(fullname, '"'), xrfrom))
                continue

            # we figured out the owner, so find the member with the ref, and add it.
            st = __instance__(sptr.id)
            refs.append(st.by_identifier(xrfrom))

        # and that's it, so we're done.
        return refs

    def down(self):
        '''Return all the structure members and addresses that are referenced by this specific structure.'''
        x, sid = idaapi.xrefblk_t(), self.id

        # grab structures that this one references
        ok = x.first_from(sid, 0)
        if not ok or x.to == idaapi.BADADDR:
            return []

        # continue collecting all structures that this one references
        res = [(x.to, x.iscode, x.type)]
        while x.next_from():
            res.append((x.to, x.iscode, x.type))

        # walk through all references figuring out if its a structure member or an address
        refs = []
        for xrto, xriscode, xrtype in res:
            # if it's  an address, then just create a regular reference
            if database.contains(xrto):
                refs.append( interface.OREF(xrto, xriscode, interface.ref_t.of(xrtype)) )
                continue

            # so it's not, which means this must be a member id
            fullname = idaapi.get_member_fullname(xrto)

            sptr = idaapi.get_member_struc(fullname)
            if not sptr:
                cls = self.__class__
                logging.warn(u"{:s}({:#x}).down() : Unable to find structure from member name \"{:s}\" while trying to handle reference for {:#x}.".format('.'.join((__name__, cls.__name__)), self.id, utils.string.escape(fullname, '"'), xrto))
                continue

            # we figured out the owner, so find the member with the ref, and add it.
            st = __instance__(sptr.id)
            refs.append(st.by_identifier(xrto))

        # and that's it, so we're done.
        return refs

    def refs(self):
        '''Return all structure or frame members within the database that reference this particular structure.'''
        x, sid = idaapi.xrefblk_t(), self.id

        # grab first reference to structure
        ok = x.first_to(sid, 0)
        if not ok:
            return []

        # collect the rest of its references
        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # iterate through figuring out if sid is applied to an address or another structure
        res = []
        for ref, _, _ in refs:

            # structure (probably a frame member)
            if interface.node.is_identifier(ref):
                # get mptr and the member name
                mpack = idaapi.get_member_by_id(ref)
                if mpack is None:
                    cls = self.__class__
                    raise E.MemberNotFoundError(u"{:s}({:#x}).refs() : Unable to locate the member identified by {:#x}.".format('.'.join((__name__, cls.__name__)), self.id, ref))
                mptr, name, _ = mpack

                # validate mptr and get the sptr from it
                if not isinstance(mptr, idaapi.member_t):
                    cls, name = self.__class__, idaapi.get_member_fullname(ref)
                    raise E.InvalidTypeOrValueError(u"{:s}({:#x}).refs() : Unexpected type {!s} returned for member \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, mptr.__class__, internal.utils.string.escape(name, '"')))
                sptr = idaapi.get_member_struc(name)

                # find out from mptr id if we're a function frame
                frname, _ = name.split('.', 1)
                frid = internal.netnode.get(frname)
                ea = idaapi.get_func_by_frame(frid)

                # if we were unable to get the function frame, then we must be
                # referencing the member of another structure
                if ea == idaapi.BADADDR:
                    st = by_identifier(sptr.id)
                    mem = st.members.by_identifier(mptr.id)
                    res.append(mem)
                    continue

                # otherwise we're referencing a frame member, and we need to grab
                # the frame for the given function
                fr = idaapi.get_frame(ea)
                if fr is None:
                    cls = self.__class__
                    raise E.MissingTypeOrAttribute(u"{:s}({:#x}).refs() : The function at {:#x} for frame member {:#x} does not have a frame.".format('.'.join((__name__, cls.__name__)), self.id, ea, mptr.id))

                # and we also need the func_t
                f = idaapi.get_func(ea)
                if f is None:
                    cls = self.__class__
                    raise E.FunctionNotFoundError(u"{:s}({:#x}).refs() : Unable to locate the function for frame member {:#x} by address {:#x}.".format('.'.join((__name__, cls.__name__)), self.id, mptr.id, ea))

                # so we can instantiate the structure with the correct offset
                # and then grab the member that was referenced
                st = by_identifier(fr.id, offset=-f.frsize)
                mem = st.members.by_identifier(mptr.id)
                res.append(mem)

            # otherwise we just got an address, so figure out if it was code
            elif database.type.is_code(ref):

                # iterate through all of its operands figuring out the opinfo for it
                for opnum, _ in enumerate(instruction.operands(ref)):
                    opinfo = instruction.opinfo(ref, opnum)
                    if opinfo is None:
                        continue

                    # check if we do have an opinfo.path, and our sid is contained in it
                    if opinfo.path.len > 0 and operator.contains(opinfo.path.ids, sid):
                        state = instruction.op_state(ref, opnum)
                        res.append( interface.OREF(ref, opnum, interface.ref_t.of_state(state)) )   # using '*' to describe being applied to the an address
                    continue

            # anything else is data and we just need to add a reference in that case
            else:
                res.append( interface.OREF(ref, None, interface.ref_t.of_state('*')) )   # using '*' to describe being applied to the an address
            continue

        return res

    @property
    def id(self):
        '''Return the identifier of the structure.'''
        return self.__id__
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.struc_t``.'''
        return idaapi.get_struc(self.id)
    @property
    def members(self):
        '''Return the members belonging to the structure.'''
        return self.__members__

    def __getstate__(self):
        cmtt, cmtf = map(functools.partial(idaapi.get_struc_cmt, self.id), (True, False))

        # decode the comments that we found in the structure
        res = map(utils.string.of, (cmtt, cmtf))

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
            logging.info(u"{:s}({:#x}) : Creating structure \"{:s}\" with {:d} fields and the comment \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, utils.string.escape(name, '"'), len(members), utils.string.escape(cmtf or cmtt or '', '"')))
            res = utils.string.to(name)
            identifier = idaapi.add_struc(idaapi.BADADDR, res)

        # now we can apply the comments to it
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtt), True)
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtf), False)

        # and set its attributes properly
        self.__id__ = identifier
        self.__members__ = members
        return

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
        res = idaapi.validate_name2(buffer(ida_string)[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(buffer(ida_string)[:], idaapi.VNT_VISIBLE)
        if ida_string and ida_string != res:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name({!r}) : Stripping invalid chars from structure name \"{:s}\" resulted in \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the structure
        return idaapi.set_struc_name(self.id, ida_string)

    @property
    def comment(self, repeatable=True):
        '''Return the repeatable comment for the structure.'''
        res = idaapi.get_struc_cmt(self.id, repeatable) or idaapi.get_struc_cmt(self.id, not repeatable)
        return utils.string.of(res)
    @comment.setter
    @utils.string.decorate_arguments('value')
    def comment(self, value, repeatable=True):
        '''Set the repeatable comment for the structure to `value`.'''
        res = utils.string.to(value)
        return idaapi.set_struc_cmt(self.id, res, repeatable)

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
        if d1.viewkeys() & d2.viewkeys():
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment() : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('.'.join((__name__, cls.__name__)), self.id, ', '.join(d1.viewkeys() & d2.viewkeys()), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it (XXX: return a dictionary that automatically updates the comment when it's updated)
        res = {}
        builtins.map(res.update, (d1, d2) if repeatable else (d2, d1))
        return res
    @utils.multicase(key=basestring)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the structure.'''
        res = self.tag()
        return res[key]
    @utils.multicase(key=basestring)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the structure.'''
        state = self.tag()
        repeatable, res, state[key] = True, state.get(key, None), value
        ok = idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), repeatable)
        return res
    @utils.multicase(key=basestring, none=types.NoneType)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the structure.'''
        state = self.tag()
        repeatable, res = True, state.pop(key)
        ok = idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), repeatable)
        return res

    @property
    def size(self):
        '''Return the size of the structure.'''
        return idaapi.get_struc_size(self.ptr)
    @size.setter
    def size(self, size):
        '''Expand the structure to the new `size` that is specified.'''
        res = idaapi.get_struc_size(self.ptr)
        ok = idaapi.expand_struc(self.ptr, 0, size - res, True)
        if not ok:
            cls = self.__class__
            logging.fatal(u"{:s}({:#x}).size({:+d}) : Unable to resize structure \"{:s}\" from {:#x} bytes to {:#x} bytes.".format('.'.join((__name__, cls.__name__)), self.id, size, utils.string.escape(self.name, '"'), res, size))
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
    def index(self, idx):
        '''Set the index of the structure to `idx`.'''
        return idaapi.set_struc_idx(self.ptr, idx)

    def destroy(self):
        '''Remove the structure from the database.'''
        return idaapi.del_struc(self.ptr)

    def __repr__(self):
        '''Display the structure in a readable format.'''
        name, offset, size, comment, tag = self.name, self.offset, self.size, self.comment or '', self.tag()
        return "<class 'structure' name={!s}{:s} size={:#x}>{:s}".format(utils.string.repr(name), (" offset={:#x}".format(offset) if offset != 0 else ''), size, " // {!s}".format(utils.string.repr(tag) if '\n' in comment else comment.encode('utf8')) if comment else '')

    def field(self, offset):
        '''Return the member at the specified offset.'''
        return self.members.by_offset(offset + self.members.baseoffset)

    def copy(self, name):
        '''Copy members into the structure `name`.'''
        raise NotImplementedError

    def __getattr__(self, name):
        return getattr(self.members, name)

    def contains(self, offset):
        '''Return whether the specified offset is contained by the structure.'''
        res, cb = self.members.baseoffset, idaapi.get_struc_size(self.ptr)
        return res <= offset < res + cb

@utils.multicase()
def name(id):
    '''Return the name of the structure identified by `id`.'''
    res = idaapi.get_struc_name(id)
    return utils.string.of(res)
@utils.multicase(structure=structure_t)
def name(structure):
    return name(structure.id)
@utils.multicase(string=basestring)
@utils.string.decorate_arguments('string', 'suffix')
def name(id, string, *suffix):
    '''Set the name of the structure identified by `id` to `string`.'''
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # convert the specified string into a form that IDA can handle
    ida_string = utils.string.to(string)

    # validate the name
    res = idaapi.validate_name2(buffer(ida_string)[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(buffer(ida_string)[:], idaapi.VNT_VISIBLE)
    if ida_string and ida_string != res:
        logging.info(u"{:s}.name({!r}, {!r}) : Stripping invalid chars from the structure name \"{:s}\" resulted in \"{:s}\".".format(__name__, id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
        ida_string = res

    # now we can set the name of the structure
    return idaapi.set_struc_name(id, ida_string)
@utils.multicase(structure=structure_t, string=basestring)
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
@utils.multicase(structure=structure_t, cmt=basestring)
@utils.string.decorate_arguments('cmt')
def comment(structure, cmt, **repeatable):
    '''Set the comment to `cmt` for the specified `structure`.'''
    return comment(structure.id, cmt, **repeatable)
@utils.multicase(id=six.integer_types, cmt=basestring)
@utils.string.decorate_arguments('cmt')
def comment(id, cmt, **repeatable):
    """Set the comment of the structure identified by `id` to `cmt`.

    If the bool `repeatable` is specified, set the repeatable comment.
    """
    res = utils.string.to(cmt)
    return idaapi.set_struc_cmt(id, res, repeatable.get('repeatable', True))

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
    if not st:
        # empty structure
        return

    size = idaapi.get_struc_size(st)

    # iterate through the number of members belonging to the struct
    offset = 0
    for i in six.moves.range(st.memqty):

        # grab the member and its size
        m = st.get_member(i)
        ms = idaapi.get_member_size(m)

        # grab the member's boundaries
        left, right = m.soff, m.eoff

        # grab the member's attributes
        res = map(utils.string.of, (idaapi.get_member_name(m.id), idaapi.get_member_cmt(m.id, 0), idaapi.get_member_cmt(m.id, 1)))

        # yield our current position and iterate to the next member
        if offset < left:
            yield (offset, left-offset), tuple(res)
            offset = left

        yield (offset, ms), tuple(res)
        offset += ms
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
    member = members(id)

    # seek
    while True:
        (m_offset, m_size), (m_name, m_cmt, m_rcmt) = member.next()

        left, right = m_offset, m_offset+m_size
        if (offset >= left) and (offset < right):
            yield (m_offset, m_size), (m_name, m_cmt, m_rcmt)
            size -= m_size
            break
        continue

    # return
    while size > 0:
        (m_offset, m_size), (m_name, m_cmt, m_rcmt) = member.next()
        yield (m_offset, m_size), (m_name, m_cmt, m_rcmt)
        size -= m_size
    return

@utils.multicase(structure=structure_t)
def remove(structure):
    '''Remove the specified `structure` from the database.'''
    ok = idaapi.del_struc(structure.ptr)
    if not ok:
        raise E.StructureNotFoundError(u"{:s}.remove({!r}) : Unable to remove structure {:#x}.".format(__name__, structure, structure.id))
    return True
@utils.multicase(name=basestring)
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
    __slots__ = ('__parent', 'baseoffset')

    # members state
    @property
    def parent(self):
        '''Return the ``structure_t`` that owns this ``members_t``.'''
        return self.__parent
    @property
    def ptr(self):
        '''Return the pointer to the ``idaapi.member_t`` that contains all the members.'''
        return self.__parent.ptr.members
    def __init__(self, parent, baseoffset=0):
        self.__parent = parent
        self.baseoffset = baseoffset

    def __getstate__(self):
        return (self.parent.name, self.baseoffset, map(self.__getitem__, six.moves.range(len(self))))
    def __setstate__(self, state):
        parentname, baseoffset, _ = state

        # grab the structure containing our members so we can instantiate it
        res = utils.string.to(parentname)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}) : Failure trying to create a `members_t` for the `structure_t` \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.parent.id, utils.string.escape(parentname, '"')))
            #logging.warn(u"{:s}.instance({!r}).members.__setstate__ : Creating structure \"{:s}\" at offset {:+#x} with {:d} members.".format(__name__, self.parent.name, utils.string.escape(parentname, '"'), baseoffset, len(members)))
            #identifier = idaapi.add_struc(idaapi.BADADDR, parentname)

        # assign the properties for our new member using the instance we figured out
        self.baseoffset = baseoffset
        self.__parent = __instance__(identifier, offset=baseoffset)
        return

    # fetching members
    def __len__(self):
        '''Return the number of members within the structure.'''
        return 0 if self.parent.ptr is None else self.parent.ptr.memqty
    def __iter__(self):
        '''Yield all the members within the structure.'''
        for idx in six.moves.range(len(self)):
            yield member_t(self.parent, idx)
        return
    def __getitem__(self, index):
        '''Return the member at the specified `index`.'''
        if isinstance(index, six.integer_types):
            index = self.parent.ptr.memqty + index if index < 0 else index
            res = member_t(self.parent, index) if index >= 0 and index < self.parent.ptr.memqty else None
        elif isinstance(index, six.string_types):
            res = self.by_name(index)
        elif isinstance(index, slice):
            res = [self.__getitem__(i) for i in six.moves.range(self.parent.ptr.memqty)].__getitem__(index)
        else:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__getitem__({!r}) : An invalid type ({!r}) was specified for the index.".format('.'.join((__name__, cls.__name__)), self.parent.id, index, index.__class__))

        if res is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.__getitem__({!r}) : Unable to find the member that was requested.".format('.'.join((__name__, cls.__name__)), self.parent.id, index))
        return res

    def index(self, member):
        '''Return the index of the specified `member`.'''
        if not hasattr(member, 'id'):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.index({!r}) : An invalid type ({!r}) was specified for the member to search for.".format('.'.join((__name__, cls.__name__)), self.parent.id, member, member.__class__))

        for i in six.moves.range(self.parent.ptr.memqty):
            if member.id == self[i].id:
                return i
            continue
        cls = self.__class__
        raise E.MemberNotFoundError(u"{:s}({:#x}).members.index({!s}) : The requested member is not in the members list.".format('.'.join((__name__, cls.__name__)), self.parent.id, "{:#x}".format(member.id) if isinstance(member, (member_t, idaapi.member_t)) else "{!r}".format(member)))

    __member_matcher = utils.matcher()
    __member_matcher.boolean('regex', re.search, 'name')
    __member_matcher.attribute('index', 'index')
    __member_matcher.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
    __member_matcher.attribute('offset', 'offset')
    __member_matcher.boolean('name', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'name')
    __member_matcher.boolean('like', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'name')
    __member_matcher.boolean('fullname', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'fullname')
    __member_matcher.boolean('comment', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'comment')
    __member_matcher.boolean('comments', lambda pattern, attribute: fnmatch.fnmatch(attribute, pattern), 'comments')
    __member_matcher.boolean('greater', operator.le, lambda member: member.offset + member.size)
    __member_matcher.boolean('ge', operator.le, lambda member: member.offset + member.size)
    __member_matcher.boolean('gt', operator.lt, lambda member: member.offset + member.size)
    __member_matcher.boolean('less', operator.ge, 'offset')
    __member_matcher.boolean('le', operator.ge, 'offset')
    __member_matcher.boolean('lt', operator.gt, 'offset')
    __member_matcher.predicate('predicate'), __member_matcher.predicate('pred')

    # searching members
    @utils.multicase()
    def iterate(self, **type):
        '''Iterate through all of the members in the structure that match the keyword specified by `type`.'''
        if not type: type = {'predicate':lambda n: True}
        res = builtins.list(iter(self))
        for key, value in six.iteritems(type):
            res = builtins.list(self.__member_matcher.match(key, value, res))
        for item in res: yield item

    @utils.multicase(string=basestring)
    @utils.string.decorate_arguments('string')
    def list(self, string):
        '''List any members that match the glob in `string`.'''
        return self.list(like=string)
    @utils.multicase()
    @utils.string.decorate_arguments('regex', 'name', 'like', 'fullname', 'comment', 'comments')
    def list(self, **type):
        '''List all the members within the structure that match the keyword specified by `type`.'''
        res = builtins.list(self.iterate(**type))

        maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) or [1])
        maxoffset = max(builtins.map(utils.fcompose(operator.attrgetter('offset'), "{:x}".format, len), res) or [1])
        maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) or [1])
        maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), utils.string.repr, len), res) or [1])
        maxtype = max(builtins.map(utils.fcompose(operator.attrgetter('type'), utils.string.repr, len), res) or [1])
        maxtypeinfo = max(builtins.map(utils.fcompose(operator.attrgetter('typeinfo'), "{!s}".format, operator.methodcaller('replace', ' *', '*'), len), res) or [0])

        for m in res:
            six.print_(u"[{:{:d}d}] {:>{:d}x}:{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {:{:d}s} (flag={:x},dt_type={:x}{:s}){:s}".format(m.index, maxindex, m.offset, int(maxoffset), m.size, maxsize, "{!s}".format(m.typeinfo).replace(' *', '*'), int(maxtypeinfo), utils.string.repr(m.name), int(maxname), m.type, int(maxtype), m.flag, m.dt_type, '' if m.typeid is None else ",typeid={:x}".format(m.typeid), u" // {!s}".format(m.tag() if '\n' in m.comment else m.comment) if m.comment else ''))
        return

    @utils.multicase()
    @utils.string.decorate_arguments('regex', 'name', 'like', 'fullname', 'comment', 'comments')
    def by(self, **type):
        '''Return the member that matches the keyword specified by `type`.'''
        searchstring = utils.string.kwargs(type)

        res = builtins.list(self.iterate(**type))
        if len(res) > 1:
            cls = self.__class__
            map(logging.info, ((u"[{:d}] {:x}{:+#x} {:s} '{:s}' {!r}".format(m.index, m.offset, m.size, "{!s}".format(m.typeinfo).replace(' *', '*'), utils.string.escape(m.name, '\''), m.type)) for m in res))
            logging.warn(u"{:s}({:#x}).members.by({:s}) : Found {:d} matching results. Returning the member at index {:d} offset {:x}{:+#x} with the name \"{:s}\" and typeinfo \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.parent.id, searchstring, len(res), res[0].index, res[0].offset, res[0].size, utils.string.escape(res[0].fullname, '"'), utils.string.escape("{!s}".format(res[0].typeinfo).replace(' *', '*'), '"')))

        res = next(iter(res), None)
        if res is None:
            cls = self.__class__
            raise E.SearchResultsError(u"{:s}({:#x}).members.by({:s}) : Found 0 matching results.".format('.'.join((__name__, cls.__name__)), self.parent.id, searchstring))
        return res
    @utils.multicase(name=basestring)
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

        # grab the member_t of the structure by its name
        mem = idaapi.get_member_by_name(self.parent.ptr, res)
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_name({!r}) : Unable to find member with requested name.".format('.'.join((__name__, cls.__name__)), self.parent.id, name))

        # figure out the index of the member so we can return the member_t we've cached
        index = self.index(mem)
        return self[index]
    byname = byName = utils.alias(by_name, 'members_t')

    @utils.string.decorate_arguments('fullname')
    def by_fullname(self, fullname):
        '''Return the member with the specified `fullname`.'''
        res = utils.string.to(fullname)

        # grab the member_t of the structure by its fullname
        member = idaapi.get_member_by_fullname(res)
        mem, _ = (None, None) if member is None else member
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_fullname({!r}) : Unable to find member with full name.".format('.'.join((__name__, cls.__name__)), self.parent.id, fullname))

        # figure out the index of the member so we can return the member_t we've cached
        index = self.index(mem)
        return self[index]
    byfullname = byFullname = utils.alias(by_fullname, 'members_t')

    def by_offset(self, offset):
        '''Return the member at the specified `offset` from the base offset of the structure.'''

        # Start out by getting our bounds, and translating them to our relative
        # offset.
        min, max = map(lambda offset: offset + self.baseoffset, (idaapi.get_struc_first_offset(self.parent.ptr), idaapi.get_struc_last_offset(self.parent.ptr)))

        # Guard against a potential OverflowError that would be raised by SWIG's typechecking
        if self.baseoffset > max:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_offset({:+#x}) : Unable to find member at specified offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # Look for the very last member so we can confirm our bounds.
        mptr = idaapi.get_member(self.parent.ptr, max - self.baseoffset)
        if mptr is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_offset({:+#x}) : Unable to find member at specified offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # Get that member's size, so that way we can really confirm that this
        # offset isn't pointing to anything.
        msize = idaapi.get_member_size(mptr)
        if (offset < min) or (offset >= max + msize):
            cls = self.__class__
            raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_offset({:+#x}) : Requested offset not within bounds {:#x}<>{:#x}.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset, min, max + msize))

        # Chain to the realoffset implementation.. This is just a wrapper.
        return self.by_realoffset(offset - self.baseoffset)
    byoffset = byOffset = utils.alias(by_offset, 'members_t')

    def by_realoffset(self, offset):
        '''Return the member at the specified `offset` of the structure.'''
        min, max = idaapi.get_struc_first_offset(self.parent.ptr), idaapi.get_struc_last_offset(self.parent.ptr)

        # Guard against a potential OverflowError that would be raised by SWIG's typechecking
        if max < 0:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Unable to find member at specified offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # Look for the very last member so we can confirm our bounds.
        mptr = idaapi.get_member(self.parent.ptr, max)
        if mptr is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Unable to find member at specified offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # Get that member's size, so that way we can really confirm that this
        # offset isn't pointing to anything.
        msize = idaapi.get_member_size(mptr)
        if (offset < min) or (offset >= max + msize):
            cls = self.__class__
            raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Requested offset not within bounds {:#x}<>{:#x}.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset, min, max + msize))

        # Now we can get a pointer to an actual member
        mem = idaapi.get_member(self.parent.ptr, offset)
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:+#x}) : Unable to find member at specified offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # And then search for it in our structure to give back to the user
        index = self.index(mem)
        return self[index]
    byrealoffset = byRealOffset = utils.alias(by_realoffset, 'members_t')

    def by_identifier(self, id):
        '''Return the member in the structure that has the specified `id`.'''
        res = idaapi.get_member_by_id(id)
        if res is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_id({:#x}) : Unable to find member with specified id.".format('.'.join((__name__, cls.__name__)), self.parent.id, id))

        # unpack the member out of the result
        mem, fn, st = res

        # search through our members for the specified member
        index = self.index(mem)
        return self[index]
    by_id = byId = byIdentifier = utils.alias(by_identifier, 'members_t')

    def near_offset(self, offset):
        '''Return the member nearest to the specified `offset` from the base offset of the structure.'''
        min, max = map(lambda sz: sz + self.baseoffset, (idaapi.get_struc_first_offset(self.parent.ptr), idaapi.get_struc_last_offset(self.parent.ptr)))
        if (offset < min) or (offset >= max):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).members.near_offset({:+#x}) : Requested offset not within bounds {:#x}<->{:#x}. Trying anyways..".format('.'.join((__name__, cls.__name__)), self.parent.id, offset, min, max))

        # Chain to the realoffset implementation.. This is just a wrapper.
        return self.near_realoffset(offset - self.baseoffset)
    near = nearoffset = nearOffset = utils.alias(near_offset, 'members_t')

    def near_realoffset(self, offset):
        '''Return the member nearest to the specified `offset`.'''
        min, max = idaapi.get_struc_first_offset(self.parent.ptr), idaapi.get_struc_last_offset(self.parent.ptr)
        if (offset < min) or (offset >= max):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).members.near_realoffset({:+#x}) : Requested offset not within bounds {:#x}<->{:#x}. Trying anyways..".format('.'.join((__name__, cls.__name__)), self.parent.id, offset, min, max))

        # Try and find the exact offset, because if we can..then we don't need
        # to execute the rest of this function.
        mem = idaapi.get_member(self.parent.ptr, offset)
        if mem:
            index = self.index(mem)
            return self[index]

        # If there aren't any elements in the structure, then there's no members
        # to search through in here. So just raise an exception and bail.
        if not len(self):
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.near_realoffset({:+#x}) : Unable to find member near offset.".format('.'.join((__name__, cls.__name__)), self.parent.id, offset))

        # We couldn't find the member, so now we'll try and search for the
        # member that is nearest..
        def recurse(offset, available):
            if len(available) == 1:
                return available[0]
            index = len(available) // 2
            return recurse(offset, available[:index]) if offset <= available[index].realoffset else recurse(offset, available[index:])

        # This should already be sorted for us..
        mem = recurse(offset, [item for item in self])

        # Now we can return the member we found.
        index = self.index(mem)
        return self[index]

    # adding/removing members
    @utils.multicase(name=(basestring, tuple))
    @utils.string.decorate_arguments('name')
    def add(self, name):
        '''Append the specified member `name` with the default type at the end of the structure.'''
        offset = self.parent.size + self.baseoffset
        return self.add(name, int, offset)
    @utils.multicase(name=(basestring, tuple))
    @utils.string.decorate_arguments('name')
    def add(self, name, type):
        '''Append the specified member `name` with the given `type` at the end of the structure.'''
        offset = self.parent.size + self.baseoffset
        return self.add(name, type, offset)
    @utils.multicase(name=(basestring, tuple), offset=six.integer_types)
    @utils.string.decorate_arguments('name')
    def add(self, name, type, offset):
        """Add a member at `offset` with the given `name` and `type`.

        To specify a particular size, `type` can be a tuple with the second element referring to the size.
        """
        flag, typeid, nbytes = interface.typemap.resolve(type)

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        realoffset = offset - self.baseoffset

        # figure out some defaults for the member name
        if name is None:
            cls = self.__class__
            logging.warn(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Name is undefined, defaulting to offset {:+#x}.".format('.'.join((__name__, cls.__name__)), self.parent.id, name, type, offset, realoffset))
            name = 'v', realoffset
        if isinstance(name, tuple):
            name = interface.tuplename(*name)

        # try and add the structure memberb
        res = idaapi.add_struc_member(self.parent.ptr, utils.string.to(name), realoffset, flag, opinfo, nbytes)
        if res == idaapi.STRUC_ERROR_MEMBER_OK:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `idaapi.add_struc_member(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})` returned success.".format('.'.join((__name__, cls.__name__)), self.parent.id, name, type, offset, utils.string.escape(self.parent.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes))

        # we failed, so try figure out a good error message to inform the user with
        else:
            error = {
                idaapi.STRUC_ERROR_MEMBER_NAME : 'Duplicate field name',
                idaapi.STRUC_ERROR_MEMBER_OFFSET : 'Invalid offset',
                idaapi.STRUC_ERROR_MEMBER_SIZE : 'Invalid size',
            }
            e = E.DuplicateItemError if res == idaapi.STRUC_ERROR_MEMBER_NAME else E.DisassemblerError
            callee = u"idaapi.add_struc_member(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})".format(utils.string.escape(self.parent.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes)
            cls = self.__class__
            raise e(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `{:s}` returned {:s}".format('.'.join((__name__, cls.__name__)), self.parent.id, name, type, offset, callee, error.get(res, u"Error code {:#x}".format(res))))

        # now we can fetch the member at the specified offset to return
        mem = idaapi.get_member(self.parent.ptr, realoffset)
        if mem is None:
            cls = self.__class__
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Unable to locate recently created member \"{:s}\" at offset {:s}{:+#x}.".format('.'.join((__name__, cls.__name__)), self.parent.id, name, type, offset, utils.string.escape(name, '"'), realoffset, nbytes))
        idx = self.index(mem)

        # and then create a new instance of the member at our guessed index
        return member_t(self.parent, idx)

    def pop(self, index):
        '''Remove the member at the specified `index`.'''
        item = self[index]
        return self.remove(item.offset - self.baseoffset)
    def __delitem__(self, index):
        '''Remove the member at the specified `index`.'''
        return self.pop(index)

    @utils.multicase()
    def remove(self, offset):
        '''Remove the member at `offset` from the structure.'''
        return idaapi.del_struc_member(self.parent.ptr, offset - self.baseoffset)
    @utils.multicase()
    def remove(self, offset, size):
        '''Remove all the members from the structure from `offset` up to `size`.'''
        res = offset - self.baseoffset
        return idaapi.del_struc_members(self.parent.ptr, res, res + size)

    def __repr__(self):
        '''Display all the fields within the specified structure.'''
        res = []
        mn, ms, mti = 0, 0, 0
        for i in six.moves.range(len(self)):
            m = self[i]
            name, t, ti, ofs, size, comment, tag = m.name, m.type, m.typeinfo, m.offset, m.size, m.comment, m.tag()
            res.append((i, name, t, ti, ofs, size, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(size)))
            mti = max(mti, len("{!s}".format(ti).replace(' *', '*')))
        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1
        mo = max(map(len, map("{:x}".format, (self.baseoffset, self[-1].offset + self[-1].size))))
        print("{:x}".format(self.baseoffset + self[-1].size))
        return "{!r}\n{:s}".format(self.parent, '\n'.join("[{:{:d}d}] {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s} {:s}".format(i, mi, o, mo, s, ms, "{!s}".format(ti).replace(' *','*'), mti, utils.string.repr(n), mn+2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else c.encode('utf8')) if c else '') for i, n, t, ti, o, s, c, T in res))

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
    __slots__ = ('__parent', '__index')

    def __init__(self, parent, index):
        '''Create a member_t for the field in the structure `parent` at `index`.'''
        self.__index = index
        self.__parent = parent

    def __getstate__(self):
        t = (self.flag, None if self.typeid is None else __instance__(self.typeid), self.size)

        # grab its comments
        cmtt = idaapi.get_member_cmt(self.id, True)
        cmtf = idaapi.get_member_cmt(self.id, False)
        res = map(utils.string.of, (cmtt, cmtf))

        # now we can return them
        ofs = self.offset - self.__parent.members.baseoffset
        return (self.__parent.name, self.__index, self.name, tuple(res), ofs, t)
    def __setstate__(self, state):
        parentname, index, name, (cmtt, cmtf), ofs, t = state
        fullname = '.'.join((parentname, name))

        # get the structure owning the member by the name we stored
        res = utils.string.to(parentname)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.info(u"{:s}({:#x}) : Creating member for structure ({:s}) at offset {:+#x} named \"{:s}\" with the comment {!r}.".format('.'.join((__name__, cls.__name__)), self.id, parentname, ofs, utils.string.escape(name, '"'), cmtt or cmtf or ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, res)
        self.__parent = parent = __instance__(identifier, offset=0)

        # extract the attributes of the member
        flag, mytype, nbytes = t

        # create an opinfo_t for the member's type
        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = 0 if mytype is None else mytype.id

        # add the member to the database
        res = utils.string.to(name)
        mem = idaapi.add_struc_member(parent.ptr, res, ofs, flag, opinfo, nbytes)

        # FIXME: handle these errors properly
        cls = self.__class__

        # duplicate name
        if mem == idaapi.STRUC_ERROR_MEMBER_NAME:
            if idaapi.get_member_by_name(parent.ptr, res).soff != ofs:
                newname = u"{:s}_{:x}".format(res, ofs)
                logging.warn(u"{:s}({:#x}): Duplicate name found for member \"{:s}\" of structure ({:s}), renaming to \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, utils.string.escape(name, '"'), parentname, utils.string.escape(newname, '"')))
                idaapi.set_member_name(parent.ptr, ofs, utils.string.to(newname))
            else:
                logging.info(u"{:s}({:#x}): Field at {:+#x} of structure ({:s}) contains the same name \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, ofs, parentname, utils.string.escape(name, '"')))
        # duplicate field
        elif mem == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            logging.info(u"{:s}({:#x}): Already existing field found at {:+#x} of structure ({:s}). Overwriting with \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, ofs, parentname, utils.string.escape(name, '"')))
            idaapi.set_member_type(parent.ptr, ofs, flag, opinfo, nbytes)
            idaapi.set_member_name(parent.ptr, ofs, res)
        # invalid size
        elif mem == idaapi.STRUC_ERROR_MEMBER_SIZE:
            logging.warn(u"{:s}({:#x}): Error code {:#x} returned while trying to create member \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, mem, utils.string.escape(fullname, '"')))
        # unknown
        elif mem != idaapi.STRUC_ERROR_MEMBER_OK:
            logging.warn(u"{:s}({:#x}): Error code {:#x} returned while trying to create member \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, mem, utils.string.escape(fullname, '"')))

        # assign some of our internal attributes
        self.__index = index
        self.__parent = parent

        # and update the members comments
        idaapi.set_member_cmt(self.ptr, utils.string.to(cmtt), True)
        idaapi.set_member_cmt(self.ptr, utils.string.to(cmtf), False)
        return

    # read-only properties
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.member_t``.'''
        return self.__parent.ptr.get_member(self.__index)
    @property
    def id(self):
        '''Return the identifier of the member.'''
        return self.ptr.id
    @property
    def size(self):
        '''Return the size of the member.'''
        return idaapi.get_member_size(self.ptr)
    @property
    def realoffset(self):
        '''Return the real offset of the member.'''
        return self.ptr.get_soff()
    @property
    def offset(self):
        '''Return the offset of the member.'''
        return self.ptr.get_soff() + self.__parent.members.baseoffset
    @property
    def flag(self):
        '''Return the "flag" attribute of the member.'''
        m = idaapi.get_member(self.__parent.ptr, self.offset - self.__parent.members.baseoffset)
        return 0 if m is None else m.flag
    @property
    def fullname(self):
        '''Return the fullname of the member.'''
        res = idaapi.get_member_fullname(self.id)
        return utils.string.of(res)
    @property
    def typeid(self):
        '''Return the identifier of the type of the member.'''
        opinfo = idaapi.opinfo_t()
        if idaapi.__version__ < 7.0:
            res = idaapi.retrieve_member_info(self.ptr, opinfo)
            return None if res is None else res.tid if res.tid != idaapi.BADADDR else None
        else:
            res = idaapi.retrieve_member_info(opinfo, self.ptr)
        return None if opinfo.tid == idaapi.BADADDR else opinfo.tid
    @property
    def index(self):
        '''Return the index of the member.'''
        return self.__index
    @property
    def left(self):
        '''Return the beginning offset of the member.'''
        return self.ptr.soff
    @property
    def right(self):
        '''Return the ending offset of the member.'''
        return self.ptr.eoff
    @property
    def parent(self):
        '''Return the structure_t that owns the member.'''
        return self.__parent

    # read/write properties
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
        res = idaapi.validate_name2(buffer(ida_string)[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(buffer(ida_string)[:], idaapi.VNT_VISIBLE)
        if ida_string and ida_string != res:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name : Stripping invalid chars from structure member name (\"{:s}\") resulted in \"{:s}\".".format('.'.join((__name__, cls.__name__)), self.id, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the member at the specified offset
        return idaapi.set_member_name(self.__parent.ptr, self.offset - self.__parent.members.baseoffset, ida_string)

    @property
    def comment(self, repeatable=True):
        '''Return the repeatable comment of the member.'''
        res = idaapi.get_member_cmt(self.id, repeatable) or idaapi.get_member_cmt(self.id, not repeatable)
        return utils.string.of(res)
    @comment.setter
    @utils.string.decorate_arguments('value')
    def comment(self, value, repeatable=True):
        '''Set the repeatable comment of the member to `value`.'''
        res = utils.string.to(value)
        return idaapi.set_member_cmt(self.ptr, res, repeatable)

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
        if d1.viewkeys() & d2.viewkeys():
            cls = self.__class__
            logging.info(u"{:s}({:#x}).comment : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('.'.join((__name__, cls.__name__)), self.id, ', '.join(d1.viewkeys() & d2.viewkeys()), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it
        # XXX: it'd be cool to return an object with a dictionary
        #      that automatically synchronizes itself to the
        #      comment when a value is actually updated.
        res = {}
        builtins.map(res.update, (d1, d2) if repeatable else (d2, d1))
        return res
    @utils.multicase(key=basestring)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the member.'''
        res = self.tag()
        return res[key]
    @utils.multicase(key=basestring)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the member.'''
        state = self.tag()
        repeatable, res, state[key] = True, state.get(key, None), value
        ok = idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), repeatable)
        return res
    @utils.multicase(key=basestring, none=types.NoneType)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the member.'''
        state = self.tag()
        repeatable, res, = True, state.pop(key)
        ok = idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), repeatable)
        return res

    @property
    def dt_type(self):
        '''Return the `dt_type` attribute of the member.'''
        m = idaapi.get_member(self.__parent.ptr, self.offset - self.__parent.members.baseoffset)
        if m is None:
            return 0
        flag = m.flag & idaapi.DT_TYPE

        # idaapi(swig) and python have different definitions of what constant values are
        max = (sys.maxint+1)*2
        return (max+flag) if flag < 0 else (flag-max) if flag > max else flag
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
            elif isinstance(t, types.ListType) and isinstance(t[0], structure_t):
                t[0] = __instance__(t[0].id, offset=self.offset)
            res = t, sz
        return res
    @type.setter
    def type(self, type):
        '''Set the type of the member.'''
        flag, typeid, nbytes = interface.typemap.resolve(type)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        return idaapi.set_member_type(self.__parent.ptr, self.offset - self.__parent.members.baseoffset, flag, opinfo, nbytes)

    @property
    def typeinfo(self):
        '''Return the type info of the member.'''
        ti = idaapi.tinfo_t()
        ok = idaapi.get_or_guess_member_tinfo2(self.ptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, self.ptr)
        if not ok:
            cls = self.__class__
            logging.fatal(u"{:s}({:#x}).typeinfo : Unable to determine `idaapi.tinfo_t()` for member {:s}.".format('.'.join((__name__, cls.__name__)), self.id, self.name))
        return ti

    @typeinfo.setter
    @utils.string.decorate_arguments('info')
    def typeinfo(self, info):
        '''Set the type info of the member to `info`.'''
        til, ti = idaapi.get_idati(), idaapi.tinfo_t(),

        # Convert info to a string if it's a tinfo_t
        info_s = "{!s}".format(info) if isinstance(info, idaapi.tinfo_t) else info

        # Firstly we need to ';'-terminate the type the user provided in order
        # for IDA's parser to understand it.
        terminated = info_s if info_s.endswith(';') else "{:s};".format(info_s)

        # Now that we've prepped everything, ask IDA to parse this into a
        # tinfo_t for us. We pass the silent flag so that we can raise an
        # exception if there's a parsing error of some sort.
        res = idaapi.parse_decl(ti, til, terminated, idaapi.PT_SIL)
        if res is None:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo : Unable to parse the specified type declaration ({!s}).".format('.'.join((__name__, cls.__name__)), self.id, utils.string.repr(info)))

        # Now we can pass our tinfo_t along with the member information to IDA.
        res = idaapi.set_member_tinfo(self.parent.ptr, self.ptr, self.ptr.get_soff(), ti, 0)
        if res == idaapi.SMT_OK:
            return

        # We failed, so just raise an exception for the user to handle.
        elif res == idaapi.SMT_FAILED:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo : Unable to assign typeinfo ({!s}) to structure member {:s}.".format('.'.join((__name__, cls.__name__)), self.id, utils.string.repr(info), utils.string.repr(self.name)))

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
        raise E.DisassemblerError(u"{:s}({:#x}).typeinfo : Unable to assign typeinfo ({!s}) to structure member {:s} ({:s}).".format('.'.join((__name__, cls.__name__)), self.id, utils.string.repr(info), utils.string.repr(self.name), message))

    def __repr__(self):
        '''Display the member in a readable format.'''
        id, name, typ, comment, tag, typeinfo = self.id, self.fullname, self.type, self.comment or '', self.tag(), "{!s}".format(self.typeinfo).replace(' *', '*')
        return "<member '{:s}' index={:d} offset={:-#x} size={:+#x}{:s}> {:s}".format(utils.string.escape(name, '\''), self.index, self.offset, self.size, " typeinfo='{:s}'".format(typeinfo) if len("{:s}".format(typeinfo)) else '', " // {!s}".format(utils.string.repr(tag) if '\n' in comment else comment.encode('utf8')) if comment else '')

    def refs(self):
        """Return the `(address, opnum, type)` of all the code and data references to this member within the database.

        If `opnum` is ``None``, then the returned `address` has the structure applied to it.
        If `opnum` is defined, then the instruction at the returned `address` references a field that contains the specified structure.
        """
        get_opinfo = (lambda (ti, ea, opnum, fl): idaapi.get_opinfo(ea, opnum, fl, ti)) if idaapi.__version__ < 7.0 else idaapi.get_opinfo

        mid = self.id
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # if structure is a frame..
        if interface.node.is_identifier(self.__parent.id) and internal.netnode.name.get(self.__parent.id).startswith('$ '):
            name, mptr = self.fullname, self.ptr
            sptr = idaapi.get_sptr(mptr)

            # get frame, func_t
            frname, _ = name.split('.', 1)
            frid = internal.netnode.get(frname)
            ea = idaapi.get_func_by_frame(frid)
            f = idaapi.get_func(ea)

            # now find all xrefs to member within function
            xl = idaapi.xreflist_t()
            idaapi.build_stkvar_xrefs(xl, f, mptr)

            # now we can add it
            res = []
            for xr in xl:
                ea, opnum = xr.ea, int(xr.opnum)
                ref = interface.OREF(ea, opnum, interface.ref_t(xr.type, instruction.op_state(ea, opnum)))
                res.append(ref)
            return res

        # otherwise, it's a structure..which means we need to specify the member to get refs for
        x = idaapi.xrefblk_t()
        ok = x.first_to(mid, 0)
        if not ok:
            return []

        # collect all references available
        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # collect all structure references that might reference us just in case
        # we need to verify that a globally defined address is using a structure
        # that contains our member
        identifiers = { self.parent } | { member.parent for member in self.parent.refs() if isinstance(member, member_t) }
        while True:
            current = identifiers.copy()

            # iterate through every single structure that we have, and gather
            # its member_t references
            for item in current:
                for member in item.refs():
                    if isinstance(item, member_t):
                        current.add(item.parent)
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
            listable = [(idx, internal.netnode.sup.get(ea, 0xf+idx)) for idx in six.moves.range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf+idx) is not None]

            # check if we found any ops that point directly to this member
            if any(listable):
                iterable = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx, val in listable)
                iterable = (idx for idx, (_, ids) in iterable if self.__parent.id in ids)    # sanity
                res.extend(interface.OREF(ea, int(opnum), interface.ref_t.of(t)) for opnum in iterable)

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
                    offset = opvalue if isinstance(opvalue, six.integer_types) else six.next((getattr(opvalue, attribute) for attribute in {'offset', 'address'} if hasattr(opvalue, attribute)), None)

                    # check if we got a valid offset, because if not then we just
                    # need to skip to the next iteration
                    if offset is None or not database.within(offset):
                        continue

                    # align the offset, and check if our address is using one
                    # of our structure identifiers
                    offset = interface.address.head(offset, silent=True)
                    if database.type.flags(offset, idaapi.DT_TYPE) == FF_STRUCT and database.type.structure.id(offset) in identifiers:
                        res.append(interface.OREF(ea, opnum, interface.ref_t.of(t)))
                    continue
                continue
            continue
        return res
