"""
Structures

generic tools for working in the context of a structure.
"""

import six
from six.moves import builtins

import functools, operator, itertools, types
import sys, logging
import math, re, fnmatch

import database, instruction
import ui, internal
from internal import utils, interface

import idaapi

## FIXME: need to add support for a union_t. add_struc takes another parameter
##        that defines whether a structure is a union or not.

### structure_t abstraction
class structure_t(object):
    """An abstraction around an IDA structure."""
    __slots__ = ('__id', '__members')

    def __init__(self, id, offset=0):
        self.__id = id
        self.__members = members_t(self, baseoffset=offset)

    def up(self):
        '''Return all the structures that reference this specific structure.'''
        x, sid = idaapi.xrefblk_t(), self.id

        # grab first structure that references this one
        ok = x.first_to(sid, 0)
        if not ok:
            return ()

        # continue collecting all structures that references this one
        res = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            res.append((x.frm, x.iscode, x.type))

        # convert refs into a list of OREFs
        refs = [ interface.OREF(xrfrom, xriscode, interface.ref_t.of(xrtype)) for xrfrom, xriscode, xrtype in res ]

        # return as a tuple
        return map(utils.fcompose(operator.itemgetter(0), instance), refs)

    def down(self):
        '''Return all the structures that are referenced by this specific structure.'''
        x, sid = idaapi.xrefblk_t(), self.id

        # grab structures that this one references
        ok = x.first_from(sid, 0)
        if not ok:
            return []

        # continue collecting all structures that this one references
        res = [(x.to, x.iscode, x.type)]
        while x.next_from():
            res.append((x.to, x.iscode, x.type))

        # convert refs into a list of OREFs
        refs = [ interface.OREF(xrto, xriscode, interface.ref_t.of(xrtype)) for xrto, xriscode, xrtype in res ]

        # return it as a tuple
        return map(utils.fcompose(operator.itemgetter(0), instance), refs)

    def refs(self):
        """Return the `(address, opnum, type)` of all the references (code & data) to this structure within the database.
        If `opnum` is `None`, then the returned `address` has the structure applied to it.
        If `opnum` is defined, then the instruction at the returned `address` references a field that contains the specified structure.
        """
        x, sid = idaapi.xrefblk_t(), self.id

        # grab first reference to structure
        ok = x.first_to(sid, 0)
        if not ok:
            return []

        # collect the rest of its references
        refs = [(x.frm, x.iscode, x.type)]
        while x.next_to():
            refs.append((x.frm, x.iscode, x.type))

        # calculate the high-byte which is used to differentiate an address from a structure
        bits = math.trunc(math.ceil(math.log(idaapi.BADADDR) / math.log(2.0)))
        highbyte = 0xff << (bits-8)

        # iterate through figuring out if sid is applied to an address or another structure
        res = []
        for ref, _, _ in refs:
            # structure (probably a frame member)
            if ref & highbyte == highbyte:
                # get sptr, mptr
                name = idaapi.get_member_fullname(ref)
                mptr, _ = idaapi.get_member_by_fullname(name)
                if not isinstance(mptr, idaapi.member_t):
                    cls = self.__class__
                    raise TypeError("{:s} : Unexpected type {!r} for netnode '{:s}'".format('.'.join((__name__, cls.__name__)), mptr.__class__, name))
                sptr = idaapi.get_sptr(mptr)

                # get frame, func_t
                frname, _ = name.split('.', 2)
                frid = internal.netnode.get(frname)
                ea = idaapi.get_func_by_frame(frid)
                f = idaapi.get_func(ea)

                # now find all xrefs to member within function
                xl = idaapi.xreflist_t()
                idaapi.build_stkvar_xrefs(xl, f, mptr)

                # now we can add it
                for xr in xl:
                    ea, opnum, state = xr.ea, int(xr.opnum), instruction.op_state(ea, opnum)
                    res.append( interface.OREF(ea, opnum, interface.ref_t.of_state(state)) )
                continue

            # address
            res.append( interface.OREF(ref, None, interface.ref_t.of_state('*')) )   # using '*' to describe being applied to the an address

        return res

    @property
    def id(self):
        '''Return the identifier of the structure.'''
        return self.__id
    @property
    def ptr(self):
        '''Return the pointer of the `idaapi.struc_t`.'''
        return idaapi.get_struc(self.id)
    @property
    def members(self):
        '''Return the members belonging to the structure.'''
        return self.__members

    def __getstate__(self):
        cmtt, cmtf = map(functools.partial(idaapi.get_struc_cmt, self.id), (True, False))
        # FIXME: perhaps we should preserve the get_struc_idx result too
        return (self.name, (cmtt, cmtf), self.members)
    def __setstate__(self, state):
        name, (cmtt, cmtf), members = state
        identifier = idaapi.get_struc_id(name)
        if identifier == idaapi.BADADDR:
            logging.warn("{:s}.structure_t.__setstate__ : Creating structure {:s} [{:d} fields]{:s}".format(__name__, name, len(members), " // {:s}".format(cmtf or cmtt) if cmtf or cmtt else ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, name)
        idaapi.set_struc_cmt(identifier, cmtt, True)
        idaapi.set_struc_cmt(identifier, cmtf, False)
        self.__id = identifier
        self.__members = members
        return

    @property
    def name(self):
        '''Return the name of the structure.'''
        return idaapi.get_struc_name(self.id)
    @name.setter
    def name(self, string):
        '''Set the name of the structure to ``string``.'''
        if isinstance(string, tuple):
            string = interface.tuplename(*string)

        res = idaapi.validate_name2(buffer(string)[:])
        if string and string != res:
            cls = self.__class__
            logging.warn("{:s}.name : Stripping invalid chars from structure name {!r}. : {!r}".format( '.'.join((__name__, cls.__name__)), string, res))
            string = res
        return idaapi.set_struc_name(self.id, string)
    @property
    #def comment(self, repeatable=True):
    def comment(self):
        '''Return the repeatable comment for the structure.'''
        return idaapi.get_struc_cmt(self.id, True) or idaapi.get_struc_cmt(self.id, False)
    @comment.setter
    def comment(self, comment, repeatable=True):
        '''Set the repeatable comment for the structure to ``comment``.'''
        return idaapi.set_struc_cmt(self.id, comment, repeatable)
    @property
    def size(self):
        '''Return the size of the structure.'''
        return idaapi.get_struc_size(self.ptr)
    @size.setter
    def size(self, new):
        res = idaapi.get_struc_size(self.ptr)
        ok = idaapi.expand_struc(self.ptr, 0, new - res, True)
        if not ok:
            logging.fatal("{:s}.instance({:s}).resize : Unable to resize structure {:s} from {:#x} bytes to {:#x} bytes.".format(__name__, self.name, self.name, res, new))
        return res

    @property
    def offset(self):
        '''Return the base-offset of the structure.'''
        return self.members.baseoffset
    @offset.setter
    def offset(self, offset):
        '''Set the base-offset of the structure to ``offset``.'''
        res, self.members.baseoffset = self.members.baseoffset, offset
        return res
    @property
    def index(self):
        '''Return the index of the structure.'''
        return idaapi.get_struc_idx(self.id)
    @index.setter
    def index(self, idx):
        '''Set the index of the structure to ``idx``.'''
        return idaapi.set_struc_idx(self.ptr, idx)

    def destroy(self):
        '''Remove the structure from the database.'''
        return idaapi.del_struc(self.ptr)

    def __repr__(self):
        return "<type 'structure' name={!r}{:s} size=+{:#x}>{:s}".format(self.name, (" offset={:#x}".format(self.offset) if self.offset > 0 else ''), self.size, " // {:s}".format(self.comment) if self.comment else '')

    def field(self, ofs):
        '''Return the member at the specified offset.'''
        return self.members.by_offset(ofs + self.members.baseoffset)

    def copy(self, name):
        '''Copy members into the structure ``name``.'''
        raise NotImplementedError

    def __getattr__(self, name):
        return getattr(self.members, name)


@utils.multicase()
def name(id):
    '''Return the name of the structure identified by ``id``.'''
    return idaapi.get_struc_name(id)
@utils.multicase(structure=structure_t)
def name(structure): return name(structure.id)
@utils.multicase(string=basestring)
def name(id, string, *suffix):
    '''Set the name of the structure identified by ``id`` to ``string``.'''
    res = (string,) + suffix
    string = interface.tuplename(*res)

    res = idaapi.validate_name2(buffer(string)[:])
    if string and string != res:
        logging.warn("{:s}.name : Stripping invalid chars from structure name \"{:s}\". : {!r}".format(__name__, string, res))
        string = res
    return idaapi.set_struc_name(id, string)
@utils.multicase(structure=structure_t, string=basestring)
def name(structure, string, *suffix): return name(structure.id, string, *suffix)

@utils.multicase(id=six.integer_types)
def comment(id, **repeatable):
    """Return the comment of the structure identified by ``id``.
    If the bool ``repeatable`` is specified, return the repeatable comment.
    """
    return idaapi.get_struc_cmt(id, repeatable.get('repeatable', True))
@utils.multicase(structure=structure_t)
def comment(structure, **repeatable):
    '''Return the comment for the specified ``structure``.'''
    return comment(structure.id, **repeatable)
@utils.multicase(cmt=basestring)
def comment(id=six.integer_types, cmt=basestring, **repeatable):
    """Set the comment of the structure identified by ``id`` to ``cmt``.
    If the bool ``repeatable`` is specified, set the repeatable comment.
    """
    return idaapi.set_struc_cmt(id, cmt, repeatable.get('repeatable', True))
@utils.multicase(structure=structure_t, cmt=basestring)
def comment(structure, cmt, **repeatable):
    '''Set the comment to ``cmt`` for the specified ``structure``.'''
    return comment(structure.id, cmt, **repeatable)

@utils.multicase(id=six.integer_types)
def index(id):
    '''Return the index of the structure identified by ``id``.'''
    return idaapi.get_struc_idx(id)
@utils.multicase(structure=structure_t)
def index(structure):
    '''Return the index of the specified ``structure``.'''
    return index(structure.id)
@utils.multicase(id=six.integer_types, index=six.integer_types)
def index(id, index):
    '''Move the structure identified by ``id`` to the specified ``index`` in the structure list.'''
    return idaapi.set_struc_idx(id, index)
@utils.multicase(structure=structure_t, index=six.integer_types)
def index(structure, index):
    '''Move the specified ``structure`` to the specified ``index`` in the structure list.'''
    return index(structure.id, index)

__matcher__ = utils.matcher()
__matcher__.boolean('regex', re.search, 'name')
__matcher__.mapping('index', idaapi.get_struc_idx, 'id')
__matcher__.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), 'name')
__matcher__.boolean('name', operator.eq, 'name')
__matcher__.predicate('predicate')
__matcher__.predicate('pred')

def __iterate__():
    '''Iterate through all structures defined in the database.'''
    idx = idaapi.get_first_struc_idx()
    while idx != idaapi.get_last_struc_idx():
        identifier = idaapi.get_struc_by_idx(idx)
        yield instance(identifier)
        idx = idaapi.get_next_struc_idx(idx)
    idx = idaapi.get_last_struc_idx()
    yield instance(idaapi.get_struc_by_idx(idx))

@utils.multicase(string=basestring)
def iterate(string):
    return cls.iterate(like=string)
@utils.multicase()
def iterate(**type):
    if not type: type = {'predicate':lambda n: True}
    res = builtins.list(__iterate__())
    for key, value in six.iteritems(type):
        res = builtins.list(__matcher__.match(key, value, res))
    for item in res: yield item

@utils.multicase(string=basestring)
def list(string):
    '''List any structures that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
def list(**type):
    """List all the structures within the database.

    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    pred = function predicate
    """
    res = builtins.list(iterate(**type))

    maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) or [1])
    maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), len), res) or [1])
    maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) or [1])

    for st in res:
        six.print_("[{:{:d}d}] {:>{:d}s} {:<+#{:d}x} ({:d} members){:s}".format(idaapi.get_struc_idx(st.id), maxindex, st.name, maxname, st.size, maxsize, len(st.members), " // {:s}".format(st.comment) if st.comment else ''))
    return

@utils.multicase(structure=structure_t)
def size(structure):
    '''Return the size of the specified ``structure``.'''
    return size(structure.id)
@utils.multicase(id=six.integer_types)
def size(id):
    """Return the size of the structure identified by ``id``."""
    return idaapi.get_struc_size(id)

@utils.multicase(structure=structure_t)
def members(structure):
    '''Yield each member of the specified ``structure``.'''
    return members(structure.id)
@utils.multicase(id=six.integer_types)
def members(id):
    """Yield each member of the structure identified by ``id``.
    Each iteration yields the `((offset, size), (name, comment, repeatable-comment))` of each member.
    """

    st = idaapi.get_struc(id)
    if not st:
        # empty structure
        return

    size = idaapi.get_struc_size(st)

    offset = 0
    for i in six.moves.range(st.memqty):
        m = st.get_member(i)
        ms = idaapi.get_member_size(m)

        left, right = m.soff, m.eoff

        if offset < left:
            yield (offset, left-offset), (idaapi.get_member_name(m.id), idaapi.get_member_cmt(m.id, 0), idaapi.get_member_cmt(m.id, 1))
            offset = left

        yield (offset, ms), (idaapi.get_member_name(m.id), idaapi.get_member_cmt(m.id, 0), idaapi.get_member_cmt(m.id, 1))
        offset += ms
    return

@utils.multicase(structure=structure_t, offset=six.integer_types, size=six.integer_types)
def fragment(structure, offset, size):
    '''Yield each member of the specified ``structure`` from the ``offset`` up to the ``size``.'''
    return fragment(structure.id, offset, size)
@utils.multicase(id=six.integer_types, offset=six.integer_types, size=six.integer_types)
def fragment(id, offset, size):
    """Yield each member of the structure identified by ``id`` from the ``offset`` up to the ``size``.
    Each iteration yields `((offset, size), (name, comment, repeatable comment))` for each member within the specified bounds.
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

# XXX: deprecate this as it's already in database
@utils.multicase(ea=six.integer_types, structure=structure_t)
def apply(ea, structure):
    '''Apply the specified ``structure`` to the address at ``ea``.'''
    ea = interface.address.inside(ea)
    ti, fl = idaapi.opinfo_t(), database.type.flags(ea)
    res = idaapi.get_opinfo(ea, 0, fl, ti)
    ti.tid = structure.id
    return idaapi.set_opinfo(ea, 0, fl | idaapi.struflag(), ti)
@utils.multicase(id=six.integer_types)
def apply(id):
    '''Apply the structure identified by ``id`` to the current address.'''
    return apply(ui.current.address(), instance(id))
@utils.multicase(structure=structure_t)
def apply(structure):
    '''Apply the specified ``structure`` to the current address.'''
    return apply(ui.current.address(), structure)
@utils.multicase(ea=six.integer_types, id=six.integer_types)
def apply(ea, id):
    '''Apply the structure identified by ``id`` to the address at ``ea``.'''
    return apply(ea, instance(id))

# XXX: move this to the instruction module
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, id=six.integer_types)
def apply_op(id, ea, opnum, **delta):
    """Apply the structure identified by ``id`` to the instruction operand ``opnum`` at the address ``ea``.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    ea = interface.address.inside(ea)
    if not database.type.is_code(ea):
        raise TypeError("{:s}.apply_op({:#x}, {:#x}, {:d}, delta={:d}) : Item type at requested address is not code.".format(__name__, id, ea, opnum, delta.get('delta', 0)))
    # FIXME: allow one to specify more than one field for tid_array
    length = 2
    tid = idaapi.tid_array(length)
    tid[0] = id
    ok = idaapi.op_stroff(ea, opnum, tid.cast(), length, delta.get('delta', 0))
    return True if ok else False
@utils.multicase(ea=six.integer_types, opnum=six.integer_types, structure=structure_t)
def apply_op(structure, ea, opnum, **delta):
    """Apply the specified ``structure`` to the instruction operand ``opnum`` at the address ``ea``.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return apply_op(structure.id, ea, opnum, **delta)
@utils.multicase(opnum=six.integer_types, structure=structure_t)
def apply_op(structure, opnum, **delta):
    """Apply the specified ``structure`` to the instruction operand ``opnum`` at the current address.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return apply_op(structure.id, ui.current.address(), opnum, **delta)
@utils.multicase(opnum=six.integer_types)
def apply_op(id, opnum, **delta):
    """Apply the structure identified by ``id`` to the instruction operand ``opnum`` at the current address.
    If the offset ``delta`` is specified, shift the structure by that amount.
    """
    return apply_op(id, ui.current.address(), opnum, **delta)

# XXX: deprecate this as it's the same as by_name
def get(name):
    '''Returns an instance of the structure named ``name``.'''
    id = idaapi.get_struc_id(name)
    if id == idaapi.BADADDR:
        try: raise DeprecationWarning
        except: logging.warn("{:s}.get auto-creation is being deprecated".format(__name__, exc_info=True))
        id = idaapi.add_struc(idaapi.BADADDR, name)
    return instance(id)

@utils.multicase(name=basestring)
def new(name):
    '''Returns a new structure ``name``.'''
    return new(name, 0)
@utils.multicase(name=basestring, offset=six.integer_types)
def new(name, offset):
    '''Returns a new structure ``name`` using ``offset`` as its base-offset.'''
    id = idaapi.add_struc(idaapi.BADADDR, name)
    assert id != idaapi.BADADDR
    # FIXME: we should probably move the new structure to the end of the list via set_struc_idx
    return instance(id, offset=offset)

@utils.multicase(structure=structure_t)
def remove(structure):
    '''Remove the specified ``structure`` from the database.'''
    ok = idaapi.del_struc(structure.ptr)
    if not ok:
        logging.fatal("{:s}.remove(\"{:s}\") : Unable to remove structure {:#x}.".format(__name__, name, res.id))
        return False
    return True
@utils.multicase(name=basestring)
def remove(name):
    '''Remove the structure with the specified ``name``.'''
    res = by_name(name)
    return remove(res)
@utils.multicase(id=six.integer_types)
def remove(id):
    '''Remove a structure by its index or ``id``.'''
    res = by(id)
    return remove(res)
@utils.multicase()
def remove(**type):
    '''Remove the first structure that matches the result described by ``type``.'''
    res = by(**type)
    return remove(res)
delete = utils.alias(remove)

@utils.multicase(name=basestring)
def by(name, **options):
    '''Return a structure by its name.'''
    return by_name(name, **options)
@utils.multicase(id=six.integer_types)
def by(id, **options):
    '''Return a structure by its index or id.'''
    res = id
    bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
    highbyte = 0xff << (bits-8)
    if res & highbyte == highbyte:
        return instance(res, **options)
    return by_index(res, **options)
@utils.multicase()
def by(**type):
    """Search through all the structures within the database and return the first result.

    like = glob match
    regex = regular expression
    index = particular index
    identifier or id = internal id number
    """

    searchstring = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

    res = builtins.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, (("[{:d}] {:s}".format(idaapi.get_struc_idx(st.id), st.name)) for i, st in enumerate(res)))
        logging.warn("{:s}.search({:s}) : Found {:d} matching results, returning the first one. : {!r}".format(__name__, searchstring, len(res), res[0]))

    res = next(iter(res), None)
    if res is None:
        raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format(__name__, searchstring))
    return res

def search(string):
    '''Search through all the structures using globbing.'''
    return by(like=string)

def by_name(name, **options):
    '''Return a structure by its name.'''
    id = idaapi.get_struc_id(name)
    if id == idaapi.BADADDR:
        raise LookupError("{:s}.by_name({!r}) : Unable to locate structure with given name.".format(__name__, name))
    return instance(id, **options)
byName = utils.alias(by_name)

def by_index(index, **options):
    '''Return a structure by its index.'''
    id = idaapi.get_struc_by_idx(index)
    if id == idaapi.BADADDR:
        raise IndexError("{:s}.by_index({:d}) : Unable to locate structure at given index.".format(__name__, index))
    return instance(id, **options)
byIndex = utils.alias(by_index)

def instance(identifier, **options):
    '''Returns the structure identified by ``identifier``.'''
    try:
        cache = instance.cache
    except AttributeError:
        instance.cache = {}
        return instance(identifier, **options)
    res = cache.setdefault((identifier, options.get('offset', 0)), structure_t(identifier, **options))
    if 'offset' in options:
        res.offset = options['offset']
    return res

by_identifier = by_id = byIdentifier = byId = utils.alias(instance)

class members_t(object):
    """An abstraction around the members of a particular IDA structure

    This allows one to treat each member as a `dict`.
    """
    __slots__ = ('__owner', 'baseoffset')

    # members state
    @property
    def owner(self):
        '''Return the `structure_t` that owns this `members_t`.'''
        return self.__owner
    @property
    def ptr(self):
        '''Return the pointer to the `idaapi.member_t` that contains all the members.'''
        return self.__owner.ptr.members
    def __init__(self, owner, baseoffset=0):
        self.__owner = owner
        self.baseoffset = baseoffset

    def __getstate__(self):
        return (self.owner.name, self.baseoffset, map(self.__getitem__, six.moves.range(len(self))))
    def __setstate__(self, state):
        ownername, baseoffset, _ = state
        identifier = idaapi.get_struc_id(ownername)
        if identifier == idaapi.BADADDR:
            raise LookupError("{:s}.instance({:s}).members.__setstate__ : Failure creating a members_t for structure_t {!r}".format(__name__, self.owner.name, ownername))
            logging.warn("{:s}.instance({:s}).members.__setstate__ : Creating structure {:s} -- [{:+#x}] {:d} members".format(__name__, self.owner.name, ownername, baseoffset, len(members)))
            identifier = idaapi.add_struc(idaapi.BADADDR, ownername)
        self.baseoffset = baseoffset
        self.__owner = instance(identifier, offset=baseoffset)
        return

    # fetching members
    def __len__(self):
        '''Return the number of members within the structure.'''
        return 0 if self.owner.ptr is None else self.owner.ptr.memqty
    def __iter__(self):
        for idx in six.moves.range(len(self)):
            yield member_t(self.owner, idx)
        return
    def __getitem__(self, index):
        '''Return the member at the specified ``index``.'''
        if isinstance(index, six.integer_types):
            index = self.owner.ptr.memqty + index if index < 0 else index
            res = member_t(self.owner, index) if index >= 0 and index < self.owner.ptr.memqty else None
        elif isinstance(index, six.string_types):
            res = self.byname(index)
        elif isinstance(index, slice):
            res = [self.__getitem__(i) for i in six.moves.range(self.owner.ptr.memqty)].__getitem__(index)
        else:
            raise TypeError, index

        if res is None:
            raise IndexError, index
        return res

    def index(self, member_t):
        '''Return the index of the member specified by ``member_t``.'''
        for i in six.moves.range(self.owner.ptr.memqty):
            if member_t.id == self[i].id:
                return i
            continue
        raise ValueError("{:s}.instance({:s}).members.index : {!r} not in list".format(__name__, self.owner.name, member_t))

    __member_matcher = utils.matcher()
    __member_matcher.boolean('regex', re.search, 'name')
    __member_matcher.attribute('index', 'index')
    __member_matcher.attribute('identifier', 'id'), __matcher__.attribute('id', 'id')
    __member_matcher.attribute('offset', 'offset')
    __member_matcher.boolean('name', lambda v, n: fnmatch.fnmatch(n, v), 'name')
    __member_matcher.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), 'name')
    __member_matcher.boolean('fullname', lambda v, n: fnmatch.fnmatch(n, v), 'fullname')
    __member_matcher.boolean('comment', lambda v, n: fnmatch.fnmatch(n, v), 'comment')
    __member_matcher.boolean('comments', lambda v, n: fnmatch.fnmatch(n, v), 'comments')
    __member_matcher.boolean('greater', operator.le, lambda m: m.offset+m.size), __member_matcher.boolean('gt', operator.lt, lambda m: m.offset+m.size)
    __member_matcher.boolean('less', operator.ge, 'offset'), __member_matcher.boolean('lt', operator.gt, 'offset')
    __member_matcher.predicate('predicate'), __member_matcher.predicate('pred')

    # searching members
    @utils.multicase()
    def iterate(self, **type):
        if not type: type = {'predicate':lambda n: True}
        res = builtins.list(iter(self))
        for key, value in six.iteritems(type):
            res = builtins.list(self.__member_matcher.match(key, value, res))
        for item in res: yield item

    @utils.multicase(string=basestring)
    def list(self, string):
        '''List any members that match the glob in `string`.'''
        return self.list(like=string)
    @utils.multicase()
    def list(self, **type):
        """List all the members within the structure.

        Search type can be identified by providing a named argument.
        like = glob match
        regex = regular expression
        index = particular index
        identifier = particular id number
        predicate = function predicate
        """
        res = builtins.list(self.iterate(**type))

        escape = repr
        maxindex = max(builtins.map(utils.fcompose(operator.attrgetter('index'), "{:d}".format, len), res) or [1])
        maxoffset = max(builtins.map(utils.fcompose(operator.attrgetter('offset'), "{:x}".format, len), res) or [1])
        maxsize = max(builtins.map(utils.fcompose(operator.attrgetter('size'), "{:+#x}".format, len), res) or [1])
        maxname = max(builtins.map(utils.fcompose(operator.attrgetter('name'), escape, len), res) or [1])
        maxtype = max(builtins.map(utils.fcompose(operator.attrgetter('type'), repr, len), res) or [1])

        for m in res:
            six.print_("[{:{:d}d}] {:>{:d}x}:{:<+#{:d}x} {:<{:d}s} {:{:d}s} (flag={:x},dt_type={:x}{:s}){:s}".format(m.index, maxindex, m.offset, int(maxoffset), m.size, maxsize, escape(m.name), int(maxname), m.type, int(maxtype), m.flag, m.dt_type, '' if m.typeid is None else ",typeid={:x}".format(m.typeid), " // {:s}".format(m.comment) if m.comment else ''))
        return

    @utils.multicase()
    def by(self, **type):
        '''Return the member with the specified ``name``.'''
        searchstring = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

        res = builtins.list(self.iterate(**type))
        if len(res) > 1:
            map(logging.info, (("[{:d}] {:x}:{:+#x} '{:s}' {!r}".format(m.index, m.offset, m.size, m.name, m.type)) for m in res))
            logging.warn("{:s}.instance({:s}).members.by({:s}) : Found {:d} matching results, returning the first one. : [{:d}] {:x}:{:+#x} '{:s}' {!r}".format(__name__, self.owner.name, searchstring, len(res), res[0].index, res[0].offset, res[0].size, res[0].fullname, res[0].type))

        res = next(iter(res), None)
        if res is None:
            raise LookupError("{:s}.instance({:s}).members.by({:s}) : Found 0 matching results.".format(__name__, self.owner.name, searchstring))
        return res
    @utils.multicase(name=basestring)
    def by(self, name):
        '''Return the member with the specified ``name``.'''
        return self.by_name(name)
    @utils.multicase(offset=six.integer_types)
    def by(self, offset):
        '''Return the member at the specified ``offset``.'''
        return self.by_offset(offset)

    def by_name(self, name):
        '''Return the member with the specified ``name``.'''
        mem = idaapi.get_member_by_name(self.owner.ptr, name)
        if mem is None:
            raise KeyError("{:s}.instance({:s}).members.by_name : Unable to find member with requested name : {!r}".format(__name__, self.owner.name, name))
        index = self.index(mem)
        return self[index]
    byname = byName = utils.alias(by_name, 'members_t')
    def by_fullname(self, fullname):
        '''Return the member with the specified ``fullname``.'''
        mem = idaapi.get_member_by_fullname(self.owner.ptr, fullname)
        if mem is None:
            raise KeyError("{:s}.instance({:s}).members.by_fullname : Unable to find member with full name : {!r}".format(__name__, self.owner.name, fullname))
        index = self.index(mem)
        return self[index]
    byfullname = byFullname = utils.alias(by_fullname, 'members_t')
    def by_offset(self, offset):
        '''Return the member at the specified ``offset``.'''
        min, max = map(lambda sz: sz + self.baseoffset, (idaapi.get_struc_first_offset(self.owner.ptr), idaapi.get_struc_last_offset(self.owner.ptr)))

        mptr = idaapi.get_member(self.owner.ptr, max - self.baseoffset)
        msize = idaapi.get_member_size(mptr)
        if (offset < min) or (offset >= max+msize):
            raise LookupError("{:s}.instance({:s}).members.by_offset : Requested offset {:+#x} not within bounds {:#x}<->{:#x}".format(__name__, self.owner.name, offset, min, max+msize))

        mem = idaapi.get_member(self.owner.ptr, offset - self.baseoffset)
        if mem is None:
            raise LookupError("{:s}.instance({:s}).members.by_offset : Unable to find member at offset : {:+#x}".format(__name__, self.owner.name, offset))

        index = self.index(mem)
        return self[index]
    byoffset = byOffset = utils.alias(by_offset, 'members_t')

    def near_offset(self, offset):
        '''Return the member near to the specified ``offset``.'''
        min, max = map(lambda sz: sz + self.baseoffset, (idaapi.get_struc_first_offset(self.owner.ptr), idaapi.get_struc_last_offset(self.owner.ptr)))
        if (offset < min) or (offset >= max):
            logging.warn("{:s}.instance({:s}).members.near_offset : Requested offset {:+#x} not within bounds {:#x}<->{:#x}. Trying anyways..".format(__name__, self.owner.name, offset, min, max))

        res = offset - self.baseoffset
        mem = idaapi.get_member(self.owner.ptr, res)
        if mem is None:
            logging.info("{:s}.instance({:s}).members.near_offset : Unable to locate member at offset {:+#x}. Trying get_best_fit_member instead.".format(__name__, self.owner.name, res))
            mem = idaapi.get_best_fit_member(self.owner.ptr, res)

        if mem is None:
            raise LookupError("{:s}.instance({:s}).members.near_offset : Unable to find member near offset : {:+#x}".format(__name__, self.owner.name, offset))

        index = self.index(mem)
        return self[index]
    near = nearoffset = nearOffset = utils.alias(near_offset, 'members_t')

    # adding/removing members
    @utils.multicase(name=(basestring, tuple))
    def add(self, name):
        '''Append the specified member ``name`` with the default type at the end of the structure.'''
        offset = self.owner.size + self.baseoffset
        return self.add(name, int, offset)
    @utils.multicase(name=(basestring, tuple))
    def add(self, name, type):
        '''Append the specified member ``name`` with the given ``type`` at the end of the structure.'''
        offset = self.owner.size + self.baseoffset
        return self.add(name, type, offset)
    @utils.multicase(name=(basestring, tuple), offset=six.integer_types)
    def add(self, name, type, offset):
        """Add a member at ``offset`` with the given ``name`` and ``type``.
        To specify a particular size, ``type`` can be a tuple with the second element referring to the size.
        """
        flag, typeid, nbytes = interface.typemap.resolve(type)

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        realoffset = offset - self.baseoffset

        if name is None:
            logging.warn("{:s}.instance({:s}).members.add : name is undefined, defaulting to offset {:+#x}".format(__name__, self.owner.name, realoffset))
            name = 'v', realoffset
        if isinstance(name, tuple):
            name = interface.tuplename(*name)

        res = idaapi.add_struc_member(self.owner.ptr, name, realoffset, flag, opinfo, nbytes)
        if res == idaapi.STRUC_ERROR_MEMBER_OK:
            logging.info("{:s}.instance({:s}).members.add : idaapi.add_struc_member(sptr={!r}, fieldname={:s}, offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x}) : Success".format(__name__, self.owner.name, self.owner.name, name, realoffset, flag, typeid, nbytes))
        else:
            error = {
                idaapi.STRUC_ERROR_MEMBER_NAME : 'Duplicate field name',
                idaapi.STRUC_ERROR_MEMBER_OFFSET : 'Invalid offset',
                idaapi.STRUC_ERROR_MEMBER_SIZE : 'Invalid size',
            }
            callee = "idaapi.add_struc_member(sptr={!r}, fieldname={:s}, offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})".format(self.owner.name, name, realoffset, flag, typeid, nbytes)
            logging.fatal(' : '.join(('members_t.add', callee, error.get(res, "Error code {:#x}".format(res)))))
            return None

        res = idaapi.get_member(self.owner.ptr, realoffset)
        if res is None:
            logging.fatal("{:s}.instance({:s}.members.add : Failed creating member {!r} {:s}:{:+#x}".format(__name__, self.owner.name, name, realoffset, nbytes))

        # sloppily figure out what the correct index is
        idx = self.index( idaapi.get_member(self.owner.ptr, realoffset) )
        return member_t(self.owner, idx)

    def pop(self, index):
        '''Remove the member at the specified ``index``.'''
        item = self[index]
        return self.remove(item.offset - self.baseoffset)
    def __delitem__(self, index):
        return self.pop(index)

    @utils.multicase()
    def remove(self, offset):
        '''Remove all the member from the structure at ``offset``.'''
        return idaapi.del_struc_member(self.owner.ptr, offset - self.baseoffset)
    @utils.multicase()
    def remove(self, offset, size):
        '''Remove all the members from the structure from ``offset`` up to ``size``.'''
        ofs = offset - self.baseoffset
        return idaapi.del_struc_members(self.owner.ptr, ofs, ofs+size)

    def __repr__(self):
        '''Display all the fields within the specified structure.'''
        result = []
        mn, ms = 0, 0
        for i in six.moves.range(len(self)):
            m = self[i]
            name, t, ofs, size, comment = m.name, m.type, m.offset, m.size, m.comment
            result.append((i, name, t, ofs, size, comment))
            mn = max((mn, len(name)))
            ms = max((ms, len("{:+#x}".format(size))))
        mi = len("{:d}".format(len(self)))
        mo = max(map(len, map("{:x}".format, (self.baseoffset, self.baseoffset+self.owner.size))))
        return "{!r}\n{:s}".format(self.owner, '\n'.join("[{:{:d}d}] {:>{:d}x}:{:<+#{:d}x} {:<{:d}s} {!r} {:s}".format(i, mi, o, mo, s, ms, "'{:s}'".format(n), mn+2, t, " // {:s}".format(c) if c else '') for i, n, t, o, s, c in result))

class member_t(object):
    '''Contains information about a particular member within a given structure'''
    __slots__ = ('__owner', '__index')

    def __init__(self, owner, index):
        '''Create a member_t for the field in the structure ``owner`` at ``index``.'''
        self.__index = index
        self.__owner = owner

    def __getstate__(self):
        t = (self.flag, None if self.typeid is None else instance(self.typeid), self.size)
        cmtt = idaapi.get_member_cmt(self.id, True)
        cmtf = idaapi.get_member_cmt(self.id, False)
        ofs = self.offset - self.__owner.members.baseoffset
        return (self.__owner.name, self.__index, self.name, (cmtt, cmtf), ofs, t)
    def __setstate__(self, state):
        ownername, index, name, (cmtt, cmtf), ofs, t = state
        fullname = '.'.join((owername, name))

        identifier = idaapi.get_struc_id(ownername)
        if identifier == idaapi.BADADDR:
            logging.warn("{:s}.instance({:s}).member_t : Creating structure {:s} -- [{:#x}] {:s}{:s}".format(__name__, ownername, ownername, ofs, name, " // {:s}".format(cmtt or cmtf) if cmtt or cmtf else ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, ownername)
        self.__owner = owner = instance(identifier, offset=0)

        flag, mytype, nbytes = t

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = 0 if mytype is None else mytype.id

        res = idaapi.add_struc_member(owner.ptr, name, ofs, flag, opinfo, nbytes)

        # FIXME: handle these errors properly
        # duplicate name
        if res == idaapi.STRUC_ERROR_MEMBER_NAME:
            if idaapi.get_member_by_name(owner.ptr, name).soff != ofs:
                newname = "{:s}_{:x}".format(name, ofs)
                logging.warn("{:s}.instace({:s}).member_t : Duplicate name found for {:s}, renaming to {:s}.".format(__name__, ownername, name, newname))
                idaapi.set_member_name(owner.ptr, ofs, newname)
            else:
                logging.info("{:s}.instance({:s}).member_t : Field at {:+#x} contains the same name {:s}.".format(__name__, ownername, ofs, name))
        # duplicate field
        elif res == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            logging.info("{:s}.instance({:s}).member_t : Field already found at {:+#x}. Overwriting with {:s}.".format(__name__, ownername, ofs, name))
            idaapi.set_member_type(owner.ptr, ofs, flag, opinfo, nbytes)
            idaapi.set_member_name(owner.ptr, ofs, name)
        # invalid size
        elif res == idaapi.STRUC_ERROR_MEMBER_SIZE:
            logging.warn("{:s}.instance({:s}).member_t : Issue creating structure member {:s} : {:#x}".format(__name__, ownername, fullname, res))
        # unknown
        elif res != idaapi.STRUC_ERROR_MEMBER_OK:
            logging.warn("{:s}.instance({:s}).member_t : Issue creating structure member {:s} : {:#x}".format(__name__, ownername, fullname, res))

        self.__index = index
        self.__owner = owner

        idaapi.set_member_cmt(self.ptr, cmtt, True)
        idaapi.set_member_cmt(self.ptr, cmtf, False)
        return

    # read-only properties
    @property
    def ptr(self):
        '''Return the pointer of the `idaapi.member_t`.'''
        return self.__owner.ptr.get_member(self.__index)
    @property
    def id(self):
        '''Return the `.id` attribute of the member.'''
        return self.ptr.id
    @property
    def size(self):
        '''Return the size of the member.'''
        return idaapi.get_member_size(self.ptr)
    @property
    def offset(self):
        '''Return the offset of the member.'''
        return self.ptr.get_soff() + self.__owner.members.baseoffset
    @property
    def flag(self):
        '''Return the `.flag` attribute of the member.'''
        m = idaapi.get_member(self.__owner.ptr, self.offset - self.__owner.members.baseoffset)
        return 0 if m is None else m.flag
    @property
    def fullname(self):
        '''Return the fullname of the member.'''
        return idaapi.get_member_fullname(self.id)
    @property
    def typeid(self):
        '''Return the `.tid` attribute of the type of the member.'''
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

    # read/write properties
    @property
    def name(self):
        '''Return the name of the member.'''
        return idaapi.get_member_name(self.id) or ''
    @name.setter
    def name(self, string):
        '''Set the name of the member to ``string``.'''
        if isinstance(string, tuple):
            string = interface.tuplename(*string)

        res = idaapi.validate_name2(buffer(string)[:])
        if string and string != res:
            cls = self.__class__
            logging.warn("{:s}.name : Stripping invalid chars from structure \"{:s}\" member {:d} name {!r}. : {!r}".format( '.'.join((__name__, cls.__name__)), self.__owner.name, self.__index, string, res))
            string = res
        return idaapi.set_member_name(self.__owner.ptr, self.offset - self.__owner.members.baseoffset, string)
    @property
    def comment(self):
        '''Return the repeatable comment of the member.'''
        return idaapi.get_member_cmt(self.id, True) or idaapi.get_member_cmt(self.id, False)
    @comment.setter
    def comment(self, value):
        '''Set the repeatable comment of the member.'''
        return idaapi.set_member_cmt(self.ptr, value, True)
    @property
    def dt_type(self):
        '''Return the `.dt_type` attribute of the member.'''
        m = idaapi.get_member(self.__owner.ptr, self.offset - self.__owner.members.baseoffset)
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
            res = instance(res.id, offset=self.offset)
        elif isinstance(res, tuple):
            t, sz = res
            if isinstance(t, structure_t):
                t = instance(t.id, offset=self.offset)
            elif isinstance(t, types.ListType) and isinstance(t[0], structure_t):
                t[0] = instance(t[0].id, offset=self.offset)
            res = t, sz
        return res
    @type.setter
    def type(self, type):
        '''Set the type of the member.'''
        flag, typeid, nbytes = interface.typemap.resolve(type)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        return idaapi.set_member_type(self.__owner.ptr, self.offset - self.__owner.members.baseoffset, flag, opinfo, nbytes)

    @type.getter
    def typeinfo(self):
        res = idaapi.tinfo_t()
        ok = idaapi.get_or_guess_member_tinfo2(self.ptr, res)
        if not ok:
            cls = self.__class__
            logging.fatal("{:s}.instance({:s}).member({:s}).typeinfo : Unable to determine tinfo_t() for member {:#x}.".format('.'.join((__name__,cls.__name__)), self.__owner.name, self.name, self.id))
        return res

    def __repr__(self):
        '''Display the member in a readable format.'''
        id, name, typ, comment = self.id, self.name, self.type, self.comment
        return "{:s}\n[{:d}] {:-#x}:{:+#x} \'{:s}\' {:s}{:s}".format(self.__class__, self.index, self.offset, self.size, name, typ, " // {:s}".format(comment) if comment else '')

    def refs(self):
        '''Return the `(address, opnum, type)` of all the references to this member within the database.'''
        mid = self.id

        # calculate the high-byte which is used to determine an address from a structure
        bits = math.trunc(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
        highbyte = 0xff << (bits-8)

        # if structure is a frame..
        if internal.netnode.name.get(self.__owner.id).startswith('$ '):
            name, mptr = self.fullname, self.ptr
            sptr = idaapi.get_sptr(mptr)

            # get frame, func_t
            frname, _ = name.split('.', 2)
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
                res.append( interface.OREF(ea, opnum, interface.ref_t(xr.type, instruction.op_state(ea, opnum))) )    # FIXME
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

        # now figure out which operand has the structure member applied to it
        res = []
        for ea, _, t in refs:
            ops = ((idx, internal.netnode.sup.get(ea, 0xf+idx)) for idx in six.moves.range(idaapi.UA_MAXOP) if internal.netnode.sup.get(ea, 0xf+idx) is not None)
            ops = ((idx, interface.node.sup_opstruct(val, idaapi.get_inf_structure().is_64bit())) for idx, val in ops)
            ops = (idx for idx, ids in ops if self.__owner.id in ids)    # sanity
            res.extend( interface.OREF(ea, int(op), interface.ref_t.of(t)) for op in ops)
        return res

#strpath_t
#op_stroff(ea, n, tid_t* path, int path_len, adiff_t delta)
#get_stroff_path(ea, n, tid_t* path, adiff_t delta)
