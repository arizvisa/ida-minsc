"""
Structure module (internal)

This internal module contains the definitions for each of the
classes that are required to wrap a structure or a union from
the database. This allows access to all of the structure types
and their members from each of the available modules. Thus
allowing us to hide away any complicated functionality needed
for processing an instance of a structure and avoiding the
definitions of these classes having to reside in a base module.
"""

import builtins, functools, operator, itertools, logging, six
import re, fnmatch

import idaapi, internal
from internal import utils, interface, types, exceptions as E

def new(identifier, offset):
    '''Create a new instance of the structure identified by `identifier` at the specified offset.'''

    # This function isn't really too necessary, but it gives us a single
    # point to identify when structures get created when either deserializing,
    # or crawling down a structure path looking for something.
    return structure_t(identifier, offset)

def has(id):
    '''Return whether a structure with the specified `id` exists within the database.'''
    return True if interface.node.identifier(id) and idaapi.get_struc(id) else False

def union(sptr):
    '''Return whether the structure in `sptr` is defined as a union.'''
    SF_UNION = getattr(idaapi, 'SF_UNION', 0x2)
    return True if sptr.props & SF_UNION else False

def frame(sptr):
    '''Return whether the structure in `sptr` belongs to a function as a frame.'''
    SF_FRAME = getattr(idaapi, 'SF_FRAME', 0x40)
    return True if sptr.props & SF_FRAME else False

class address(object):
    """
    This namespace is a placeholder for some of the functions that
    are needed for getting information about an address or identifier.
    """
    flags = utils.alias(interface.address.flags, 'interface.address')
    reference = utils.alias(interface.instruction.reference, 'interface.instruction')

    @classmethod
    def code(cls, ea):
        '''Return if the address specified by `ea` is marked as code.'''
        return interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE

    @utils.multicase(ea=types.integer)
    @classmethod
    def type(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        guess_tinfo = (lambda ti, ea: idaapi.guess_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo

        # Try super hard to get the type information, first doing it the official way
        # and then guessing it. If none of that worked, then return None for no type.
        ti, error = idaapi.tinfo_t(), 0
        ok = get_tinfo(ti, ea) or guess_tinfo(ti, ea) != idaapi.GUESS_FUNC_FAILED
        if not ok:
            return None

        # Concretize the type because this is likely going to be returned or serialized.
        elif hasattr(idaapi, 'replace_ordinal_typerefs'):
            error = idaapi.replace_ordinal_typerefs(ti.get_til(), ti)
        return None if error < 0 else ti

    @utils.multicase(ea=types.integer, none=types.none)
    @classmethod
    def type(cls, ea, none):
        '''Remove the type information from the address `ea`.'''
        del_tinfo = idaapi.del_tinfo2 if idaapi.__version__ < 7.0 else idaapi.del_tinfo
        result, _ = cls.type(ea), del_tinfo(ea)
        return result
    @utils.multicase(ea=types.integer, string=types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def type(cls, ea, string):
        '''Parse the type information in `string` into an ``idaapi.tinfo_t`` and apply it to the address `ea`.'''
        info = internal.declaration.parse(string)
        if info is None:
            raise E.InvalidTypeOrValueError(u"{:s}.type({:#x}, {!r}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), ea, string, utils.string.repr(string)))
        return cls.type(ea, info)
    @utils.multicase(ea=types.integer, info=idaapi.tinfo_t)
    @classmethod
    def type(cls, ea, info):
        '''Apply the ``idaapi.tinfo_t`` in `info` to the address `ea`.'''
        info_s = "{!s}".format(info)

        # All we need to do is to use idaapi to apply our tinfo_t to the address.
        result, ok = cls.type(ea), idaapi.apply_tinfo(ea, info, idaapi.TINFO_DEFINITE)
        if not ok:
            raise E.DisassemblerError(u"{:s}.type({:#x}, {!r}) : Unable to apply typeinfo ({!s}) to the address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, info_s, utils.string.repr(info_s), ea))
        return result

    @classmethod
    def structure(cls, ea):
        '''Return the identifier of the structure at address `ea`.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        ea = interface.address.head(ea, warn=True)

        info, flags = idaapi.opinfo_t(), cls.flags(ea)
        if flags & idaapi.DT_TYPE != FF_STRUCT:
            raise E.MissingTypeOrAttribute(u"{:s}.structure({:#x}) : The type at specified address is not an FF_STRUCT({:#x}) and is instead {:#x}.".format('.'.join([__name__, cls.__name__]), ea, FF_STRUCT, flags & idaapi.DT_TYPE))

        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        if not ok:
            raise E.DisassemblerError(u"{:s}.structure({:#x}) : The call to `{:s}({:#x}, {:d}, {:#x})` failed for the address at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.pycompat.fullname(idaapi.get_opinfo), ea, idaapi.OPND_ALL, flags, ea))
        return info.tid

    @classmethod
    def operands(cls, ea):
        '''Returns all of the ``idaapi.op_t`` instances for the instruction at the address `ea`.'''
        return tuple(interface.instruction.operands(ea))

    @classmethod
    def access(cls, ea, opnum):
        '''Returns the access for the operand `opnum` belonging to the instruction at the address `ea`.'''
        items = [access for access in interface.instruction.access(ea)]
        return items[opnum]

    @classmethod
    def opinfo(cls, ea, opnum):
        '''Returns the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
        info, flags = idaapi.opinfo_t(), cls.flags(ea)
        ok = idaapi.get_opinfo(ea, opnum, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, opnum, flags)
        return info if ok else None

class xref(object):
    """
    This namespace is a placeholder for some of the functions that
    are needed for returning and navigating any cross-references
    to addresses, structures, or their members.
    """
    @classmethod
    def up(cls, ea):
        '''Return all of the addresses that reference the address `ea`.'''
        ea, xiterate = interface.address.inside(ea), interface.xref.to
        for xr, iscode, xrtype in xiterate(ea):
            if not(iscode and xrtype == idaapi.fl_F):
                yield xr
            continue
        return

    @classmethod
    def down(cls, ea):
        '''Return all of the addresses that are referred by the address `ea`.'''
        ea, xiterate = interface.address.inside(ea), interface.xref.of
        for xr, iscode, xrtype in xiterate(ea):
            if not(iscode and xrtype == idaapi.fl_F):
                yield xr
            continue
        return

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
        if not isinstance(sptr, (idaapi.struc_t, types.integer)):
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
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(self.name), ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it (XXX: return a dictionary that automatically updates the comment when it's updated)
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # Now we need to add implicit tags which are related to the structure.
        sptr = self.ptr

        # If we're a frame or we're unlisted, then we don't add the implicit
        # "__name__" tag. This way the user can select for "__name__" and use
        # it to distinguish local types and ghost types (which always have a name).
        excluded = ['SF_FRAME', 'SF_NOLIST']
        name = utils.string.of(idaapi.get_struc_name(sptr.id))
        if name and not any([sptr.props & getattr(idaapi, attribute) for attribute in excluded if hasattr(idaapi, attribute)]):
            res.setdefault('__name__', name)

        # Now we need to do the '__typeinfo__' tag. This is going to be a little
        # bit different than how we usually determine it, because we're going to
        # use it to determine whether the user created this type themselves or it
        # was created automatically. So, if it was copied from the type library
        # (SF_TYPLIB), from the local types (SF_GHOST), or the user chose not to
        # list it (SF_NOLIST), then we don't assign '__typeinfo__'.
        excluded = ['SF_FRAME', 'SF_GHOST', 'SF_TYPLIB', 'SF_NOLIST']
        if any([sptr.props & getattr(idaapi, attribute) for attribute in excluded if hasattr(idaapi, attribute)]):
            pass

        # SF_NOLIST is justified because if the user didn't want the structure to
        # be listed, then we're just doing as we're told. Everything else should
        # be justifiable because if the user did anything with the type, then
        # the other flags should've been cleared.
        else:
            ti = self.typeinfo
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, '', '')
            res.setdefault('__typeinfo__', ti_s)
        return res
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the structure.'''
        res = self.tag()
        if key in res:
            return res[key]
        cls = self.__class__
        raise E.MissingTagError(u"{:s}({:#x}).tag({!r}) : Unable to read the non-existing tag named \"{:s}\" from the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, utils.string.escape(key, '"'), utils.string.repr(self.name)))
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the structure.'''
        repeatable = True

        # Guard against a bunk type being used to set the value.
        if value is None:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Tried to set the tag named \"{:s}\" with an unsupported type {!r}.".format('.'.join([__name__, cls.__name__]), self.id, key, value, utils.string.escape(key, '"'), value))

        # First we need to read both comments to figure out what the user is trying to say.
        comment_right = utils.string.of(idaapi.get_struc_cmt(self.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_struc_cmt(self.id, not repeatable))

        # Decode the tags that are written to both comment types to figure out which
        # comment type the user actually means. The logic here reads weird because the
        # "repeatable" variable toggles which comment to give priority. We explicitly
        # check the "wrong" place but fall back to the "right" one.
        state_right, state_wrong = map(internal.comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If there were any duplicate keys in any of the dicts, then warn the user about it.
        duplicates = six.viewkeys(state_right) & six.viewkeys(state_wrong)
        if key in duplicates:
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, key, value, utils.string.repr(self.name), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we can just update the dict and re-encode to the proper comment location.
        res, state[key] = state.get(key, None), value
        if not idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), where):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, value, 'repeatable' if where else 'non-repeatable', utils.string.repr(self.name)))
        return res
    @utils.multicase(key=types.string, none=types.none)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the structure.'''
        repeatable = True

        # First we check if the key is one of the implicit tags that we support. These
        # aren't we can modify since they only exist in special circumstances.
        if key in {'__name__', '__typeinfo__'} and key in self.tag():
            message_typeinfo = 'modified by the user from the default type library'
            message_name = 'flagged as listed by the user'

            # The characteristics aren't actually documented anywhere, so we'll raise an
            # exception that attempts to describe what causes them to exist. Hopefully
            # the user figures out that they can use them to find structures they created.
            cls, message = self.__class__, message_typeinfo if key == '__typeinfo__' else message_name
            raise E.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove the implicit tag \"{:s}\" due to the structure being {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, none, utils.string.escape(key, '"'), message))

        # We need to read both comments to figure out where the tag is that we're trying to remove.
        comment_right = utils.string.of(idaapi.get_struc_cmt(self.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_struc_cmt(self.id, not repeatable))

        # Decode the tags that are written to both comment types, and then test them
        # to figure out which comment the key is encoded in. In this, we want
        # "repeatable" to be a toggle and we want to default to the selected comment.
        state_right, state_wrong = map(internal.comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If the key isn't where we expect it, then raise an exception since we can't
        # remove it if it doesn't actually exist.
        if key not in state:
            cls = self.__class__
            raise E.MissingTagError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove non-existing tag \"{:s}\" from the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, none, utils.string.escape(key, '"'), utils.string.repr(self.name)))

        # If the key is in both dictionaries, then be kind and warn the user about it
        # so that they'll know that their key will still be part of the dict.
        duplicates = six.viewkeys(state_right) & six.viewkeys(state_wrong)
        if key in (six.viewkeys(state_right) & six.viewkeys(state_wrong)):
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, key, none, utils.string.repr(self.name), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we can just pop the value out of the dict and re-encode back into the comment.
        res = state.pop(key)
        if not idaapi.set_struc_cmt(self.id, utils.string.to(internal.comment.encode(state)), where):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, none, 'repeatable' if repeatable else 'non-repeatable', utils.string.repr(self.name)))
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
        iterable = itertools.chain([self.id], map(operator.attrgetter('id'), self.members))
        items = [identifier for identifier in iterable]

        # Now we need to iterate through all of our members and grab all references
        # to absolutely everything. This is pretty much bypassing the "cross-reference depth"
        # option since if the user is using the api, they probably want everything anywayz.
        ichainable = (interface.xref.to(identifier, idaapi.XREF_ALL) for identifier in items)
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in itertools.chain(*ichainable)]

        # That should've given us absolutely every reference related to this
        # structure, so the last thing to do is to filter our list for references
        # to addresses within the database.
        results, matches = {item for item in []}, {identifier for identifier in items}
        for xrfrom, xriscode, xrtype in refs:

            # If the reference is an identifier, then it's not what we're looking
            # for as this method only cares about database addresses.
            if interface.node.identifier(xrfrom):
                continue

            # If the reference is not pointing to code, then we skip this because
            # there's no way it can actually be pointing to an operand.
            if not address.code(xrfrom):
                cls = self.__class__
                logging.debug(u"{:s}({:#x}).refs() : Skipping {:s}({:d}) reference at {:#x} with the type ({:d}) due to the reference address not marked as code.".format('.'.join([__name__, cls.__name__]), self.id, 'code' if xriscode else 'data', xriscode, xrfrom, xrtype))
                continue

            # Iterate through all of its operands and only care about the
            # ones that have operand information for it. We also keep track
            # of any operands that have a refinfo_t so we can add those too.
            references = {item for item in []}
            for opnum, _ in enumerate(address.operands(xrfrom)):

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
                        ref = address.access(xrfrom, opnum)
                        results.add(interface.opref_t(xrfrom, opnum, interface.reftype_t.of_action(ref.access)))
                    continue

                # Otherwise this is likely a refinfo, and we need to follow
                # the reference in order to grab _all_ of its references.
                drefs = [ea for ea in xref.down(xrfrom) if not interface.node.identifier(ea)]
                references |= {ea for ea in itertools.chain(*map(xref.up, drefs))}

            # Last thing to do is to iterate through the references that we collected
            # in order to determine which operand was referencing the structure.
            for ea in references:
                if not address.code(ea): continue

                # FIXME: figure out which operand is the correct one for our reference.
                for opnum, _ in enumerate(address.operands(ea)):
                    fl, ref = address.flags(ea), address.access(ea, opnum)

                    # Do a final check to see if the operand is referencing a stroff
                    # or a stkvar because then we're definitely pointing to a member.
                    if any(F(fl, opnum) for F in [idaapi.is_stkvar, idaapi.is_stroff]):
                        results.add(interface.opref_t(ea, opnum, interface.reftype_t.of_action(ref.access)))
                    continue
                continue
            continue
        return sorted(results)

    def up(self):
        '''Return all structure or frame members within the database that reference this particular structure.'''
        res = []

        # Iterate through each reference figuring out what exactly our
        # structure id was actually applied to.
        for xrfrom, xriscode, xrtype in interface.xref.to(self.id, idaapi.XREF_ALL):

            # If the reference is an identifier, then we need to the mptr, full member name,
            # and the sptr for what it's referencing so that we can yield what the ref is.
            if interface.node.identifier(xrfrom):
                mpack = idaapi.get_member_by_id(xrfrom)
                if mpack is None:
                    cls = self.__class__
                    raise E.MemberNotFoundError(u"{:s}({:#x}).up() : Unable to locate the member identified by {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, xrfrom))

                mptr, name, sptr = mpack
                if not interface.node.identifier(sptr.id):
                    sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

                # Validate that the type of the mptr is what we're expecting.
                if not isinstance(mptr, idaapi.member_t):
                    cls, name = self.__class__, utils.string.of(idaapi.get_member_fullname(xrfrom))
                    raise E.InvalidTypeOrValueError(u"{:s}({:#x}).up() : Unexpected type {!s} returned for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, mptr.__class__, utils.string.escape(name, '"')))

                # Try and fetch the frame's address (which should fail if not a frame),
                # and then use it to get the func_t that owns the member.
                ea = idaapi.get_func_by_frame(sptr.id)
                func = idaapi.get_func(ea)

                # If we were unable to get the function frame, then we're referencing a
                # member from a different structure and we already have everything.
                if ea == idaapi.BADADDR:
                    sptr, soffset = sptr, 0

                # If we couldn't grab the func, then we just bail.
                elif not func:
                    cls = self.__class__
                    raise E.FunctionNotFoundError(u"{:s}({:#x}).up() : Unable to locate the function for frame member {:#x} by address {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, mptr.id, ea))

                # If we couldn't grab the frame, then we bail on that too.
                elif not idaapi.get_frame(func):
                    cls = self.__class__
                    raise E.MissingTypeOrAttribute(u"{:s}({:#x}).up() : The function at {:#x} for frame member {:#x} does not have a frame.".format('.'.join([__name__, cls.__name__]), self.id, ea, mptr.id))

                # Otherwise we're referencing a frame member, and we need to figure out
                # the structure and the base that we'll be creating its structure at.
                else:
                    sptr, soffset = idaapi.get_frame(func), -idaapi.frame_off_args(func)

                # Now we just need to figure out the index of the member within the sptr.
                iterable = ((index, sptr.members[index]) for index in range(sptr.memqty))
                index = next((index for index, mem in iterable if mem.id == mptr.id), -1)

                if index < 0:
                    logging.critical(u"{:s}({:#x}).up() : Unable to find the referenced member ({:#x}) named \"{:s}\" in the members of its structure ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, mptr.id, utils.string.escape(utils.string.of(name), '"'), sptr.id))
                    continue

                # And then we can create a structure and fetch the specific member.
                res.append(structure_t(sptr, soffset).members[index])

            # If it's not code, then we're just a reference to an address and so we
            # need to yield the address it's for along with its type.
            elif not address.code(xrfrom):
                res.append(interface.ref_t(xrfrom, interface.reftype_t.of(xrtype)))

            # If it's code, then we skip this because structure_t.up only returns
            # data references to the structure and operands are for structure_t.refs.
            else:
                cls = self.__class__
                logging.debug(u"{:s}({:#x}).up() : Skipping {:s}({:d}) reference at {:#x} with the type ({:d}) due to the reference address not marked as data.".format('.'.join([__name__, cls.__name__]), self.id, 'code' if xriscode else 'data', xriscode, xrfrom, xrtype))
            continue
        return res

    ### Properties
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.struc_t``.'''
        ptr, name = self.__ptr__, self.__name__

        # If the pointer has been deleted out from underneath us,
        # then we need to raise an exception to inform the user.
        if ptr is None:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({!r}).ptr : The structure with the name (\"{:s}\") is currently unavailable and was likely removed from the database.".format('.'.join([__name__, cls.__name__]), name, utils.string.escape(name, '"')))

        # Verify if our ptr is still within scope by verifying
        # that its identifier is valid. Otherwise we need to use
        # the name that we've cached to fetch it.
        identifier = ptr.id if interface.node.identifier(ptr.id) else idaapi.get_struc_id(name)

        # Now we can check if we okay with returning the ptr. We also
        # update our cached name with whatever the current name is.
        if identifier == ptr.id:
            result, self.__name__ = ptr, idaapi.get_struc_name(identifier)

        # Otherwise we need to use the identifier to grab the
        # sptr from the identifier we just grabbed.
        else:
            result = self.__ptr__ = idaapi.get_struc(identifier)

        # Do one final check on our result to make sure that we actually
        # got something in case we're racing against SWIG's removal of it.
        if result:
            return result

        # This means that we lost the race against SWIG, and it scoped
        # out our result before we got a chance to actually use it...
        cls = self.__class__
        raise E.DisassemblerError(u"{:s}({!r}).ptr : The structure with the name (\"{:s}\") is currently unavailable and was likely removed from the database.".format('.'.join([__name__, cls.__name__]), name, utils.string.escape(name, '"')))

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
        ptr = self.__ptr__

        # if there's no pointer, then use the name that we have cached, but
        # make sure we log a critical message for the user to freak out about.
        if ptr is None:
            cls, name = self.__class__, self.__name__
            logging.critical(u"{:s}({!r}).name : Returning the cached name (\"{:s}\") for a structure that is unavailable and was likely removed from the database.".format('.'.join([__name__, cls.__name__]), name, utils.string.escape(name, '"')))
            return name

        # otherwise we can extract the identifier and get the actual name, but
        # go figure that sometimes IDAPython will return None when the structure
        # was deleted, so we need to check what it actually gave us.
        res = idaapi.get_struc_name(ptr.id)
        if res is not None:
            return utils.string.of(res)

        # if the name is undefined, then we actually have to raise an exception.
        cls, name = self.__class__, self.__name__
        if name is None:
            raise E.DisassemblerError(u"{:s}({:#x}).name : The structure with the identifier ({:#x}) is currently unavailable and was likely removed from the database.".format('.'.join([__name__, cls.__name__]), ptr.id, ptr.id))

        # otherwise, we can return the one that's cached while logging a message.
        logging.critical(u"{:s}({!r}).name : Returning the cached name (\"{:s}\") for a structure that is unavailable and was likely removed from the database.".format('.'.join([__name__, cls.__name__]), name, utils.string.escape(name, '"')))
        return name

    @name.setter
    @utils.string.decorate_arguments('string')
    def name(self, string):
        '''Set the name of the structure to `string`.'''
        if isinstance(string, types.ordered):
            string = interface.tuplename(*string)

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.SN_IDBENC)
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
    def ordinal(self):
        '''Return the ordinal number of the structure within the current type library.'''
        sptr = self.ptr
        return max(0, sptr.ordinal)

    @property
    def typeinfo(self):
        '''Return the type information of the current structure.'''
        ti = address.type(self.id)

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
            ti = address.type(self.id, info)

        # If we caught a TypeError, then we received a parsing error that
        # we should re-raise for the user.
        except E.InvalidTypeOrValueError:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo({!s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), info))

        # If we caught an exception trying to get the typeinfo for the
        # structure, then port it to our class and re-raise.
        except E.DisassemblerError:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to apply `{:s}` to structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(info), utils.pycompat.fullname(idaapi.tinfo_t), self.name))
        return

    @property
    def realbounds(self):
        sptr = self.ptr
        return interface.bounds_t(0, idaapi.get_struc_size(self.ptr))

    @property
    def bounds(self):
        bounds, base = self.realbounds, self.members.baseoffset
        return operator.add(bounds, base)

    ### Private methods
    def __str__(self):
        '''Render the current structure in a readable format.'''
        sptr, name, offset, size, comment, tag = self.ptr, self.name, self.offset, self.size, self.comment or '', self.tag()
        return "<class '{:s}' name={!s}{:s} size={:#x}>{:s}".format('union' if union(sptr) else 'structure', utils.string.repr(name), (" offset={:#x}".format(offset) if offset != 0 else ''), size, " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __unicode__(self):
        '''Render the current structure in a readable format.'''
        sptr, name, offset, size, comment, tag = self.ptr, self.name, self.offset, self.size, self.comment or '', self.tag()
        return u"<class '{:s}' name={!s}{:s} size={:#x}>{:s}".format('union' if union(sptr) else 'structure', utils.string.repr(name), (" offset={:#x}".format(offset) if offset != 0 else ''), size, " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

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
        sptr = self.ptr

        # grab the index
        idx = idaapi.get_struc_idx(sptr.id)

        # then its name
        name = utils.string.of(idaapi.get_struc_name(sptr.id) or '')

        # decode the comments that we found in the structure
        cmtt, cmtf = map(functools.partial(idaapi.get_struc_cmt, self.id), [True, False])
        comments = tuple(utils.string.of(cmt) for cmt in [cmtt, cmtf])

        # pack our state into a tuple.
        state = idx, sptr.props, name, comments

        # FIXME: is there anything other attributes that we might need?
        return state, self.members

    def __setstate__(self, state):

        # Restore the index (discarded), properties, name, and comments.
        if len(state) == 2:
            state, members = state
            idx, props, name, (cmtt, cmtf) = state

        # For backwards compatibility...
        else:
            name, (cmtt, cmtf), members = state
            idx, props = -1, 0

        # try and find the structure in the database by its name
        res = utils.string.to(name)
        identifier = idaapi.get_struc_id(res)

        # if we didn't find it, then just add it and notify the user
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.info(u"{:s}({:#x}) : Creating structure \"{:s}\" with {:d} fields and the comment \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, utils.string.escape(name, '"'), len(members), utils.string.escape(cmtf or cmtt or '', '"')))
            res = utils.string.to(name)
            identifier = idaapi.add_struc(idaapi.BADADDR, res, True if props & idaapi.SF_UNION else False)

        # now we can apply the comments to it
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtt), True)
        idaapi.set_struc_cmt(identifier, utils.string.to(cmtf), False)

        # set its individual properties (ignoring SF_FRAME and SF_GHOST of course)
        sptr = idaapi.get_struc(identifier)
        idaapi.set_struc_listed(sptr, False if props & idaapi.SF_NOLIST else True)
        idaapi.set_struc_hidden(sptr, True if props & idaapi.SF_HIDDEN else False)
        idaapi.set_struc_align(sptr, (props & idaapi.SF_ALIGN) >> 7)

        # we don't really bother with changing the index, because we
        # want to be able to preserve the order when they're added.
        if False and 0 <= idx < idaapi.get_struc_qty():
            if idaapi.get_struc_by_idx(idx) == idaapi.BADADDR:
                idaapi.set_struc_idx(sptr, idx)

        # and set its attributes properly
        self.__ptr__, self.__name__ = idaapi.get_struc(sptr.id), name
        self.__members__ = members
        return

    ## operators
    def __operator__(self, operation, other):
        cls, sptr, offset = self.__class__, self.ptr, self.members.baseoffset
        if isinstance(other, types.integer):
            res = operation(offset, other)
        elif isinstance(other, member_t):
            res = operation(offset, other.offset)
        elif isinstance(other, cls):
            res = operation(offset, other.size)
        elif hasattr(other, '__int__'):
            res = operation(offset, int(other))
        else:
            raise TypeError(u"{:s}({:#x}).__operator__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, operation, other, operation.__name__, other.__class__.__name__, cls.__name__))
        return cls(sptr, offset=res)

    # general arithmetic (adjusts base offset)
    def __add__(self, other):
        '''Add `other` to the base offset of the structure.'''
        return self.__operator__(operator.add, other)
    def __sub__(self, other):
        '''Subtract `other` from the base offset of the structure.'''
        return self.__operator__(operator.sub, other)
    def __and__(self, other):
        return self.__operator__(operator.and_, other)
    def __or__(self, other):
        return self.__operator__(operator.or_, other)
    def __xor__(self, other):
        return self.__operator__(operator.xor, other)

    # repetition and multiplication
    def __mul__(self, count):
        '''Return a list of structures with each member arranged contiguously as an array of `count` elements.'''
        cls, sptr = self.__class__, self.ptr
        if not isinstance(count, types.integer):
            other, operation = count, operator.mul
            raise TypeError(u"{:s}({:#x}).__mul__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, operation, other, operation.__name__, other.__class__.__name__, cls.__name__))

        offset, size = self.members.baseoffset, self.size
        start, stop = sorted([size * count, 0])
        return [ cls(sptr, offset=offset + relative) for relative in range(start, stop, size) ]

    def __pow__(self, index):
        '''Return an instance of the structure with its offset adjusted similar to an array element at the specified `index`.'''
        cls, sptr = self.__class__, self.ptr
        if not isinstance(index, types.integer):
            other, operation = index, operator.pow
            raise TypeError(u"{:s}({:#x}).__pow__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, operation, other, operation.__name__, other.__class__.__name__, cls.__name__))

        offset, relative = self.members.baseoffset, self.size * index
        return cls(sptr, offset=offset + relative)

    # reverse operators (adjusts base offset)
    __radd__ = __add__
    def __rsub__(self, other):
        return self.__operator__(operator.add, operator.neg(other))
    __rand__ = __and__
    __ror__ = __or__
    __rxor__ = __xor__
    __rmul__ = __mul__
    #__rpow__ = __pow__

    # operations
    def __abs__(self):
        '''Return an instance of the structure without an offset.'''
        cls, sptr = self.__class__, self.ptr
        return cls(sptr)
    def __neg__(self):
        '''Return an instance of the structure with its offset negated.'''
        cls, sptr, offset = self.__class__, self.ptr, self.members.baseoffset
        return cls(sptr, -offset)
    def __invert__(self):
        '''Return an instance of the structure with its offset inverted.'''
        cls, sptr = self.__class__, self.ptr
        offset, size = self.members.baseoffset, self.size
        res = offset + size
        return cls(sptr, -res)

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
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr(self.fullname), ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one before adding implicit tags.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # the format of the implicit tags depend on the type of the member, which
        # we actually extract from a combination of the name, and is_special_member.
        specialQ = True if idaapi.is_special_member(self.id) else False

        # now we need to check the name via is_dummy_member_name, and explicitly
        # check to see if the name begins with field_ so that we don't use it if so.
        idaname = idaapi.get_member_name(self.id) or ''
        anonymousQ = True if any(F(idaname) for F in [idaapi.is_dummy_member_name, idaapi.is_anonymous_member_name, operator.methodcaller('startswith', 'field_')]) else False
        name = utils.string.of(idaname)

        # if the name is defined and not special in any way, then its a tag.
        aname = '' if any([specialQ, anonymousQ]) else name
        if aname:
            res.setdefault('__name__', aname)

        # The next tag is the type information that we'll need to explicitly check for
        # because IDA will always figure it out and only want to include it iff the
        # user has created the type through some explicit action.

        # The documentation says that we should be checking the NALT_AFLAGS(8) or really
        # the aflags_t of the member which works on structures (since the user will always
        # be creating them). However, for frames we miss out on types that are applied by
        # prototypes or ones that have been propagated to the member by Hex-Rays. So for
        # frames it definitely seems like NSUP_TYPEINFO(0x3000) is the way to go here.
        user_tinfoQ = idaapi.get_aflags(self.id) & idaapi.AFL_USERTI == idaapi.AFL_USERTI
        sup_tinfoQ = internal.netnode.sup.has(self.id, idaapi.NSUP_TYPEINFO)
        has_typeinfo = sup_tinfoQ if frame(self.parent.ptr) else user_tinfoQ
        if has_typeinfo:
            ti = self.typeinfo

            # Now we need to attach the member name to our type. Hopefully it's not
            # mangled in some way that will need consideration if it's re-applied.
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(aname), '')
            res.setdefault('__typeinfo__', ti_s)
        return res
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` belonging to the member.'''
        res = self.tag()
        if key in res:
            return res[key]
        cls = self.__class__
        raise E.MissingTagError(u"{:s}({:#x}).tag({!r}) : Unable to read the non-existing tag named \"{:s}\" from the member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, utils.string.escape(key, '"'), utils.string.repr(self.fullname)))
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the member.'''
        repeatable = True

        # Guard against a bunk type being used to set the value.
        if value is None:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Tried to set the tag named \"{:s}\" with an unsupported type {!r}.".format('.'.join([__name__, cls.__name__]), self.id, key, value, utils.string.escape(key, '"'), value))

        # Before we do absolutely anything, we need to check if the user is updating
        # one of the implicit tags and act on them by assigning their new value.
        if key == '__name__':
            tags = self.tag()
            result, self.name = tags.pop(key, None), value
            return result

        elif key == '__typeinfo__':
            tags = self.tag()
            result, self.typeinfo = tags.pop(key, None), value
            return result

        # We need to grab both types of comments so that we can figure out
        # where the one that we're modifying is going to be located at.
        comment_right = utils.string.of(idaapi.get_member_cmt(self.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_member_cmt(self.id, not repeatable))

        # Now we'll decode both comments and figure out which one contains the key
        # that the user is attempting to modify. The "repeatable" variable is used
        # to toggle which comment gets priority which modifying the member's tags.
        state_right, state_wrong = map(internal.comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # Check if the key is a dupe so that we can warn the user about it.
        duplicates = six.viewkeys(state_right) & six.viewkeys(state_wrong)
        if key in duplicates:
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for member {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, key, value, utils.string.repr(self.fullname), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we just need to modify the state with the new value and re-encode it.
        res, state[key] = state.get(key, None), value
        if not idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), where):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, value, 'repeatable' if where else 'non-repeatable', utils.string.repr(self.fullname)))
        return res
    @utils.multicase(key=types.string, none=types.none)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Removes the tag specified by `key` from the member.'''
        repeatable = True

        # Check if the key is an implicit tag that we're being asked to
        # remove so that we can remove it from whatever it represents.
        if key == '__name__':
            tags = self.tag()
            result, self.name = tags.pop(key, None), None
            return result

        elif key == '__typeinfo__':
            tags = self.tag()
            result, self.typeinfo = tags.pop(key, None), None
            return result

        # Read both the comment types to figure out where the tag we want to remove is located at.
        comment_right = utils.string.of(idaapi.get_member_cmt(self.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_member_cmt(self.id, not repeatable))

        # Now we need to decode them and figure out which comment the tag we need
        # to remove is located in. This reads weird because "repeatable" is intended
        # to toggle which comment type we give priority to during removal.
        state_right, state_wrong = map(internal.comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If the key is not in the dictionary that we determined, then it's missing
        # and so we need to bail with an exception since it doesn't exist.
        if key not in state:
            cls = self.__class__
            raise E.MissingTagError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove non-existing tag \"{:s}\" from the member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, none, utils.string.escape(key, '"'), utils.string.repr(self.fullname)))

        # If there's any duplicate keys and the user's key is one of them, then warn
        # the user about it so they'll know that they'll need to remove it twice.
        duplicates = six.viewkeys(state_right) & six.viewkeys(state_wrong)
        if key in duplicates:
            cls = self.__class__
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for member {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), self.id, key, none, utils.string.repr(self.fullname), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # The very last thing to do is to remove the key from the dictionary
        # and then encode our updated state into the member's comment.
        res = state.pop(key)
        if not idaapi.set_member_cmt(self.ptr, utils.string.to(internal.comment.encode(state)), where):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, none, 'repeatable' if repeatable else 'non-repeatable', utils.string.repr(self.fullname)))
        return res

    def refs(self):
        """Return the `(address, opnum, type)` of all the code and data references to this member within the database.

        If `opnum` is ``None``, then the returned `address` has the structure applied to it.
        If `opnum` is defined, then the instruction at the returned `address` references a field that contains the specified structure.
        """
        cls, FF_STRUCT = self.__class__, idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        Fnetnode, Fidentifier = (getattr(idaapi, api, utils.fidentity) for api in ['ea2node', 'node2ea'])
        FF_STROFF = idaapi.stroff_flag() if hasattr(idaapi, 'stroff_flag') else idaapi.stroffflag()
        FF_STKVAR = idaapi.stkvar_flag() if hasattr(idaapi, 'stkvar_flag') else idaapi.stkvarflag()

        # if structure is a frame..
        if interface.node.identifier(self.parent.id) and internal.netnode.name.get(Fnetnode(self.parent.id)).startswith('$ '):
            name, mptr = self.fullname, self.ptr
            sptr = idaapi.get_sptr(mptr)

            # get frame, func_t
            frname, _ = name.split('.', 1)
            frid = Fidentifier(internal.netnode.get(frname))
            ea = idaapi.get_func_by_frame(frid)

            # now we can collect all the xrefs to the member within the function
            res = []
            for ea, opnum, type in interface.xref.frame(ea, mptr):
                ref = address.access(ea, opnum)
                res.append(interface.opref_t(ea, opnum, interface.reftype_t(type, ref.access)))
            return res

        # otherwise, it's a structure..which means we need to specify the member to get refs for
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(self.id, idaapi.XREF_ALL)]

        # collect the identifiers of all of the members that can possibly
        # refer to this same one which means we track unions as well. this
        # requires us to recursively walk through all of the references
        # for each parent until we've collected everything.
        parents, members, queue = {self.parent}, {self}, {self.parent}
        while True:
            work = {item for item in []}

            # now that we have our work, we can add it to our list. however, we also
            # need to check if our parent is a union so that we can descend through
            # its members for ones at the same offset of our referring member.
            for item in itertools.chain(*map(operator.methodcaller('up'), queue)):
                if isinstance(item, interface.ref_t) or item.parent.ptr.props & idaapi.SF_FRAME:
                    continue
                if union(item.parent.ptr):
                    members |= {member for member in item.parent.members if member.realbounds.contains(item.realoffset)}
                    work |= {member.type for member in item.parent.members if isinstance(member.type, structure_t)}
                work |= {item.parent}
                members |= {item}

            # If all of our work is already in our results (parents), then exit our loop.
            if work & parents == work:
                break

            # Otherwise we merge it, reload the queue with our new work, and try..try...again.
            parents, queue = parents | work, work - parents

        # okay, now we can convert this set into a set of structures and members to look for
        candidates = { item.parent.id for item in members } | { item.id for item in members }

        # now figure out which operand has the structure member applied to it
        results = []
        for ea, _, t in refs:
            flags = address.flags(ea, idaapi.MS_0TYPE|idaapi.MS_1TYPE)
            listable = [(opnum, address.opinfo(ea, opnum)) for opnum, _ in enumerate(address.operands(ea)) if address.opinfo(ea, opnum)]

            # If we have any stack operands, then figure out which ones contain it. Fortunately,
            # we don't have to filter it through our candidates because IDA seems to get this right.
            if flags & FF_STKVAR in {FF_STKVAR, idaapi.FF_0STK, idaapi.FF_1STK}:
                logging.debug(u"{:s}.refs() : Found stkvar_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                masks = [(idaapi.MS_0TYPE, idaapi.FF_0STK), (idaapi.MS_1TYPE, idaapi.FF_1STK)]
                results.extend(interface.opref_t(ea, int(opnum), interface.reftype_t.of(t)) for opnum, (mask, ff) in enumerate(masks) if flags & mask == ff)

            # Otherwise, we can skip this reference because there's no way to process it.
            elif not listable:
                logging.debug(u"{:s}.refs() : Skipping reference to member ({:#x}) at {:#x} with flags ({:#x}) due to no operand information.".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))

            # If our flags mention a structure offset, then we can just get the structure path.
            elif flags & FF_STROFF in {FF_STROFF, idaapi.FF_0STRO, idaapi.FF_1STRO}:
                logging.debug(u"{:s}.refs() : Found strpath_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                iterable = [(opnum, {identifier for identifier in interface.node.get_stroff_path(ea, opnum)[1]}) for opnum, _ in listable]
                iterable = (opnum for opnum, identifiers in iterable if identifiers & candidates)
                results.extend(interface.opref_t(ea, int(opnum), interface.reftype_t.of(t)) for opnum in iterable)

            # Otherwise, we need to extract the information from the operand's refinfo_t. We
            # filter these by only taking the ones which we can use to calculate the target.
            else:
                logging.debug(u"{:s}.refs() : Found refinfo_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                iterable = ((opnum, info.ri, address.reference(ea, opnum)) for opnum, info in listable if info.ri.is_target_optional())

                # now we can do some math to determine if the operands really are pointing
                # to our structure member by checking that the operand value is in-bounds.
                left, right = interface.address.bounds()
                for opnum, ri, integer in iterable:
                    offset = interface.address.head(integer, silent=True)
                    if not (left <= offset < right): continue

                    # if our operand address wasn't valid, then we've bailed. so we just
                    # need to align the operand address to the head of the reference.
                    offset = interface.address.head(offset, silent=True)

                    # all that's left to do is verify that the structure is in our list of
                    # candidates that we collected earlier. although, we can totally do a
                    # better job here and calculate the boundaries of the exact member to
                    # confirm that the offset we resolved actually points at it.
                    if address.flags(offset, idaapi.DT_TYPE) == FF_STRUCT and address.structure(offset) in candidates:
                        results.append(interface.opref_t(ea, opnum, interface.reftype_t.of(t)))
                    continue
                continue
            continue
        return results

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
        mptr, sptr = self.ptr, self.parent.ptr
        return 0 if union(sptr) else mptr.soff
    @property
    def offset(self):
        '''Return the offset of the member.'''
        parent = self.parent
        return self.realoffset + parent.members.baseoffset
    @property
    def flag(self):
        '''Return the "flag" attribute of the member.'''
        res = self.ptr.flag
        return idaapi.as_uint32(res)
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
        return interface.bounds_t(0 if union(sptr) else mptr.soff, mptr.eoff)
    @property
    def bounds(self):
        '''Return the boundaries of the member.'''
        parent = self.parent
        bounds, base = self.realbounds, parent.members.baseoffset
        return operator.add(bounds, base)
    @property
    def parent(self):
        '''Return the structure_t that owns the member.'''
        return self.__parent__
    @property
    def dt_type(self):
        '''Return the `dt_type` attribute of the member.'''
        res = self.ptr.flag & idaapi.DT_TYPE
        return idaapi.as_uint32(res)
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
        if isinstance(string, types.ordered):
            string = interface.tuplename(*string)

        # Type safety is fucking valuable.
        if not isinstance(string, (types.none, types.string)):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).name({!r}) : Unable to assign the provided type ({!s}) as the name for the member.".format('.'.join([__name__, cls.__name__]), self.id, string, string.__class__))

        # If our string is empty, then we need to actually clear the name. This
        # is actually a little tricky because the default name for a field is
        # (field_%X) and two different ones for a frame (var_%X, arg_%X).
        if not string:
            sptr, mptr = self.parent.ptr, self.ptr

            # Define our name formatters that we will eventually use.
            fmtField = "field_{:X}".format
            fmtVar = "var_{:X}".format
            fmtArg = "arg_{:X}".format

            # If it's not a function frame, then this is easy as we can just
            # use mptr.soff to get the correct offset exactly.
            if not frame(sptr):
                result, self.name = self.name, fmtField(mptr.soff)
                return result

            # To process the frame, we first need the address of the function
            # to get the func_t and the actual member offset to calculate with.
            ea = idaapi.get_func_by_frame(sptr.id)
            if ea == idaapi.BADADDR:
                cls = self.__class__
                raise E.DisassemblerError(u"{:s}({:#x}).name({!s}) : Unable to get the function for the frame ({:#x}) containing the structure member.".format('.'.join([__name__, cls.__name__]), self.id, string, sptr.id))

            # We need to figure out all of the attributes we need in order to
            # calculate the position within a frame this includes the integer size.
            fn, moff = idaapi.get_func(ea), mptr.get_soff()
            if fn is None:
                cls = self.__class__
                raise E.FunctionNotFoundError(u"{:s}({:#x}).name({!s}) : Unable to get the function at the specified address ({:#x}) which owns the frame ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, string, ea, sptr.id))

            # Now we need to figure out whether where our member is. If it's
            # within the func_t.frsize, then we're a var_.
            if moff < fn.frsize:
                fmt, offset = fmtVar, fn.frsize - moff

            # If it's within func_t.frregs, then we're a special ' s' name.
            elif moff < idaapi.frame_off_retaddr(fn):
                fmt, offset = (lambda _: ' s'), None

            # If it's at the saved register, then we're a special ' r' name.
            elif moff < idaapi.frame_off_args(fn):
                fmt, offset = (lambda _: ' r'), None

            # Anything else should be an argument so we will use 'arg_'
            elif moff < idaapi.frame_off_args(fn) + fn.argsize:
                fmt, offset = fmtArg, moff - idaapi.frame_off_args(fn)

            # Anything else though...is a bug, it shouldn't happen unless IDA is not
            # actually populating the fields correctly (looking at you x64). So, lets
            # just be silently pedantic here.
            else:
                fmt, offset = fmtArg, moff - idaapi.frame_off_args(fn)
                cls, mdescr = self.__class__, "index ({:d})".format(mptr.soff) if union(sptr) else "offset ({:#x})".format(mptr.soff)
                logging.debug(u"{:s}({:#x}).name({!s}) : Treating the name for the member at {:s} as an argument due being located ({:#x}) outside of the frame ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, string, mdescr, moff, sum([idaapi.frame_off_args(fn), fn.argsize])))

            # Okay, now the last thing to do is to format our name and assign it..weeee, that was fun.
            result, self.name = self.name, fmt(offset)
            return result

        # for the sake of being pedantic here too, we check to see if this is a special
        # member, because if we touch it...it becomes non-special for some reason.
        if idaapi.is_special_member(self.id):
            cls, mdescr = self.__class__, "index ({:d})".format(mptr.soff) if union(sptr) else "offset ({:#x})".format(mptr.soff)
            logging.warning(u"{:s}({:#x}).name({!r}) : Modifying the name for the special member at {:s} will unfortunately demote its special properties.".format('.'.join([__name__, cls.__name__]), self.id, string, mdescr))

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.SN_IDBENC)
        if ida_string and ida_string != res:
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name({!r}) : Stripping invalid chars from structure member name (\"{:s}\") resulted in \"{:s}\".".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the member at the specified offset
        oldname = self.name
        if not idaapi.set_member_name(self.parent.ptr, self.offset - self.parent.members.baseoffset, ida_string):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).name({!r}) : Unable to assign the specified name ({:s}) to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.repr(ida_string), utils.string.repr(oldname)))

        # verify that the name was actually assigned properly
        assigned = idaapi.get_member_name(self.id) or ''
        if utils.string.of(assigned) != utils.string.of(ida_string):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).name({!r}) : The name ({:s}) that was assigned to the structure member does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, string, utils.string.repr(utils.string.of(assigned)), utils.string.repr(ida_string)))
        return oldname

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
        res = interface.typemap.dissolve(self.flag, self.typeid, self.size, offset=self.offset)
        if isinstance(res, structure_t):
            res = new(res.id, offset=self.offset)
        elif isinstance(res, types.tuple):
            iterable = (item for item in res)
            t = next(iterable)
            if isinstance(t, structure_t):
                t = new(t.id, offset=self.offset)
            elif isinstance(t, types.list) and isinstance(t[0], structure_t):
                t[0] = new(t[0].id, offset=self.offset)
            res = tuple(itertools.chain([t], iterable))
        return res
    @type.setter
    def type(self, type):
        '''Set the type of the member to the provided `type`.'''
        cls, set_member_tinfo = self.__class__, idaapi.set_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_member_tinfo

        # if we were given a tinfo_t or a string to use, then we pretty much use
        # it with the typeinfo api, but allow it the ability to destroy other members.
        if isinstance(type, (types.string, idaapi.tinfo_t)):
            info = type if isinstance(type, idaapi.tinfo_t) else internal.declaration.parse(type)
            if info is None:
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}).type({!s}) : Unable to parse the specified type declaration ({!s}) for structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr("{!s}".format(type)), utils.string.escape("{!s}".format(type), '"'), utils.string.repr(self.name)))

            res = set_member_tinfo(self.parent.ptr, self.ptr, self.ptr.soff, info, idaapi.SET_MEMTI_MAY_DESTROY)
            if res in {idaapi.SMT_OK, idaapi.SMT_KEEP}:
                return

            elif res == idaapi.SMT_FAILED:
                raise E.DisassemblerError(u"{:s}({:#x}).type({!s}) : Unable to assign the type information ({!s}) to structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr("{!s}".format(info)), utils.string.escape("{!s}".format(info), '"'), utils.string.repr(self.name)))

            errtable = {
                idaapi.SMT_BADARG: 'invalid parameters', idaapi.SMT_NOCOMPAT: 'incompatible type', idaapi.SMT_WORSE: 'worse type',
                idaapi.SMT_SIZE: 'invalid type for member size', idaapi.SMT_ARRAY: 'setting function argument as an array is illegal',
                idaapi.SMT_OVERLAP: 'the specified type would result in member overlap', idaapi.SMT_KEEP: 'the specified type is not ideal',
            }
            message = errtable.get(res, "unknown error {:#x}".format(res))
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the type information ({!s}) to structure member {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr("{!s}".format(info)), utils.string.escape("{!s}".format(info), '"'), utils.string.repr(self.name), message))

        # decompose the pythonic type into the actual information to apply.
        flag, typeid, nbytes = interface.typemap.resolve(type)

        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        if not idaapi.set_member_type(self.parent.ptr, self.offset - self.parent.members.baseoffset, flag, opinfo, nbytes):
            raise E.DisassemblerError(u"{:s}({:#x}).type({!s}) : Unable to assign the provided type ({!s}) to the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, type, type, utils.string.repr(self.name)))

        # verify that our type has been applied before we update its refinfo,
        # because if it hasn't then we need to warn the user about it so that
        # they know what's up and why didn't do what we were asked.
        expected, expected_tid = (flag, nbytes), typeid
        resulting, resulting_tid = (self.flag, self.size), self.typeid

        if expected == resulting:
            interface.address.update_refinfo(self.id, flag)
        else:
            logging.warning(u"{:s}({:#x}).type({!s}) : Applying the given flags and size ({:#x}, {:d}) resulted in different flags and size being assigned ({:#x}, {:d}).".format('.'.join([__name__, cls.__name__]), self.id, type, *itertools.chain(expected, resulting)))

        # smoke-test that we actually updated the type identifier and log it if it
        # didn't actually work. this is based on my ancient logic which assumed
        # that opinfo.tid should be BADADDR which isn't actually the truth when
        # you're working with a refinfo. hence we try to be quiet about it.
        if expected_tid != (resulting_tid or idaapi.BADADDR):
            logging.info(u"{:s}({:#x}).type({!s}) : The provided typeid ({:#x}) was incorrectly assigned as {:#x}.".format('.'.join([__name__, cls.__name__]), self.id, type, expected_tid, resulting_tid or idaapi.BADADDR))

        # return the stuff that actually applied.
        flag, size = resulting
        return flag, resulting_tid, size

    @property
    def typeinfo(self):
        '''Return the type information of the current member.'''
        ti = idaapi.tinfo_t()

        # Guess the typeinfo for the current member. If we're unable to get the
        # typeinfo then we just raise whatever we have. Let IDA figure it out.
        ok = idaapi.get_or_guess_member_tinfo2(self.ptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, self.ptr)
        if not ok:
            cls = self.__class__
            logging.debug(u"{:s}({:#x}).typeinfo : Returning the guessed type that was determined for member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, self.name))
        return ti
    @typeinfo.setter
    def typeinfo(self, info):
        '''Set the type information of the current member to `info`.'''
        get_member_tinfo = idaapi.get_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.get_member_tinfo
        set_member_tinfo = idaapi.set_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_member_tinfo
        tinfo_equals_to = idaapi.equal_types if idaapi.__version__ < 6.8 else lambda til, t1, t2: t1.equals_to(t2)

        # Type safety is fucking valuable, and anything that doesn't match gives you an exception.
        if not isinstance(info, (idaapi.tinfo_t, types.none, types.string)):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the provided type ({!s}) to the type information for the member.".format('.'.join([__name__, cls.__name__]), self.id, info if info is None else utils.string.repr(info), info.__class__))

        # If we're being asked to assign None to the type information, then we need to remove it.
        if not info and hasattr(idaapi, 'del_member_tinfo') and idaapi.del_member_tinfo(self.parent.ptr, self.ptr):
            return

        # Otherwise the best we can do is to re-assign an empty type to clear it.
        elif not info:
            ti = idaapi.tinfo_t()

            # Create an unknown type...since it's the best we can do without the api.
            if not ti.create_simple_type(idaapi.BTF_UNK):
                logging.warning(u"{:s}({:#x}).typeinfo({!s}) : Unable to create an unknown ({:s}) type to assign to structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, info if info is None else utils.string.repr(info), 'BTF_UNK', utils.string.repr(self.name)))
            info_description = "{!s}".format(info)

        # Otherwise if it's a string, then we'll need to parse our info parameter into a
        # tinfo_t, so that we can assign it to the typeinfo for the member.
        elif isinstance(info, types.string):
            ti = internal.declaration.parse(info)
            if ti is None:
                cls = self.__class__
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo({!s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), self.id, info if info is None else utils.string.repr(info), utils.string.repr(info)))
            info_description = utils.string.repr(info)

        # If it's a tinfo_t, then we can just use it as-is.
        elif isinstance(info, idaapi.tinfo_t):
            ti, info_description = info, utils.string.repr("{!s}".format(info))

        # We have no idea what kind of type this is, so we need to bitch and complain about it.
        else:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign an unsupported type ({!s}) ot type type information for the member.".format('.'.join([__name__, cls.__name__]), self.id, info if info is None else utils.string.repr(info), info.__class__()))

        # We want to detect type changes, so we need to get the previous type information of
        # the member so that we can distinguish between an actual SMT_KEEP error or an error
        # that occurred because the previous member type is the same as the new requested type.
        prevti = idaapi.tinfo_t()
        if not get_member_tinfo(prevti, self.ptr):
            cls = self.__class__
            logging.info(u"{:s}({:#x}).typeinfo({!s}) : Unable to get the previous type information for the structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, info_description, utils.string.repr(self.name)))

        # Now we can pass our tinfo_t along with the member information to the api.
        res = set_member_tinfo(self.parent.ptr, self.ptr, self.ptr.soff, ti, idaapi.SET_MEMTI_COMPATIBLE)

        # If we got an SMT_OK or we received SMT_KEEP with the previous member type and new
        # member type being the same, then this request was successful and we can return.
        if res == idaapi.SMT_OK or res == idaapi.SMT_KEEP and tinfo_equals_to(idaapi.get_idati(), ti, prevti):
            return

        # We failed, so just raise an exception for the user to handle.
        elif res == idaapi.SMT_FAILED:
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the provided type information to structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, info_description, utils.string.repr(self.name)))

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
        raise E.DisassemblerError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the provided type information to structure member {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), self.id, info_description, utils.string.repr(self.name), message))

    ### Private methods
    def __str__(self):
        '''Render the current member in a readable format.'''
        id, name, typ, comment, tag, typeinfo = self.id, self.fullname, self.type, self.comment or '', self.tag(), "{!s}".format(self.typeinfo.dstr()).replace(' *', '*')
        return "<member '{:s}' index={:d} offset={:-#x} size={:+#x}{:s}>{:s}".format(utils.string.escape(name, '\''), self.index, self.offset, self.size, " typeinfo='{:s}'".format(typeinfo) if typeinfo else '', " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __unicode__(self):
        '''Render the current member in a readable format.'''
        id, name, typ, comment, tag, typeinfo = self.id, self.fullname, self.type, self.comment or '', self.tag(), "{!s}".format(self.typeinfo.dstr()).replace(' *', '*')
        return u"<member '{:s}' index={:d} offset={:-#x} size={:+#x}{:s}>{:s}".format(utils.string.escape(name, '\''), self.index, self.offset, self.size, " typeinfo='{:s}'".format(typeinfo) if typeinfo else '', " // {!s}".format(utils.string.repr(tag) if '\n' in comment else utils.string.to(comment)) if comment else '')

    def __repr__(self):
        return u"{!s}".format(self)

    ## Hashable
    def __hash__(self):
        return self.ptr.id
    def __ne__(self, other):
        return not self.__eq__(other)
    def __eq__(self, other):
        if isinstance(other, idaapi.member_t):
            return self.ptr.id == other.id
        elif isinstance(other, member_t):
            return self.ptr.id == other.ptr.id
        return False

    ## Serialization
    def __getstate__(self):
        parentbase = self.__parent__.members.baseoffset

        # Grab the member information and unpack it so we can serialize its state.
        packed_result = idaapi.get_member_by_id(self.ptr.id)
        if packed_result:
            mptr, fullname, sptr = packed_result

        # If we couldn't get the member tuple, then this is a "lost field" as per
        # the disassembler's naming. So, we need a dummy member of some kind for it.
        else:
            Fnetnode = getattr(idaapi, 'ea2node', utils.fidentity)
            Flost_field_name, Ftry_name = "lost_field_name_{:x}".format, lambda id: internal.netnode.name.get(Fnetnode(id))
            sptr = self.__parent__.ptr
            mptr = sptr.get_member(self.__index__)

            # Get any member attributes that we're able to. we don't have any typeinfo
            # to serialize, but we still need tinfo_t.deserialize to fail successfully.
            comments = tuple(utils.string.of(idaapi.get_member_cmt(mptr.id, item)) for item in [True, False])
            msize = idaapi.get_member_size(mptr)
            ty = mptr.flag, idaapi.BADADDR, msize
            typeinfo = ty, (b'', b'')

            # The disassembler uses the prefix "lost_field_name_" for the member name,
            # but since the type is lost there really isn't any other attributes that
            # are relevant other than comments. Instead of using the "lost_field_name_"
            # prefix, we use an empty string. This way, during deserialization we can
            # explicitly check for it and then modify the name using the netnode api.
            mname = Ftry_name(mptr.id) or u''

            # Pack together our parent intermation and member state so that we can
            # return everything that we grabbed.
            parent = Ftry_name(sptr.id), sptr.props, parentbase
            state = mptr.props, mptr.soff, typeinfo, mname, comments
            return parent, self.__index__, state

        # grab its typeinfo and serialize it
        tid = self.typeid
        tid = None if tid is None else new(tid, self.offset) if has(tid) else tid
        flag, size = mptr.flag, idaapi.get_member_size(mptr)
        ty = mptr.flag, tid, size

        # if the user applied some type information to the member, then we make sure
        # to serialize it (print_tinfo) so we can parse it back into the member.
        ti = self.typeinfo
        if '__typeinfo__' in self.tag():
            res = idaapi.PRTYPE_1LINE | idaapi.PRTYPE_SEMI | idaapi.PRTYPE_NOARRS | idaapi.PRTYPE_RESTORE
            tname = idaapi.print_tinfo('', 0, 0, res, ti, '', '')
            tinfo = idaapi.print_tinfo('', 0, 0, res | idaapi.PRTYPE_DEF, ti, tname, '')

            # use a list so we can differentiate older version from newer
            typeinfo = ty, [tname, tinfo]

        # otherwise, we serialize the type into the older version. this shouldn't
        # get applied because there's a chance the type doesn't exist.
        else:
            typeinfo = ty, ti.serialize()

        # grab its comments
        cmtt = idaapi.get_member_cmt(mptr.id, True)
        cmtf = idaapi.get_member_cmt(mptr.id, False)
        comments = tuple(utils.string.of(cmt) for cmt in [cmtt, cmtf])

        # grab its parent name along with its name, and then we can
        # pack the information about its parent into a tuple.
        pname, name = fullname.split('.', 1)
        parent = pname, sptr.props, parentbase

        # pack up our state
        state = mptr.props, mptr.soff, typeinfo, name, comments

        # combine parent state with our location (index) and state
        return parent, self.__index__, state
    def __setstate__(self, state):
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # Restore all the attributes we need to deserialize.
        if len(state) == 3:
            parent, index, state = state
            parentname, parentprops, parentbase = parent
            props, soff, typeinfo, name, (cmtt, cmtf) = state

        # In order to remain backwards compatible...
        else:
            parentname, index, name, (cmtt, cmtf), soff, typeinfo = state
            parentprops = props = 0
            parentbase = 0
        cls, fullname = self.__class__, '.'.join([parentname, name])

        # get the structure owning the member by the name we stored
        # creating it if necessary.
        res = utils.string.to(parentname)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            logging.info(u"{:s}({:#x}, index={:d}) : Creating structure ({:s}) for member named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, index, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, res, True if parentprops & idaapi.SF_UNION else False)

        if identifier == idaapi.BADADDR:
            raise E.DisassemblerError(u"{:s}({:#x}, {:s}) : Unable to get structure ({:s}) for member named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, index, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))

        # now we can get our structure and run with it
        sptr = idaapi.get_struc(identifier)
        count = sptr.memqty

        # extract the type information of the member so that we can
        # construct the opinfo_t and later apply the tinfo_t.
        t, ti = typeinfo
        flag, mytype, nbytes = t

        opinfo = idaapi.opinfo_t()
        if mytype is None:
            if flag & idaapi.DT_TYPE == FF_STRUCT:
                logging.warning(u"{:s}({:#x}, index={:d}): Unexpected DT_TYPE was found in flags ({:#x}) for the untyped member \"{:s}\" of structure ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, flag, utils.string.escape(name, '"'), parentname))

        # if we have an integer or a structure_t, then assign it as the identifier for the opinfo.
        else:
            opinfo.tid = mytype if isinstance(mytype, types.integer) else mytype.id

        # add the member to the database if the name exists, and then check whether
        # there was a naming issue of some sort so that we can warn the user or resolve it.
        res = utils.string.to(name)
        if res:
            mem = idaapi.add_struc_member(sptr, res, 0 if sptr.props & idaapi.SF_UNION else soff, flag, opinfo, nbytes)

        # now for a trick. since the member name doesn't exist and we need the disassembler to
        # display the name prefixed with "lost_field_name_", we create the member with a placeholder
        # based on the offset. iff we succeed, then we modify the member name using a netnode.
        else:
            Fgenerate_unique_name = lambda recurse, sptr, aggro=u'': (lambda unique_name: unique_name if not idaapi.get_member_by_name(sptr, unique_name) else recurse(recurse, sptr, aggro + u'_'))(unique_name=''.join([u"_{:x}".format(sptr.id), aggro]))
            unique = Fgenerate_unique_name(Fgenerate_unique_name, sptr)
            mem = idaapi.add_struc_member(sptr, unique, 0 if sptr.props & idaapi.SF_UNION else soff, flag, opinfo, nbytes)

            # If that was successful, then we just need to get our id and then we can rename it. If
            # renaming it resulted in an error, then we bail with a fabricated error code which should
            # be okay because we handle any error that's not equal to STRUC_ERROR_MEMBER_OK below.
            if mem == idaapi.STRUC_ERROR_MEMBER_OK:
                F, mptr = getattr(idaapi, 'ea2node', utils.fidentity), idaapi.get_member(sptr, soff)
                mem = idaapi.STRUC_ERROR_MEMBER_OK if internal.netnode.name.set(mptr.id, res) else -idaapi.BADADDR

        # FIXME: handle these naming errors properly
        # duplicate name
        if mem == idaapi.STRUC_ERROR_MEMBER_NAME:
            mptr = idaapi.get_member_by_name(sptr, res)
            if mptr and mptr.soff != soff:
                newname = u"{:s}_{:x}".format(res, soff)
                logging.warning(u"{:s}({:#x}, index={:d}): Duplicate name found for member \"{:s}\" of structure ({:s}), renaming it to \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(name, '"'), parentname, utils.string.escape(newname, '"')))
                idaapi.set_member_name(sptr, soff, utils.string.to(newname))

            elif mptr:
                logging.info(u"{:s}({:#x}, index={:d}): Ignoring field at index {:d} of structure ({:s}) with the same name (\"{:s}\") and position ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, index, parentname, utils.string.escape(name, '"'), soff))

            else:
                logging.warning(u"{:s}({:#x}, index={:d}): Field at index {:d} of structure ({:s}) could not be found using its expected name (\"{:s}\").".format('.'.join([__name__, cls.__name__]), sptr.id, index, index, parentname, utils.string.escape(name, '"')))

        # duplicate field (same offset)
        elif mem == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            mptr = idaapi.get_member(sptr, soff)
            if (utils.string.of(idaapi.get_member_name(mptr.id)), mptr.flag, idaapi.get_member_size(mptr)) != (res, flag, nbytes):
                logging.warning(u"{:s}({:#x}, index={:d}): Already existing field found at offset {:+#x} of structure ({:s}), overwriting it with \"{:s}\" of size ({:#x}) and flags ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, soff, parentname, utils.string.escape(name, '"'), nbytes, flag))
                idaapi.set_member_type(sptr, soff, flag, opinfo, nbytes)
                idaapi.set_member_name(sptr, soff, res)

        # unknown
        elif mem != idaapi.STRUC_ERROR_MEMBER_OK:
            errors = {getattr(idaapi, name): name for name in dir(idaapi) if name.startswith('STRUC_ERROR_')}
            logging.warning(u"{:s}({:#x}, index={:d}): Error {:s} returned while trying to create member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, "{:s}({:#x})".format(errors[mem], mem) if mem in errors else "code ({:#x})".format(mem), utils.string.escape(fullname, '"')))

        # check the index and count, as we've already added it properly (STRUC_ERROR_MEMBER_OK)
        elif index != count:
            logging.warning(u"{:s}({:#x}, index={:d}): The member that was created (\"{:s}\") was expected at index {:d} but was created at index {:d}.".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), index, count))
            index = count

        # now that we know our parent exists and the member has been added
        # we can use the soff to grab the the member's mptr.
        mptr = idaapi.get_member(sptr, soff)
        parent = new(sptr.id, offset=parentbase)
        self.__parent__, self.__index__ = parent, index

        # update both of the member's comments prior to fixing its type.
        idaapi.set_member_cmt(mptr, utils.string.to(cmtt), True)
        idaapi.set_member_cmt(mptr, utils.string.to(cmtf), False)

        # if we're using the new tinfo version (a list), then try our hardest
        # to parse it. if we succeed, then we likely can apply it later.
        if isinstance(ti, types.list) and len(ti) == 2:
            tname, tinfo = ti
            typeinfo = internal.declaration.parse(tname) if tname else None
            typeinfo = typeinfo if typeinfo else internal.declaration.parse(tinfo)
            None if typeinfo is None else logging.info(u"{:s}({:#x}, index={:d}): Successfully parsed type information for member \"{:s}\" as \"{!s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), typeinfo))

        # otherwise it's the old version (a tuple), and it shouldn't need to
        # exist... but, if we can actually deserialize it then later we can
        # likely apply it...unless it has an ordinal.
        else:
            typeinfo = idaapi.tinfo_t()
            if typeinfo.deserialize(None, *ti):
                logging.info(u"{:s}({:#x}, index={:d}): Successfully deserialized type information for member \"{:s}\" as \"{!s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), typeinfo))
            else:
                logging.info(u"{:s}({:#x}, index={:d}): Skipping application of corrupted type information ({!r}) for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, ti, utils.string.escape(fullname, '"')))
                typeinfo = None

        # if tinfo was defined and it doesn't use an ordinal, then we can apply it.
        # FIXME: we are likely going to need to traverse this to determine if it's using an ordinal or not
        if typeinfo and not any([typeinfo.get_ordinal(), typeinfo.is_array() and typeinfo.get_array_element().get_ordinal()]):
            try:
                self.typeinfo = typeinfo

            # if the type is not ideal, then we can pretty much ignore this because
            # the type is already there and IDA thinks that it's okay.
            except E.DisassemblerError as exc:
                if 'type is not ideal' in "{!s}".format(exc):
                    logging.info(u"{:s}({:#x}, index={:d}): The disassembler refused to apply the type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))
                    logging.debug(u"{!s}".format(exc))

                # otherwise, we need to warn the user about what happened.
                else:
                    logging.warning(u"{:s}({:#x}, index={:d}): The disassembler was unable to apply the type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))
                    logging.warning(u"{!s}".format(exc))

            # we're good, it was applied.
            else:
                logging.info(u"{:s}({:#x}, index={:d}): Applied the type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))

        # otherwise, we had type information that was an ordinal which might not
        # exist in our database...so we ask IDA to make a guess at what it is.
        elif typeinfo:
            ti = idaapi.tinfo_t()
            ok = idaapi.get_or_guess_member_tinfo2(mptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, mptr)
            try:
                if ok:
                    self.typeinfo = ti

            # if the type was not ideal, then this can be ignored because IDA
            # really knows best, and if it says we're wrong..then we're wrong.
            except E.DisassemblerError as exc:
                if 'type is not ideal' in "{!s}".format(exc):
                    logging.info(u"{:s}({:#x}, index={:d}): The disassembler refused to apply the guessed type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))
                    logging.debug(u"{!s}".format(exc))

                else:
                    logging.warning(u"{:s}({:#x}, index={:d}): The disassembler was unable to apply the guesed type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))
                    logging.warning(u"{!s}".format(exc))

            # if we applied it, then we're good.
            else:
                ok and logging.info(u"{:s}({:#x}, index={:d}): Applied the type information \"{!s}\" to the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"')))
        return

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

        `name` - Filter the structure members by a name or a list of names
        `offset` - Match the structure member by its offset
        `like` - Filter the structure members according to a glob
        `regex` - Filter the structure members according to a regular-expression
        `index` - Filter the structure members by an index or a list of indices
        `fullname` - Filter the structure members by matching its full name according to a glob
        `comment` or `comments` - Filter the structure members by applying a glob to its comment
        `identifier` or `id` - Filter the structure members by an identifier or a list of identifiers
        `bounds` - Match the structure members that overlap with the given boundaries
        `location` - Match the structure members that overlap with the specified location
        `within` - Filter the structure members within the given boundaries
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
    @utils.multicase(string=(types.string, types.ordered))
    @utils.string.decorate_arguments('string', 'suffix')
    def iterate(self, string, *suffix):
        '''Iterate through all of the members in the structure with a name that matches the glob in `string`.'''
        res = string if isinstance(string, types.ordered) else (string,)
        return self.iterate(like=interface.tuplename(*itertools.chain(res, suffix)))
    @utils.multicase(bounds=interface.bounds_t)
    def iterate(self, bounds):
        '''Iterate through all of the members of the structure that overlap the given `bounds`.'''
        return self.iterate(predicate=operator.truth, bounds=bounds)
    @utils.multicase(location=interface.location_t)
    def iterate(self, location):
        '''Iterate through all of the members of the structure that overlap the given `location`.'''
        return self.iterate(predicate=operator.truth, location=location)

    @utils.multicase(string=(types.string, types.ordered))
    @utils.string.decorate_arguments('string', 'suffix')
    def list(self, string, *suffix):
        '''List any members that match the glob in `string`.'''
        res = string if isinstance(string, types.ordered) else (string,)
        return self.list(like=interface.tuplename(*itertools.chain(res, suffix)))
    @utils.multicase(bounds=interface.bounds_t)
    def list(self, bounds):
        '''List any members that overlap the given `bounds`.'''
        return self.list(predicate=operator.truth, bounds=bounds)
    @utils.multicase(location=interface.location_t)
    def list(self, location):
        '''List any members that overlap the specified `location`.'''
        return self.list(predicate=operator.truth, location=location)
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
    @utils.multicase(name=types.string)
    @utils.string.decorate_arguments('name', 'suffix')
    def by(self, name, *suffix):
        '''Return the member with the specified `name`.'''
        return self.by_name(name, *suffix)
    @utils.multicase(offset=types.integer)
    def by(self, offset):
        '''Return the member at the specified `offset`.'''
        return self.by_offset(offset)
    @utils.multicase(location=interface.location_t)
    def by(self, location):
        '''Return the member at the specified `location`.'''
        offset, size = location
        if isinstance(offset, interface.symbol_t):
            offset, = (int(item) for item in offset)
        member = self.by_offset(offset)
        if (offset, size) != (member.offset, member.size):
            cls = self.__class__
            message = "is a different size ({:d}) than requested".format(size) if member.offset == offset else "is not at the exact offset ({:#x}) as requested".format(offset)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by({!s}) : The member ({:s}) at the given location ({:#x}<->{:#x}) {:s}.".format('.'.join([__name__, cls.__name__]), self.owner.ptr.id, location, member.name, member.left, member.right, message))
        return member

    @utils.multicase(name=(types.string, types.ordered))
    @utils.string.decorate_arguments('name', 'suffix')
    def has(self, name, *suffix):
        '''Return whether a member with the specified `name` exists.'''
        if not suffix and isinstance(name, interface.location_t): return self.has(location=name)
        string = name if isinstance(name, types.ordered) else (name,)
        owner, res = self.owner, utils.string.to(interface.tuplename(*itertools.chain(string, suffix)))
        return idaapi.get_member_by_name(owner.ptr, res) is not None
    @utils.multicase(location=interface.location_t)
    def has(self, location):
        '''Return whether a member exists at the specified `location`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize

        # First unpack the location to convert both its components to integers.
        offset, size = location
        if isinstance(offset, interface.symbol_t):
            [offset] = (int(item) for item in offset.symbols)

        # Then we need to figure out the realoffset of the entire structure.
        sptr, realoffset, realsize = self.owner.ptr, offset - self.baseoffset, size
        size, unionQ = idaapi.get_struc_size(sptr), union(sptr)

        # If we're using a variable-length structure, then we'll need
        # to check the last member if none of the others matched.
        variable = sptr.props & idaapi.SF_VAR and 0 <= realoffset and size <= realoffset

        # Otherwise, we start by checking that the offset is within bounds.
        if not any([0 <= realoffset < size, variable]):
            return False

        # Now we just iterate through all our members to find a match.
        ok = False
        for midx in range(sptr.memqty):
            opinfo, mptr = idaapi.opinfo_t(), sptr.get_member(midx)
            mleft, mright, msize = 0 if unionQ else mptr.soff, mptr.eoff, idaapi.get_member_size(mptr)

            # Get any information about the member and use it to get the size of the type.
            retrieved = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            mrealsize = get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None)

            # If we're a variable-length structure and the member has no size, then we
            # need to check if the location is a multiple of the member location.
            if all([variable, mleft == mright, mleft <= realoffset, mrealsize, realsize % mrealsize == 0]):
                index, remainder = divmod(realoffset - mleft, mrealsize)
                ok = ok if remainder else True

            # Otherwise, we can simply check if the whole element matches.
            elif all([msize, realoffset == mleft, realsize == msize]):
                ok = ok or all([msize, realoffset == mleft, realsize == msize])

            # Or we check to see if the member is an array and we match any number of elements.
            elif all([mrealsize, mrealsize != msize, realsize < msize, realsize % mrealsize == 0]):
                index, remainder = divmod(realoffset - mleft, mrealsize)
                ok = ok if remainder else True
            continue
        return ok
    @utils.multicase(offset=types.integer)
    def has(self, offset):
        '''Return whether a member exists at the specified `offset`.'''
        owner = self.owner
        base, size, unionQ = self.baseoffset, idaapi.get_struc_size(owner.ptr), union(owner.ptr)

        # Calculate the realoffset so that we can verify the offset is within some valid boundaries.
        realoffset = offset - base

        # If we're a variable-length structure, then our bounds are technically from 0 to infinity.
        if owner.ptr.props & idaapi.SF_VAR and 0 <= realoffset and size <= realoffset:
            pass

        # Otherwise, we can check that the offset is within our valid boundaries.
        elif not (0 <= realoffset < size):
            return False

        # Iterate through all of our members and figure out which one contains us.
        for member in self.__iterate__():
            mptr = member.ptr
            mleft, mright = 0 if unionQ else mptr.soff, mptr.eoff

            # If our member has no size and we're using a variable-length structure,
            # then the realoffset is "within" the member if it comes after it.
            if owner.ptr.props & idaapi.SF_VAR and mleft == mright and mleft <= realoffset:
                return True

            # Otherwise, we just check its boundaries like normal.
            elif mleft <= realoffset < mright:
                return True
            continue
        return False
    @utils.multicase(start=types.integer, end=types.integer)
    def has(self, start, end):
        '''Return whether any members exist from the offset `start` to the offset `end`.'''
        owner = self.owner
        base, size, unionQ = self.baseoffset, idaapi.get_struc_size(owner.ptr), union(owner.ptr)

        # We mostly copy the member_t.has(int) implementation.
        left, right = map(functools.partial(operator.add, -base), sorted([start, end]))

        # If we're a variable-length structure, then our bounds are technically from 0 to infinity.
        if owner.ptr.props & idaapi.SF_VAR and 0 <= realoffset and size <= realoffset:
            pass

        # Iterate through all of our members and figure out which one contains us.
        for member in self.__iterate__():
            mptr = member.ptr
            mleft, mright = 0 if unionQ else mptr.soff, mptr.eoff

            # If our member has no size and we're using a variable-length structure,
            # then the realoffset is "within" the member if it comes after it.
            if owner.ptr.props & idaapi.SF_VAR and mleft == mright and mleft <= left:
                return True

            # Otherwise, check if the segment overlaps with the member.
            elif left < mright and right > mleft:
                return True
            continue
        return False
    @utils.multicase(bounds=interface.bounds_t)
    def has(self, bounds):
        '''Return whether any members exist within the specified `bounds`.'''
        start, stop = sorted(bounds)
        return self.has(start, stop)

    @utils.string.decorate_arguments('name', 'suffix')
    def by_name(self, name, *suffix):
        '''Return the member with the specified `name`.'''
        string = name if isinstance(name, types.ordered) else (name,)
        res = utils.string.to(interface.tuplename(*itertools.chain(string, suffix)))
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

    @utils.string.decorate_arguments('fullname', 'suffix')
    def by_fullname(self, fullname, *suffix):
        '''Return the member with the specified `fullname`.'''
        string = fullname if isinstance(fullname, types.ordered) else (fullname,)
        res = utils.string.to(interface.tuplename(*itertools.chain(string, suffix)))
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
        cls, owner = self.__class__, self.owner

        # Chain to the realoffset implementation.. This is just a wrapper.
        try:
            result = self.by_realoffset(offset - self.baseoffset)

        # Pivot any expected exceptions so that we can output the parameter the user gave us.
        except (E.MemberNotFoundError, E.OutOfBoundsError):
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_offset({:+#x}) : Unable to locate a member at the specified offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset))
        return result
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
        items, unionQ = [], union(owner.ptr)
        for mptr in self.__members_at__(offset):
            mleft, mright = 0 if unionQ else mptr.soff, mptr.eoff

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
                realoffset = offset - (0 if unionQ else mptr.soff)

                # First we need to check to see if it's an array, because this
                # might actually be an array of structures which we'll need to
                # check the requested offset against.
                if isinstance(res, types.list):
                    type, length = res

                    # If we received a tuple, then we can extract the member size
                    # directly to see if it aligns properly.
                    if isinstance(type, types.tuple):
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
                elif isinstance(res, structure_t) and union(res.ptr):
                    selected.append(mptr) if realoffset else selected.insert(0, mptr)

                # Finally, check if it's a structure and our real offset points
                # directly to a particular member. If it does, then this is
                # a legitimate candidate.
                elif isinstance(res, structure_t):
                    mem = idaapi.get_member(res.ptr, realoffset)
                    selected.append(mptr) if mem and realoffset - mem.soff else selected.insert(0, mptr)

                # If it's a tuple, then this only matches if we're pointing
                # directly to the member.
                elif isinstance(res, types.tuple):
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
            messages = (u"[{:d}] {:s} {:#x}{:+#x}".format(1 + i, fullname, 0 if unionQ else mptr.soff, mptr.eoff) for i, (mptr, fullname) in enumerate(iterable))
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

        # unpack the sptr, name, and mptr out of the result. if the sptr doesn't
        # exist, then use the member's fullname to find the correct sptr.
        mptr, fullname, sptr = res
        if not interface.node.identifier(sptr.id):
            sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

        # search through our list of members for the specified member
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
    @utils.multicase(name=(types.string, types.ordered))
    @utils.string.decorate_arguments('name')
    def add(self, name):
        '''Append the specified member `name` with the default type to the end of the structure.'''
        return self.add(name, int)
    @utils.multicase(name=(types.string, types.ordered))
    @utils.string.decorate_arguments('name')
    def add(self, name, type):
        '''Append the specified member `name` with the given `type` to the end of the structure.'''
        owner = self.owner

        # If this structure is a union, then the offset should always be 0.
        # This means that when translated to our baseoffset, will always
        # result in the baseoffset itself.
        if union(owner.ptr):
            return self.add(name, type, self.baseoffset)

        # Otherwise, it's not a union and so we'll just calculate
        # the offset to add the member at, and proceed as asked.
        offset = owner.size + self.baseoffset
        return self.add(name, type, offset)
    @utils.multicase(name=(types.string, types.ordered), offset=types.integer)
    @utils.string.decorate_arguments('name')
    def add(self, name, type, offset):
        '''Add a member at the specified `offset` of the structure with the given `name` and `type`.'''
        owner, set_member_tinfo = self.owner, idaapi.set_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_member_tinfo

        # Figure out whether we're adding a pythonic type or we were given a tinfo_t.
        # If we were given a tinfo_t, then use the size of the type as a placeholder.
        res = internal.declaration.parse(type) if isinstance(type, types.string) else type
        type, tinfo, tdescr = ([None, res.get_size()], res, "{!s}".format(res)) if isinstance(res, idaapi.tinfo_t) else (res, None, "{!s}".format(res))
        flag, typeid, nbytes = interface.typemap.resolve(type if tinfo is None or 0 < tinfo.get_size() < idaapi.BADSIZE else None)

        # If the member is being added to a union, then the offset doesn't
        # matter because it's always zero. We need to check this however because
        # we're aiming to be an "intuitive" piece of software.
        if union(owner.ptr):

            # If the offset is zero, then maybe the user does know what they're
            # doing, but they don't know that they need to use the base offset.
            if offset == 0:
                pass

            # If the user really is trying to add a member with a non-zero offset
            # to our union, then we need to warn the user so that they know not
            # to do it again in the future.
            elif offset != self.baseoffset:
                cls = self.__class__
                logging.warning(u"{:s}({:#x}).members.add({!r}, {!r}, {:+#x}) : Corrected the invalid offset ({:#x}) being used when adding member ({!s}) to union \"{:s}\", and changed it to {:+#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, offset, interface.tuplename(*name) if isinstance(name, types.ordered) else name, owner.name, self.baseoffset))

            # Now we can actually correct the offset they gave us.
            offset = self.baseoffset

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        index, realoffset = owner.ptr.memqty, offset - self.baseoffset

        # If we were given a tuple, then we need to pack it into a string and check
        # to see that it's valid before we use it.
        packedname = interface.tuplename(*name) if isinstance(name, types.ordered) else name or ''
        if packedname:
            name = packedname

        # If the name isn't valid (empty, then we figure out the default name using
        # the disassembler's regular prefix with the field's offset as the suffix.
        # FIXME: we should support default frame member names too...but we don't.
        else:
            cls, res = self.__class__, interface.tuplename('field', index if union(owner.ptr) else realoffset)
            logging.warning(u"{:s}({:#x}).members.add({!r}, {!r}, {:+#x}) : Name is undefined, defaulting to {:s} name \"{:s}\".".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, 'union' if union(sptr) else 'structure', utils.string.escape(res, '"')))
            name = res

        # Finally we can use IDAPython to add the structure member with the
        # parameters that we either figured out or were given.
        res = idaapi.add_struc_member(owner.ptr, utils.string.to(name), realoffset, flag, opinfo, nbytes)

        # If we received a failure error code, then we convert the error code to
        # an error message so that we can raise an exception that actually means
        # something and enables the user to correct it.
        if res != idaapi.STRUC_ERROR_MEMBER_OK:
            error = {
                idaapi.STRUC_ERROR_MEMBER_NAME : 'Duplicate field name',
                idaapi.STRUC_ERROR_MEMBER_OFFSET : 'Invalid offset',
                idaapi.STRUC_ERROR_MEMBER_SIZE : 'Invalid size',
            }
            e = E.DuplicateItemError if res == idaapi.STRUC_ERROR_MEMBER_NAME else E.DisassemblerError
            callee = u"{:s}(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})".format(utils.pycompat.fullname(idaapi.add_struc_member), utils.string.escape(owner.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes)
            cls = self.__class__
            raise e(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `{:s}` returned {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, callee, error.get(res, u"error code {:#x}".format(res))))

        # Now we need to return the newly created member to the caller. Since
        # all we get is an error code from IDAPython's api, we try and fetch the
        # member that was just added by the offset it's supposed to be at.
        mptr = idaapi.get_member(owner.ptr, index if union(owner.ptr) else realoffset)
        if mptr is None:
            cls, where = self.__class__, "index {:d}".format(index) if union(owner.ptr) else "offset {:#x}{:+#x}".format(realoffset, nbytes)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Unable to locate recently created member \"{:s}\" at {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, utils.string.escape(name, '"'), where))

        # If we were given a tinfo_t for the type, then we need to apply it to
        # the newly-created member. Our size should already be correct, so we
        # can just apply the typeinfo in a non-destructive (compatible) manner.
        res = idaapi.SMT_OK if tinfo is None else set_member_tinfo(owner.ptr, mptr, mptr.soff, tinfo, idaapi.SET_MEMTI_COMPATIBLE)

        # If we couldn't apply the tinfo_t, then we need to bail. We can't remove
        # the already-created field, so instead we log a critical error since the
        # size should pretty much be exactly what they wanted.
        if res == idaapi.SMT_FAILED:
            logging.fatal(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The type information (\"{:s}\") for structure member \"{:s}\" could not be completely applied.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, utils.string.escape(tdescr, '"'), utils.string.escape(name, '"')))

        elif res not in {idaapi.SMT_OK, idaapi.SMT_KEEP}:
            errtable = {
                idaapi.SMT_BADARG: 'an invalid parameter', idaapi.SMT_NOCOMPAT: 'the type being incompatible', idaapi.SMT_WORSE: 'the type being terrible',
                idaapi.SMT_SIZE: 'the type being invalid for the member size', idaapi.SMT_ARRAY: 'setting a function argument as an array being illegal',
                idaapi.SMT_OVERLAP: 'the specified type would result in an overlapping member', idaapi.SMT_KEEP: 'the specified type not being ideal',
            }
            message = errtable.get(res, "an unknown error {:#x}".format(res))
            logging.fatal(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The type information (\"{:s}\") for structure member \"{:s}\" could not be completely applied due to {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, utils.string.escape(tdescr, '"'), utils.string.escape(name, '"')))

        # We can now log our small success and update the member's refinfo if it
        # was actually necessary.
        cls, refcount = self.__class__, interface.address.update_refinfo(mptr.id, flag)
        logging.debug(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : The api call to `{:s}(sptr=\"{:s}\", fieldname=\"{:s}\", offset={:+#x}, flag={:#x}, mt={:#x}, nbytes={:#x})` returned success{:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, utils.pycompat.fullname(idaapi.add_struc_member), utils.string.escape(owner.name, '"'), utils.string.escape(name, '"'), realoffset, flag, typeid, nbytes, " ({:d} references)".format(refcount) if refcount > 0 else ''))

        # If we successfully grabbed the member, then we need to figure out its
        # actual index in our structure. Then we can use the index to instantiate
        # a member_t that we'll return back to the caller.
        idx = self.index(mptr)
        return member_t(owner, idx)

    @utils.multicase(index=types.integer)
    def pop(self, index):
        '''Remove the member at the specified `index`.'''
        owner, item = self.owner, self[index]
        if not union(owner.ptr):
            return self.remove(item.offset)

        # grab the owner, the member, and all of the member's attributes.
        sptr, mptr = owner.ptr, item.ptr
        moffset, mindex, msize = self.baseoffset, mptr.soff, idaapi.get_member_size(mptr)
        mname, location = utils.string.of(idaapi.get_member_name(mptr.id) or ''), interface.location_t(moffset, msize)

        # grab the type information so we can pythonify and return it.
        info = idaapi.retrieve_member_info(mptr, idaapi.opinfo_t()) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(idaapi.opinfo_t(), mptr)
        type = interface.typemap.dissolve(mptr.flag, info.tid if info else idaapi.BADADDR, msize, offset=moffset)

        # delete the member and return what we just removed.
        if not idaapi.del_struc_member(sptr, mindex):
            raise E.DisassemblerError(u"{:s}({:#x}).members.pop({:d}) : Unable to remove the union member at the specified index ({:d}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, mindex))
        return mname, type, location

    @utils.multicase(offset=types.integer)
    def remove(self, offset):
        '''Remove the member at `offset` from the structure.'''
        cls, owner, items = self.__class__, self.owner, [mptr for mptr in self.__members_at__(offset - self.baseoffset)] if offset >= self.baseoffset else []

        # If there are no items at the requested offset, then we bail.
        if not items:
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.remove({:+#x}) : Unable to find a member at the specified offset ({:#x}) of the structure ({:s}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset, self.owner.bounds))

        # If more than one item was found, then we also need to bail.
        elif len(items) > 1:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).members.remove({:+#x}) : Refusing to remove more than {:d} member{:s} ({:d}) at offset {:#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, 1, '' if len(items) == 1 else 's', len(items), offset))

        # Now we know exactly what we can remove.
        mptr, = items
        results = self.remove(self.baseoffset + mptr.soff, mptr.eoff - mptr.soff)
        if not results:
            raise E.DisassemblerError(u"{:s}({:#x}).members.remove({:+#x}) : Unable to remove the member at the specified offset ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, self.baseoffset + mptr.soff))
        result, = results
        return result
    @utils.multicase(offset=types.integer, size=types.integer)
    def remove(self, offset, size):
        '''Remove all the members from the structure from the specified `offset` up to `size` bytes.'''
        cls, sptr, soffset = self.__class__, self.owner.ptr, offset - self.baseoffset
        if not sptr.memqty:
            logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : The structure has no members that are able to be removed.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size))
            return []

        # If we're a union, then we need to raise an exception because
        # there's a likely chance that the user might empty out the
        # union entirely.
        if union(sptr):
            raise E.InvalidParameterError(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Refusing to remove members from the specified union by the specified offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, offset))

        # We need to calculate range that we're actually going to be removing, so
        # that we can clamp it to the boundaries of the structure. If the range
        # doesn't overlap, then we simply abort here with a warning.
        (left, right), (sleft, sright) = sorted([soffset, soffset + size]), (0, idaapi.get_struc_size(sptr))
        if not all([left <= sright - 1, right - 1  >= sleft]):
            logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : The specified range ({:#x}..{:#x}) is outside the range of the structure ({:#x}..{:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, *map(functools.partial(operator.add, self.baseoffset), [left, right - 1, sleft, sright - 1])))
            return []

        # Now that we know the range overlaps, we just need to clamp our values
        # to the overlapping part and recalculate the size.
        else:
            soffset, ssize = max(left, sleft), min(right, sright) - max(left, sleft)

        # First we'll need to figure out the index of the member that we will
        # start removing things at so we can collect the members to remove.
        previndex, nextindex = idaapi.get_prev_member_idx(sptr, soffset), idaapi.get_next_member_idx(sptr, soffset)
        index = previndex if nextindex < 0 else nextindex - 1
        if not (0 <= index < sptr.memqty):
            logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to determine the index of the member at the specified offset ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, soffset + self.baseoffset))
            return []

        # Next we need to collect each member that will be removed so
        # that we can return them back to the caller after removal.
        items = []
        while index < sptr.memqty and sptr.members[index].soff < soffset + ssize:
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
            type, location = interface.typemap.dissolve(mptr.flag, tid, msize, offset=moffset), interface.location_t(moffset, msize)
            result.append((mptr.id, name, type, location))

        # Figure out whether we're just going to remove one element, or
        # multiple elements so that we can call the correct api and figure
        # out how to compare the number of successfully removed members.
        if len(items) > 1:
            count = idaapi.del_struc_members(sptr, soffset, soffset + ssize)
        elif len(items):
            count = 1 if idaapi.del_struc_member(sptr, soffset) else 0
        else:
            count = 0

        # If we didn't remove anything and we were supposed to, then let
        # the user know that it didn't happen.
        if result and not count:
            start, stop = result[0], result[-1]
            bounds = interface.bounds_t(start[3].bounds.left, stop[3].bounds.right)
            logging.fatal(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove the requested elements ({:s}) from the structure.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, bounds))
            return []

        # If our count matches what was expected, then we're good and can
        # just return our results to the user.
        if len(result) == count:
            items = [(name, type, location) for _, name, type, location in result]
            return items[::-1] if size < 0 else items

        # Otherwise, we only removed some of the elements and we need to
        # figure out what happened so we can let the user know.
        removed, expected = {id for id in []}, {id : (name, type, location) for id, name, type, location in result}
        for id, name, _, location in result:
            moffset, _ = location
            if idaapi.get_member(sptr, moffset - self.baseoffset):
                logging.debug(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove member {:s} at offset {:+#x} with the specified id ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, name, moffset, id))
                continue
            removed.add(id)

        # We have the list of identities that were removed. So let's proceed
        # with our warnings and return whatever we successfully removed.
        start, stop = result[0], result[-1]
        bounds = interface.bounds_t(start[3].bounds.left, stop[3].bounds.right)
        logging.warning(u"{:s}({:#x}).members.remove({:+#x}, {:+#x}) : Unable to remove {:d} members out of an expected {:d} members within the specified range ({:s}) of the structure.".format('.'.join([__name__, cls.__name__]), sptr.id, offset, size, len(expected) - len(removed), len(expected), bounds))
        items = [(name, type, location) for id, name, type, location in result if id in removed]
        return items[::-1] if size < 0 else items
    @utils.multicase(bounds=interface.bounds_t)
    def remove(self, bounds):
        '''Remove all the members from the structure within the specified `bounds`.'''
        start, stop = sorted(bounds)
        return self.remove(start, stop - start)

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
        if not union(owner.ptr):
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
        def dissolve(mptr, offset):
            opinfo = idaapi.opinfo_t()
            res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            tid = res.tid if res else idaapi.BADADDR
            return interface.typemap.dissolve(mptr.flag, tid, idaapi.get_member_size(mptr), offset=offset)

        # Start out by finding all of the members at our current offset.
        items = []
        for mptr in self.__members_at__(offset):
            mleft, mright = 0 if union(owner.ptr) else mptr.soff, mptr.eoff

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
            if union(owner.ptr):
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
        moffset = 0 if union(owner.ptr) else mptr.soff
        mtype = dissolve(mptr, self.baseoffset + moffset)

        # If our member type is an array, then we need to do some things
        # to try and figure out which index we're actually going to be
        # at. Before that, we need to take our dissolved type and unpack it.
        if isinstance(mtype, types.list):
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
            if isinstance(item, types.tuple):
                return prefix, offset - moffset

            # If our array type is a structure, we will need to recurse in
            # order to figure out what the next field will be, and then we
            # can adjust the returned offset so that it corresponds to the
            # offset into the array.
            sptr = idaapi.get_sptr(mptr)
            if sptr:
                st = new(sptr.id, offset=self.baseoffset + moffset + res)
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
            return tuple(prefix), offset - moffset

        # Otherwise, the member type is a structure, and we'll need
        # to recurse in order to figure out which field should be at
        # the relative offset from the member.
        st = new(sptr.id, offset=self.baseoffset + moffset)
        result, nextoffset = st.members.__walk_to_realoffset__(offset - moffset, filter=filter)

        # Bail if we don't know what the type is.
        if not isinstance(result, (types.tuple, types.list)):
            raise TypeError(result)

        # Otherwise use the type of our result to concatenate our
        # prefix to our current results, and then return what we've
        # aggregated back to our caller with the next offset.
        iterable = (self.by_identifier(item.id) for item in [mptr])
        return result.__class__(itertools.chain(iterable, result)), nextoffset

    ## Matching
    __members_matcher = utils.matcher()
    __members_matcher.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
    __members_matcher.combinator('index', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), 'index')
    __members_matcher.combinator('identifier', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), 'id')
    __members_matcher.alias('id', 'identifier')
    __members_matcher.combinator('offset', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), 'offset')
    __members_matcher.combinator('name', utils.fcondition(utils.finstance(types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), types.set, utils.fpartial(utils.fpartial, operator.contains))), 'name', operator.methodcaller('lower'))
    __members_matcher.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
    __members_matcher.combinator('fullname', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'fullname')
    __members_matcher.combinator('comment',  utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match'), utils.fpartial(utils.fcompose, utils.fdefault(''))), 'comment')
    __members_matcher.alias('comments', 'comment')
    __members_matcher.combinator('bounds', utils.fcondition(utils.finstance(interface.bounds_t))(utils.fpartial(operator.methodcaller, 'overlaps'), utils.fcompose(utils.funpack(interface.bounds_t), utils.fpartial(operator.methodcaller, 'overlaps'))), 'bounds')
    __members_matcher.combinator('location', utils.fcondition(utils.finstance(interface.location_t))(utils.fcompose(operator.attrgetter('bounds'), utils.fpartial(operator.methodcaller, 'overlaps')), utils.fcompose(utils.funpack(interface.location_t), operator.attrgetter('bounds'), utils.fpartial(operator.methodcaller, 'overlaps'))), 'bounds')
    __members_matcher.combinator('within', utils.fcondition(utils.finstance(interface.bounds_t))(utils.fcompose(utils.fpartial(operator.methodcaller, 'contains')), utils.fcompose(utils.funpack(interface.bounds_t), utils.fpartial(operator.methodcaller, 'contains'))), 'bounds')
    __members_matcher.boolean('ge', operator.le, utils.fmap(operator.attrgetter('offset'), utils.fcompose(operator.attrgetter('size'), utils.fpartial(operator.add, -1), utils.fpartial(max, 0))), utils.funpack(operator.add)), __members_matcher.alias('greater', 'ge')
    __members_matcher.boolean('gt', operator.lt, utils.fmap(operator.attrgetter('offset'), utils.fcompose(operator.attrgetter('size'), utils.fpartial(operator.add, -1), utils.fpartial(max, 0))), utils.funpack(operator.add))
    __members_matcher.boolean('le', operator.ge, 'offset')
    __members_matcher.boolean('lt', operator.gt, 'offset'), __members_matcher.alias('less', 'lt')
    __members_matcher.predicate('predicate'), __members_matcher.predicate('pred')

    def __iterate__(self):
        '''Yield each of the members within the structure.'''
        for idx in range(len(self)):
            yield member_t(self.owner, idx)
        return

    @utils.multicase(tag=types.string)
    @utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(self, tag, *required, **boolean):
        '''Query the structure members for the given `tag` and any others that may be `required`.'''
        res = {tag} | {item for item in required}
        boolean['required'] = {item for item in boolean.get('required', [])} | res
        return self.select(**boolean)
    @utils.multicase(bounds=interface.bounds_t, tag=types.string)
    @utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(self, bounds, tag, *required, **boolean):
        '''Query the structure members within the specified `bounds` for the given `tag` and any others that may be `required`.'''
        res = {tag} | {item for item in required}
        boolean['required'] = {item for item in boolean.get('required', [])} | res
        return self.select(bounds, **boolean)
    @utils.multicase(bounds=interface.bounds_t)
    @utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(self, bounds, **boolean):
        '''Query the structure members within the specified `bounds` for any tags specified by `boolean`.'''
        start, stop = sorted(bounds)
        for member, content in self.select(**boolean):
            mstart, mstop = member.bounds
            if start <= mstop and stop > mstart:
                yield member, content
            continue
        return
    @utils.multicase()
    @utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(self, **boolean):
        """Query the structure members for the tags specified by `boolean` and yield a tuple for each matching member along with selected tags and values.

        If `require` is given as an iterable of tag names then require that each returned member uses them.
        If `include` is given as an iterable of tag names then include the tags for each returned member if available.
        """
        boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

        # For some reason the user wants to iterate through everything, so
        # we'll try and do as we're told but only if they have tags.
        if not boolean:
            for m in self.__iterate__():
                content = m.tag()
                if content:
                    yield m, content
                continue
            return

        # Do the same thing we've always done to consoldate our parameters
        # into a form that we can do basic set arithmetic with.
        included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])

        # All that's left to do is to slowly iterate through all of our
        # members while looking for the matches requested by the user.
        for m in self.__iterate__():
            collected, content = {}, m.tag()

            # Start out by collecting any tagnames that should be included which is similar to Or(|).
            collected.update({key : value for key, value in content.items() if key in included})

            # Then we need to include any specific tags that are required which is similar to And(&).
            if required:
                if required & six.viewkeys(content) == required:
                    collected.update({key : value for key, value in content.items() if key in required})
                else: continue

            # Easy to do and easy to yield.
            if collected: yield m, collected
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
        if isinstance(index, types.integer):
            index = owner.ptr.memqty + index if index < 0 else index
            res = member_t(owner, index) if 0 <= index < owner.ptr.memqty else None

        elif isinstance(index, types.string):
            res = self.by_name(index)

        elif isinstance(index, slice):
            sliceable = [self[idx] for idx in range(owner.ptr.memqty)]
            res = sliceable[index]

        else:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__getitem__({!r}) : An invalid type ({!s}) was specified for the index.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, index.__class__))

        if res is None:
            cls, where = self.__class__, "with the specified name (\"{:s}\")".format(index) if isinstance(index, types.string) else "at the given index ({:d})".format(index)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.__getitem__({:d}) : Unable to find a member {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, where))
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
        sptr, items = self.owner.ptr, [self[idx] for idx in range(len(self))]
        parent = sptr.props, utils.string.of(idaapi.get_struc_name(sptr.id))
        return (parent, self.baseoffset, items)
    def __setstate__(self, state):
        owner, baseoffset, _ = state

        # figure out our parent here.
        if isinstance(owner, types.tuple) and len(owner) == 2:
            sprops, ownername = owner

        # backwards compatibility
        elif isinstance(owner, types.string):
            sprops, ownername = 0, owner

        # grab the structure containing our members so we can instantiate it
        res = utils.string.to(ownername)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.info(u"{:s}({:#x}) : Creating `members_t` for `structure_t` \"{:s}\" with no members.".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(ownername, '"')))
            identifier = idaapi.add_struc(idaapi.BADADDR, res, True if sprops & idaapi.SF_UNION else False)

        # assign the properties for our new member using the instance we figured out
        self.baseoffset = baseoffset
        self.__owner__ = new(identifier, offset=baseoffset)
        return

    ## operators
    def __operator__(self, operation, other):
        result = operation(self.__owner__, other)
        return result.members if isinstance(result, self.__owner__.__class__) else [item.members for item in result]
    def __operation__(self, operation):
        result = operation(self.__owner__)
        return result.members

    # general arithmetic (adjusts base offset)
    def __add__(self, other):
        '''Add `other` to the base offset for the members.'''
        return self.__operator__(operator.add, other)
    def __sub__(self, other):
        '''Subtract `other` from the base offset of the members.'''
        return self.__operator__(operator.sub, other)
    def __and__(self, other):
        return self.__operator__(operator.and_, other)
    def __or__(self, other):
        return self.__operator__(operator.or_, other)
    def __xor__(self, other):
        return self.__operator__(operator.xor, other)
    def __mul__(self, other):
        return self.__operator__(operator.mul, other)
    def __pow__(self, other):
        return self.__operator__(operator.pow, other)

    # reverse operators (adjusts base offset)
    __radd__ = __add__
    def __rsub__(self, other):
        return self.__operator__(operator.add, operator.neg(other))
    __rand__ = __and__
    __ror__ = __or__
    __rxor__ = __xor__
    __rmul__ = __mul__

    # operations
    def __abs__(self):
        '''Return the structure members without an offset.'''
        return self.__operation__(operator.abs)
    def __neg__(self):
        '''Return the structure members with their offset negated.'''
        return self.__operation__(operator.neg)
    def __invert__(self):
        '''Return the structure members with their offset inverted.'''
        return self.__operation__(operator.invert)
