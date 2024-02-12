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

import builtins, six, operator, functools, itertools, logging, math
import re, fnmatch, pickle

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

def by_index(index):
    '''Return the structure at the specified `index` or identifier from the database.'''
    if interface.node.identifier(index):
        return idaapi.get_struc(index)

    # otherwise, the index is definitely an index and we'll use it to grab the sptr.
    sid = idaapi.get_struc_by_idx(index)
    return None if sid == idaapi.BADADDR else idaapi.get_struc(sid)

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
        info = interface.tinfo.parse(None, string, idaapi.PT_SIL)
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

class member(object):
    """
    This namespace is _not_ the `member_t` class. Its purpose is to
    expose some of the complicated disassembler-specific logic that is
    found within that class to the outside world. It would be expected
    that this type of namespace would be found in `internal.interface`,
    but since the logic is only specific to structure members..it is
    declared here instead. Similar to other namespaces, the functionality
    within this one does not use objects of any kind.
    """

    @classmethod
    def index(cls, mptr):
        '''Return the index of the member specified by `mptr`.'''
        packed = idaapi.get_member_by_id(mptr if isinstance(mptr, internal.types.integer) else mptr.id)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.index({:#x}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr if isinstance(mptr, types.integer) else mptr.id, mptr if isinstance(mptr, types.integer) else mptr.id))

        # Verify that we have at least one member in the structure for sanity.
        mptr, fullname, sptr = packed
        if not sptr.memqty:
            raise E.MemberNotFoundError(u"{:s}.index({:#x}) : Unable to find the member with the specified identifier ({:#x}) in a {:s} ({:#x}) with {:d} member{:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, mptr.id, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, sptr.memqty, '' if sptr.memqty == 1 else 's'))

        # If the member is a union member, then we can trust the member_t.soff field.
        elif mptr & idaapi.MF_UNIMEM:
            return mptr.soff

        # Otherwise, we need to use the sptr to figure out the index. Newer versions of the
        # disassembler return an index of +1, so we first figure out which one we have.
        base = idaapi.get_prev_member_idx(sptr, sptr.members[0].eoff)

        # If the structure has more than two members, we check the previous index from
        # the end of the current member. This should always succeed in newer versions.
        if base and sptr.memqty > 2:
            prev, next = idaapi.get_prev_member_idx(sptr, mptr.eoff), idaapi.get_next_member_idx(sptr, mptr.soff)
            mindex = prev if prev >= 0 else next
            return mindex - base

        # If the base index is 0, then we only need to subtract one from the next member index.
        elif sptr.memqty > 2:
            next = idaapi.get_next_member_idx(sptr, mptr.soff)
            mindex = sptr.memqty if next < 0 else next
            return mindex - 1

        # If there's only 1 or 2 members in the structure, then we can simply check the
        # first index to see if it matches. If it doesn't, then it is the other index.
        return 0 if mptr.id == sptr.get_member(0).id else 1

    @classmethod
    def has_name(cls, mptr):
        '''Return whether the name of the member specified by `mptr` is user-defined.'''
        packed = idaapi.get_member_by_id(mptr.id)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.has_name({:#x}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, mptr.id))
        mptr, fullname, sptr = packed

        # now we can grab the name of the member. we could also extract
        # it from `fullname`, but this is how i've been always doing it.
        res = idaapi.get_member_name(mptr.id) or ''
        name = utils.string.of(res)

        # if the sptr is not a function frame, then this is easy and we
        # only have to check to see if the name matches "field_%X".
        if not frame(sptr):
            #return name.startswith('field_')   # XXX: this is how the disassembler does it..
            expected = "field_{:X}".format(mptr.soff)
            return name != expected             # but this is more accurate.

        # otherwise this is a frame and we can use the disassembler api. we _could_
        # check the member location and use it to differentiate lvars, registers,
        # and args..but the disassembler doesn't let users use those prefixes anyways.
        idaname = utils.string.to(name)
        return not (idaapi.is_dummy_member_name(idaname) or idaapi.is_anonymous_member_name(idaname) or idaapi.is_special_member(mptr.id))

    @classmethod
    def get_name(cls, mptr):
        '''Return the name of the member given by `mptr` as a string.'''
        identifier = getattr(mptr, 'id', mptr)
        res = idaapi.get_member_name(identifier) or ''
        return utils.string.of(res)

    @classmethod
    def fullname(cls, mptr):
        '''Return the full name of the member given my `mptr` as a string.'''
        Fnetnode = getattr(idaapi, 'ea2node', utils.fidentity)
        netnode = Fnetnode(getattr(mptr, 'id', mptr))
        return utils.string.of(internal.netnode.name.get(netnode) if internal.netnode.name.get(netnode) else '')

    @classmethod
    def set_name(cls, mptr, string):
        '''Set the name of the member given by `mptr` to `string` and return the original name.'''
        string = interface.tuplename(*string) if isinstance(string, types.ordered) else string
        if not isinstance(string, types.string):
            raise E.InvalidParameterError(u"{:s}.set_name({:#x}, {!s}) : Unable to assign the unsupported type ({!s}) as the name for the member.".format('.'.join([__name__, cls.__name__]), getattr(mptr, 'id', mptr), string, string.__class__))

        # we need the sptr for the member to rename it. this is likely because the
        # fullname is really a combination of the structure name and member name.
        packed = idaapi.get_member_by_id(getattr(mptr, 'id', mptr))
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.set_name({:#x}, {!r}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), getattr(mptr, 'id', mptr), string, getattr(mptr, 'id', mptr)))

        # technically we have the member name here if we extract the netnode name
        # from sptr and subtract it from the beginning of fullname. this'd be how
        # we could support the usage of (potentially) illegal characters.
        mptr, fullname, sptr = packed

        # for the sake of being pedantic here, we check to see if this is a special
        # member, because if we touch it...it becomes non-special for some reason.
        if idaapi.is_special_member(mptr.id):
            mdescr = "index ({:d})".format(mptr.soff) if union(sptr) else "offset ({:#x})".format(mptr.soff)
            logging.warning(u"{:s}.set_name({:#x}, {!r}) : Modifying the name for the special member \"{:s}\" at {:s} will unfortunately demote its special properties.".format('.'.join([__name__, cls.__name__]), mptr.id, string, utils.string.escape(utils.string.of(fullname), '"'), mdescr))

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name using the constraints for a netnode name.
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.SN_IDBENC)
        if ida_string and ida_string != res:
            logging.info(u"{:s}.set_name({:#x}, {!r}) : Stripping invalid characters from desired {:s} member name \"{:s}\" resulted in \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, string, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(string, '"'), utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # now we can set the name of the member using its offset. another
        # way that we can do this is to use `internal.netnode.name.set`.
        oldname = cls.get_name(mptr)
        if not idaapi.set_member_name(sptr, mptr.soff, ida_string):
            raise E.DisassemblerError(u"{:s}.set_name({:#x}, {!r}) : Unable to assign the specified name \"{:s}\" to the {:s} member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, string, utils.string.escape(utils.string.of(ida_string), '"'), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(fullname, '"')))

        # verify that the name was actually assigned properly
        assigned = idaapi.get_member_name(mptr.id) or ''
        if utils.string.of(assigned) != utils.string.of(ida_string):
            logging.info(u"{:s}.set_name({:#x}, {!r}) : The name ({:s}) that was assigned to the {:s} member does not match what was requested ({:s}).".format('.'.join([__name__, cls.__name__]), mptr.id, string, utils.string.repr(utils.string.of(assigned)), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.repr(ida_string)))
        return oldname

    @classmethod
    def remove_name(cls, mptr):
        '''Reset the user-specified name on the member given by `mptr` and return the original name.'''
        packed = idaapi.get_member_by_id(getattr(mptr, 'id', mptr))

        # we need the sptr for the member to reset its name since the default name
        # actually depends on the type of the structure and where it's used.
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.remove_name({:#x}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), getattr(mptr, 'id', mptr), getattr(mptr, 'id', mptr)))

        # again, if we extract the netnode names from these we can combine them to confirm
        # that they match the "fullname". we can support arbitrary characters like this.
        mptr, fullname, sptr = packed

        # if the sptr is a function frame, then this name varies based on which
        # "segment" the offset is located in (lvars, registers, or args).
        ea = idaapi.get_func_by_frame(sptr.id)
        if frame(sptr) and ea == idaapi.BADADDR:
            raise E.DisassemblerError(u"{:s}.remove_name({:#x}) : Unable to determine the function from the frame ({:#x}) containing the member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, None, sptr.id, utils.string.escape(internal.netnode.name.get(mptr.id), '"')))

        # otherwise, this is easy as we can just use mptr.soff to get the
        # correct offset, and use it to format the name as "field_%X".
        default = cls.default_name(sptr, mptr, mptr.soff)
        return cls.set_name(mptr, default)

    @classmethod
    def default_name(cls, sptr, mptr, *offset):
        '''Return the default name for the member given by `mptr` belonging to the structure `sptr` at the given `offset` if provided.'''
        fmtVar, fmtArg, fmtField = (fmt.format for fmt in ["var_{:X}", "arg_{:X}", "field_{:X}"])
        fmtSpecial_s, fmtSpecial_r = (utils.fconstant(format) for format in [' s', ' r'])

        # To process the frame, we first need the address of the function
        # to get the func_t and the actual member offset to calculate with.
        ea = idaapi.get_func_by_frame(sptr.id)
        if ea == idaapi.BADADDR:
            fmt, moff = fmtField, mptr.get_soff() if mptr else sptr.memqty if union(sptr) else idaapi.get_struc_size(sptr)
            return fmt(*offset) if offset else fmt(moff)

        # We need to figure out all of the attributes we need in order to
        # calculate the position within a frame this includes the integer size.
        fn = idaapi.get_func(ea)
        if fn is None:
            raise E.FunctionNotFoundError(u"{:s}.default_name({:#x}, {:#x}) : Unable to get the function at the specified address ({:#x}) which owns the frame ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id if mptr else idaapi.BADNODE, ea, sptr.id))

        # Now we need to figure out where our member is. If it's within the
        # `func_t.frsize`, then we're a "var_" relative to `func_t.frsize`.
        [moff] = offset if offset else [mptr.get_soff() if mptr else sptr.memqty if union(sptr) else idaapi.get_struc_size(sptr)]
        if moff < fn.frsize:
            fmt, offset = fmtVar, fn.frsize - moff

        # If it's within `func_t.frregs`, then we're a special " s" name.
        elif moff < idaapi.frame_off_retaddr(fn):
            fmt, offset = fmtSpecial_s, None

        # If it's at the saved registers, then we're a special " r" name.
        elif moff < idaapi.frame_off_args(fn):
            fmt, offset = fmtSpecial_r, None

        # Anything else should be an argument that is relative to the sum
        # of all the segments we chopped out. So we will use "arg_" here.
        elif moff < idaapi.frame_off_args(fn) + fn.argsize:
            fmt, offset = fmtArg, moff - idaapi.frame_off_args(fn)

        # Anything else though...is a bug, it shouldn't happen unless IDA is not
        # actually populating the fields correctly (looking at you x64). So, lets
        # just be silently pedantic here.
        else:
            fmt, offset = fmtArg, moff - idaapi.frame_off_args(fn)
            mdescr = "index ({:d})".format(moff) if union(sptr) else "offset ({:#x})".format(moff)
            logging.debug(u"{:s}.default_name({:#x}, {:#x}) : Treating the name for the member at {:s} as an argument due to its location ({:#x}) being outside of the frame ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id if mptr else idaapi.BADNODE, mdescr, moff, sum([idaapi.frame_off_args(fn), fn.argsize])))

        # We have our formatter and translated offset, so we can simply return it.
        return fmt(offset)

    @classmethod
    def get_type(cls, mptr, *offset):
        '''Return the pythonic type of the member specified by `mptr` translated to the given `offset`.'''
        opinfo = idaapi.opinfo_t()

        # First, we'll need to get the structure associated with the member.
        packed = idaapi.get_member_by_id(mptr.id if isinstance(mptr, idaapi.member_t) else mptr)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.get_type({:#x}{:s}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr if isinstance(mptr, types.integer) else mptr.id, ", {:#x}".format(*map(int, offset)) if offset else '', mptr if isinstance(mptr, types.integer) else mptr.id))
        mptr, fullname, sptr = packed
        [moffset] = map(int, offset) if offset else [0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff]

        # Now we can retrieve the information for the member in an opinfo_t.
        flags, size = idaapi.as_uint32(mptr.flag), idaapi.get_member_size(mptr)
        ok = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)

        # Everything has been populated, so we need it in its pythonic form.
        res = interface.typemap.dissolve(flags, opinfo.tid if ok else None, size, offset=moffset)
        if isinstance(res, structure_t):
            res = new(res.id, moffset)

        elif isinstance(res, types.tuple):
            iterable = (item for item in res)
            item = next(iterable)
            if isinstance(item, structure_t):
                item = new(item.id, moffset)
            elif isinstance(item, types.list) and isinstance(item[0], structure_t):
                item[0] = new(item[0].id, moffset)
            res = tuple(itertools.chain([item], iterable))
        return res

    @classmethod
    def set_type(cls, mptr, type, *offset):
        '''Apply the pythonic `type` at the given `offset` to the member specified by `mptr`.'''
        flag, typeid, nbytes = interface.typemap.resolve(type)

        # First, we'll need to get the structure associated with the member.
        packed = idaapi.get_member_by_id(mptr.id)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.set_type({:#x}, {!s}{:s}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr if isinstance(mptr, types.integer) else mptr.id, ", {:#x}".format(*map(int, offset)) if offset else '', type, mptr if isinstance(mptr, types.integer) else mptr.id))
        mptr, fullname, sptr = packed
        [moffset] = map(int, offset) if offset else [0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff]

        # Grab the previous type from our member so we can return it later.
        opinfo, flags, size = idaapi.opinfo_t(), idaapi.as_uint32(mptr.flag), idaapi.get_member_size(mptr)
        ok = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
        result = interface.typemap.dissolve(flags, opinfo.tid if ok else None, size, offset=moffset)

        # Now we have everything we need to apply the type that we resolved
        # and we only need to ensure everything has the right signedness.
        opinfo, unsigned = idaapi.opinfo_t(), idaapi.ea_pointer()
        opinfo.tid, _ = typeid, unsigned.assign(flag)
        if not idaapi.set_member_type(sptr, mptr.soff, unsigned.value(), opinfo, nbytes):
            raise E.DisassemblerError(u"{:s}.set_type({:#x}, {!s}{:s}) : Unable to assign the provided type ({!s}) to the {:s} member \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, type, ", {:#x}".format(*map(int, offset)) if offset else '', type, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(utils.string.of(fullname), '"'), mptr.id))

        # XXX: On older versions of the disassembler, the structure might not have been "saved" and
        #      required us to race the member out of the database and re-verify.. To be fair, it
        #      only happened when modifying in bulk. However, we're now avoiding that entirely.

        # Update the reference information to handle pointers and return our result.
        interface.address.update_refinfo(mptr.id, flag)
        return result

    @classmethod
    def get_typeinfo(cls, mptr):
        '''Return the type information of the member given by `mptr` guessing it if necessary.'''
        ti = idaapi.tinfo_t()

        # Guess the typeinfo for the current member. If we're unable to get the
        # typeinfo then we just return whatever we have. Let IDA figure it out.
        ok = idaapi.get_or_guess_member_tinfo2(mptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, mptr)
        if not ok:
            logging.debug(u"{:s}.get_typeinfo({:#x}) : Returning the guessed type that was determined for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, utils.string.escape(cls.fullname(mptr.id), '"')))

        error = idaapi.replace_ordinal_typerefs(ti.get_til(), ti) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if error < 0:
            logging.debug(u"{:s}.get_typeinfo({:#x}) : Unable to strip the ordinals from the type associated with member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, utils.string.escape(cls.fullname(mptr.id), '"')))
        return ti

    @classmethod
    def format_error_typeinfo(cls, code):
        '''Return the specified error `code` as a tuple composed of the error name and its description.'''
        descriptions, names = {}, {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('SMT_')}
        descriptions[idaapi.SMT_BADARG] = 'bad parameters'
        descriptions[idaapi.SMT_NOCOMPAT] = 'the new type is not compatible with the old type'
        descriptions[idaapi.SMT_WORSE] = 'the new type is worse than the old type'
        descriptions[idaapi.SMT_SIZE] = 'the new type is incompatible with the member size'
        descriptions[idaapi.SMT_ARRAY] = 'arrays are forbidden as function arguments'
        descriptions[idaapi.SMT_OVERLAP] = 'member would overlap with members that cannot be deleted'
        descriptions[idaapi.SMT_FAILED] = 'failed to set new member type'
        descriptions[idaapi.SMT_OK] = 'success: changed the member type'
        descriptions[idaapi.SMT_KEEP] = 'no need to change the member type, the old type is better'
        return names.get(code, ''), descriptions.get(code, '')

    @classmethod
    def set_typeinfo(cls, mptr, info, flags=idaapi.SET_MEMTI_COMPATIBLE):
        '''Apply the type information in `info` to the member specified by `mptr` using the given `flags`.'''
        if not isinstance(info, (idaapi.tinfo_t, types.string)):
            raise E.InvalidParameterError(u"{:s}.set_typeinfo({:#x}, {!s}) : Unable to assign an unsupported type ({!s}) to the type information for the member.".format('.'.join([__name__, cls.__name__]), mptr.id, info if info is None else utils.string.repr(info), info.__class__))

        # We first need to collect the correct APIs depending on the disassembler version.
        get_member_tinfo = idaapi.get_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.get_member_tinfo
        set_member_tinfo = idaapi.set_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_member_tinfo

        # Now we need to forcefully convert our parameter to a `tinfo_t`.
        ti, info_description = (info, utils.string.repr("{!s}".format(info))) if isinstance(info, idaapi.tinfo_t) else (interface.tinfo.parse(None, info, idaapi.PT_SIL), utils.string.repr(info))

        # Then we need the sptr for the member so that we can actually apply the type.
        packed = idaapi.get_member_by_id(mptr.id)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.set_typeinfo({:#x}, {!s}, {:#x}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, info_description, flags, mptr.id))
        mptr, fullname, sptr = packed

        # We want to detect type changes, so we need to get the previous type information of
        # the member so that we can distinguish between an actual SMT_KEEP error or an error
        # that occurred because the previous member type is the same as the new requested type.
        prevti = idaapi.tinfo_t()
        ok = get_member_tinfo(prevti, mptr)
        if not ok:
            logging.info(u"{:s}.set_typeinfo({:#x}, {!s}, {:#x}) : Unable to get the previous type information for the {:s} member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, info_description, flags, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(cls.fullname(mptr.id), '"')))
        original = prevti if ok else None

        # Now we can pass our tinfo_t along with the member information to the api.
        res = set_member_tinfo(sptr, mptr, mptr.soff, ti, flags)

        # If we got an SMT_OK or we received SMT_KEEP with the previous member type and new
        # member type being the same, then this request was successful and we can return.
        if res == idaapi.SMT_OK or res == idaapi.SMT_KEEP and interface.tinfo.equals(ti, prevti):
            return original

        # We failed, so just raise an exception for the user to comprehend.
        elif res == idaapi.SMT_FAILED:
            raise E.DisassemblerError(u"{:s}.set_typeinfo({:#x}, {!s}, {:#x}) : Unable to assign the provided type information to {:s} member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, info_description, flags, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(cls.fullname(mptr.id), '"')))

        # If we received an alternative return code, then build a relevant message
        # that we can raise with an exception, so that the user knows what's up.
        error_name, error_description = cls.format_error_typeinfo(res)
        raise E.DisassemblerError(u"{:s}.set_typeinfo({:#x}, {!s}, {:#x}) : Unable to assign the type to {:s} member \"{:s}\" due to error {:s}{:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, info_description, flags, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(cls.fullname(mptr.id), '"'), "{:s}({:d})".format(error_name, res) if error_name else "code ({:d})".format(res), ", {:s}".format(error_description) if error_description else ''))

    @classmethod
    def remove_typeinfo(cls, mptr):
        '''Remove the type information from the member specified by `mptr`.'''
        ti = idaapi.tinfo_t()

        # First we need to grab the original type, but only if it was explicitly assigned
        # by the user. This is because our regular api _always_ guesses the type, and
        # whenever applying or clearing the member's type we want to remain honest.
        get_member_tinfo = idaapi.get_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.get_member_tinfo
        original = ti if get_member_tinfo(ti, mptr) else None

        # Then we need the sptr for the member so that we can actually remove the type.
        packed = idaapi.get_member_by_id(mptr.id)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.remove_typeinfo({:#x}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, mptr.id))
        mptr, fullname, sptr = packed

        # Next we need to check if the correct api for removing member type
        # information, `idaapi.del_member_tinfo`, is available and use it if so.
        if hasattr(idaapi, 'del_member_tinfo') and idaapi.del_member_tinfo(sptr, mptr):
            return original

        # Otherwise the best we can do is to re-assign an empty type to clear it. We
        # try to create an unknown type since it's the best we can do without the api.
        ti = idaapi.tinfo_t()
        if not ti.create_simple_type(idaapi.BTF_UNK):
            logging.warning(u"{:s}.remove_typeinfo({:#x}) : Unable to create an unknown {:s}({:d}) type to assign to the {:s} member \"{:s}\".".format('.'.join([__name__, cls.__name__]), mptr.id, 'BTF_UNK', idaapi.BTF_UNK, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(cls.fullname(mptr.id), '"')))
        return cls.set_typeinfo(mptr, info)

    @classmethod
    def get_comment(cls, mptr, *repeatable):
        """Return the comment from the member specified by `mptr` as a string, giving priority to the repeatable comment.

        If `repeatable` is given as a boolean, return only that specific comment type from the member.
        """
        identifier = mptr.id if isinstance(mptr, idaapi.member_t) else mptr
        res = idaapi.get_member_cmt(identifier, *repeatable) if repeatable else idaapi.get_member_cmt(identifier, True) or idaapi.get_member_cmt(identifier, False)
        return utils.string.of(res or '')

    @classmethod
    def set_comment(cls, mptr, string, *repeatable):
        """Assign the given `string` to the member specified by `mptr` and return the previous value, giving priority to the repeatable comment.

        If `repeatable` is given as a boolean, then affect only that specific comment type of the member.
        """
        if not repeatable:
            comment_r, comment_n = (utils.string.of(idaapi.get_member_cmt(mptr.id, repeatable)) for repeatable in [True, False])
            prioritized = all([comment_r, comment_n]) or not any([comment_r, comment_n])
            return cls.set_comment(mptr, string, True if prioritized or comment_r else comment_n)

        # Now we should be able to use the repeatable parameter and raise an error if it fails.
        result = idaapi.get_member_cmt(mptr.id, *repeatable)
        if not idaapi.set_member_cmt(mptr, utils.string.to(string or ''), *repeatable):
            [repeat], description = repeatable, cls.fullname(mptr)
            raise E.DisassemblerError(u"{:s}.set_comment({:#x}, {!r}, {!s}) : Unable to assign the specified {:s}comment to the given member {:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, string, repeat, 'repeatable ' if repeat else '', "\"{:s}\"".format(utils.string.escape(description, '"')) if description else "{:#x}".format(mptr.id)))
        return utils.string.of(result or '')

    @classmethod
    def contains(cls, mptr, offset):
        '''Return whether the given `offset` resides within the member specified by `mptr`.'''
        packed, realoffset = idaapi.get_member_by_id(mptr if isinstance(mptr, internal.types.integer) else mptr.id), int(offset)
        if not packed:
            return False

        # Unpack the tuple we received from get_member_by_id, and check the member's boundaries.
        mptr, fullname, sptr = packed
        if mptr.props & idaapi.MF_UNIMEM:
            return 0 <= realoffset < idaapi.get_member_size(mptr)
        elif sptr.props & idaapi.SF_VAR and mptr.soff == mptr.eoff:
            return mptr.eoff <= realoffset
        return False if mptr.soff == mptr.eoff else mptr.soff <= realoffset < mptr.eoff

    @classmethod
    def element(cls, mptr):
        '''Return the size for a single element belonging to the member specified by `mptr`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        opinfo, packed = idaapi.opinfo_t(), idaapi.get_member_by_id(mptr if isinstance(mptr, internal.types.integer) else mptr.id)
        if packed:
            mptr, fullname, sptr = packed
            retrieved = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            return get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None)
        description = "{:#x}".format(mptr.id) if hasattr(mptr, 'id') else "{:#x}".format(mptr) if isinstance(mptr, internal.types.integer) else "{!s}".format(mptr)
        identifier = mptr.id if hasattr(mptr, 'id') else mptr if isinstance(mptr, internal.types.integer) else idaapi.BADNODE
        raise E.MemberNotFoundError(u"{:s}.element({:s}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), description, identifier))

    @classmethod
    def size(cls, mptr):
        '''Return the size for the member that is specified by `mptr`.'''
        packed = idaapi.get_member_by_id(mptr if isinstance(mptr, internal.types.integer) else mptr.id)
        if packed:
            mptr, fullname, sptr = packed
            return idaapi.get_member_size(mptr)
        description = "{:#x}".format(mptr.id) if hasattr(mptr, 'id') else "{:#x}".format(mptr) if isinstance(mptr, internal.types.integer) else "{!s}".format(mptr)
        identifier = mptr.id if hasattr(mptr, 'id') else mptr if isinstance(mptr, internal.types.integer) else idaapi.BADNODE
        raise E.MemberNotFoundError(u"{:s}.size({:s}) : Unable to find the member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), description, identifier))

    @classmethod
    def at(cls, mptr, offset):
        '''Return the distance of the given `offset` from the member in `mptr` as a tuple composed of an array index and element offset.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        opinfo, moffset, msize = idaapi.opinfo_t(), 0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff, idaapi.get_member_size(mptr)

        # Get any information about the member and use it to get the size of the type.
        retrieved = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
        element = get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None)

        index, remainder = divmod(int(offset) - moffset, element)
        return index, remainder

    @classmethod
    def packed(cls, offset, mptr):
        '''Pack the information about the member `mptr` with its structure at the specified `offset` into a tuple in case it is to be removed.'''
        is_union_member = True if mptr.props & idaapi.MF_UNIMEM else False

        # first we'll grab the name and the size. we need the size in order
        # to dissolve the member into an actual type of some sort.
        mname = utils.string.of(idaapi.get_member_name(mptr.id)) or ''
        msize = idaapi.get_member_size(mptr)

        # then we'll need to figure out the offset and use it to calculate
        # the location. the member's offset is the parameter unless we're
        # a member of a union. if so, then we just use the parameter as-is.
        moffset = int(offset) if is_union_member else int(offset) + mptr.soff
        location = interface.location_t(moffset, msize)

        # snag both comment types so that we can include them in our result.
        iterable = (idaapi.get_member_cmt(mptr.id, repeatable) for repeatable in [True, False])
        mcomment1, mcomment2 = (utils.string.of(cmt) for cmt in iterable)
        mcomments = mcomment1, mcomment2

        # now we need to grab the type information since we're going to
        # be pythonifying our type information prior to returning it.
        opinfo = idaapi.opinfo_t()
        if idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr):
            tid = opinfo.tid
        else:
            tid = idaapi.BADADDR

        # now we can dissolve it the type, and use it to
        # return a tuple containing everything we collected.
        dissolved = interface.typemap.dissolve(mptr.flag, tid, msize, offset=moffset)
        return mptr.id, mname, dissolved, location, mcomments

class members(object):
    """
    This namespace is _not_ the `members_t` class. Its purpose is to
    expose any disassembler-specific logic related to the members
    associated with a structure. The offsets within the functions
    belonging to this namespace are not translated and are instead
    always guaranteed to be relative to the top of the structure.

    This namespace is similar to the `member` namespace and is
    intended to be used for searching through members in a given
    structure, or recursively through its members. It explicitly
    avoids handling the holes that can be found within a structure.

    When returning an individual member, the functions within this
    namespace will always return it as a 3-element tuple composed
    of the ``idaapi.struc_t``, an integer for its index, and the
    ``idaapi.member_t`` which contains its database identifier.
    """

    @classmethod
    def iterate(cls, sptr, *slice):
        '''Yield each member specified by `slice` from the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        [selection] = slice if slice else [builtins.slice(None)]
        for index in range(*selection.indices(sptr.memqty)):
            mptr = sptr.get_member(index)
            yield sptr, index, mptr
        return

    @classmethod
    def index(cls, sptr, mptr):
        '''Return the index of the member `mptr` in the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)

        # We assume that the member actually belongs to the specified structure to
        # avoid having to do a get_member_by_id every time this gets called. If the
        # member and structure are from a union, we can just return member_t.soff.
        if union(sptr) and mptr.props & idaapi.MF_UNIMEM:
            return mptr.soff

        # Now we can use the member offset to ask the disassembler about the
        # index. However, we will need to adjust the result by a base index
        # due to newer versions not returning an index of 0 for the first member.
        base = idaapi.get_prev_member_idx(sptr, sptr.members[0].eoff)

        # If our structure has more than two members, we ask the disassembler. Due to
        # checking the end of the member, the result should always be the previous
        # index unless it failed. If it fails, then it definitely should be the next.
        if base and sptr.memqty > 2:
            prev, next = idaapi.get_prev_member_idx(sptr, mptr.eoff), idaapi.get_next_member_idx(sptr, mptr.soff)
            mindex = next if prev < 0 else prev
            return mindex - base

        # Otherwise, we need to deal with previous versions which requires us to
        # always take the previous of the next index in order to figure it out.
        elif sptr.memqty > 2:
            next = idaapi.get_next_member_idx(sptr, mptr.soff)
            mindex = sptr.memqty if next < 0 else next
            return mindex - 1

        # Otherwise, there's only one or two members and we can simply check the member
        # against the first from the structure since it can only be one or the other.
        return 0 if mptr.id == sptr.get_member(0).id else 1

    @classmethod
    def index_after(cls, sptr, offset):
        '''Return the index of a member at the given `offset` or after from the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        is_variable, size = sptr.props & idaapi.SF_VAR, idaapi.get_struc_size(sptr.id)

        # Grab the last member of the structure so that we can distinguish whether
        # the offset is pointing to it, or goes past the length of the structure.
        last = sptr.get_member(sptr.memqty - 1) if sptr.memqty else None
        right = last.eoff + 1 if is_variable and last.soff == last.eoff else last.eoff if last else size

        # If the offset comes after the last member, then we can use the number of
        # members to determine the index. We only need to adjust for variable-length.
        if right <= offset:
            return sptr.memqty

        # If the offset comes before the entire structure, then we return 0 as
        # this function should always select the first element if available.
        elif offset < 0:
            return 0

        # Now we can use the get_next_member_idx function, which isn't busted.
        index = idaapi.get_next_member_idx(sptr, offset)
        return sptr.memqty if index < 0 else index

    @classmethod
    def index_before(cls, sptr, offset):
        '''Return the index of a member at the given `offset` or before from the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        is_variable, size = sptr.props & idaapi.SF_VAR, idaapi.get_struc_size(sptr.id)

        # First grab the ends of the structure. This is because newer versions of the
        # disassembler seem to have borked up the get_prev_member_idx function.
        first, last = (sptr.get_member(0), sptr.get_member(sptr.memqty - 1)) if sptr.memqty else (None, None)
        left, right = first.eoff if first else 0, last.eoff if last else size

        # Now we'll check the get_prev_member_idx function, by asking it to return
        # the index of the member that comes before the end of the first member.
        broken = idaapi.get_prev_member_idx(sptr, first.eoff if first else size) > 0

        # If the offset comes before the end of the first member, then return index 0.
        if offset < left:
            return 0

        # If the offset goes past the end of the last member, then we return the
        # number of members unless the last member has a variable-length size.
        elif right <= offset:
            return sptr.memqty - 1 if last and is_variable and last.soff == last.eoff else sptr.memqty

        # Now we'll check to see if there's a member at the specified offset. If
        # there is, then we can use the broken function. If there wasn't a member
        # at the requested offset, then get_prev_member_idx should work correctly.
        mptr = idaapi.get_member(sptr, offset)
        if broken:
            return max(0, idaapi.get_prev_member_idx(sptr, mptr.soff if mptr else offset))
        return max(0, idaapi.get_prev_member_idx(sptr, mptr.eoff) if mptr else idaapi.get_next_member_idx(sptr, offset))

    @classmethod
    def contains(cls, sptr, offset):
        '''Return whether the given `offset` is within the boundaries of the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        size, realoffset = idaapi.get_struc_size(sptr), int(offset)

        # If it's a variable-length structure, then we only need to check the
        # lower bounds. Otherwise, we check the offset against the size.
        if sptr.props & idaapi.SF_VAR:
            return 0 <= realoffset
        return 0 <= realoffset < size

    @classmethod
    def has_name(cls, sptr, name):
        '''Return whether a member with the specified `name` exists within the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        string = name if isinstance(name, types.ordered) else [name]
        return idaapi.get_member_by_name(sptr, utils.string.to(interface.tuplename(*string))) is not None

    @classmethod
    def has_offset(cls, sptr, offset):
        '''Return whether a member exists at the `offset` of the structure identified by `sptr`.'''
        realoffset, sptr = int(offset), idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        is_union, is_variable = union(sptr), True if sptr.props & idaapi.SF_VAR else False

        # First verify that the offset is within the bounds of the structure.
        if not cls.contains(sptr, realoffset):
            return False

        # Iterate through all of our members and figure out which one contains us.
        for index in range(sptr.memqty):
            mptr = sptr.get_member(index)

            # Unpack the boundaries from the member at the current index.
            # If it's a union, then the lower bounds should always be 0.
            mleft, mright, msize = 0 if is_union else mptr.soff, mptr.eoff, idaapi.get_member_size(mptr)

            # If it's a union, then it just needs to overlap with the size.
            if is_union and 0 <= realoffset < msize:
                return True

            # If it exists within the boundaries of the member, then we're done.
            elif mleft <= realoffset < mright:
                return True

            # Otherwise, if our member has no size and we're using a variable-length structure,
            # then the offset is always "within" the member as long as it comes afterwards.
            elif is_variable and mleft == mright and mright == min(mright, realoffset):
                return True
            continue
        return False

    @classmethod
    def has_bounds(cls, sptr, start, stop):
        '''Return whether any members exist in the structure identified by `sptr` from the offset `start` to `stop`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        size, is_union, is_variable = idaapi.get_struc_size(sptr), union(sptr), True if sptr.props & idaapi.SF_VAR else False
        left, right = sorted(map(int, [start, stop]))

        # Check for early termination by confirming if both boundaries come before or after the
        # structure. If the boundaries are the same, then they also can't contain anything.
        if all(point < 0 for point in [left, right]) or left == right:
            return False

        # If both boundaries come after the structure, then the structure isn't containing
        # them. If it's a variable-length structure, though, then as long the length of
        # the boundaries are larger than 0, then they overlaps with the last member.
        elif all(point >= size for point in [left, right]):
            return True if is_variable and left != right else False

        # Iterate through all of our members and figure out which one contains us.
        for index in range(sptr.memqty):
            mptr, opinfo = sptr.get_member(index), idaapi.opinfo_t()
            retrieved = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)

            # Snag the current member's boundaries. If the structure is
            # a union, then the left boundary should always start at 0.
            mleft, mright = 0 if is_union else mptr.soff, mptr.eoff
            msize, melement = idaapi.get_member_size(mptr), get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None)

            # If it's a union, then we check the boundaries against the size.
            if is_union and left <= mleft and msize <= right:
                return True

            # Otherwise, check if the given bounds contains the member's boundaries.
            elif mleft < mright and left <= mleft and mright <= right:
                return True

            # If our member has no size and we're using a variable-length structure, then
            # the bounds cover it as long as it covers at least one member afterwards.
            elif is_variable and mleft == mright and left <= mleft and mright + melement <= right:
                return True
            continue
        return False

    @classmethod
    def by_identifier(cls, sptr, identifier):
        '''Return the member with the given `identifier` belonging to the structure identified by `sptr`.'''
        sptr = sptr and idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        identifier = identifier if isinstance(identifier, types.integer) else identifier.id

        # We can just ask the API to give us the member for the given identifier.
        result = idaapi.get_member_by_id(identifier)
        if not result:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({!s}, {:#x}) : Unable to locate the member using the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(sptr.id) if sptr else None, identifier, identifier))

        # Now we unpack the information that we retrieved. We also sanity check the
        # sptr to ensure that it is not different from the parameter we were given.
        mptr, fullname, sptr_ = result
        if sptr and sptr.id != sptr_.id:
            this = 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure'
            that = 'union' if union(sptr_) else 'frame' if frame(sptr_) else 'structure'
            raise E.MemberNotFoundError(u"{:s}.by_identifier({!s}, {:#x}) : The member for the specified identifier ({:#x}) is owned by a {:s} ({:#x}) that is different from the requested {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(sptr.id) if sptr else None, identifier, identifier, that, sptr_.id, this, sptr.id))

        # The `idaapi.struc_t` can be racy in some conditions, so we validate the
        # identifier for the sptr and fetch it again using the full name if it is
        # necessary. We also check which get_prev_member_idx/get_next_member_idx
        # we've got since newer versions will actually return 1 for the first member.
        sptr = sptr_ if not sptr or interface.node.identifier(sptr.id) else idaapi.get_member_struc(utils.string.to(fullname))
        base = idaapi.get_prev_member_idx(sptr, sptr.members[0].eoff)

        # Now we need to figure out the index for the member. If our structure
        # is a union, the index is found in the member_t.soff and we can use it.
        if union(sptr):
            mindex = mptr.soff

        # Otherwise, we will need to use the member offset to determine the index. For performance
        # reasons, we ask the disassembler. However, we need to adjust the result by the base index
        # due to newer versions of the disassembler not returning an index of 0 for the first member.
        elif sptr.memqty > 2:
            prev, next = idaapi.get_prev_member_idx(sptr, mptr.eoff), idaapi.get_next_member_idx(sptr, mptr.soff)
            res = prev if next < 0 else next
            mindex = res - base

        # Otherwise, there's only one or two members and we can simply check it since
        # get_member_by_id shouldn't have returned anything if there weren't any members.
        else:
            mindex = 0 if mptr.id == sptr.get_member(0).id else 1

        # Before returning our result, we do one final sanity check just in case.
        if not(0 <= mindex < sptr.memqty) or mptr.id != sptr.get_member(mindex).id:
            raise E.MemberNotFoundError(u"{:s}.by_identifier({:#x}, {:#x}) : Unable to determine the index ({:d} of {:d}) for the member using the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, identifier, mindex, sptr.memqty, identifier))
        return sptr, mindex, mptr

    @classmethod
    def by_index(cls, sptr, index):
        '''Return the member at the specified `index` of the structure identified by `sptr`.'''
        if not(0 <= index < sptr.memqty):
            is_union, sid = union(sptr), sptr.id if isinstance(sptr, idaapi.struc_t) else sptr
            raise E.MemberNotFoundError(u"{:s}.by_index({:#x}, {:d}) : Unable to find a member at the specified index ({:d}) of the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, index, index, 'union' if is_union else 'frame' if frame(sptr) else 'structure', sid))

        mptr = sptr.get_member(index)
        return sptr, index, mptr

    @classmethod
    def by_name(cls, sptr, name):
        '''Return the member with the given `name` belonging to the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        string = name if isinstance(name, types.ordered) else [name]
        packed_string = interface.tuplename(*string)
        mptr = idaapi.get_member_by_name(sptr, utils.string.to(packed_string))
        if not mptr:
            raise E.MemberNotFoundError(u"{:s}.by_name({:#x}, {!r}) : Unable to locate a member with the specified name \"{:s}\" for the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, name, utils.string.escape(packed_string, '"'), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
        return cls.by_identifier(sptr, mptr.id)

    @classmethod
    def by_fullname(cls, name):
        '''Return the member with the given full `name` which is composed of both the structure and member names.'''
        string = name if isinstance(name, types.ordered) else [name]
        packed_string = interface.tuplename(*string)
        packed = idaapi.get_member_by_fullname(utils.string.to(packed_string))
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.by_fullname({!r}) : Unable to locate a member with the specified name \"{:s}\".".format('.'.join([__name__, cls.__name__]), name, utils.string.escape(packed_string, '"')))
        mptr, sptr = packed
        return cls.by_identifier(sptr, mptr.id)

    @classmethod
    def at_offset(cls, sptr, offset):
        '''Yield the members at the specified `offset` of the structure or union identified by `sptr`.'''
        realoffset, sptr = int(offset), idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        size, is_union, is_variable = idaapi.get_struc_size(sptr), union(sptr), True if sptr.props & idaapi.SF_VAR else False

        # First verify that our structure can actually contain the offset and bail if it can't.
        if not cls.contains(sptr, realoffset):
            return

        # If it's not a variable-length structure or union, then we can simply
        # trust the API since there'll only be one member at any given offset.
        elif not any([is_union, is_variable]):
            mptr = idaapi.get_member(sptr, realoffset)
            if mptr:
                yield cls.by_identifier(sptr, mptr)
            return

        # If it's a variable-length structure, then we should be able to just clamp
        # the offset by the size and trust the API. To be sure, we sanity-check the
        # member boundaries if the offset is larger or equal to the structure size.
        elif is_variable and not is_union:
            mptr = idaapi.get_member(sptr, min(size, realoffset))

            # This is just a passthrough that checks the offset is within the member's bounds.
            if any([realoffset < size, size <= realoffset and mptr and mptr.soff == mptr.eoff]):
                pass

            # If the offset is larger than the structure and there wasn't a member
            # or it has a size, then we log a warning about it as a sanity-check.
            elif size <= realoffset:
                description = "instead of member ({:#x}) of size {:+#x}".format(mptr.id, mptr.eoff - mptr.soff) if mptr else ''
                logging.warning(u"{:s}.at_offset({:+#x}, {:s}) : Expected a non-sized member{:s} at the requested offset ({:+#x}) for the variable-length structure ({:#x}) with size {:+#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, "{:#x}".format(offset) if isinstance(offset, types.integer) else "{!s}".format(offset), " {:s}".format(description) if description else '', realoffset, sptr.id, size))

            # At this point, we trust the API and return the member if one was found.
            if mptr:
                yield cls.by_identifier(sptr, mptr)
            return

        # If both flags are set, then technically we should raise an error as they're supposed to be
        # mutally-exclusive. Despite this, this should actually be possible and just wasn't implemented.
        elif all([is_union, is_variable]):
            logging.warning(u"{:s}.at_offset({:+#x}, {:s}) : Disassembler returned a union ({:#x}) with properties ({:#x}) and size (+{:#x}) that is also a variable-length structure.".format('.'.join([__name__, cls.__name__]), sptr.id, "{:#x}".format(offset) if isinstance(offset, types.integer) else "{!s}".format(offset), sptr.id, sptr.props, size))

        # Now we can iterate through the union from the very first index. We filter
        # each member by its bounds and then we discard anything that doesn't match.
        for packed in cls.iterate(sptr):
            sptr, index, mptr = packed
            msize = idaapi.get_member_size(mptr)

            # If the requested offset is within the boundaries of our union member,
            # then we're good and this matches what we were looking for.
            if 0 <= realoffset < msize:
                yield packed

            # This should never happen.. but in case it does, we check the offset
            # against the end of the variable-length member and then yield it.
            elif is_variable and mptr.eoff <= min(mptr.eoff, realoffset):
                yield packed
            continue
        return

    @classmethod
    def at_bounds(cls, sptr, start, stop):
        '''Yield the members from the offset `start` to `stop` within the structure or union identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        size, is_union, is_variable = idaapi.get_struc_size(sptr), union(sptr), True if sptr.props & idaapi.SF_VAR else False
        left, right = sorted(map(int, [start, stop]))

        # If the boundaries are the same, then we can immediately bail because of it
        # being impossible for anything to exist within a 0-length segment.
        if left == right:
            return

        # If it's a union, then we capture the members and sort them by size. This way we
        # can filter them and support returning them in reverse order if we were asked to.
        elif is_union:
            members, direction = {}, +1 if start <= stop else -1
            for packed in cls.iterate(sptr):
                _, _, mptr = packed
                msize = idaapi.get_member_size(mptr)
                members.setdefault(msize, []).append(packed)

            # Now that we've collected them with their sizes, we can traverse them in
            # order and exclude the members that are not within the requested boundaries.
            for msize in sorted(members)[::direction]:
                ordered = members[msize][::direction]

                # If it's not a variable-length member, then we only need to
                # check its boundaries to determine if it should be skipped.
                if not is_variable and not(left <= 0 and msize <= right):
                    continue

                # If the member is variable length, and the boundaries do not
                # encompass the entire member, then we can go ahead and skip it.
                elif is_variable and not(left <= 0 and mptr.eoff <= min(mptr.eoff, right)):
                    continue

                # Now we just have to yield each member (in the correct order).
                for packed in ordered:
                    yield packed
                continue
            return

        # First we need to know what indices are used to represent each member
        # within the given boundaries. This way we can create a slice for iteration.
        lindex = cls.index_before(sptr, left) if left >= 0 else None
        rindex = cls.index_after(sptr, right) if start <= stop else cls.index_before(sptr, right)
        ordering = slice(lindex, rindex, +1) if start <= stop else slice(rindex, lindex - 1 if lindex else None, -1)

        # Iterate through all of the members and check their boundaries one-by-one.
        # We also need to calculate the member size differently if the member is
        # variable-length'd in order to determine whether it should be included.
        for packed in cls.iterate(sptr, ordering):
            sptr, index, mptr = packed
            mleft, mright, msize = mptr.soff, mptr.eoff, idaapi.get_data_elsize(mptr.id, mptr.flag) if is_variable and mptr.soff == mptr.eoff else idaapi.get_member_size(mptr)

            if is_variable and mleft == mright and right >= mright + msize:
                yield packed

            elif mright > mleft and left <= mleft and right >= mright:
                yield packed
            continue
        return

    @classmethod
    def overlaps(cls, sptr, start, stop):
        '''Yield the members belong to the structure or union identified by `sptr` that overlap the given offset from `start` to `stop`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        size, is_union, is_variable = idaapi.get_struc_size(sptr), union(sptr), True if sptr.props & idaapi.SF_VAR else False
        left, right = sorted(map(int, [start, stop]))

        # If the boundares are not different from one another, then technically
        # they're a zero-sized segment and are unable to overlap with anything.
        if left == right:
            return

        # If it's a union, then we need to order the members so that we can determine
        # which direction to process them in and yield them in reverse if desired.
        elif is_union:
            members, direction = {}, +1 if start <= stop else -1
            for packed in cls.iterate(sptr):
                _, _, mptr = packed
                msize = idaapi.get_member_size(mptr)
                members.setdefault(msize, []).append(packed)

            # Now we can sort the members by their size, traverse them and
            # exclude any of the members that aren't overlapping our segment.
            for msize in sorted(members)[::direction]:
                ordered = members[msize][::direction]

                # Although this condition should be impossible, if nothing
                # exists past the union member then this doesn't overlap.
                if is_variable and not(msize <= left):
                    continue

                # If nothing overlaps the boundaries of the member, skip it.
                elif not(left < msize and right > 0):
                    continue

                # Traverse the members we collected in the correct order.
                for packed in members[msize][::direction]:
                    yield packed
                continue
            return

        # We can reduce the number of members that we'll need to iterate through
        # if we know which indices to use so that we can build a slice. This has
        # the added benefit of yielding elements in the same order as was requested.
        lindex = cls.index_before(sptr, left) if left >= 0 else None
        rindex = cls.index_after(sptr, right) if start <= stop else cls.index_before(sptr, right)
        ordering = slice(lindex, rindex, +1) if start <= stop else slice(rindex, lindex - 1 if lindex else None, -1)

        # This is a little different than at_bounds in that we don't really need to calculate the
        # member size correctly since we're only trying to find an intersection with the member.
        for packed in cls.iterate(sptr, ordering):
            _, _, mptr = packed
            mleft, mright = mptr.soff, mptr.eoff

            if is_variable and mptr.soff == mptr.eoff and min(left, mright) <= mright and min(right, mright + 1) > mleft:
                yield packed

            elif left < mright and right > mleft:
                yield packed
            continue
        return

####### The rest of this file contains only definitions of classes that may be instantiated.

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
        '''Return a dictionary of the tags associated with the structure.'''
        return internal.tags.structure.get(self.ptr)
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` for the structure.'''
        res = internal.tags.structure.get(self.ptr)
        if key in res:
            return res[key]
        cls = self.__class__
        raise E.MissingTagError(u"{:s}({:#x}).tag({!r}) : Unable to read the non-existing tag named \"{:s}\" from the structure {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, utils.string.escape(key, '"'), utils.string.repr(self.name)))
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the structure.'''
        return internal.tags.structure.set(self.ptr, key, value)
    @utils.multicase(key=types.string, none=types.none)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Remove the tag identified by `key` from the structure.'''
        return internal.tags.structure.remove(self.ptr, key, none)

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
        cls, Fnetnode = self.__class__, getattr(idaapi, 'ea2node', utils.fidentity)
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
        results, matches = {}, {identifier for identifier in items}
        for xrfrom, xriscode, xrtype in refs:
            flags = address.flags(xrfrom)

            # If the reference is an identifier, then it's not what we're looking
            # for as this method only cares about database addresses.
            if interface.node.identifier(xrfrom):
                continue

            # If the reference is not pointing to code, then we skip this because
            # there's no way it can actually be pointing to an operand.
            if not address.code(xrfrom):
                logging.debug(u"{:s}({:#x}).refs() : Skipping {:s} reference at {:#x} with the type ({:d}) due to its address not being marked as code.".format('.'.join([__name__, cls.__name__]), self.id, 'code' if xriscode else 'data', xrfrom, xrtype))
                continue

            # Iterate through all of its operands and only care about
            # the ones that have operand information for it.
            access = [ref.access for ref in interface.instruction.access(xrfrom)]
            for opnum, operand in enumerate(address.operands(xrfrom)):
                value = idaapi.as_signed(operand.value if operand.type in {idaapi.o_imm} else operand.addr)

                # Collect the operand information into a proper path in case
                # the opinfo_t is damaged...which happens sometimes.
                delta, tids = interface.node.get_stroff_path(xrfrom, opnum)

                # If we grabbed a path, then we can use it to grab the
                # structure and all of its member identifiers.
                if tids:
                    path = interface.strpath.of_tids(delta + value, tids)
                    members, nomember = {member.id for _, member, _ in path if member}, any(member is None for _, member, _ in path)

                    # Verify that one of our ids is contained within it unless the path is
                    # referencing the structure directly. If none of the members in the path
                    # are related to our structure, then we can just ignore this reference.
                    if not any([members & matches, nomember]):
                        continue

                    # Unify the reference we found with the access from the operand.
                    #results.setdefault(xrfrom, []).append(interface.opref_t(xrfrom, opnum, interface.access_t(xrtype, xriscode) | access[opnum]))
                    results.setdefault(xrfrom, []).append(interface.opref_t(xrfrom, opnum, interface.access_t(xrtype, xriscode)))

                # Otherwise this is likely a refinfo or stack variable, and we only need
                # to follow the reference in order to grab it.
                elif idaapi.is_stkvar(flags, opnum) or idaapi.is_stroff(flags, opnum) or idaapi.is_off(flags, opnum):
                    results.setdefault(xrfrom, []).append(interface.opref_t(xrfrom, opnum, interface.access_t(xrtype, xriscode)))
                continue
            continue

        merged = {ea : functools.reduce(operator.or_, items) for ea, items in results.items()}
        return [merged[ea] for ea in sorted(results)]

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
        '''Return the boundaries of the entire structure.'''
        bounds, base = self.realbounds, self.members.baseoffset
        return operator.add(bounds, base)

    @property
    def location(self):
        '''Return the location of the entire structure.'''
        sptr, offset = self.ptr, self.members.baseoffset
        return interface.location_t(offset, idaapi.get_struc_size(sptr))

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
        cls, sptr = self.__class__, self.ptr

        # grab the index
        idx = idaapi.get_struc_idx(sptr.id)

        # then its name...which we need to check since we wouldn't be able to parse it.
        originalname = utils.string.of(idaapi.get_struc_name(sptr.id) or '')
        validname = internal.declaration.unmangled.parsable(originalname)
        if originalname != validname:
            logging.warning(u"{:s}({:#x}) : Structure name \"{:s}\" will not be parsable by the disassembler and could be changed to \"{:s}\" during deserialization.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.escape(originalname, '"'), utils.string.escape(validname, '"')))
        name = originalname if originalname == validname else (originalname, validname)

        # decode the comments that we found in the structure
        cmtt, cmtf = map(functools.partial(idaapi.get_struc_cmt, self.id), [True, False])
        comments = tuple(utils.string.of(cmt) for cmt in [cmtt, cmtf])

        # pack our state into a tuple.
        state = idx, sptr.props, name, comments

        # FIXME: we double-pickle here to ensure the structure gets created before the members
        #        because 15 years ago when i wrote this, i was an idiot and didn't consider
        #        the order of the relationships that pickle infers during deserialization.
        return state, pickle.dumps(self.members)

    def __setstate__(self, state):

        # Restore the index (discarded), properties, name, and comments.
        if len(state) == 2:
            state, members = state
            idx, props, packed_name, (cmtt, cmtf) = state

        # For backwards compatibility...
        else:
            packed_name, (cmtt, cmtf), members = state
            idx, props = -1, 0

        # First check if the name is a tuple, if it isn't then we can use the name as-is.
        if not isinstance(packed_name, tuple):
            name = original = packed_name

        # If it is a tuple, then the structure name will not be parsable in types
        # and we need to figure out whether to use the original or the parsable one.
        else:
            original, parsable = packed_name
            name = parsable if idaapi.get_struc_id(utils.string.to(original)) == idaapi.BADADDR else original

        # try and find the structure in the database by its name. if we couldn't find
        # it and the original doesn't match then we'll need to warn the user about it.
        cls, identifier = self.__class__, idaapi.get_struc_id(utils.string.to(name))
        if identifier == idaapi.BADADDR and name != original:
            logging.warning(u"{:s}({:#x}) : Structure will be created with the name \"{:s}\" instead of the original \"{:s}\" which would not be parsable by the disassembler.".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(name, '"'), utils.string.escape(original, '"')))
        elif isinstance(packed_name, tuple) and name == original:
            logging.warning(u"{:s}({:#x}) : Structure with the name \"{:s}\" is not parsable and may cause an issue with local types.".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(name, '"')))

        # if we didn't find it, then just add it and notify the user
        if identifier == idaapi.BADADDR:
            logging.info(u"{:s}({:#x}) : Creating structure \"{:s}\" with {:d} fields and the comment \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(name, '"'), len(members), utils.string.escape(cmtf or cmtt or '', '"')))
            identifier = idaapi.add_struc(idaapi.BADADDR, utils.string.to(name), True if props & idaapi.SF_UNION else False)

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
        self.__members__ = pickle.loads(members) if isinstance(members, bytes) else members
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
        if not isinstance(index, (types.integer, types.float)):
            other, operation = index, operator.pow
            raise TypeError(u"{:s}({:#x}).__pow__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, operation, other, operation.__name__, other.__class__.__name__, cls.__name__))

        offset, relative = self.members.baseoffset, math.trunc(self.size * index)
        return cls(sptr, offset=offset + relative)

    def __lshift__(self, count):
        '''Return an instance of the structure shifted `count` times to a lower address.'''
        return self.__pow__(-count)

    def __rshift__(self, count):
        '''Return an instance of the structure shifted `count` times to a higher address.'''
        return self.__pow__(+count)

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
        '''Return a dictionary of the tags associated with the member.'''
        return internal.tags.member.get(self.ptr)
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key')
    def tag(self, key):
        '''Return the tag identified by `key` for the member.'''
        res = internal.tags.member.get(self.ptr)
        if key in res:
            return res[key]
        cls = self.__class__
        raise E.MissingTagError(u"{:s}({:#x}).tag({!r}) : Unable to read the non-existing tag named \"{:s}\" from the member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, key, utils.string.escape(key, '"'), utils.string.repr(self.fullname)))
    @utils.multicase(key=types.string)
    @utils.string.decorate_arguments('key', 'value')
    def tag(self, key, value):
        '''Set the tag identified by `key` to `value` for the member.'''
        return internal.tags.member.set(self.ptr, key, value)
    @utils.multicase(key=types.string, none=types.none)
    @utils.string.decorate_arguments('key')
    def tag(self, key, none):
        '''Remove the tag identified by `key` from the member.'''
        return internal.tags.member.remove(self.ptr, key, none)

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
            for ea, opnum, xtype in interface.xref.frame(ea, mptr):
                res.append(interface.opref_t(ea, opnum, interface.access_t(xtype, True)))

            # include any xrefs too in case the user (or the database) has
            # explicitly referenced the frame variable using a structure path.
            for ea, iscode, xtype in interface.xref.to(mptr.id, idaapi.XREF_ALL):
                flags, access = interface.address.flags(ea, idaapi.MS_0TYPE|idaapi.MS_1TYPE), [ref.access for ref in interface.instruction.access(ea)]

                # first we need to figure out which operand the reference is
                # referring to. if we couldn't find any, then complain about it.
                listable = [(opnum, operand, address.opinfo(ea, opnum)) for opnum, operand in enumerate(address.operands(ea)) if address.opinfo(ea, opnum)]
                if not listable:
                    logging.debug(u"{:s}.refs() : Skipping reference to member ({:#x}) at {:#x} with flags ({:#x}) due to no operand information.".format('.'.join([__name__, cls.__name__]), mptr.id, ea, address.flags(ea)))

                # if our flags represent a structure offset (they should), then we
                # use the structure path to find the operand that exists.
                elif flags & FF_STROFF in {FF_STROFF, idaapi.FF_0STRO, idaapi.FF_1STRO}:
                    logging.debug(u"{:s}.refs() : Found strpath_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, ea, address.flags(ea)))
                    iterable = [(opnum, idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr), interface.node.get_stroff_path(ea, opnum)) for opnum, op, _ in listable]
                    iterable = ((opnum, interface.strpath.of_tids(delta + value, tids)) for opnum, value, (delta, tids) in iterable if tids)
                    iterable = ((opnum, {member.id for _, member, _ in path}) for opnum, path in iterable)
                    iterable = ((opnum, access[opnum]) for opnum, identifiers in iterable if mptr.id in identifiers)
                    res.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

                # if we couldn't figure it out, then we log a warning and bail.
                # there really shouldn't be any other operand flag for a stkvar.
                else:
                    logging.warning(u"{:s}.refs() : Skipping reference to member ({:#x}) at {:#x} with flags ({:#x}) due to the operand type being unexpected.".format('.'.join([__name__, cls.__name__]), mptr.id, ea, address.flags(ea)))
                continue
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
        for ea, iscode, xtype in refs:
            flags, access = interface.address.flags(ea, idaapi.MS_0TYPE|idaapi.MS_1TYPE), [item for item in interface.instruction.access(ea)]
            listable = [(opnum, operand, address.opinfo(ea, opnum)) for opnum, operand in enumerate(address.operands(ea)) if address.opinfo(ea, opnum)]

            # If we have any stack operands, then figure out which ones contain it. Fortunately,
            # we don't have to filter it through our candidates because IDA seems to get this right.
            if flags & FF_STKVAR in {FF_STKVAR, idaapi.FF_0STK, idaapi.FF_1STK}:
                logging.debug(u"{:s}.refs() : Found stkvar_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                masks = [(idaapi.MS_0TYPE, idaapi.FF_0STK), (idaapi.MS_1TYPE, idaapi.FF_1STK)]
                iterable = ((opnum, access[opnum]) for opnum, (mask, ff) in enumerate(masks) if flags & mask == ff)
                results.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

            # Otherwise, we can skip this reference because there's no way to process it.
            elif not listable:
                logging.debug(u"{:s}.refs() : Skipping reference to member ({:#x}) at {:#x} with flags ({:#x}) due to no operand information.".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))

            # If our flags mention a structure offset, then we can just get the structure path.
            elif flags & FF_STROFF in {FF_STROFF, idaapi.FF_0STRO, idaapi.FF_1STRO}:
                logging.debug(u"{:s}.refs() : Found strpath_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                iterable = [(opnum, idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr), interface.node.get_stroff_path(ea, opnum)) for opnum, op, _ in listable]
                iterable = ((opnum, interface.strpath.of_tids(delta + value, tids)) for opnum, value, (delta, tids) in iterable if tids)
                iterable = ((opnum, {member.id for _, member, _ in path}) for opnum, path in iterable)
                iterable = ((opnum, access[opnum]) for opnum, identifiers in iterable if identifiers & candidates)
                results.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

            # Otherwise, we need to extract the information from the operand's refinfo_t. We
            # filter these by only taking the ones which we can use to calculate the target.
            else:
                logging.debug(u"{:s}.refs() : Found refinfo_t to member ({:#x}) at {:#x} with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), self.id, ea, address.flags(ea)))
                iterable = ((opnum, info.ri, address.reference(ea, opnum)) for opnum, _, info in listable if info.ri.is_target_optional())

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
                        results.append(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)))
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
    def location(self):
        '''Return the location of the member.'''
        parent = self.parent
        bounds, base = self.realbounds, parent.members.baseoffset
        left, right = bounds
        return interface.location_t(base + left, bounds.size)
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
        return member.get_name(self.ptr)
    @name.setter
    @utils.string.decorate_arguments('string')
    def name(self, string):
        '''Set the name of the member to `string`.'''
        string = interface.tuplename(*string) if isinstance(string, types.ordered) else string

        # Type safety is fucking valuable, and in python it's an after-thought.
        if isinstance(string, (types.none, types.string)):
            return member.set_name(self.ptr, string) if string else member.remove_name(self.ptr)

        cls = self.__class__
        raise E.InvalidParameterError(u"{:s}({:#x}).name({!r}) : Unable to assign an unsupported type ({!s}) as the name for the member.".format('.'.join([__name__, cls.__name__]), self.id, string, string.__class__))

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
            info = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if info is None:
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}).type({!s}) : Unable to parse the specified type declaration ({!s}) for structure member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr("{!s}".format(type)), utils.string.escape("{!s}".format(type), '"'), utils.string.repr(self.name)))
            return member.set_typeinfo(self.ptr, info, idaapi.SET_MEMTI_MAY_DESTROY)

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
        return member.get_typeinfo(self.ptr)

    @typeinfo.setter
    def typeinfo(self, info):
        '''Set the type information of the current member to `info`.'''
        mptr = self.ptr

        # Type safety is fucking valuable, and we are contractually obligated
        # to deliver an exception for anything that doesn't match our needs.
        if not isinstance(info, (idaapi.tinfo_t, types.none, types.string)):
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).typeinfo({!s}) : Unable to assign the provided type ({!s}) to the type information for the member.".format('.'.join([__name__, cls.__name__]), self.id, info if info is None else utils.string.repr(info), info.__class__))

        # If we're being asked to assign None to the type information, then we
        # remove it..Otherwise, we'll make a compatible attempt to assign it.
        return member.set_typeinfo(mptr, info) if info else member.remove_typeinfo(mptr)

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

        # grab its parent name along with its name and a parsable name.
        parentname, name = fullname.split('.', 1)
        validname = internal.declaration.unmangled.parsable(parentname)

        # now we need to check if the parent name is parsable, because if it isn't
        # then we need to pack both the original and valid name for the parent.
        parent = parentname if parentname == validname else (parentname, validname), sptr.props, parentbase

        # pack up our state
        state = mptr.props, mptr.soff, typeinfo, name, comments

        # combine parent state with our location (index) and state
        return parent, self.__index__, state
    def __setstate__(self, state):
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # Restore all the attributes we need to deserialize.
        if len(state) == 3:
            parent, index, state = state
            packed_parentname, parentprops, parentbase = parent
            props, soff, typeinfo, name, (cmtt, cmtf) = state

        # In order to remain backwards compatible...
        else:
            packed_parentname, index, name, (cmtt, cmtf), soff, typeinfo = state
            parentprops = props = 0
            parentbase = 0

        # If our parentname is a tuple, then the parent name is non-parsable and
        # we need to figure out if this is what the user explicitly wanted or not.
        if isinstance(packed_parentname, tuple):
            original, parsable = packed_parentname
            parentname = parsable if idaapi.get_struc_id(utils.string.to(original)) == idaapi.BADADDR else original

        # Otherwise the names match and the declaration should be parsable.
        else:
            parentname = original = packed_parentname

        # get the structure owning the member by the name we determined. if we couldn't
        # find it and the original doesn't match, then we need to complain about it.
        cls, identifier, fullname = self.__class__, idaapi.get_struc_id(utils.string.to(parentname)), '.'.join([parentname, name])
        if identifier == idaapi.BADADDR and parentname != original:
            logging.warning(u"{:s}({:#x}, index={:d}) : Field will be created as \"{:s}\" instead of the original \"{:s}\" which had a structure name that is not parsable.".format('.'.join([__name__, cls.__name__]), identifier, index, utils.string.escape(fullname, '"'), utils.string.escape(original, '"')))

        elif isinstance(packed_parentname, tuple) and parentname == original:
            logging.info(u"{:s}({:#x}, index={:d}) : Field being created as \"{:s}\" with an unparsable structure name (\"{:s}\") which may cause an issue with local types.".format('.'.join([__name__, cls.__name__]), identifier, index, utils.string.escape(fullname, '"'), utils.string.escape(parentname, '"')))

        # get the structure owning the member by the name we stored creating it if necessary.
        if identifier == idaapi.BADADDR:
            logging.info(u"{:s}({:#x}, index={:d}) : Creating structure ({:s}) for field named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, index, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, utils.string.to(parentname), True if parentprops & idaapi.SF_UNION else False)

        if identifier == idaapi.BADADDR:
            raise E.DisassemblerError(u"{:s}({:#x}, {:s}) : Unable to get structure ({:s}) for field named \"{:s}\" with the comment {!r}.".format('.'.join([__name__, cls.__name__]), identifier, index, parentname, utils.string.escape(name, '"'), cmtt or cmtf or ''))

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
                logging.warning(u"{:s}({:#x}, index={:d}): Unexpected DT_TYPE was found in flags ({:#x}) for the untyped field \"{:s}\" of structure ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, flag, utils.string.escape(name, '"'), parentname))

        # if we have an integer or a structure_t, then assign it as the identifier for the opinfo.
        else:
            opinfo.tid = mytype if isinstance(mytype, types.integer) else mytype.id

        # add the member to the database if the name exists, and then check whether
        # there was a naming issue of some sort so that we can warn the user or resolve it.
        res = utils.string.to(name)
        if res:
            mem = idaapi.add_struc_member(sptr, res, idaapi.BADADDR if sptr.props & idaapi.SF_UNION else soff, flag, opinfo, nbytes)

        # now for a trick. since the member name doesn't exist and we need the disassembler to
        # display the name prefixed with "lost_field_name_", we create the member with a placeholder
        # based on the offset. iff we succeed, then we modify the member name using a netnode.
        else:
            Fgenerate_unique_name = lambda recurse, sptr, aggro=u'': (lambda unique_name: unique_name if not idaapi.get_member_by_name(sptr, unique_name) else recurse(recurse, sptr, aggro + u'_'))(unique_name=''.join([u"_{:x}".format(sptr.id), aggro]))
            unique = Fgenerate_unique_name(Fgenerate_unique_name, sptr)
            mem = idaapi.add_struc_member(sptr, unique, idaapi.BADADDR if sptr.props & idaapi.SF_UNION else soff, flag, opinfo, nbytes)

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
                logging.warning(u"{:s}({:#x}, index={:d}): Duplicate name found for field \"{:s}\" of {:s} ({:s}), renaming it to \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(name, '"'), 'union' if sptr.props & idaapi.SF_UNION else 'structure', parentname, utils.string.escape(newname, '"')))
                idaapi.set_member_name(sptr, soff, utils.string.to(newname))

            elif mptr:
                logging.info(u"{:s}({:#x}, index={:d}): Ignoring field at index {:d} of {:s} ({:s}) with the same name (\"{:s}\") and position ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, index, 'union' if sptr.props & idaapi.SF_UNION else 'structure', parentname, utils.string.escape(name, '"'), soff))

            else:
                logging.warning(u"{:s}({:#x}, index={:d}): Field at index {:d} of {:s} ({:s}) could not be found using its expected name (\"{:s}\").".format('.'.join([__name__, cls.__name__]), sptr.id, index, index, 'union' if sptr.props & idaapi.SF_UNION else 'structure', parentname, utils.string.escape(name, '"')))

        # duplicate field (same offset)
        elif mem == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            mptr = idaapi.get_member(sptr, soff)
            if (utils.string.of(idaapi.get_member_name(mptr.id)), mptr.flag, idaapi.get_member_size(mptr)) != (res, flag, nbytes):
                logging.warning(u"{:s}({:#x}, index={:d}): Already existing field found at {:s} ({:s}) with size ({:#x}) and flags ({:#x}), overwriting it with \"{:s}\" of size ({:#x}) and flags ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, "index {:d} of union".format(soff) if sptr.props & idaapi.SF_UNION else "offset {:+#x} of structure".format(soff), parentname, idaapi.get_member_size(mptr), mptr.flag, utils.string.escape(name, '"'), nbytes, flag))
                idaapi.set_member_type(sptr, soff, flag, opinfo, nbytes)
                idaapi.set_member_name(sptr, soff, res)

        # unknown
        elif mem != idaapi.STRUC_ERROR_MEMBER_OK:
            errors = {getattr(idaapi, name): name for name in dir(idaapi) if name.startswith('STRUC_ERROR_')}
            logging.warning(u"{:s}({:#x}, index={:d}): Error {:s} returned while trying to create field \"{:s}\" at {:s} with size ({:#x}) and flags ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index, "{:s}({:#x})".format(errors[mem], mem) if mem in errors else "code ({:#x})".format(mem), utils.string.escape(fullname, '"'), "index {:d} of union".format(soff) if sptr.props & idaapi.SF_UNION else "offset {:+#x} of structure".format(soff), nbytes, flag))

        # check the index and count, as we've already added it properly (STRUC_ERROR_MEMBER_OK)
        elif index != count:
            logging.warning(u"{:s}({:#x}, index={:d}): The field that was created (\"{:s}\") was expected at index {:d} but was created at index {:d}.".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), index, count))
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
            typeinfo = interface.tinfo.parse(None, tname, idaapi.PT_SIL) if tname else None
            typeinfo = typeinfo if typeinfo else interface.tinfo.parse(None, tinfo, idaapi.PT_SIL)
            None if typeinfo is None else logging.info(u"{:s}({:#x}, index={:d}): Successfully parsed type information for field \"{:s}\" as \"{!s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), typeinfo))

        # otherwise it's the old version (a tuple), and it shouldn't need to
        # exist... but, if we can actually deserialize it then later we can
        # likely apply it...unless it has an ordinal.
        else:
            typeinfo = idaapi.tinfo_t()
            if typeinfo.deserialize(None, *ti):
                logging.debug(u"{:s}({:#x}, index={:d}): Successfully deserialized type information for field \"{:s}\" as \"{!s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, utils.string.escape(fullname, '"'), typeinfo))
            else:
                logging.info(u"{:s}({:#x}, index={:d}): Skipping application of corrupted type information ({!r}) for field \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, ti, utils.string.escape(fullname, '"')))
                typeinfo = None

        # before we do anything, we need to grab the original type information and check
        # it against what we deserialized in case we don't need to apply anything.
        original = self.typeinfo if mem == idaapi.STRUC_ERROR_MEMBER_OK else None
        original_typeinfo = "{!s}".format(original if original else idaapi.tinfo_t())
        typeinfo = typeinfo if typeinfo and original and original.compare_with(typeinfo, idaapi.TCMP_EQUAL) else None

        # if tinfo was defined and it doesn't use an ordinal, then we can apply it.
        # FIXME: we are likely going to need to traverse this to determine if it's using an ordinal or not
        if typeinfo and not any([typeinfo.get_ordinal(), typeinfo.is_array() and typeinfo.get_array_element().get_ordinal()]):
            try:
                self.typeinfo = typeinfo

            # if the type is not ideal, then we can pretty much ignore this because
            # the type is already there and IDA thinks that it's okay.
            except E.DisassemblerError as exc:
                if 'type is not ideal' in "{!s}".format(exc):
                    logging.info(u"{:s}({:#x}, index={:d}): Refused to apply the type information \"{!s}\" to the field \"{:s}\" with current type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))
                    logging.debug(u"{!s}".format(exc))

                # otherwise, we need to warn the user about what happened.
                else:
                    logging.warning(u"{:s}({:#x}, index={:d}): Unable to apply the type information \"{!s}\" to the field \"{:s}\" with current type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))
                    logging.warning(u"{!s}".format(exc))

            # we're good, it was applied.
            else:
                logging.info(u"{:s}({:#x}, index={:d}): Applied the type information \"{!s}\" to the field \"{:s}\" with original type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))

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
                    logging.info(u"{:s}({:#x}, index={:d}): Refused to apply the guessed type information \"{!s}\" to the field \"{:s}\" with current type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))
                    logging.debug(u"{!s}".format(exc))

                else:
                    logging.warning(u"{:s}({:#x}, index={:d}): Unable to apply the guesed type information \"{!s}\" to the field \"{:s}\" with current type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))
                    logging.warning(u"{!s}".format(exc))

            # if we applied it, then we're good.
            else:
                ok and logging.info(u"{:s}({:#x}, index={:d}): Applied the type information \"{!s}\" to the field \"{:s}\" with original type \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index, typeinfo, utils.string.escape(fullname, '"'), utils.string.escape(original_typeinfo, '"')))
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
        `iregex` - Filter the structure members according to a case-insensitive regular-expression
        `index` - Filter the structure members by an index or a list of indices
        `fullname` - Filter the structure members by matching its full name according to a glob
        `comment` or `comments` - Filter the structure members by applying a glob to its comment
        `named` - Filter the structure members for any that use a name specified by the user
        `tagged` - Filter the structure members for any that use the specified tag(s)
        `typed` or `types` - Filter the structure members for any that use the specified type
        `identifier` or `id` - Filter the structure members by an identifier or a list of identifiers
        `bounds` - Match the structure members that overlap with the given boundaries
        `location` - Match the structure members that overlap with the specified location
        `within` - Filter the structure members within the given boundaries
        `greater` or `ge` - Filter the structure members for any after the specified offset (inclusive)
        `gt` - Filter the structure members for any after the specified offset (exclusive)
        `less` or `le` - Filter the structure members for any before the specified offset (inclusive)
        `lt` - Filter the structure members for any before the specified offset (exclusive)
        `member` - Filter the structure members by their ``member_t`` or a list of ``member_t``
        `structures` or `struc` - Filter the structure members that use or reference the given structures
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

    def __call__(self, *string, **type):
        '''Return each of the members within the structure as a list.'''
        return [member for member in self.iterate(*string, **type)]

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
    @utils.string.decorate_arguments('regex', 'iregex', 'name', 'like', 'fullname', 'comment', 'comments')
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
    @utils.string.decorate_arguments('regex', 'iregex', 'name', 'like', 'fullname', 'comment', 'comments')
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
    @utils.multicase(structure=(idaapi.struc_t, structure_t))
    def has(self, structure):
        '''Return whether any members uses the specified `structure` as a field or references it as a pointer.'''
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        owner, tid, tinfo = self.owner.ptr, None if sptr.id == idaapi.BADADDR else sptr.id, address.type(sptr.id)
        stype = None if tinfo is None else interface.tinfo.structure(tinfo)
        for midx in range(owner.memqty):
            mptr = owner.get_member(midx)

            # First retrieve the type and check if the type-id matches.
            opinfo = idaapi.opinfo_t()
            res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            if res and res.tid == tid:
                return True

            # Otherwise we need to check if we're able to compare the type
            # and then we can extract the type information and compare.
            mtype = address.type(mptr.id)
            if any([mtype is None, stype is None]):
                continue

            # Try to resolve the member's type. We use the exception
            # to assign "None" to candidate if we couldn't resolve it.
            try: candidate = interface.tinfo.structure(mtype)
            except (E.DisassemblerError, TypeError): candidate = None

            # If the types actually matched, then we can return success.
            if candidate and interface.tinfo.equals(stype, candidate):
                return True
            continue
        return False
    @utils.multicase(info=idaapi.tinfo_t)
    def has(self, info):
        '''Return whether the types of any of the members are the same as the type information in `info`.'''
        owner = self.owner.ptr
        for midx in range(owner.memqty):
            mptr = owner.get_member(midx)
            mtype = address.type(mptr.id)
            if mtype is not None and interface.tinfo.equals(mtype, info):
                return True
            continue
        return False

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
    @utils.multicase()
    def add(self, **offset):
        '''Append a member with the default type to the end of the structure.'''
        return self.add((), int, **offset)
    @utils.multicase(name=(types.string, types.ordered))
    @utils.string.decorate_arguments('name')
    def add(self, name, **offset):
        '''Append the specified member `name` with the default type to the end of the structure.'''
        return self.add(name, int, **offset)
    @utils.multicase(name=(types.string, types.tuple))
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
        res = interface.tinfo.parse(None, type, idaapi.PT_SIL) if isinstance(type, types.string) else type
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
            cls, res = self.__class__, member.default_name(owner.ptr, None, index if union(owner.ptr) else realoffset)
            logging.info(u"{:s}({:#x}).members.add({!r}, {!r}, {:+#x}) : Name is undefined, defaulting to {:s} name \"{:s}\".".format('.'.join([__name__, cls.__name__]), owner.ptr.id, name, utils.string.repr(tdescr), offset, 'union' if union(owner.ptr) else 'structure', utils.string.escape(res, '"')))
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
    __members_matcher.combinator('iregex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), 'name')
    __members_matcher.combinator('regex', utils.fcompose(re.compile, operator.attrgetter('match')), 'name')
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
    __members_matcher.mapping('named', operator.truth, 'ptr', member.has_name)
    __members_matcher.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, internal.types.bool) else operator.contains(keys, parameter) if isinstance(parameter, internal.types.string) else keys & internal.types.set(parameter), 'ptr', internal.tags.member.get, operator.methodcaller('keys'), internal.types.set, utils.freverse(operator.sub, {'__name__', '__typeinfo__'}))
    __members_matcher.alias('tag', 'tagged')
    __members_matcher.combinator('type', utils.fcondition(utils.finstance(internal.types.bool, internal.types.integer), utils.finstance(idaapi.tinfo_t), utils.finstance(idaapi.struc_t, structure_t), utils.finstance(internal.types.unordered))(utils.fcompose(utils.fcompose(operator.truth, utils.fpartial(utils.fpartial, operator.eq)), utils.fpartial(utils.fcompose, utils.fpartial(idaapi.get_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.get_member_tinfo, idaapi.tinfo_t()))), utils.fcompose(utils.fpartial(utils.fpartial, interface.tinfo.equals), utils.fpartial(utils.fcompose, member.get_typeinfo)), utils.fcompose(operator.attrgetter('id'), address.type, utils.fpartial(utils.fpartial, interface.tinfo.equals), utils.fpartial(utils.fcompose, member.get_typeinfo)), utils.fcompose(utils.fpartial(map, utils.fcondition(utils.finstance(idaapi.struc_t, structure_t), utils.finstance(idaapi.tinfo_t))(utils.fcompose(operator.attrgetter('id'), address.type), utils.fidentity, utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('__class__'), operator.attrgetter('__name__')), utils.fidentity), utils.funpack(utils.fpartial("{:s} : Unable to match the requested filter (\"{:s}\") with an unsupported type \"{:s}\" ({!r}).".format, '.'.join([__name__, 'members_t']), 'type')), utils.fthrow(E.InvalidMatchTypeError)))), utils.fpartial(filter, None), utils.fpartial(map, utils.fpack(utils.fidentity, None)), utils.fpartial(map, utils.funpack(utils.fpartial, interface.tinfo.equals)), utils.fpartial(map, utils.fpartial(utils.fcompose, member.get_typeinfo)), utils.funpack(utils.fthrough), utils.frpartial(utils.fcompose, any)), utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('__class__'), operator.attrgetter('__name__')), utils.fidentity), utils.funpack(utils.fpartial("{:s} : Unable to match the requested filter (\"{:s}\") with an unsupported type \"{:s}\" ({!r}).".format, '.'.join([__name__, 'members_t']), 'type')), utils.fthrow(E.InvalidMatchTypeError))), 'ptr')
    __members_matcher.alias('typed', 'type'), __members_matcher.alias('types', 'type')
    __members_matcher.boolean('ge', operator.le, utils.fthrough(operator.attrgetter('offset'), utils.fcompose(operator.attrgetter('size'), utils.fpartial(operator.add, -1), utils.fpartial(max, 0))), utils.funpack(operator.add)), __members_matcher.alias('greater', 'ge')
    __members_matcher.boolean('gt', operator.lt, utils.fthrough(operator.attrgetter('offset'), utils.fcompose(operator.attrgetter('size'), utils.fpartial(operator.add, -1), utils.fpartial(max, 0))), utils.funpack(operator.add))
    __members_matcher.boolean('le', operator.ge, 'offset')
    __members_matcher.boolean('lt', operator.gt, 'offset'), __members_matcher.alias('less', 'lt')
    __members_matcher.combinator('member', utils.fcondition(utils.finstance(idaapi.member_t, member_t))(utils.fcompose(operator.attrgetter('id'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(filter, utils.finstance(idaapi.member_t, member_t)), utils.fpartial(map, operator.attrgetter('id')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), 'id')
    __members_matcher.alias('members', 'member')
    __members_matcher.combinator('structure', utils.fcondition(utils.finstance(internal.types.string), utils.finstance(idaapi.struc_t, structure_t), utils.finstance(idaapi.tinfo_t), utils.finstance(internal.types.unordered))(utils.fcompose(idaapi.get_struc_id, utils.fcondition(utils.fpartial(operator.ne, idaapi.BADADDR))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, utils.fconstant(False)))), utils.fcompose(operator.attrgetter('id'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(operator.methodcaller('get_type_name'), idaapi.get_struc_id, utils.fcondition(utils.fpartial(operator.ne, idaapi.BADADDR))(utils.fidentity, None), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, utils.fcondition(utils.finstance(internal.types.string), utils.finstance(idaapi.struc_t, structure_t), utils.finstance(idaapi.tinfo_t))(utils.fcompose(idaapi.get_struc_id, utils.fcondition(utils.fpartial(operator.ne, idaapi.BADADDR))(utils.fidentity, utils.fpartial(utils.fpartial, utils.fconstant(None)))), operator.attrgetter('id'), utils.fcompose(utils.fcatch(None)(None)(interface.tinfo.resolve), utils.fcondition(utils.fpartial(operator.ne, None))(utils.fcompose(operator.methodcaller('get_type_name'), idaapi.get_struc_id), utils.fidentity)), utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('__class__'), operator.attrgetter('__name__')), utils.fidentity), utils.funpack(utils.fpartial("{:s} : Unable to match the requested filter (\"{:s}\") with an unsupported type \"{:s}\" ({!r}).".format, '.'.join([__name__, 'members_t']), 'structure')), utils.fthrow(E.InvalidMatchTypeError)))), utils.fpartial(filter, utils.fpartial(operator.ne, None)), internal.types.set, utils.fpartial(utils.fpartial, operator.contains)), utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('__class__'), operator.attrgetter('__name__')), utils.fidentity), utils.funpack(utils.fpartial("{:s} : Unable to match the requested filter (\"{:s}\") with an unsupported type {:s} ({!r}).".format, '.'.join([__name__, 'members_t']), 'structure')), utils.fthrow(E.InvalidMatchTypeError))), 'ptr', member.get_typeinfo, utils.fcatch(None)(None)(interface.tinfo.structure), utils.fcondition(utils.finstance(idaapi.tinfo_t))(utils.fcompose(operator.methodcaller('get_type_name'), idaapi.get_struc_id), idaapi.BADADDR))
    __members_matcher.alias('structures', 'structure'), __members_matcher.alias('struc', 'structure'),
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
        offset, mn, ms, mti = self.baseoffset, 0, 0, 0
        for i in range(len(self)):
            m = self[i]
            name, t, ti, moffset, msize, comment, tag = m.name, m.type, m.typeinfo, m.offset, m.size, m.comment, m.tag()
            res.append((-1, '', [None, moffset - offset], None, offset, moffset - offset, '', {})) if offset < moffset else None
            res.append((i, name, t, ti, moffset, msize, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(moffset - offset)))
            ms = max(ms, len("{:+#x}".format(msize)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))
            offset = moffset + msize

        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1

        if len(self):
            mo = max(map(len, map("{:x}".format, [self.baseoffset, self[-1].offset + self[-1].size])))
            return "{!r}\n{:s}".format(self.owner, '\n'.join("{:<{:d}s} {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s}{:s}".format('' if i < 0 else "[{:d}]".format(i), 2 + mi, o, mo, s, ms, "{!s}".format(ti.dstr()).replace(' *','*') if ti else '', mti, '' if i < 0 else utils.string.repr(n), mn + 2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else utils.string.to(c)) if c else '') for i, n, t, ti, o, s, c, T in res))
        return "{!r}".format(self.owner)

    def __unicode__(self):
        '''Render all of the fields within the current structure.'''
        res = []
        offset, mn, ms, mti = self.baseoffset, 0, 0, 0
        for i in range(len(self)):
            m = self[i]
            name, t, ti, moffset, msize, comment, tag = m.name, m.type, m.typeinfo, m.offset, m.size, m.comment, m.tag()
            res.append((-1, '', [None, moffset - offset], None, offset, moffset - offset, '', {})) if offset < moffset else None
            res.append((i, name, t, ti, moffset, msize, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(moffset - offset)))
            ms = max(ms, len("{:+#x}".format(msize)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))
            offset = moffset + msize

        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1

        if len(self):
            mo = max(map(len, map("{:x}".format, (self.baseoffset, self[-1].offset + self[-1].size))))
            return u"{!r}\n{:s}".format(self.owner, '\n'.join("{:<{:d}s} {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s}{:s}".format('' if i < 0 else "[{:d}]".format(i), mi, o, mo, s, ms, "{!s}".format(ti.dstr()).replace(' *','*') if ti else '', mti, '' if i < 0 else utils.string.repr(n), mn + 2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else utils.string.to(c)) if c else '') for i, n, t, ti, o, s, c, T in res))
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
            start, stop, items = interface.strpath.members(owner.ptr, index)
            iterable = itertools.chain([] if union(owner.ptr) else [start] if start and index.start is None else [], (member for offset, member in items))
            res = [member for member in iterable]
            offset, last = items[-1] if items else (stop, 0)
            size = idaapi.get_member_size(last) if isinstance(last, idaapi.member_t) else last
            point = offset + size
            res.append(stop - point) if index.stop is None and stop > point else point
            res = [(self.by_identifier(mptr.id) if isinstance(mptr, idaapi.member_t) else mptr) for mptr in res]

        else:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__getitem__({!r}) : An invalid type ({!s}) was specified for the index.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, index.__class__))

        if res is None:
            cls, where = self.__class__, "with the specified name (\"{:s}\")".format(index) if isinstance(index, types.string) else "at the given index ({:d})".format(index)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.__getitem__({:d}) : Unable to find a member {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, where))
        return res

    def __setitem__(self, index, item):
        '''Replace the member(s) within the specified `index` with a copy of the specified `item` or list of items.'''
        cls, sptr, base, index_description = self.__class__, self.owner.ptr, self.baseoffset, "{!s}".format(index)
        multiple = isinstance(item, types.ordered) and not isinstance(item, interface.namedtypedtuple)
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # First we need to validate our parameters to ensure we were given
        # a slice if we're being asked to assign an iterable of items.
        if multiple and not isinstance(index, slice):
            iterable = interface.contiguous.describe(item if multiple else [item])
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to assign a non-iterable to a slice ({!r}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, ', '.join(iterable), index))

        # Now we can convert our items to a list and use the index to select all of the
        # contiguous members using the slice that we are being asked to assign to.
        items = item if multiple else [item]
        items_description = "[{:s}]".format(', '.join(interface.contiguous.describe(items)))
        left, right, selected = interface.strpath.members(sptr, index)

        # If our structure is a function frame, then certain members cannot be replaced.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        special = idaapi.get_member(sptr, idaapi.frame_off_retaddr(fn)) if fn and idaapi.get_frame_retsize(fn) and selected else None
        if special and any(special.id == mptr.id for _, mptr in selected if isinstance(mptr, idaapi.member_t)):
            midx, mname = next(idx for idx in range(sptr.memqty) if sptr.members[idx].id == special.id), member.get_name(special)
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to replace the special member \"{:s}\" at index {:d} of the frame belonging to function {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, mname, midx, ea))

        # Since our assignment will be desctructive, we need to calculate the
        # original size and the new size before figuring out how to assign things.
        iterable = (mptr for offset, mptr in selected)
        oldsize, newsize = (interface.contiguous.size(members) for members in [iterable, items])

        # Next since we want to confirm any references that get destroyed, we
        # collect all references to any of the members that were selected.
        iterable = ((offset, mptr, interface.xref.to(mptr.id, idaapi.XREF_ALL)) for offset, mptr in selected if isinstance(mptr, idaapi.member_t))
        references = {offset : (mptr.id, [packed_frm_iscode_type for packed_frm_iscode_type in refs]) for offset, mptr, refs in iterable}
        references[idaapi.get_struc_size(sptr.id)] = sptr.id, [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(sptr.id, idaapi.XREF_ALL)]

        # Before we do any serious damage to the union/structure, save the
        # selected member data that we plan on overwriting with our new items.
        iterable = ((offset, mptr) for offset, mptr in selected if isinstance(mptr, idaapi.member_t))
        olditems = {offset : member.packed(base, mptr) for offset, mptr in iterable}

        # Now we can layout each member that we're going to assign contiguously. This
        # way we can collect their offset and the minimum attributes into a list.
        newitems, area_t, iterable = [], idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t, interface.contiguous.layout(left, items, +1)
        layout = ((sptr.memqty + idx, item) for idx, (_, item) in enumerate(iterable)) if union(sptr) else iterable
        for offset, item in layout:
            if isinstance(item, (types.integer, interface.bounds_t, area_t, interface.namedtypedtuple, interface.symbol_t)):
                msize = interface.range.size(item) if isinstance(item, area_t) else item.size if hasattr(item, 'size') else item
                assert(isinstance(msize, types.integer)), u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to determine member size ({!r}) for an unsupported type {!s} ({!r}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, msize, item.__class__, item)
                mptr = msize

            # If it's one of the known member types, then we can extract the mptr.
            elif isinstance(item, (member_t, idaapi.member_t)):
                mptr = item if isinstance(item, idaapi.member_t) else item.ptr

            # If it's structure-like, then we need to convert it into its sptr.
            elif isinstance(item, (structure_t, members_t, idaapi.struc_t)):
                owner = item.owner if isinstance(item, idaapi.member_t) else item
                mptr = owner if isinstance(owner, idaapi.struc_t) else owner.ptr

            # If it's a type of some sort, then we need to see if we can actually parse it.
            elif isinstance(item, (idaapi.tinfo_t, types.string)):
                ti = item if isinstance(item, idaapi.tinfo_t) else interface.tinfo.parse(None, item, idaapi.PT_SIL|idaapi.PT_VAR) or interface.tinfo.parse(None, item, idaapi.PT_SIL)
                if not ti:
                    raise E.InvalidTypeOrValueError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to parse the given string (\"{:s}\") into a valid type.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, utils.string.escape("{!s}".format(item), '"')))
                mptr = item

            # If it's pythonic and we can get a non-zero size, then preserve it for later.
            elif interface.typemap.size(item):
                mptr = item

            # Anything else, we have no idea how to handle and so we can just bail here.
            else:
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to determine member attributes for an unsupported type {!s} ({!r}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, item.__class__, item))

            # Now we can add the member and offset, but we first need to validate it
            # in that we can't add the same structure to itself, and convert it into
            # an flag, opinfo, bytes, and other stuff so and that we can add it as a member.
            if isinstance(mptr, idaapi.struc_t):
                opinfo, nbytes = idaapi.opinfo_t(), idaapi.get_struc_size(mptr)
                if mptr.id == sptr.id:
                    logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Trying to assign a {:s} ({:#x}) to itself at {:s} will result in an empty member of {:d} byte{:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, 'union' if union(sptr) else 'structure', mptr.id, "index {:d}".format(offset) if union(sptr) else "offset {:#x}".format(offset), nbytes, '' if nbytes == 1 else 's'))
                opinfo.tid = mptr.id

                # We were given a structure, so we just need to get the type and the correct flags.
                tinfo = None if mptr.id == sptr.id else address.type(mptr.id)
                flag = idaapi.struflag() if idaapi.__version__ < 7.0 else idaapi.stru_flag()

                # Copy any repeatable comment from the structure as a non-repeatable comment.
                cmt = idaapi.get_struc_cmt(mptr.id, True)
                comments = [utils.string.of(cmt)]   # index 0 (False)

            # Make an exact copy of the member information, comments, type information, and all.
            elif isinstance(mptr, idaapi.member_t):
                nbytes, tinfo, opinfo = idaapi.get_member_size(mptr), member.get_typeinfo(mptr), idaapi.opinfo_t()
                flag, res = mptr.flag, idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
                opinfo = opinfo if res else None

                # Extract the comments in order...index 0 (False) is non-repeatable, index 1 (True) is repeatable.
                comments = [utils.string.of(idaapi.get_member_cmt(mptr.id, repeatable)) for repeatable in [False, True]]

            # If we received a type or a string, then we'll need to figure out
            # the flags so that we can properly assign things to the structure.
            elif isinstance(mptr, (idaapi.tinfo_t, types.string)):
                has_name = interface.tinfo.parse(None, "{!s}".format(mptr), idaapi.PT_SIL|idaapi.PT_VAR)
                tinfo = mptr if isinstance(mptr, idaapi.tinfo_t) else interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR)[-1] if has_name else interface.tinfo.parse(None, mptr, idaapi.PT_SIL)

                # Figure out the operand info and flags using the type we received.
                opinfo, comments, nbytes = idaapi.opinfo_t(), [], tinfo.get_size()
                sid = opinfo.tid = idaapi.get_struc_id(tinfo.get_type_name() or '')
                flag = idaapi.get_flags_by_size(tinfo.get_size()) if sid == idaapi.BADADDR else FF_STRUCT

            # If our mptr is not a size, then this is a pythonic type that we need to resolve.
            elif not isinstance(mptr, types.integer):
                flag, typeid, nbytes = interface.typemap.resolve(mptr)
                opinfo, tinfo, comments = idaapi.opinfo_t(), idaapi.tinfo_t(), []
                opinfo.tid = typeid

            # This should just be a size and nothing else.
            else:
                opinfo, flag, nbytes, tinfo, comments = None, 0, mptr, None, []

            # Pack all of the member information so that we can add the information later,
            # and verify the size to ensure we aren't trying to add a variable-sized member.
            packed = opinfo, flag, nbytes, tinfo, comments
            if nbytes:
                newitems.append((offset, mptr, packed))
            else:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Skipping the addition of member at {:s} of {:s} due to not having a valid size ({:d}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, "index {:d}".format(offset) if union(sptr) else "offset {:#x}".format(base + offset), 'union' if union(sptr) else 'structure', nbytes))
            continue

        # So, in order to ensure we don't have any errors we need to confirm that any new members
        # we create do not have a duplicate name. This can happen when expanding or shrinking a
        # structure without adjusting the names, or if the user explicitly specifies a default name.
        iterable = (sptr.members[index] for index in builtins.range(sptr.memqty))
        filtered = ((mptr, member.get_name(mptr)) for mptr in iterable if mptr.soff not in olditems)
        used = {utils.string.of(mname) : mptr for mptr, mname in filtered if mname}

        # We need to go through all of the newitems and figure out if any of the names
        # will end up being duplicated. To accomplish this, we'll figure out the names
        # in multiple passes. The first pass will gather all of the user-proposed names.
        newnames = {}
        for offset, mptr, _ in newitems:
            if isinstance(mptr, idaapi.member_t):
                mname = member.get_name(mptr)
            elif isinstance(mptr, idaapi.struc_t):
                mname = member.default_name(sptr, None, offset)
            elif isinstance(mptr, types.string) and interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR):
                mname, _ = interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR)
            elif not isinstance(mptr, types.integer):
                mname = member.default_name(sptr, None, offset)
            else:
                mname = ''
            newnames[offset] = mname

        # The second pass requires us to go through each of the newnames. We check all
        # of them to ensure that none of them match any of the names that have been
        # used elsewhere within the structure. If so, then we give them a field name.
        original, candidates, unavailable = {}, {}, {name for name in used} | {''}
        for offset, mptr, _ in newitems:
            if isinstance(mptr, (idaapi.tinfo_t, types.string)):
                has_name = interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR) if isinstance(mptr, types.string) else False
                ti = mptr if isinstance(mptr, idaapi.tinfo_t) else interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR)[-1] if has_name else interface.tinfo.parse(None, mptr, idaapi.PT_SIL)
                mname = interface.tinfo.parse(None, mptr, idaapi.PT_SIL|idaapi.PT_VAR)[0] if isinstance(mptr, types.string) and has_name else newnames[offset]
                originalname = mname or member.default_name(sptr, None, offset)
                original[offset] = newnames[offset] = originalname
                candidates.setdefault(originalname, []).append(offset)

            # We skip all anonymous members, so we only need to determine the default
            # name when there's a field with some type information to use.
            elif isinstance(mptr, idaapi.member_t):
                mname = '' if idaapi.is_special_member(mptr.id) else newnames[offset]
                originalname = mname or member.default_name(sptr, None, offset)
                original[offset] = newnames[offset] = originalname
                candidates.setdefault(mname, []).append(offset)

            # Check if the item is non-anonymous type by checking against an
            # integer. If it's not an integer, then sure it gets a default name.
            elif not isinstance(mptr, types.integer):
                mname = member.default_name(sptr, None, offset)
                original[offset] = newnames[offset] = mname
                candidates.setdefault(mname, []).append(offset)
            continue

        # Now we should have all the candidate names, so we start by figuring out
        # which of our names are duplicates that we can't use. Any name with more
        # than one offset or that exists within our used names needs to be fixed.
        duplicates = {mname : offsets for mname, offsets in candidates.items() if len(offsets) > 1 or mname in used}
        unavailable = unavailable | {mname for mname in candidates}
        frargs = idaapi.frame_off_args(fn) if fn else 0
        for mname, offsets in duplicates.items():
            for offset in offsets:
                oldname = newnames[offset]
                assert(oldname == mname)

                name, adjusted = mname, offset if not fn else offset - frargs if frargs <= offset else offset - fn.frsize
                while name in unavailable:
                    name = '_'.join([name, "{:X}".format(adjusted)])
                newname = name

                newnames[offset] = newname
            continue

        # Now we'll do a final pass through all of the members so that we can
        # log what names we were able to use and what names were duplicates.
        for offset, mptr, _ in newitems:
            if isinstance(mptr, types.integer) or original[offset] == newnames[offset]:
                continue

            # We only need to log name changes for non-anonymous members.
            oldname, newname = original[offset], newnames[offset]
            if isinstance(mptr, idaapi.member_t):
                new_descr = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)
                old_descr = "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + mptr.soff)
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s}({:#x}) as the member ({:#x}) at {:s} is currently using the requested name \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'structure', sptr.id, mptr.id, old_descr, utils.string.escape(oldname, '"')))

            elif isinstance(mptr, (idaapi.tinfo_t, types.string)):
                conflict = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
                new_descr = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)
                old_descr = "member ({:#x}) at {:s} is currently using the requested name \"{:s}\"".format(conflict.id, "index {:d}".format(conflict.soff) if union(sptr) else "offset {:+#x}".format(base + conflict.soff), utils.string.escape(oldname, '"')) if conflict else "original name \"{:s}\" is currenty being used".format(utils.string.escape(oldname, '"'))
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s}({:#x}) as the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'structure', sptr.id, old_descr))

            elif not isinstance(mptr, types.integer):
                conflict = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
                new_descr = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)
                old_descr = "member ({:#x}) at {:s} is currently using the requested name \"{:s}\"".format(conflict.id, "index {:d}".format(conflict.soff) if union(sptr) else "offset {:+#x}".format(base + conflict.soff), utils.string.escape(oldname, '"')) if conflict else "original name \"{:s}\" is currenty being used".format(utils.string.escape(oldname, '"'))
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s}({:#x}) as the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'structure', sptr.id, old_descr))
            continue

        # If we're using a union, we need some way to identify each member since removing a
        # member changes the index and reorders things. I tried snagging the member_t.soff,
        # but it didn't seem to work. So instead, we grab the id and look it up every time.
        if union(sptr):
            res, identifiers = 0, {mptr.id for idx, mptr in selected if idx in olditems}
            for packed in map(idaapi.get_member_by_id, identifiers):
                if not packed:
                    continue

                # Unpack the member using its identifier and smoke-check the structure that owns it.
                mptr, fullname, owner = packed
                ok = owner.id == sptr.id and idaapi.del_struc_member(sptr, mptr.soff)

                # If the identifier didn't match, then the identifer we used returned the
                # wrong structure somehow. This warrants an exception, but we're in the
                # process of modifying the structure and we need to finish our changes.
                if not ok and owner.id != sptr.id:
                    logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : The {:s} owning the member ({:#x}) at {:s} that is attempting to be removed does not actually belong to us and may result in fatal error.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, 'union' if union(owner) else 'structure', mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset)))

                # Now we can attempt to remove the damned thing.
                res += 1 if ok else 0

            count = res

        # Now, since we've extracted all of the packed information and references for the old
        # items, we can delete the entire range in preparation to adjust the structure size.
        else:
            count = idaapi.del_struc_members(sptr, left, right) if olditems else 0
        errors = {} if count == len(olditems) else {offset : idaapi.get_member(sptr, offset) for offset in olditems}

        # If we collected any errors, then here's where we'll expose our failures to the user.
        if errors:
            for offset, mptr in selected:
                if errors.get(offset):
                    logging.critical(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to remove the selected member ({:#x}) from {:s} of {:s} for replacement.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure'))
                continue

        # If we didn't remove all of the items that we expected, then we should prolly bail.
        # FIXME: We should probably revert and restore the olditems that we've already partially removed.
        if count != len(olditems):
            raise E.DisassemblerError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Expected to remove {:d} member{:s}, but {:d} were removed.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, len(olditems), '' if len(olditems) == 1 else 's', count))

        # Now we need to figure out whether we're growing the structure, or shrinking it.
        delta = 0 if union(sptr) else newsize - oldsize
        if delta and not idaapi.expand_struc(sptr, left, delta):
            raise E.DisassemblerError(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to {:s} the size of the structure by {:d} byte{:s} at offset {:+#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, 'decrease' if delta < 0 else 'increase', abs(delta), '' if abs(delta) == 1 else 's', left))

        # If we shifted any of the members, then we need to add them to our
        # olditems list if we still want to track their references.
        midx = idaapi.get_next_member_idx(sptr, left)
        if delta > 0 and 0 <= midx:
            iterable = (sptr.members[idx] for idx in range(midx, sptr.memqty))
            olditems.update({mptr.soff : member.packed(base, mptr) for mptr in iterable})

        # That should do it.. So, we should only need to add the newitems to the structure.
        results, oldsize = [], idaapi.get_struc_size(sptr)
        for offset, item, packed in newitems:
            opinfo, flag, nbytes, _, _ = packed

            # Skip the member if it's just empty space.
            if isinstance(item, types.integer):
                logging.debug(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Skipping {!r} byte{:s} of space at {:s} of {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, nbytes, '' if nbytes == 1 else 's', "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure'))
                err, position = idaapi.STRUC_ERROR_MEMBER_OK, offset

            # Otherwise add it using the attributes that were packed into newitems.
            else:
                position = sptr.memqty if union(sptr) else offset
                logging.debug(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Adding member at {:s} as {:d} byte{:s} of space with the specified flags ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), nbytes, '' if nbytes == 1 else 's', flag))
                err = idaapi.add_struc_member(sptr, newnames[offset], idaapi.BADADDR if union(sptr) else position, flag, opinfo, nbytes)

            # Check to see if we encountered an error of some sort while trying to add the member.
            if err == idaapi.STRUC_ERROR_MEMBER_NAME:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) adding member at {:s} of {:s} due to {:s} (\"{:s}\").".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure', 'a duplicate field name', newnames[offset]))
            elif err == idaapi.STRUC_ERROR_MEMBER_OFFSET:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) adding member at {:s} of {:s} due to {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure', 'invalid offset', offset))
            elif err == idaapi.STRUC_ERROR_MEMBER_SIZE:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) adding member at {:s} of {:s} due to {:s} ({:d}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure', 'invalid field size', nbytes))
            elif err == idaapi.STRUC_ERROR_MEMBER_TINFO:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) adding member at {:s} of {:s} due to {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure', 'invalid type id', opinfo.tid))
            elif err == idaapi.STRUC_ERROR_MEMBER_STRUCT:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) adding member at {:s} of {:s} due to {:s} for {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure', 'bad structure identifier', sptr.id))
            elif err != idaapi.STRUC_ERROR_MEMBER_OK:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Error ({:#x}) while adding member at {:s} of {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'structure'))

            # Immediately rip the identifier out of the member if we were able to add it to the
            # structure/union succesfully. Apparently, the mptr (member_t) can completely go out
            # of scope for no good reason (whatsoever) while we're processing the new items list.
            mptr = idaapi.get_member(sptr, position)
            if err == idaapi.STRUC_ERROR_MEMBER_OK and mptr:
                results.append((position, mptr.id, packed))
            continue

        # And now the very last thing we need to do is to update the member
        # with any metadata such as comments, type information, etc.
        for offset, id, packed in results:
            opinfo, _, _, tinfo, comments = packed

            # Grab the member using the identifer we saved when we first added each member.
            mptr_fullname_owner = idaapi.get_member_by_id(id)
            if mptr_fullname_owner:
                mptr, fullname, owner = idaapi.get_member_by_id(id)

            # If we couldn't find it via its identifier, then skip onto the next one.
            else:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Skipping the application of type information for the member ({:#x}) at {:s} due to its identifier being invalid.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, id, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)))
                continue

            # If the member doesn't belong to our structure/union at all, then ignore it and move on.
            if owner.id != sptr.id:
                logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : The {:s} owning the member ({:#x}) at {:s} that is attempting to be removed does not actually belong to us ({:#x}) and will not have its type information copied.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, 'union' if union(owner) else 'structure', mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset), sptr.id))
                continue

            # Apply any type information that we were able to snag to the newly created member.
            # XXX: we should catch any exceptions raised here so that we don't interrupt the
            #      application of type information and other metadata to any missed members.
            if opinfo is not None and tinfo:
                member.set_typeinfo(mptr, tinfo)

            # Apply any comments that we might've needed to copy.
            for repeatable, string in enumerate(map(utils.string.to, comments)):
                if string and not idaapi.set_member_cmt(mptr, string, repeatable):
                    logging.debug(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Unable to update member ({:s}) at {:s} with {:s} comment \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, mptr.id, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'repeatable' if repeatable else 'non-repeatable', utils.string.escape(string, '"')))
                continue
            continue

        # XXX: The following logic updates any references that were made by the actions
        #      of this method. This is done by tracking the original references, stepping,
        #      the auto-queue, and then identifying which members gained which references.
        #      This allows us to whine to the user if a reference was lost, but really
        #      it's just so we can output everything that the action changed.

        # XXX: There's probably a huge performance cost to doing this, but personally I
        #      can't come up with a legitimate reason for wanting to script mass-assignments
        #      to structures/unions. Thus the reason for outputting these references is so
        #      you can verify that the assignment did exactly what you intended it to do.

        # Flatten all of the references so that we can step the auto queue for them.
        iterable = (([id] * len(refs), refs) for offset, (id, refs) in references.items())
        old = {xfrm : id for id, (xfrm, xiscode, xtype) in itertools.chain.from_iterable(itertools.starmap(zip, iterable))}
        [idaapi.auto_make_step(xfrm, xfrm + 1) for xfrm in old]

        # Next we'll grab all of the identifiers for the members we added, and use them
        # to filter the old references. This way we can filter those references and
        # identify which member the reference was moved to during our reassignment.
        name = utils.string.of(idaapi.get_struc_name(sptr.id))
        oldmembers = {id : (name, offset) for offset, (id, name, _, location, _) in olditems.items()}
        newmembers = {id : (member.get_name(id), offset) for offset, id, packed in results}
        oldmembers[sptr.id] = name, oldsize
        newmembers[sptr.id] = name, idaapi.get_struc_size(sptr)

        # If we shifted any of the old members, then include their references too.
        if delta > 0:
            newmembers.update({id : (name, offset + delta) for id, (name, offset) in oldmembers.items()})

        # Use the list of new members to grab the references that we stepped the auto-queue
        # for. This way we can compare both the new and old refs to verify they were applied.
        iterable = ((xfrm, interface.xref.of(xfrm, idaapi.XREF_ALL)) for xfrm in old)
        filtered = ((xfrm, {xto for xto, xiscode, xtype in refs if xto in newmembers}) for xfrm, refs in iterable)
        new = {xfrm : xtos for xfrm, xtos in filtered if xtos}

        # Now we can just take a union of the old and the new references to
        # figure out what has just transpired with regards to them.
        oldrefs, newrefs = ({ea for ea in refs} for refs in [old, new])
        for ea in oldrefs & newrefs:
            assert(new[ea])
            old_ea = old[ea]
            for new_ea in new[ea]:
                olditem, newitem = oldmembers[old[ea]], newmembers[new_ea]
                newname, newoffset = newitem
                oldname, oldoffset = olditem
                old_descr, new_descr = ("structure \"{:s}\"".format(utils.string.escape(name, '"')) if id == sptr.id else "field \"{:s}\" ({:+#x})".format(utils.string.escape(name, '"'), offset) for id, offset, name in zip([old_ea, new_ea], [oldoffset, newoffset], [oldname, newname]))
                logging.info(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Reference at address {:#x} has moved from {:s} to new {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, ea, old_descr, new_descr))
            continue

        # Any old references that aren't in the new references have been lost. This
        # should actually never happen if the disassembler is working properly.
        for ea in oldrefs - newrefs:
            old_ea = old[ea]
            oldname, oldoffset = oldmembers[old[ea]]
            logging.warning(u"{:s}({:#x}).members.__setitem__({:s}, {:s}) : Reference at address {:#x} that was referencing {:s} \"{:s}\" ({:+#x}) was lost during assignment.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, items_description, ea, 'structure' if old_ea == sptr.id else 'field', utils.string.escape(oldname, '"'), oldoffset))

        # Finally we can return everything that we've just removed back to the caller.
        iterable = (olditems[offset] for offset, _ in selected if offset in olditems)
        return [(mname, mtype, mlocation) for id, mname, mtype, mlocation, mcomments in iterable]

    def __delitem__(self, index):
        '''Remove the member(s) at the specified `index` non-destructively.'''
        cls, sptr, base, index_description = self.__class__, self.owner.ptr, self.baseoffset, "{!s}".format(index)
        _, _, selected = interface.strpath.members(sptr, index)

        # If our structure is a function frame, then certain members cannot be removed.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        special = idaapi.get_member(sptr, idaapi.frame_off_retaddr(fn)) if fn and idaapi.get_frame_retsize(fn) and selected else None
        if special and any(special.id == mptr.id for _, mptr in selected if isinstance(mptr, idaapi.member_t)):
            midx, mname = next(idx for idx in range(sptr.memqty) if sptr.members[idx].id == special.id), member.get_name(special)
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__delitem__({:s}) : Unable to remove the special member \"{:s}\" at index {:d} of the frame belonging to function {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, mname, midx, ea))

        # Iterate through and collect information about the members that we're going
        # to remove. This way we can still reference something despite the removal.
        members, references = {}, {}
        for offset, mptr in selected:
            if isinstance(mptr, idaapi.member_t):
                references[offset] = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mptr.id, idaapi.XREF_ALL)]
                members[offset] = member.packed(base, mptr)
            continue

        # If the structure is a union then we can simply remove the member at each
        # index, because there's no way to remove a union member non-descrutively.
        if union(sptr):
            order = sorted(index for index, mptr in selected if isinstance(mptr, idaapi.member_t))

            # Now we need to delete each union member. We do this in reverse order
            # so that when the indices get reordered, our copy will still reference
            # the correct index for the ones that we haven't processed yet.
            results = [(index, idaapi.del_struc_member(sptr, index)) for index in order[::-1]]
            failures = {index for index, success in results if not success}

        # Otherwise we need to cleanly remove each member that was selected. We just iterate
        # through everything, remove a member, add some space if necessary, rinse, repeat.
        else:
            size, delta, failures = idaapi.get_struc_size(sptr), 0, {offset for offset in []}
            for offset, mptr in sorted(selected, key=operator.itemgetter(0)):
                identifier, msize = (mptr.id, idaapi.get_member_size(mptr)) if isinstance(mptr, idaapi.member_t) else (None, mptr)

                # If we're an empty member, then our mptr is an integer size. So,
                # in this case we can just skip it because it can't store anything.
                if identifier is None:
                    continue

                # We need to track every time we remove a member, but are unable to
                # expand the struc. This has the effect of shifting the member offset,
                # and so we track the delta and adjust our offset using it.
                realoffset = offset + delta

                # Delete the member. If we did but a member still exists..then add the
                # space back. This only happens on older versions of the disassembler.
                ok = idaapi.del_struc_member(sptr, realoffset)
                if ok and (idaapi.expand_struc(sptr, realoffset, msize) if idaapi.get_member(sptr, realoffset) else True):
                    pass

                # We were unable to add the empty space back into the structure.
                elif ok and size != idaapi.get_struc_size(sptr):
                    logging.info(u"{:s}({:#x}).members.__delitem__({:s}) : Unable to add space ({:d}) back to offset {:#x} of structure after removing member {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, msize, realoffset, offset, identifier))
                    delta -= msize

                # We couldn't remove the structure at all, which means that we
                # couldn't honor the request the user has made of us.
                else:
                    failures.add(offset)
                continue

            # We need both the order and failures initialized in order to proceed.
            order = sorted(offset for offset, mptr in selected)

        # Before we emit any error messages, we need to collect any references to the
        # union/structure that owns the member. This is so we can exclude any xrefs that
        # have been promoted, and only warn about the xrefs that have been truly lost.
        iterable = (packed_frm_iscode_type for offset, packed_frm_iscode_type in references.items() if offset not in failures)
        processed = {xfrm for xfrm, _, _ in itertools.chain(*iterable) if idaapi.auto_make_step(xfrm, xfrm + 1)}
        promoted = {xfrm for xfrm, xiscode, xtype in interface.xref.to(sptr.id, idaapi.XREF_ALL)}

        # Now we should have a list of member indices/offsets that were processed, a set of
        # indices/offsets that failed, references, and packed information for the members.
        for offset, mptr in selected:
            if offset not in members: continue
            packed = members[offset]

            # Unpack some member attributes so that we can reference them in any logs.
            identifier, mname, _, _, _ = packed
            location_description = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(offset)

            # If we were unable to remove a specific member, then log information about
            # the member so that the user knows that something unexpected happened.
            if offset in failures:
                logging.warning(u"{:s}({:#x}).members.__delitem__({:s}) : Unable to remove member \"{:s}\" ({:#x}) that was at {:s} of {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, utils.string.escape(mname, '"'), identifier, location_description, 'union' if union(sptr) else 'structure'))
                mreferences = []

            # Otherwise, we removed the member and we need to check if any references
            # were lost. We preloaded these, so we just need to format them properly.
            else:
                mreferences = references[offset]

            # Now we collect our member references into a list of descriptiosn so that
            # we can let the user know which refs have been lost in the member removal.
            cdrefs = [((None, xfrm) if interface.node.identifier(xfrm) else (xfrm, None)) for xfrm, xiscode, xtype in mreferences if xfrm not in promoted]
            crefs, drefs = ([ea for ea in xrefs if ea is not None] for xrefs in zip(*cdrefs)) if cdrefs else [(), ()]

            # First we do the list of addresses...
            if crefs:
                logging.warning(u"{:s}({:#x}).members.__delitem__({:s}) : Removal of member \"{:s}\" ({:#x}) has resulted in the removal of {:d} reference{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, utils.string.escape(mname, '"'), identifier, len(crefs), '' if len(crefs) == 1 else 's', ', '.join(map("{:#x}".format, crefs))))

            # ...then we can do the identifiers which includes structures/unions, members, or whatever.
            if drefs:
                logging.warning(u"{:s}({:#x}).members.__delitem__({:s}) : Removal of member \"{:s}\" ({:#x}) has resulted in the removal of {:d} referenced identifier{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, utils.string.escape(mname, '"'), identifier, len(drefs), '' if len(drefs) == 1 else 's', ', '.join(map("{:#x}".format, drefs))))
                [logging.info(u"{:s}({:#x}).members.__delitem__({:s}) : Removed member \"{:s}\" ({:#x}) used to reference \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, index_description, utils.string.escape(mname, '"'), identifier, internal.netnode.name.get(id), id)) for id in drefs]
            continue

        # Finally we can just return the packed information that we deleted from the structure.
        iterable = ((offset, mptr) for offset, mptr in selected)
        iterable = ((offset, members[offset] if offset in members else mptr) for offset, mptr in iterable if offset not in failures)
        iterable = ((('', None, interface.location_t(base + offset, packed)) if isinstance(packed, types.integer) else packed[+1 : -1]) for offset, packed in iterable)
        return [(mname, mtype, mlocation) for mname, mtype, mlocation in iterable]

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

        originalname = utils.string.of(idaapi.get_struc_name(sptr.id) or '')
        validname = internal.declaration.unmangled.parsable(originalname)
        name = originalname if originalname == validname else (originalname, validname)
        parent = sptr.props, name

        return (parent, self.baseoffset, items)
    def __setstate__(self, state):
        owner, baseoffset, _ = state

        # figure out our parent here.
        if isinstance(owner, types.tuple) and len(owner) == 2:
            sprops, packed_name = owner

        # backwards compatibility
        elif isinstance(owner, types.string):
            sprops, packed_name = 0, owner

        # first check if the name is a tuple, if it isn't then we're good.
        if not isinstance(packed_name, tuple):
            ownername = original = packed_name

        # but if it's a tuple, then the name is not be parsable from the type library
        # and we need to figure out whether to use the original or the parsable one.
        else:
            original, parsable = packed_name
            ownername = parsable if idaapi.get_struc_id(utils.string.to(original)) == idaapi.BADADDR else original

        # grab the structure containing our members so we can instantiate it
        res = utils.string.to(ownername)
        identifier = idaapi.get_struc_id(res)
        if identifier == idaapi.BADADDR:
            cls = self.__class__
            logging.warning(u"{:s}({:#x}) : Creating `members_t` for `structure_t` \"{:s}\" with no members.".format('.'.join([__name__, cls.__name__]), identifier, utils.string.escape(ownername, '"')))
            identifier = idaapi.add_struc(idaapi.BADADDR, res, True if sprops & idaapi.SF_UNION else False)

        # assign the properties for our new member using the instance we figured out
        self.baseoffset = baseoffset
        self.__owner__ = new(identifier, offset=baseoffset)

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
